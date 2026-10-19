package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// RoutePrefix is the path prefix the Prism client puts in front of the
	// upstream host: <relay>/r/<upstream-host>/<upstream-path>?<query>
	RoutePrefix = "/r/"
	// TokenHeader carries the shared secret. It is never forwarded upstream.
	TokenHeader = "X-Relay-Token"
	// MinTokenLen is the shortest token the relay accepts.
	MinTokenLen = 24

	maxAuthFailures = 10
	authLockout     = 15 * time.Minute
)

// Config configures a Server.
type Config struct {
	Token        string
	Allow        *Allowlist
	Scheme       string // scheme used toward upstream; "https" unless testing
	AllowPrivate bool   // allow upstream IPs in private ranges; tests only
	MaxBody      int64  // max request body accepted from the client
	MaxRedirects int
	OnEvent      func(Event) // called for everything the relay does; may be nil
}

// Server is an authenticated, allowlisted HTTP relay. The token and the
// allowlist can be replaced while it is serving.
type Server struct {
	cfg     Config
	token   atomic.Pointer[[sha256.Size]byte]
	allow   atomic.Pointer[Allowlist]
	client  *http.Client
	limiter *authLimiter
}

// NewServer validates cfg and builds a Server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Allow == nil {
		return nil, errors.New("allowlist is required")
	}
	if cfg.Scheme == "" {
		cfg.Scheme = "https"
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 64 << 20
	}
	if cfg.MaxRedirects <= 0 {
		cfg.MaxRedirects = 8
	}

	s := &Server{cfg: cfg, limiter: newAuthLimiter(maxAuthFailures, authLockout)}
	if err := s.SetToken(cfg.Token); err != nil {
		return nil, err
	}
	s.SetAllowlist(cfg.Allow)

	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	if !cfg.AllowPrivate {
		dialer.Control = refusePrivateAddresses
	}
	transport := &http.Transport{
		Proxy:                 nil, // never inherit HTTP(S)_PROXY from the environment
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   16,
		ForceAttemptHTTP2:     true,
		// Pass Content-Encoding through untouched instead of decoding it here.
		DisableCompression: true,
	}
	s.client = &http.Client{
		Transport:     transport,
		CheckRedirect: s.checkRedirect,
		// no overall Timeout: libraries and Java runtimes can be large.
	}
	return s, nil
}

// SetToken replaces the shared secret. Existing connections are not affected,
// but new requests must present the new token.
func (s *Server) SetToken(token string) error {
	if len(token) < MinTokenLen {
		return fmt.Errorf("token must be at least %d characters", MinTokenLen)
	}
	h := sha256.Sum256([]byte(token))
	s.token.Store(&h)
	return nil
}

// SetAllowlist replaces the set of upstream hosts the relay may contact.
func (s *Server) SetAllowlist(a *Allowlist) { s.allow.Store(a) }

// Client returns the HTTP client the relay uses toward upstream hosts (for diagnostics).
func (s *Server) Client() *http.Client { return s.client }

func (s *Server) emit(e Event) {
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(e)
	}
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ip := clientIP(r)

	if s.limiter.locked(ip) {
		s.emit(Event{Kind: KindLocked, Client: ip, Note: "too many wrong tokens"})
		http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
		return
	}
	if !s.authorized(r) {
		s.limiter.fail(ip)
		s.emit(Event{Kind: KindAuth, Method: r.Method, Client: ip, Note: "missing or wrong token"})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.limiter.succeed(ip)

	if r.URL.Path == "/healthz" {
		fmt.Fprintln(w, "ok")
		return
	}

	host, rest, ok := splitRoute(r.URL.EscapedPath())
	if !ok {
		s.emit(Event{Kind: KindBad, Method: r.Method, Path: r.URL.Path, Client: ip, Note: "bad route"})
		http.Error(w, "bad route: expected "+RoutePrefix+"<host>/<path>", http.StatusBadRequest)
		return
	}
	if !s.allow.Load().Match(host) {
		s.emit(Event{Kind: KindDeny, Method: r.Method, Host: host, Path: rest, Client: ip, Note: "host not on allowlist"})
		http.Error(w, "relay: host not allowed: "+host+" (add it on the Allowed hosts tab)", http.StatusForbidden)
		return
	}

	target, err := url.Parse(s.cfg.Scheme + "://" + host + rest)
	if err != nil || !strings.EqualFold(target.Host, host) {
		s.emit(Event{Kind: KindBad, Method: r.Method, Host: host, Client: ip, Note: "bad upstream url"})
		http.Error(w, "bad upstream url", http.StatusBadRequest)
		return
	}
	target.RawQuery = r.URL.RawQuery

	body := io.Reader(http.NoBody)
	if r.ContentLength != 0 {
		body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBody)
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.ContentLength = r.ContentLength
	copyRequestHeaders(req.Header, r.Header)

	resp, err := s.client.Do(req)
	if err != nil {
		s.emit(Event{Kind: KindError, Method: r.Method, Host: host, Path: rest, Client: ip,
			Millis: time.Since(start).Milliseconds(), Note: upstreamErrorText(err)})
		http.Error(w, "relay: upstream error: "+upstreamErrorText(err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	n, copyErr := io.Copy(w, resp.Body)

	ev := Event{Kind: KindOK, Method: r.Method, Host: host, Path: rest, Status: resp.StatusCode, Bytes: n,
		Millis: time.Since(start).Milliseconds(), Client: ip}
	if copyErr != nil {
		ev.Note = "copy aborted: " + copyErr.Error()
	}
	// The query string is deliberately not part of the event: it can carry tokens.
	s.emit(ev)
}

func (s *Server) authorized(r *http.Request) bool {
	got := sha256.Sum256([]byte(r.Header.Get(TokenHeader)))
	return subtle.ConstantTimeCompare(got[:], s.token.Load()[:]) == 1
}

// checkRedirect follows redirects on the relay side so the client never sees
// them, but only toward allowlisted hosts over the configured scheme.
func (s *Server) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= s.cfg.MaxRedirects {
		return fmt.Errorf("stopped after %d redirects", s.cfg.MaxRedirects)
	}
	if req.URL.Scheme != s.cfg.Scheme {
		return fmt.Errorf("redirect to %s:// is not allowed", req.URL.Scheme)
	}
	if !s.allow.Load().Match(req.URL.Host) {
		return fmt.Errorf("redirect to host %q which is not on the allowlist", req.URL.Host)
	}
	return nil
}

// splitRoute splits "/r/<host>/<rest>" into host and "/<rest>" (still escaped).
func splitRoute(escapedPath string) (host, rest string, ok bool) {
	if !strings.HasPrefix(escapedPath, RoutePrefix) {
		return "", "", false
	}
	p := escapedPath[len(RoutePrefix):]
	host, rest, _ = strings.Cut(p, "/")
	rest = "/" + rest
	if host == "" || !validHost(host) {
		return "", "", false
	}
	return strings.ToLower(host), rest, true
}

func validHost(h string) bool {
	for _, c := range h {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == ':':
		default:
			return false
		}
	}
	return true
}

var hopByHop = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true,
	"Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true,
	"Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

// stripped from requests so upstream sees a plain client, not a relayed one.
var requestOnlyDrop = map[string]bool{
	"Host": true, "Forwarded": true, "Via": true,
	"X-Forwarded-For": true, "X-Forwarded-Host": true, "X-Forwarded-Proto": true, "X-Real-Ip": true,
	"X-Relay-Token": true,
}

func copyRequestHeaders(dst, src http.Header) {
	extra := connectionTokens(src)
	for k, vv := range src {
		if hopByHop[k] || requestOnlyDrop[k] || extra[k] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func copyResponseHeaders(dst, src http.Header) {
	extra := connectionTokens(src)
	for k, vv := range src {
		if hopByHop[k] || extra[k] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// connectionTokens returns header names listed in the Connection header.
func connectionTokens(h http.Header) map[string]bool {
	out := map[string]bool{}
	for _, v := range h.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				out[http.CanonicalHeaderKey(t)] = true
			}
		}
	}
	return out
}

func upstreamErrorText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.Canceled) {
		return "client went away"
	}
	return err.Error()
}

// refusePrivateAddresses is a net.Dialer.Control hook. Hosts are checked
// against the allowlist by name, but DNS could still point an allowed name at
// the home LAN, so the resolved address is checked too.
func refusePrivateAddresses(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("unparseable dial address %q", address)
	}
	if isPrivateIP(ip) {
		return fmt.Errorf("refusing to connect to non-public address %s", ip)
	}
	return nil
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || cgnat.Contains(ip)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authLimiter locks out an address after too many bad tokens.
type authLimiter struct {
	mu       sync.Mutex
	max      int
	lockFor  time.Duration
	failures map[string]*failState
}

type failState struct {
	count int
	until time.Time // lockout end, zero if not locked
	last  time.Time
}

func newAuthLimiter(max int, lockFor time.Duration) *authLimiter {
	return &authLimiter{max: max, lockFor: lockFor, failures: map[string]*failState{}}
}

func (l *authLimiter) locked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.failures[ip]
	if st == nil {
		return false
	}
	if !st.until.IsZero() {
		if time.Now().Before(st.until) {
			return true
		}
		delete(l.failures, ip)
	}
	return false
}

func (l *authLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, st := range l.failures { // opportunistic cleanup keeps the map bounded
		if now.Sub(st.last) > l.lockFor {
			delete(l.failures, k)
		}
	}
	st := l.failures[ip]
	if st == nil {
		st = &failState{}
		l.failures[ip] = st
	}
	st.count++
	st.last = now
	if st.count >= l.max {
		st.until = now.Add(l.lockFor)
	}
}

func (l *authLimiter) succeed(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, ip)
}
