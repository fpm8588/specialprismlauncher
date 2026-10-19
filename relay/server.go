package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// RoutePrefix is the path prefix the Prism client puts in front of the
	// upstream host: <relay>/r/<upstream-host>/<upstream-path>?<query>
	RoutePrefix = "/r/"
	// TokenHeader carries the shared secret. It is never forwarded upstream.
	TokenHeader = "X-Relay-Token"

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
	Logger       *log.Logger
}

// Server is an authenticated, allowlisted HTTP relay.
type Server struct {
	cfg       Config
	tokenHash [sha256.Size]byte
	client    *http.Client
	limiter   *authLimiter
}

// NewServer validates cfg and builds a Server.
func NewServer(cfg Config) (*Server, error) {
	if len(cfg.Token) < 16 {
		return nil, errors.New("token must be at least 16 characters")
	}
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
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}

	s := &Server{
		cfg:       cfg,
		tokenHash: sha256.Sum256([]byte(cfg.Token)),
		limiter:   newAuthLimiter(maxAuthFailures, authLockout),
	}

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

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ip := clientIP(r)

	if s.limiter.locked(ip) {
		http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
		return
	}
	if !s.authorized(r) {
		s.limiter.fail(ip)
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
		http.Error(w, "bad route: expected "+RoutePrefix+"<host>/<path>", http.StatusBadRequest)
		return
	}
	if !s.cfg.Allow.Match(host) {
		s.cfg.Logger.Printf("DENY  %s %s (host not on allowlist)", r.Method, host)
		http.Error(w, "relay: host not allowed: "+host+" (add it with -allow or -allow-file)", http.StatusForbidden)
		return
	}

	target, err := url.Parse(s.cfg.Scheme + "://" + host + rest)
	if err != nil || !strings.EqualFold(target.Host, host) {
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
		s.cfg.Logger.Printf("ERR   %s %s%s: %v", r.Method, host, rest, err)
		http.Error(w, "relay: upstream error: "+upstreamErrorText(err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	n, copyErr := io.Copy(w, resp.Body)

	status := fmt.Sprintf("%d", resp.StatusCode)
	if copyErr != nil {
		status += " (copy aborted: " + copyErr.Error() + ")"
	}
	// The query string is deliberately not logged: it can carry tokens.
	s.cfg.Logger.Printf("OK    %s %s%s -> %s %dB %s", r.Method, host, rest, status, n, time.Since(start).Round(time.Millisecond))
}

func (s *Server) authorized(r *http.Request) bool {
	got := sha256.Sum256([]byte(r.Header.Get(TokenHeader)))
	return subtle.ConstantTimeCompare(got[:], s.tokenHash[:]) == 1
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
	if !s.cfg.Allow.Match(req.URL.Host) {
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
