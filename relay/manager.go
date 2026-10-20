package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Relay states.
const (
	StateStopped          = "stopped"
	StateRunning          = "running"
	StateError            = "error"
	letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Status describes the relay listener.
type Status struct {
	State         string    `json:"state"`
	Error         string    `json:"error,omitempty"`
	Addr          string    `json:"addr,omitempty"`
	StartedAt     time.Time `json:"startedAt,omitempty"`
	RestartNeeded bool      `json:"restartNeeded"`
}

// CertInfo describes the certificate the relay presents.
type CertInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	DNSNames  []string  `json:"dnsNames"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	Staging   bool      `json:"staging"`
}

// ProbeResult is one line of the self-test.
type ProbeResult struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	OK     bool   `json:"ok"`
	Status int    `json:"status,omitempty"`
	Millis int64  `json:"ms"`
	Error  string `json:"error,omitempty"`
}

type probeTarget struct{ Name, URL string }

// defaultProbes are one reachable URL per service the launcher depends on. Any HTTP
// response counts as reachable: libraries.minecraft.net, for instance, answers its root with an error page.
var defaultProbes = []probeTarget{
	{"Minecraft libraries", "https://libraries.minecraft.net/"},
	{"Minecraft version manifest", "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"},
	{"Minecraft assets", "https://resources.download.minecraft.net/"},
	{"Minecraft services (login)", "https://api.minecraftservices.com/"},
	{"Microsoft sign-in", "https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration"},
	{"Xbox sign-in", "https://user.auth.xboxlive.com/"},
	{"Prism metadata", "https://meta.prismlauncher.org/v1/index.json"},
	{"Forge Maven", "https://maven.minecraftforge.net/"},
	{"Modrinth", "https://api.modrinth.com/v2/"},
	{"CurseForge", "https://api.curseforge.com/"},
	{"GitHub", "https://github.com/"},
}

// Manager owns the relay: its settings, its listener, and what it has been doing.
type Manager struct {
	Dir     string
	Version string
	Store   *Store
	Events  *EventLog
	Stats   *Stats
	Relay   *Server

	mu      sync.Mutex
	state   string
	lastErr string
	started time.Time
	addr    string
	httpSrv *http.Server
	acm     *autocert.Manager
	// challengeSrv answers Let's Encrypt's "http-01" challenge on port 80 (automatic mode only).
	challengeSrv *http.Server
	httpAddr     string   // where challengeSrv listens; ":80" unless a test overrides it
	acmeFailures []string // reasons Let's Encrypt gave for failed validations since the last check began
	running      Settings // settings the listener was started with

	// overridable for tests
	probes []probeTarget
}

// NewManager opens the settings in dir and prepares (but does not start) the relay.
func NewManager(dir, version string, opts ...func(*Config)) (*Manager, error) {
	store, err := OpenStore(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil, err
	}
	var out io.Writer
	if f, err := NewRotatingFile(filepath.Join(dir, "relay.log"), 5<<20); err == nil {
		out = f
	}
	m := &Manager{Dir: dir, Version: version, Store: store, Events: NewEventLog(1000, out), Stats: NewStats(),
		state: StateStopped, probes: defaultProbes, httpAddr: ":80"}

	cfg := Config{OnEvent: m.record}
	for _, o := range opts {
		o(&cfg)
	}
	s := store.Get()
	cfg.Token, cfg.Allow = s.Token, s.Allowlist()
	if m.Relay, err = NewServer(cfg); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) record(e Event) {
	e = m.Events.Add(e)
	m.Stats.Add(e)
}

func (m *Manager) note(kind, msg string) { m.record(Event{Kind: kind, Note: msg}) }

// Apply pushes the token and allowlist from settings into the running relay.
func (m *Manager) Apply() error {
	s := m.Store.Get()
	if err := m.Relay.SetToken(s.Token); err != nil {
		return err
	}
	m.Relay.SetAllowlist(s.Allowlist())
	return nil
}

// Status returns the current listener state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{State: m.state, Error: m.lastErr, Addr: m.addr, StartedAt: m.started}
	if m.state == StateRunning {
		cur := m.Store.Get()
		st.RestartNeeded = cur.Domain != m.running.Domain || cur.TLSMode != m.running.TLSMode ||
			cur.ListenAddr() != m.running.ListenAddr() || cur.CertFile != m.running.CertFile ||
			cur.KeyFile != m.running.KeyFile || cur.LetsEncryptStaging != m.running.LetsEncryptStaging
	}
	return st
}

// Start begins listening. It returns an error (and records it in Status) if the settings or the port are unusable.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == StateRunning {
		return nil
	}
	err := m.startLocked()
	if err != nil {
		m.state, m.lastErr = StateError, err.Error()
		m.note(KindError, "could not start: "+err.Error())
		return err
	}
	return nil
}

func (m *Manager) startLocked() error {
	s := m.Store.Get()
	if err := s.Validate(); err != nil {
		return err
	}
	if err := m.Apply(); err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           m.Relay,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		// No Read/WriteTimeout: large downloads and uploads must be able to run.
	}

	var certFile, keyFile string
	switch s.TLSMode {
	case TLSAuto:
		if s.Domain == "" {
			return errors.New("set your domain name first (Server tab)")
		}
		m.acm = m.newAutocert(s)
		cfg := m.acm.TLSConfig() // handles the TLS-ALPN-01 challenge on the main port
		inner := cfg.GetCertificate
		cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			for _, proto := range h.SupportedProtos {
				if proto == acme.ALPNProto {
					m.record(Event{Kind: KindOK, Client: remoteHost(h.Conn), Note: "Let's Encrypt connected on the main port to verify the domain (tls-alpn-01)"})
				}
			}
			return inner(h)
		}
		srv.TLSConfig = cfg
	case TLSFiles:
		if s.CertFile == "" || s.KeyFile == "" {
			return errors.New("choose a certificate file and a key file first (Server tab)")
		}
		if _, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile); err != nil {
			return fmt.Errorf("could not load the certificate: %w", err)
		}
		certFile, keyFile = s.CertFile, s.KeyFile
	}

	ln, err := net.Listen("tcp", s.ListenAddr())
	if err != nil {
		return friendlyListenError(s.ListenAddr(), err)
	}

	m.httpSrv, m.addr, m.started, m.running = srv, ln.Addr().String(), time.Now(), s
	m.state, m.lastErr = StateRunning, ""
	m.note(KindOK, fmt.Sprintf("relay started on %s (%s)", m.addr, s.TLSMode))
	if s.TLSMode == TLSAuto {
		m.startChallengeServer()
	}

	go func() {
		var serveErr error
		if s.TLSMode == TLSPlain {
			serveErr = srv.Serve(ln)
		} else {
			serveErr = srv.ServeTLS(ln, certFile, keyFile)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			m.mu.Lock()
			if m.httpSrv == srv {
				m.state, m.lastErr = StateError, serveErr.Error()
			}
			m.mu.Unlock()
			m.note(KindError, "relay stopped unexpectedly: "+serveErr.Error())
		}
	}()
	return nil
}

// startChallengeServer listens on port 80 and answers Let's Encrypt's "http-01" challenge, in addition to the
// "tls-alpn-01" challenge on the main port. Let's Encrypt may offer only one of the two for a given order,
// and autocert fails with "no viable challenge type found" if it is prepared for only the other.
// Anything else arriving on port 80 is redirected to https. Failing to bind port 80 is not fatal.
func (m *Manager) startChallengeServer() {
	ln, err := net.Listen("tcp", m.httpAddr)
	if err != nil {
		m.note(KindError, "port 80 is not available ("+friendlyListenError(m.httpAddr, err).Error()+"); certificates will only be requested through the main port")
		return
	}
	challenge := m.acm.HTTPHandler(nil)
	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ev := Event{Kind: KindOK, Method: r.Method, Host: "(port 80)", Path: r.URL.Path, Client: clientIP(r)}
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			ev.Note = "Let's Encrypt connected on port 80 to verify the domain (http-01)"
		} else {
			ev.Note = "plain-http visitor, redirected to https"
		}
		m.record(ev)
		challenge.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: logged, ReadHeaderTimeout: 10 * time.Second}
	m.challengeSrv = srv
	m.note(KindOK, "listening on "+ln.Addr().String()+" for Let's Encrypt")
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.note(KindError, "port 80 listener stopped: "+err.Error())
		}
	}()
}

func (m *Manager) newAutocert(s Settings) *autocert.Manager {
	a := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(s.Domain),
		Cache:      autocert.DirCache(filepath.Join(m.Dir, certDirName(s))),
	}
	directory := acme.LetsEncryptURL
	if s.LetsEncryptStaging {
		directory = letsEncryptStagingURL
	}
	a.Client = &acme.Client{
		DirectoryURL: directory,
		HTTPClient:   &http.Client{Transport: &acmeSpy{base: http.DefaultTransport, onFailure: m.addACMEFailure}},
	}
	return a
}

func (m *Manager) addACMEFailure(msg string) {
	m.mu.Lock()
	dup := false
	for _, f := range m.acmeFailures {
		if f == msg {
			dup = true
		}
	}
	if !dup {
		m.acmeFailures = append(m.acmeFailures, msg)
	}
	m.mu.Unlock()
	m.note(KindError, "Let's Encrypt could not validate the domain: "+msg)
}

// takeACMEFailures returns and clears the failures collected so far.
func (m *Manager) takeACMEFailures() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := strings.Join(m.acmeFailures, " | ")
	m.acmeFailures = nil
	return out
}

// certDirName keeps staging certificates apart from real ones, so switching between them is safe.
func certDirName(s Settings) string {
	if s.LetsEncryptStaging {
		return "certs-staging"
	}
	return "certs"
}

func friendlyListenError(addr string, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "address already in use"), strings.Contains(msg, "Only one usage of each socket address"):
		return fmt.Errorf("port %s is already in use by another program (a web server, Skype, or a second copy of this app?). Pick another port on the Server tab, or close the other program", addr)
	case strings.Contains(msg, "permission denied"), strings.Contains(msg, "forbidden by its access permissions"):
		return fmt.Errorf("not allowed to listen on %s. Try another port, or run as administrator", addr)
	}
	return fmt.Errorf("cannot listen on %s: %w", addr, err)
}

// Stop shuts the listener down, letting in-flight requests finish for up to 10 seconds.
func (m *Manager) Stop() {
	m.mu.Lock()
	srv := m.httpSrv
	m.httpSrv = nil
	challenge := m.challengeSrv
	m.challengeSrv = nil
	wasRunning := m.state == StateRunning
	m.state, m.lastErr = StateStopped, ""
	m.mu.Unlock()
	if challenge != nil {
		_ = challenge.Close()
	}
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		_ = srv.Close()
	}
	if wasRunning {
		m.note(KindOK, "relay stopped")
	}
}

// Restart stops and starts the relay with the current settings.
func (m *Manager) Restart() error {
	m.Stop()
	return m.Start()
}

// CheckCertificate returns the certificate the relay would present. In automatic mode it asks Let's Encrypt for one
// if none is cached yet, which proves that port 443 is reachable from the internet. That can take up to 90 seconds.
func (m *Manager) CheckCertificate() (CertInfo, error) {
	s := m.Store.Get()
	switch s.TLSMode {
	case TLSPlain:
		return CertInfo{}, errors.New("plain HTTP mode has no certificate")
	case TLSFiles:
		pair, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			return CertInfo{}, err
		}
		return certInfo(pair, s.Domain, false)
	}
	if s.Domain == "" {
		return CertInfo{}, errors.New("set your domain name first")
	}
	m.takeACMEFailures() // forget failures from earlier checks
	m.mu.Lock()
	acm := m.acm
	live := m.state == StateRunning && m.running.TLSMode == TLSAuto && acm != nil
	stale := m.running.Domain != s.Domain || m.running.LetsEncryptStaging != s.LetsEncryptStaging
	m.mu.Unlock()
	if !live {
		return CertInfo{}, errors.New("start the relay first: Let's Encrypt connects to it from the internet to prove you own the domain")
	}
	if stale {
		return CertInfo{}, errors.New("you changed the domain or test mode since the relay started: restart the relay, then check again")
	}

	type result struct {
		cert *tls.Certificate
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := acm.GetCertificate(&tls.ClientHelloInfo{ServerName: s.Domain})
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			reason := m.takeACMEFailures()
			var lookupErr error
			if reason == "" { // nothing was seen go by: ask for the failed authorization itself
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				reason, lookupErr = letsEncryptReason(ctx, filepath.Join(m.Dir, certDirName(s)), s.LetsEncryptStaging, r.err)
				cancel()
			}
			switch {
			case reason != "":
				m.note(KindError, "certificate check failed; Let's Encrypt said: "+reason)
			case lookupErr != nil:
				m.note(KindError, "certificate check failed; could not fetch Let's Encrypt's reason: "+lookupErr.Error())
			}
			return CertInfo{}, certFailure(reason, lookupErr, r.err)
		}
		return certInfo(*r.cert, s.Domain, s.LetsEncryptStaging)
	case <-time.After(90 * time.Second):
		return CertInfo{}, errors.New("timed out waiting for Let's Encrypt. Ports 80 and 443 are probably not reachable from the internet; check the router's port forwarding")
	}
}

func explainCertError(err error) error {
	msg := err.Error()
	if strings.Contains(msg, "no viable challenge type") {
		return fmt.Errorf("Let's Encrypt could not verify the domain with either method. Forward both port 80 and port 443 to this PC, allow both in the firewall, then restart the relay and try again. If you have retried many times, wait an hour (Let's Encrypt limits failed attempts) or use test mode: %w", err)
	}
	if strings.Contains(msg, "no such host") || strings.Contains(msg, "NXDOMAIN") || strings.Contains(msg, "DNS problem") {
		return fmt.Errorf("Let's Encrypt cannot find your domain in DNS. Check that it points at your home IP address: %w", err)
	}
	if strings.Contains(msg, "Timeout") || strings.Contains(msg, "Connection refused") || strings.Contains(msg, "connection refused") || strings.Contains(msg, "Fetching") {
		return fmt.Errorf("Let's Encrypt could not connect to your domain. Forward both port 80 and port 443 to this PC and allow both in the Windows firewall: %w", err)
	}
	return err
}

func certInfo(pair tls.Certificate, domain string, staging bool) (CertInfo, error) {
	if len(pair.Certificate) == 0 {
		return CertInfo{}, errors.New("empty certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return CertInfo{}, err
	}
	return CertInfo{Subject: leaf.Subject.CommonName, Issuer: leaf.Issuer.CommonName, DNSNames: leaf.DNSNames,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Staging: staging}, nil
}

// SelfTest asks the relay's own HTTP client to reach each service the launcher needs. It shows whether
// this computer's connection, DNS and filtering allow what Prism will ask for.
func (m *Manager) SelfTest(ctx context.Context) []ProbeResult {
	results := make([]ProbeResult, len(m.probes))
	var wg sync.WaitGroup
	for i, p := range m.probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = m.probe(ctx, p)
		}()
	}
	wg.Wait()
	return results
}

func (m *Manager) probe(ctx context.Context, p probeTarget) ProbeResult {
	r := ProbeResult{Name: p.Name, URL: p.URL}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	req.Header.Set("User-Agent", "prism-relay/"+m.Version+" self-test")
	resp, err := m.Relay.Client().Do(req)
	r.Millis = time.Since(start).Milliseconds()
	if err != nil {
		r.Error = upstreamErrorText(err)
		return r
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 64<<10)
	r.Status, r.OK = resp.StatusCode, true
	return r
}

// DataPath returns a file name inside the data directory.
func (m *Manager) DataPath(name string) string { return filepath.Join(m.Dir, name) }

// LANAddresses lists this computer's private IPv4 addresses (what a router's port forward should point at).
func LANAddresses() []string {
	out := []string{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip := ipn.IP.To4(); ip != nil && ip.IsPrivate() {
					out = append(out, ip.String())
				}
			}
		}
	}
	return out
}

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// remoteHost returns the peer address of c without its port, or "" if there is no connection.
func remoteHost(c net.Conn) string {
	if c == nil {
		return ""
	}
	h, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return h
}
