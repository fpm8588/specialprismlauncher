package main

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

//go:embed ui/index.html
var uiHTML []byte

const (
	adminCookie = "relay_admin"
	adminHeader = "X-Admin"
)

// Admin serves the admin interface: a page and a small JSON API. It listens on loopback or one private network
// address only, refuses connections that do not come from such an address, and refuses requests that do not
// carry the admin key, so a web page you happen to visit cannot drive it.
type Admin struct {
	m       *Manager
	exe     string
	host    string // address the page is served on, as used in the sign-in link
	port    string
	quit    func()
	hostsOK map[string]bool
	mux     *http.ServeMux
	handler http.Handler
}

// NewAdmin builds the admin handler. addr is the loopback or private address it will be served on.
func NewAdmin(m *Manager, exe, addr string, quit func()) *Admin {
	host, port, _ := net.SplitHostPort(addr)
	if host == "" || host == "localhost" {
		host = "127.0.0.1"
	}
	a := &Admin{m: m, exe: exe, host: host, port: port, quit: quit, mux: http.NewServeMux(), hostsOK: map[string]bool{}}
	names := []string{"127.0.0.1", "localhost", "[::1]", host}
	if strings.Contains(host, ":") {
		names[len(names)-1] = "[" + host + "]"
	}
	for _, h := range names {
		a.hostsOK[h+":"+port] = true
	}
	a.routes()
	a.handler = a.guard(a.mux)
	return a
}

// Handler returns the http.Handler to serve.
func (a *Admin) Handler() http.Handler { return a.handler }

// LoginURL is the address that signs a browser in (it sets the cookie, then redirects to the page).
func (a *Admin) LoginURL() string {
	return "http://" + net.JoinHostPort(a.host, a.port) + "/?k=" + url.QueryEscape(a.m.Store.Get().AdminKey)
}

func (a *Admin) routes() {
	a.mux.HandleFunc("GET /{$}", a.page)
	a.mux.HandleFunc("GET /api/state", a.handleState)
	a.mux.HandleFunc("GET /api/events", a.handleEvents)
	a.mux.HandleFunc("GET /api/stats", a.handleStats)
	a.mux.HandleFunc("GET /api/allowlist", a.handleAllowlist)
	a.mux.HandleFunc("POST /api/settings", a.handleSettings)
	a.mux.HandleFunc("POST /api/relay/{action}", a.handleRelay)
	a.mux.HandleFunc("POST /api/token", a.handleToken)
	a.mux.HandleFunc("POST /api/allow", a.handleAllow)
	a.mux.HandleFunc("POST /api/allowlist/check", a.handleAllowCheck)
	a.mux.HandleFunc("POST /api/cert/check", a.handleCert)
	a.mux.HandleFunc("POST /api/selftest", a.handleSelfTest)
	a.mux.HandleFunc("POST /api/autostart", a.handleAutostart)
	a.mux.HandleFunc("POST /api/firewall", a.handleFirewall)
	a.mux.HandleFunc("POST /api/open-folder", a.handleOpenFolder)
	a.mux.HandleFunc("POST /api/stats/reset", a.handleStatsReset)
	a.mux.HandleFunc("POST /api/quit", a.handleQuit)
}

// guard rejects anything that is not the signed-in browser of someone on this computer or this network.
func (a *Admin) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Even if the router were set to forward the admin port, a request from the internet is refused.
		if peer, _, err := net.SplitHostPort(r.RemoteAddr); err != nil || !privateOrLoopback(net.ParseIP(peer)) {
			http.Error(w, "the admin page is only available from inside the local network", http.StatusForbidden)
			return
		}
		// A web page on another site can make the browser send requests to this address under a name it
		// controls (DNS rebinding). Only our own addresses are accepted as the Host.
		if !a.hostsOK[strings.ToLower(r.Host)] {
			http.Error(w, "unexpected Host header", http.StatusForbidden)
			return
		}
		key := a.m.Store.Get().AdminKey

		if r.Method == http.MethodGet && r.URL.Path == "/" && r.URL.Query().Get("k") != "" {
			if !keyEqual(r.URL.Query().Get("k"), key) {
				http.Error(w, "wrong admin key", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: key, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(adminCookie)
		if err != nil || !keyEqual(c.Value, key) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "<!doctype html><title>Prism Relay</title><body style='font:16px system-ui;margin:3rem auto;max-width:34rem'>"+
				"<h1>Not signed in</h1><p>Open the relay program again (double-click it); it opens this page with the right link.</p>")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get(adminHeader) != "1" {
				http.Error(w, "missing "+adminHeader+" header", http.StatusForbidden)
				return
			}
			if o := r.Header.Get("Origin"); o != "" && !a.hostsOK[strings.TrimPrefix(strings.ToLower(o), "http://")] {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func keyEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (a *Admin) page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(uiHTML)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("bad request body: %w", err)
	}
	return nil
}

// ---- state ----

type stateResponse struct {
	Version   string   `json:"version"`
	Platform  string   `json:"platform"`
	DataDir   string   `json:"dataDir"`
	Settings  Settings `json:"settings"`
	Status    Status   `json:"status"`
	PrismURL  string   `json:"prismUrl"`
	Port      int      `json:"port"`
	Ports     []int    `json:"ports"` // every port that must be reachable (443, plus 80 for automatic certificates)
	LAN       []string `json:"lan"`
	Autostart struct {
		Supported bool `json:"supported"`
		Enabled   bool `json:"enabled"`
	} `json:"autostart"`
	Firewall struct {
		Supported bool   `json:"supported"`
		Command   string `json:"command"`
	} `json:"firewall"`
	DefaultHosts int `json:"defaultHosts"`
}

func (a *Admin) state() stateResponse {
	s := a.m.Store.Get()
	var r stateResponse
	r.Version, r.Platform, r.DataDir = a.m.Version, runtime.GOOS, a.m.Dir
	s.AdminKey = "" // the page never needs it
	r.Settings, r.Status = s, a.m.Status()
	r.PrismURL, r.Port, r.LAN = s.PrismURL(), s.ListenPort(), LANAddresses()
	r.Autostart.Supported, r.Autostart.Enabled = autostartSupported(), autostartEnabled()
	r.Ports = neededPorts(s)
	cmds := []string{}
	for _, port := range r.Ports {
		cmds = append(cmds, firewallCommand(port))
	}
	r.Firewall.Supported, r.Firewall.Command = firewallSupported(), strings.Join(cmds, "\n")
	r.DefaultHosts = len(DefaultHosts)
	return r
}

func (a *Admin) handleState(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, a.state()) }

func (a *Admin) handleEvents(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	ev, last := a.m.Events.Since(since, 300)
	writeJSON(w, 200, map[string]any{"events": ev, "last": last})
}

func (a *Admin) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.m.Stats.Snapshot())
}

func (a *Admin) handleStatsReset(w http.ResponseWriter, r *http.Request) {
	a.m.Stats.Reset()
	writeJSON(w, 200, a.m.Stats.Snapshot())
}

// ---- settings ----

type settingsPatch struct {
	Domain             *string   `json:"domain"`
	TLSMode            *string   `json:"tlsMode"`
	Listen             *string   `json:"listen"`
	CertFile           *string   `json:"certFile"`
	KeyFile            *string   `json:"keyFile"`
	LetsEncryptStaging *bool     `json:"letsEncryptStaging"`
	ExtraHosts         *[]string `json:"extraHosts"`
	DisabledHosts      *[]string `json:"disabledHosts"`
}

func (a *Admin) handleSettings(w http.ResponseWriter, r *http.Request) {
	var p settingsPatch
	if err := readJSON(r, &p); err != nil {
		fail(w, 400, err)
		return
	}
	_, err := a.m.Store.Update(func(s *Settings) {
		if p.Domain != nil {
			s.Domain = *p.Domain
		}
		if p.TLSMode != nil {
			s.TLSMode = *p.TLSMode
		}
		if p.Listen != nil {
			s.Listen = strings.TrimSpace(*p.Listen)
		}
		if p.CertFile != nil {
			s.CertFile = strings.TrimSpace(*p.CertFile)
		}
		if p.KeyFile != nil {
			s.KeyFile = strings.TrimSpace(*p.KeyFile)
		}
		if p.LetsEncryptStaging != nil {
			s.LetsEncryptStaging = *p.LetsEncryptStaging
		}
		if p.ExtraHosts != nil {
			s.ExtraHosts = *p.ExtraHosts
		}
		if p.DisabledHosts != nil {
			s.DisabledHosts = *p.DisabledHosts
		}
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	_ = a.m.Apply()
	writeJSON(w, 200, a.state())
}

func (a *Admin) handleToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"` // empty: generate a new one
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, 400, err)
		return
	}
	tok := strings.TrimSpace(body.Token)
	if tok == "" {
		var err error
		if tok, err = newSecret(); err != nil {
			fail(w, 500, err)
			return
		}
	}
	if _, err := a.m.Store.Update(func(s *Settings) { s.Token = tok }); err != nil {
		fail(w, 400, err)
		return
	}
	_ = a.m.Apply()
	a.m.note(KindOK, "token changed; the launcher must be given the new one")
	writeJSON(w, 200, a.state())
}

func (a *Admin) handleRelay(w http.ResponseWriter, r *http.Request) {
	var err error
	switch r.PathValue("action") {
	case "start":
		if err = a.m.Start(); err == nil {
			_, err = a.m.Store.Update(func(s *Settings) { s.RelayEnabled = true })
		}
	case "stop":
		a.m.Stop()
		_, err = a.m.Store.Update(func(s *Settings) { s.RelayEnabled = false })
	case "restart":
		if err = a.m.Restart(); err == nil {
			_, err = a.m.Store.Update(func(s *Settings) { s.RelayEnabled = true })
		}
	default:
		fail(w, 404, errors.New("unknown action"))
		return
	}
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error(), "state": a.state()})
		return
	}
	writeJSON(w, 200, a.state())
}

// ---- allowlist ----

type hostRow struct {
	Host    string `json:"host"`
	Enabled bool   `json:"enabled"`
}

func (a *Admin) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	s := a.m.Store.Get()
	off := map[string]bool{}
	for _, h := range s.DisabledHosts {
		off[normalizeHost(h)] = true
	}
	defaults := make([]hostRow, 0, len(DefaultHosts))
	for _, h := range DefaultHosts {
		defaults = append(defaults, hostRow{h, !off[normalizeHost(h)]})
	}
	writeJSON(w, 200, map[string]any{"defaults": defaults, "extra": s.ExtraHosts})
}

func (a *Admin) handleAllow(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, 400, err)
		return
	}
	host := normalizeHost(body.Host)
	if !ValidEntry(host) {
		fail(w, 400, fmt.Errorf("%q is not a valid host (examples: cdn.example.org, *.example.net)", body.Host))
		return
	}
	_, err := a.m.Store.Update(func(s *Settings) {
		// A built-in host that was switched off just gets switched back on.
		kept := s.DisabledHosts[:0]
		reenabled := false
		for _, d := range s.DisabledHosts {
			if normalizeHost(d) == host {
				reenabled = true
			} else {
				kept = append(kept, d)
			}
		}
		s.DisabledHosts = kept
		if !reenabled {
			s.ExtraHosts = append(s.ExtraHosts, host)
		}
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	_ = a.m.Apply()
	a.m.Stats.Forget(host)
	a.m.note(KindOK, "allowed host "+host)
	a.handleAllowlist(w, r)
}

func (a *Admin) handleAllowCheck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Input string `json:"input"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, 400, err)
		return
	}
	host := hostFromInput(body.Input)
	if host == "" {
		fail(w, 400, errors.New("enter a web address or host name"))
		return
	}
	rule, ok := a.m.Store.Get().Allowlist().Rule(host)
	writeJSON(w, 200, map[string]any{"host": host, "allowed": ok, "rule": rule})
}

// hostFromInput accepts "https://host/path", "host/path" or "host" and returns host[:port] with default ports removed.
func hostFromInput(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	if !strings.Contains(in, "://") {
		in = "https://" + in
	}
	u, err := url.Parse(in)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	if p := u.Port(); p != "" && p != "443" {
		return strings.ToLower(net.JoinHostPort(u.Hostname(), p))
	}
	return strings.ToLower(u.Hostname())
}

// ---- diagnostics and system helpers ----

func (a *Admin) handleCert(w http.ResponseWriter, r *http.Request) {
	info, err := a.m.CheckCertificate()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "cert": info})
}

func (a *Admin) handleSelfTest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	writeJSON(w, 200, map[string]any{"results": a.m.SelfTest(ctx)})
}

func (a *Admin) handleAutostart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &body); err != nil {
		fail(w, 400, err)
		return
	}
	if err := setAutostart(body.Enabled, a.exe); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, a.state())
}

func (a *Admin) handleFirewall(w http.ResponseWriter, r *http.Request) {
	var out string
	for _, port := range neededPorts(a.m.Store.Get()) {
		o, err := addFirewallRule(port)
		if err != nil {
			state := a.state()
			writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "command": state.Firewall.Command})
			return
		}
		out += o
	}
	writeJSON(w, 200, map[string]any{"ok": true, "output": out})
}

func (a *Admin) handleOpenFolder(w http.ResponseWriter, r *http.Request) {
	if err := openFolder(a.m.Dir); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *Admin) handleQuit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]bool{"ok": true})
	go func() {
		time.Sleep(200 * time.Millisecond)
		a.quit()
	}()
}

// executablePath returns the absolute path of the running program.
func executablePath() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return os.Args[0]
}

// neededPorts lists the TCP ports that must reach this PC: the relay's own, plus port 80 when Let's Encrypt
// certificates are managed automatically (it answers the "http-01" challenge there).
func neededPorts(s Settings) []int {
	ports := []int{s.ListenPort()}
	if s.TLSMode == TLSAuto {
		ports = append(ports, 80)
	}
	return ports
}
