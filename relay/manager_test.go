package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir(), "test", func(c *Config) { c.AllowPrivate = true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	return m
}

func TestStoreCreatesSecretsAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.json")
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s := st.Get()
	if len(s.Token) < MinTokenLen || len(s.AdminKey) < MinTokenLen {
		t.Errorf("secrets not generated: token %d chars, admin key %d chars", len(s.Token), len(s.AdminKey))
	}
	if s.TLSMode != TLSAuto || s.AdminAddr != DefaultAdminAddr {
		t.Errorf("defaults wrong: %+v", s)
	}
	if _, err := st.Update(func(s *Settings) {
		s.Domain = "Relay.Example.COM"
		s.ExtraHosts = []string{"B.example.org", "a.example.org", "b.example.org", " "}
	}); err != nil {
		t.Fatal(err)
	}

	again, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	g := again.Get()
	if g.Token != s.Token || g.AdminKey != s.AdminKey {
		t.Error("secrets changed across reload")
	}
	if g.Domain != "relay.example.com" {
		t.Errorf("domain = %q, want lowercased", g.Domain)
	}
	if strings.Join(g.ExtraHosts, ",") != "a.example.org,b.example.org" {
		t.Errorf("extra hosts = %v, want sorted and de-duplicated", g.ExtraHosts)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm()&0o077 != 0 && filepath.Separator == '/' {
		t.Errorf("config file is readable by others: %v", fi.Mode())
	}
}

func TestStoreRejectsInvalidSettingsAndKeepsOldOnes(t *testing.T) {
	st, _ := OpenStore(filepath.Join(t.TempDir(), "config.json"))
	bad := map[string]func(*Settings){
		"domain with scheme": func(s *Settings) { s.Domain = "https://relay.example.com" },
		"domain is an IP":    func(s *Settings) { s.Domain = "203.0.113.5" },
		"bad mode":           func(s *Settings) { s.TLSMode = "magic" },
		"bad listen":         func(s *Settings) { s.Listen = "443" },
		"port too big":       func(s *Settings) { s.Listen = ":70000" },
		"bad extra host":     func(s *Settings) { s.ExtraHosts = []string{"not a host"} },
		"short token":        func(s *Settings) { s.Token = "short" },
		"public admin addr":  func(s *Settings) { s.AdminAddr = "0.0.0.0:9777" },
	}
	for name, fn := range bad {
		before := st.Get()
		if _, err := st.Update(fn); err == nil {
			t.Errorf("%s: expected an error", name)
		}
		if got := st.Get(); got.Domain != before.Domain || got.TLSMode != before.TLSMode || got.Token != before.Token {
			t.Errorf("%s: settings changed despite the error", name)
		}
	}
}

func TestPrismURLAndPorts(t *testing.T) {
	cases := []struct {
		s    Settings
		url  string
		port int
	}{
		{Settings{TLSMode: TLSAuto, Domain: "relay.example.com"}, "https://relay.example.com", 443},
		{Settings{TLSMode: TLSAuto}, "", 443},
		{Settings{TLSMode: TLSFiles, Domain: "relay.example.com"}, "https://relay.example.com:8443", 8443},
		{Settings{TLSMode: TLSFiles, Domain: "relay.example.com", Listen: ":443"}, "https://relay.example.com", 443},
		{Settings{TLSMode: TLSPlain}, "http://127.0.0.1:8080", 8080},
		{Settings{TLSMode: TLSPlain, Listen: "0.0.0.0:9000"}, "http://127.0.0.1:9000", 9000},
		{Settings{TLSMode: TLSPlain, Listen: ":9000", Domain: "prism.example.com"}, "http://prism.example.com:9000", 9000},
		{Settings{TLSMode: TLSPlain, Listen: "127.0.0.1:9000", Domain: "prism.example.com"}, "http://127.0.0.1:9000", 9000},
	}
	for _, c := range cases {
		if got := c.s.PrismURL(); got != c.url {
			t.Errorf("%+v: PrismURL = %q, want %q", c.s, got, c.url)
		}
		if got := c.s.ListenPort(); got != c.port {
			t.Errorf("%+v: ListenPort = %d, want %d", c.s, got, c.port)
		}
	}
}

func TestEffectiveAllowlist(t *testing.T) {
	s := Settings{ExtraHosts: []string{"cdn.example.org"}, DisabledHosts: []string{"api.curseforge.com"}}
	a := s.Allowlist()
	if !a.Match("libraries.minecraft.net") || !a.Match("cdn.example.org") {
		t.Error("built-in and extra hosts must both be allowed")
	}
	if a.Match("api.curseforge.com") {
		t.Error("a disabled built-in host must not be allowed")
	}
}

func startPlain(t *testing.T, m *Manager) string {
	t.Helper()
	addr := freeAddr(t)
	if _, err := m.Store.Update(func(s *Settings) { s.TLSMode, s.Listen = TLSPlain, addr }); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestManagerStartServeStop(t *testing.T) {
	m := newTestManager(t)
	if m.Status().State != StateStopped {
		t.Fatal("new manager should be stopped")
	}
	addr := startPlain(t, m)
	if st := m.Status(); st.State != StateRunning || st.Addr != addr {
		t.Fatalf("status = %+v", st)
	}

	req, _ := http.NewRequest("GET", "http://"+addr+"/healthz", nil)
	req.Header.Set(TokenHeader, m.Store.Get().Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "ok" {
		t.Fatalf("healthz: %d %q", resp.StatusCode, body)
	}

	m.Stop()
	if m.Status().State != StateStopped {
		t.Error("state should be stopped after Stop")
	}
	if _, err := http.DefaultClient.Get("http://" + addr + "/healthz"); err == nil {
		t.Error("the port should be closed after Stop")
	}
	if err := m.Start(); err != nil {
		t.Errorf("restart after stop: %v", err)
	}
}

func TestStartExplainsProblems(t *testing.T) {
	m := newTestManager(t)

	// automatic mode without a domain
	if err := m.Start(); err == nil || !strings.Contains(err.Error(), "domain") {
		t.Errorf("auto mode without domain: %v", err)
	}
	if st := m.Status(); st.State != StateError || st.Error == "" {
		t.Errorf("status after failed start = %+v", st)
	}

	// port already taken
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busy.Close()
	m.Store.Update(func(s *Settings) { s.TLSMode, s.Listen = TLSPlain, busy.Addr().String() })
	if err := m.Start(); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Errorf("busy port: %v", err)
	}

	// certificate files that do not exist
	m.Store.Update(func(s *Settings) {
		s.TLSMode, s.Listen, s.CertFile, s.KeyFile = TLSFiles, freeAddr(t), "nope.pem", "nope.key"
	})
	if err := m.Start(); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("missing cert files: %v", err)
	}
}

func TestRestartNeededAfterListenerSettingsChange(t *testing.T) {
	m := newTestManager(t)
	startPlain(t, m)
	if m.Status().RestartNeeded {
		t.Error("no restart needed right after start")
	}
	m.Store.Update(func(s *Settings) { s.ExtraHosts = []string{"cdn.example.org"} })
	m.Apply()
	if m.Status().RestartNeeded {
		t.Error("changing the allowlist applies live; no restart needed")
	}
	m.Store.Update(func(s *Settings) { s.Listen = freeAddr(t) })
	if !m.Status().RestartNeeded {
		t.Error("changing the port needs a restart")
	}
	if err := m.Restart(); err != nil {
		t.Fatal(err)
	}
	if m.Status().RestartNeeded {
		t.Error("restart should clear the flag")
	}
}

func selfSignedFiles(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay.test"},
		DNSNames: []string{"relay.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kb, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return
}

func TestTLSWithOwnCertificateFiles(t *testing.T) {
	m := newTestManager(t)
	certPath, keyPath := selfSignedFiles(t, t.TempDir())
	addr := freeAddr(t)
	if _, err := m.Store.Update(func(s *Settings) {
		s.TLSMode, s.Listen, s.CertFile, s.KeyFile, s.Domain = TLSFiles, addr, certPath, keyPath, "relay.test"
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	req, _ := http.NewRequest("GET", "https://"+addr+"/healthz", nil)
	req.Header.Set(TokenHeader, m.Store.Get().Token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.TLS == nil {
		t.Fatalf("status %d, tls %v", resp.StatusCode, resp.TLS != nil)
	}

	info, err := m.CheckCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if info.Subject != "relay.test" || !info.NotAfter.After(time.Now()) {
		t.Errorf("cert info = %+v", info)
	}
}

func TestSelfTestReportsReachableAndUnreachable(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/err" {
			http.Error(w, "nope", 503)
			return
		}
		io.WriteString(w, "hi")
	}))
	defer up.Close()
	dead := freeAddr(t)

	m := newTestManager(t)
	m.probes = []probeTarget{
		{"up", up.URL + "/"},
		{"server error still counts as reachable", up.URL + "/err"},
		{"nothing listening", "http://" + dead + "/"},
	}
	res := m.SelfTest(context.Background())
	if !res[0].OK || res[0].Status != 200 {
		t.Errorf("up: %+v", res[0])
	}
	if !res[1].OK || res[1].Status != 503 {
		t.Errorf("503: %+v", res[1])
	}
	if res[2].OK || res[2].Error == "" {
		t.Errorf("dead: %+v", res[2])
	}
}

func TestEventsAndStatsFlowThroughTheManager(t *testing.T) {
	m := newTestManager(t)
	m.record(Event{Kind: KindOK, Host: "libraries.minecraft.net", Status: 200, Bytes: 1000})
	m.record(Event{Kind: KindOK, Host: "libraries.minecraft.net", Status: 200, Bytes: 500})
	m.record(Event{Kind: KindError, Host: "api.modrinth.com"})
	m.record(Event{Kind: KindDeny, Host: "cdn.example.org"})
	m.record(Event{Kind: KindAuth})

	snap := m.Stats.Snapshot()
	if snap.Requests != 3 || snap.BytesDown != 1500 || snap.Errors != 1 || snap.Denied != 1 || snap.AuthFails != 1 {
		t.Errorf("snapshot = %+v", snap)
	}
	if snap.Hosts[0].Host != "libraries.minecraft.net" || snap.Hosts[0].Requests != 2 {
		t.Errorf("hosts not sorted by traffic: %+v", snap.Hosts)
	}
	if len(snap.DeniedFor) != 1 || snap.DeniedFor[0].Host != "cdn.example.org" {
		t.Errorf("denied hosts = %+v", snap.DeniedFor)
	}
	m.Stats.Forget("cdn.example.org")
	if len(m.Stats.Snapshot().DeniedFor) != 0 {
		t.Error("Forget should clear a denied host")
	}

	ev, last := m.Events.Since(0, 100)
	if len(ev) != 5 || last != 5 {
		t.Errorf("events: %d, last %d", len(ev), last)
	}
	ev, _ = m.Events.Since(3, 100)
	if len(ev) != 2 || ev[0].Seq != 4 {
		t.Errorf("Since(3) = %+v", ev)
	}
}

func TestEventLogKeepsOnlyTheNewest(t *testing.T) {
	l := NewEventLog(3, nil)
	for i := 0; i < 10; i++ {
		l.Add(Event{Kind: KindOK})
	}
	ev, last := l.Since(0, 100)
	if len(ev) != 3 || ev[0].Seq != 8 || last != 10 {
		t.Errorf("got %d events starting at %d, last %d", len(ev), ev[0].Seq, last)
	}
}

func TestRotatingFileRollsOver(t *testing.T) {
	p := filepath.Join(t.TempDir(), "relay.log")
	f, err := NewRotatingFile(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := 0; i < 20; i++ {
		f.Write([]byte("0123456789\n"))
	}
	if !fileExists(p + ".1") {
		t.Error("expected a rolled-over file")
	}
	if fi, _ := os.Stat(p); fi.Size() > 100 {
		t.Errorf("current log is %d bytes, over the limit", fi.Size())
	}
}

func TestHostFromInput(t *testing.T) {
	cases := map[string]string{
		"https://libraries.minecraft.net/a/b.jar": "libraries.minecraft.net",
		"Libraries.Minecraft.net/x":               "libraries.minecraft.net",
		"cdn.example.org":                         "cdn.example.org",
		"https://example.org:8443/x":              "example.org:8443",
		"https://example.org:443/x":               "example.org",
		"":                                        "",
		"   ":                                     "",
	}
	for in, want := range cases {
		if got := hostFromInput(in); got != want {
			t.Errorf("hostFromInput(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAutomaticModeAnswersHTTPChallengeOnPort80(t *testing.T) {
	m := newTestManager(t)
	m.httpAddr = freeAddr(t) // stands in for port 80
	if _, err := m.Store.Update(func(s *Settings) { s.TLSMode, s.Domain, s.Listen = TLSAuto, "relay.example.com", freeAddr(t) }); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// ordinary requests on the plain port are sent to https for the domain
	resp, err := noRedirect.Get("http://" + m.httpAddr + "/anything")
	if err != nil {
		t.Fatalf("the challenge listener is not up: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode > 399 || !strings.HasPrefix(resp.Header.Get("Location"), "https://") {
		t.Errorf("plain-port request: %d to %q, want a redirect to https", resp.StatusCode, resp.Header.Get("Location"))
	}
	evs, _ := m.Events.Since(0, 100)
	sawVisitor := false
	for _, e := range evs {
		if e.Host == "(port 80)" && strings.Contains(e.Note, "redirected") {
			sawVisitor = true
		}
	}
	if !sawVisitor {
		t.Error("a visitor on port 80 should appear in the activity log")
	}
	// the challenge path is handled by autocert (an unknown token is refused with 403), not redirected
	resp, err = noRedirect.Get("http://" + m.httpAddr + "/.well-known/acme-challenge/unknown-token")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unknown challenge token: %d, want 403 from the ACME handler (a redirect would break validation)", resp.StatusCode)
	}
	evs, _ = m.Events.Since(0, 100)
	sawChallenge := false
	for _, e := range evs {
		if strings.Contains(e.Note, "(http-01)") && strings.Contains(e.Path, "acme-challenge") {
			sawChallenge = true
		}
	}
	if !sawChallenge {
		t.Error("a Let's Encrypt challenge request should appear in the activity log")
	}

	m.Stop()
	if _, err := http.Get("http://" + m.httpAddr + "/"); err == nil {
		t.Error("port 80 listener should close when the relay stops")
	}
}

func TestCertificateCheckNeedsTheRelayRunning(t *testing.T) {
	m := newTestManager(t)
	m.Store.Update(func(s *Settings) { s.TLSMode, s.Domain = TLSAuto, "relay.example.com" })
	if _, err := m.CheckCertificate(); err == nil || !strings.Contains(err.Error(), "start the relay first") {
		t.Errorf("not running: %v", err)
	}
}

func TestPlainAndFilesModesDoNotOpenPort80(t *testing.T) {
	m := newTestManager(t)
	m.httpAddr = freeAddr(t)
	startPlain(t, m)
	if conn, err := net.Dial("tcp", m.httpAddr); err == nil {
		conn.Close()
		t.Error("plain mode must not listen for Let's Encrypt")
	}
}

func TestNeededPorts(t *testing.T) {
	if got := neededPorts(Settings{TLSMode: TLSAuto}); len(got) != 2 || got[0] != 443 || got[1] != 80 {
		t.Errorf("auto: %v", got)
	}
	if got := neededPorts(Settings{TLSMode: TLSFiles}); len(got) != 1 || got[0] != 8443 {
		t.Errorf("files: %v", got)
	}
}

func TestDescribeAuthorizationAndHints(t *testing.T) {
	a := &acme.Authorization{Challenges: []*acme.Challenge{
		{Type: "http-01", Error: &acme.Error{Detail: "173.215.17.142: Fetching http://prism.example.com/.well-known/acme-challenge/x: Timeout during connect (likely firewall problem)"}},
		{Type: "dns-01"}, // not attempted: no error, must be skipped
		{Type: "tls-alpn-01", Error: &acme.Error{Detail: "Connection refused"}},
	}}
	got := describeAuthorization(a)
	if !strings.Contains(got, "http-01: 173.215.17.142: Fetching") || !strings.Contains(got, "tls-alpn-01: Connection refused") || strings.Contains(got, "dns-01") {
		t.Errorf("describeAuthorization = %q", got)
	}
	cases := map[string]string{
		"Timeout during connect (likely firewall problem)": "not reachable",
		"Connection refused":                           "nothing accepted",
		"CAA record for example.com prevents issuance": "CAA",
		"No valid A or AAAA records found":             "A record",
		"Invalid response from http://x: 404":          "not this relay",
	}
	for reason, want := range cases {
		if h := reasonHint(reason); !strings.Contains(h, want) {
			t.Errorf("reasonHint(%q) = %q, want mention of %q", reason, h, want)
		}
	}
	if reasonHint("something unrecognised") != "" {
		t.Error("unknown reasons must not get a made-up hint")
	}
}

func TestLetsEncryptReasonIgnoresOtherFailures(t *testing.T) {
	ctx := context.Background()
	if r, err := letsEncryptReason(ctx, t.TempDir(), true, errors.New("something else entirely")); r != "" || err != nil {
		t.Errorf("unrelated error produced %q, %v", r, err)
	}
	// the failure names an authorization, but there is no cached account key to ask with
	failure := errors.New(`acme/autocert: unable to satisfy "https://acme-staging-v02.api.letsencrypt.org/acme/authz/1/2" for domain "x.example.com": no viable challenge type found`)
	r, lookupErr := letsEncryptReason(ctx, t.TempDir(), true, failure)
	if r != "" || lookupErr == nil || !strings.Contains(lookupErr.Error(), "account key") {
		t.Errorf("missing key: reason %q, error %v; the failure to look up must be reported, not hidden", r, lookupErr)
	}
	if !authzRe.MatchString(failure.Error()) {
		t.Error("the authorization address must be extractable from the real error text")
	}
	if got := certFailure("", nil, failure).Error(); !strings.Contains(got, "port 80") || !strings.Contains(got, "Activity tab") {
		t.Errorf("with no reason, the generic advice and a pointer to Activity must remain: %q", got)
	}
	if got := certFailure("", errors.New("boom"), failure).Error(); !strings.Contains(got, "could not fetch Let's Encrypt's reason: boom") {
		t.Errorf("a failed lookup must be named: %q", got)
	}
}

func TestLetsEncryptAlpnVisitIsLoggedOnTheMainPort(t *testing.T) {
	m := newTestManager(t)
	m.httpAddr = freeAddr(t)
	addr := freeAddr(t)
	if _, err := m.Store.Update(func(s *Settings) { s.TLSMode, s.Domain, s.Listen = TLSAuto, "relay.example.com", addr }); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	// What Let's Encrypt's validator does: a TLS handshake offering the ACME-TLS ALPN protocol. There is no
	// pending challenge here, so the handshake fails; what matters is that the visit is recorded.
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "relay.example.com", NextProtos: []string{"acme-tls/1"}, InsecureSkipVerify: true})
	if err == nil {
		conn.Close()
	}
	evs, _ := m.Events.Since(0, 100)
	for _, e := range evs {
		if strings.Contains(e.Note, "(tls-alpn-01)") {
			return
		}
	}
	t.Errorf("the tls-alpn-01 visit was not logged: %+v", evs)
}
