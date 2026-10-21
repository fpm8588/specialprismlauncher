package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type adminFixture struct {
	t      *testing.T
	m      *Manager
	url    string // http://127.0.0.1:PORT
	key    string
	quit   chan struct{}
	client *http.Client // cookie-holding, follows redirects
}

func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	m := newTestManager(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &adminFixture{t: t, m: m, quit: make(chan struct{}, 1), key: m.Store.Get().AdminKey}
	admin := NewAdmin(m, "/path/to/prism-relay", ln.Addr().String(), func() { f.quit <- struct{}{} })
	ts := httptest.NewUnstartedServer(admin.Handler())
	ts.Listener.Close()
	ts.Listener = ln
	ts.Start()
	t.Cleanup(ts.Close)
	f.url = "http://" + ln.Addr().String()
	jar, _ := cookiejar.New(nil)
	f.client = &http.Client{Jar: jar}
	return f
}

func (f *adminFixture) login() {
	f.t.Helper()
	resp, err := f.client.Get(f.url + "/?k=" + f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		f.t.Fatalf("login ended with status %d", resp.StatusCode)
	}
}

// call sends a JSON request the way the page does.
func (f *adminFixture) call(method, path string, body any) (int, map[string]any) {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.url+path, rd)
	if method != "GET" {
		req.Header.Set("X-Admin", "1")
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAdminRequiresSignIn(t *testing.T) {
	f := newAdminFixture(t)

	for _, path := range []string{"/", "/api/state", "/api/events", "/api/stats"} {
		resp, _ := http.Get(f.url + path)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without cookie: %d, want 401", path, resp.StatusCode)
		}
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := noRedirect.Get(f.url + "/?k=wrong-key")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("wrong key: %d, want 403", resp.StatusCode)
	}

	resp, _ = noRedirect.Get(f.url + "/?k=" + f.key)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) == 0 {
		t.Fatalf("right key: %d with %d cookies, want a redirect that sets the cookie", resp.StatusCode, len(resp.Cookies()))
	}
	c := resp.Cookies()[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie must be HttpOnly and SameSite=Strict: %+v", c)
	}

	f.login()
	resp, _ = f.client.Get(f.url + "/")
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(page), "<title>") {
		t.Errorf("page after sign-in: %d", resp.StatusCode)
	}
	if code, st := f.call("GET", "/api/state", nil); code != 200 || st["version"] != "test" {
		t.Errorf("state: %d %v", code, st)
	}
}

func TestAdminRefusesRebindingAndCrossSiteWrites(t *testing.T) {
	f := newAdminFixture(t)
	f.login()

	// DNS rebinding: the browser connects to 127.0.0.1 but the page believes it is talking to evil.example
	req, _ := http.NewRequest("GET", f.url+"/api/state", nil)
	req.Host = "evil.example:" + strings.Split(f.url, ":")[2]
	resp, _ := f.client.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("foreign Host header: %d, want 403", resp.StatusCode)
	}

	post := func(hdr map[string]string) int {
		req, _ := http.NewRequest("POST", f.url+"/api/relay/stop", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post(nil); c != http.StatusForbidden {
		t.Errorf("POST without X-Admin header: %d, want 403", c)
	}
	if c := post(map[string]string{"X-Admin": "1", "Origin": "http://evil.example"}); c != http.StatusForbidden {
		t.Errorf("POST from another origin: %d, want 403", c)
	}
	if c := post(map[string]string{"X-Admin": "1", "Origin": f.url}); c != http.StatusOK {
		t.Errorf("POST from the page itself: %d, want 200", c)
	}
}

func TestAdminSettingsAndPrismURL(t *testing.T) {
	f := newAdminFixture(t)
	f.login()

	code, st := f.call("POST", "/api/settings", map[string]any{"domain": "Relay.Example.com"})
	if code != 200 || st["prismUrl"] != "https://relay.example.com" {
		t.Fatalf("set domain: %d %v", code, st)
	}
	code, st = f.call("POST", "/api/settings", map[string]any{"domain": "https://nope"})
	if code != 400 || !strings.Contains(st["error"].(string), "domain") {
		t.Errorf("bad domain: %d %v", code, st)
	}
	if f.m.Store.Get().Domain != "relay.example.com" {
		t.Error("a rejected change must not alter the settings")
	}
}

func TestAdminStartStopRelayRemembersChoice(t *testing.T) {
	f := newAdminFixture(t)
	f.login()
	addr := freeAddr(t)
	f.call("POST", "/api/settings", map[string]any{"tlsMode": "plain", "listen": addr})

	code, st := f.call("POST", "/api/relay/start", nil)
	if code != 200 || st["status"].(map[string]any)["state"] != "running" {
		t.Fatalf("start: %d %v", code, st)
	}
	if !f.m.Store.Get().RelayEnabled {
		t.Error("starting should be remembered so the relay comes back after a restart of the app")
	}
	_, st = f.call("POST", "/api/relay/stop", nil)
	if st["status"].(map[string]any)["state"] != "stopped" || f.m.Store.Get().RelayEnabled {
		t.Errorf("stop: %v", st)
	}

	f.call("POST", "/api/settings", map[string]any{"tlsMode": "auto", "domain": ""})
	code, st = f.call("POST", "/api/relay/start", nil)
	if code != 400 || !strings.Contains(st["error"].(string), "domain") {
		t.Errorf("start without a domain: %d %v", code, st)
	}
}

func TestAdminAllowDeniedHostWithOneClick(t *testing.T) {
	f := newAdminFixture(t)
	f.login()

	f.m.record(Event{Kind: KindDeny, Host: "cdn.example.org"})
	if _, st := f.call("GET", "/api/stats", nil); len(st["deniedHosts"].([]any)) != 1 {
		t.Fatalf("denied list: %v", st)
	}
	if f.m.Store.Get().Allowlist().Match("cdn.example.org") {
		t.Fatal("precondition: host must not be allowed yet")
	}

	if code, _ := f.call("POST", "/api/allow", map[string]any{"host": "CDN.example.org"}); code != 200 {
		t.Fatalf("allow: %d", code)
	}
	if !f.m.Relay.allow.Load().Match("cdn.example.org") {
		t.Error("the running relay must pick up the new host immediately")
	}
	if _, st := f.call("GET", "/api/stats", nil); len(st["deniedHosts"].([]any)) != 0 {
		t.Errorf("host should leave the denied list: %v", st)
	}

	if code, st := f.call("POST", "/api/allow", map[string]any{"host": "not a host"}); code != 400 {
		t.Errorf("invalid host: %d %v", code, st)
	}
}

func TestAdminReenablesDisabledBuiltInHost(t *testing.T) {
	f := newAdminFixture(t)
	f.login()
	f.call("POST", "/api/settings", map[string]any{"disabledHosts": []string{"api.curseforge.com"}})
	if f.m.Store.Get().Allowlist().Match("api.curseforge.com") {
		t.Fatal("host should be switched off")
	}
	f.call("POST", "/api/allow", map[string]any{"host": "api.curseforge.com"})
	s := f.m.Store.Get()
	if !s.Allowlist().Match("api.curseforge.com") || len(s.DisabledHosts) != 0 || len(s.ExtraHosts) != 0 {
		t.Errorf("should be re-enabled without becoming an extra: %+v", s)
	}
}

func TestAdminAllowlistCheck(t *testing.T) {
	f := newAdminFixture(t)
	f.login()
	_, r := f.call("POST", "/api/allowlist/check", map[string]any{"input": "https://libraries.minecraft.net/a.jar"})
	if r["allowed"] != true || r["rule"] != "libraries.minecraft.net" {
		t.Errorf("builtin: %v", r)
	}
	_, r = f.call("POST", "/api/allowlist/check", map[string]any{"input": "evil.example.com"})
	if r["allowed"] != false {
		t.Errorf("unknown host: %v", r)
	}
	if code, _ := f.call("POST", "/api/allowlist/check", map[string]any{"input": ""}); code != 400 {
		t.Errorf("empty input: %d", code)
	}
}

func TestAdminTokenRegenerationLocksOutOldToken(t *testing.T) {
	f := newAdminFixture(t)
	f.login()
	old := f.m.Store.Get().Token

	code, st := f.call("POST", "/api/token", map[string]any{})
	if code != 200 {
		t.Fatalf("regenerate: %d", code)
	}
	fresh := st["settings"].(map[string]any)["token"].(string)
	if fresh == old || len(fresh) < MinTokenLen {
		t.Errorf("token not regenerated: %q", fresh)
	}

	relay := httptest.NewServer(f.m.Relay)
	defer relay.Close()
	try := func(tok string) int {
		req, _ := http.NewRequest("GET", relay.URL+"/healthz", nil)
		req.Header.Set(TokenHeader, tok)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		return resp.StatusCode
	}
	if try(old) != 401 || try(fresh) != 200 {
		t.Error("old token must stop working at once and the new one must work")
	}

	if code, _ := f.call("POST", "/api/token", map[string]any{"token": "too-short"}); code != 400 {
		t.Errorf("short custom token: %d, want 400", code)
	}
}

func TestAdminEventsPollingAndQuit(t *testing.T) {
	f := newAdminFixture(t)
	f.login()
	f.m.record(Event{Kind: KindOK, Host: "a.example.com"})
	f.m.record(Event{Kind: KindOK, Host: "b.example.com"})

	_, r := f.call("GET", "/api/events?since=1", nil)
	evs := r["events"].([]any)
	if len(evs) != 1 || evs[0].(map[string]any)["host"] != "b.example.com" || r["last"].(float64) != 2 {
		t.Errorf("events since=1: %v", r)
	}

	if code, _ := f.call("POST", "/api/quit", nil); code != 200 {
		t.Fatalf("quit: %d", code)
	}
	select {
	case <-f.quit:
	case <-timeAfterSecond():
		t.Error("quit callback was not called")
	}
}

func timeAfterSecond() <-chan time.Time { return time.After(2 * time.Second) }

func TestAdminListsAreNeverNull(t *testing.T) {
	// The page calls .length / .filter on these; JSON null would break it.
	f := newAdminFixture(t)
	f.login()
	_, st := f.call("GET", "/api/state", nil)
	s := st["settings"].(map[string]any)
	for _, k := range []string{"extraHosts", "disabledHosts"} {
		if _, ok := s[k].([]any); !ok {
			t.Errorf("settings.%s = %v, want a list", k, s[k])
		}
	}
	if _, ok := st["lan"].([]any); !ok {
		t.Errorf("lan = %v, want a list", st["lan"])
	}
	_, al := f.call("GET", "/api/allowlist", nil)
	if _, ok := al["extra"].([]any); !ok {
		t.Errorf("allowlist.extra = %v, want a list", al["extra"])
	}
	_, ev := f.call("GET", "/api/events?since=0", nil)
	if _, ok := ev["events"].([]any); !ok {
		t.Errorf("events = %v, want a list", ev["events"])
	}
	_, ss := f.call("GET", "/api/stats", nil)
	for _, k := range []string{"hosts", "deniedHosts"} {
		if _, ok := ss[k].([]any); !ok {
			t.Errorf("stats.%s = %v, want a list", k, ss[k])
		}
	}
}

func TestAdminAddressMustBeLoopbackOrPrivate(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:9777", "localhost:9777", "[::1]:9777", "192.168.0.127:9777", "10.1.2.3:9777", "172.16.5.5:9777"} {
		if err := checkAdminAddr(ok); err != nil {
			t.Errorf("%s was refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:9777", ":9777", "[::]:9777", "173.215.17.151:9777", "8.8.8.8:9777", "example.com:9777", "192.168.0.127"} {
		if err := checkAdminAddr(bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}

func TestAdminOnAPrivateAddress(t *testing.T) {
	m := newTestManager(t)
	a := NewAdmin(m, "/path/to/prism-relay", "192.168.0.127:9777", func() {})
	if got, want := a.LoginURL(), "http://192.168.0.127:9777/?k="+url.QueryEscape(m.Store.Get().AdminKey); got != want {
		t.Errorf("login URL %q, want %q", got, want)
	}
	h := a.Handler()
	key := m.Store.Get().AdminKey

	get := func(host, remote string) int {
		req := httptest.NewRequest("GET", "http://"+host+"/?k="+url.QueryEscape(key), nil)
		req.Host = host
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := get("192.168.0.127:9777", "192.168.0.50:51000"); c != http.StatusSeeOther {
		t.Errorf("a computer on the home network got %d, want a sign-in redirect", c)
	}
	if c := get("192.168.0.127:9777", "173.215.17.200:51000"); c != http.StatusForbidden {
		t.Errorf("a connection from the internet got %d, want 403", c)
	}
	if c := get("evil.example:9777", "192.168.0.50:51000"); c != http.StatusForbidden {
		t.Errorf("a made-up Host name got %d, want 403", c)
	}
	if c := get("192.168.0.128:9777", "192.168.0.50:51000"); c != http.StatusForbidden {
		t.Errorf("another address got %d, want 403", c)
	}
}
