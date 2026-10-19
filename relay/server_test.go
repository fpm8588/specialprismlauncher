package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testToken = "test-token-0123456789abcdef"

// newTestRelay returns a relay that talks plain HTTP to test upstreams.
func newTestRelay(t *testing.T, allowedHosts ...string) *httptest.Server {
	t.Helper()
	s, err := NewServer(Config{
		Token:        testToken,
		Allow:        NewAllowlist(allowedHosts),
		Scheme:       "http",
		AllowPrivate: true, // upstreams are on 127.0.0.1
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return ts
}

func hostOf(ts *httptest.Server) string {
	u, _ := url.Parse(ts.URL)
	return u.Host
}

func do(t *testing.T, method, rawURL, token string, body io.Reader, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set(TokenHeader, token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestRejectsMissingOrWrongToken(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secret") }))
	defer up.Close()
	relay := newTestRelay(t, hostOf(up))

	for _, tok := range []string{"", "wrong-token-0123456789abcdef"} {
		resp, body := do(t, "GET", relay.URL+"/r/"+hostOf(up)+"/x", tok, nil, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("token %q: status %d, want 401", tok, resp.StatusCode)
		}
		if strings.Contains(body, "secret") {
			t.Errorf("token %q: upstream body leaked", tok)
		}
	}
}

func TestRejectsHostNotOnAllowlist(t *testing.T) {
	called := false
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer up.Close()
	relay := newTestRelay(t, "api.modrinth.com") // upstream is NOT allowed

	resp, body := do(t, "GET", relay.URL+"/r/"+hostOf(up)+"/x", testToken, nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(body, hostOf(up)) {
		t.Errorf("error should name the blocked host, got %q", body)
	}
	if called {
		t.Error("upstream was contacted for a disallowed host")
	}
}

func TestForwardsGETPathQueryAndHeaders(t *testing.T) {
	var got *http.Request
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		w.Header().Set("X-Upstream", "yes")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, "hello")
	}))
	defer up.Close()
	relay := newTestRelay(t, hostOf(up))

	resp, body := do(t, "GET", relay.URL+"/r/"+hostOf(up)+"/a/b%20c/d.jar?x=1&y=two", testToken, nil, map[string]string{
		"Authorization":   "Bearer abc",
		"User-Agent":      "PrismLauncher/test",
		"X-Forwarded-For": "1.2.3.4",
	})
	if resp.StatusCode != http.StatusTeapot || body != "hello" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Error("upstream response header not passed through")
	}
	if got.URL.EscapedPath() != "/a/b%20c/d.jar" {
		t.Errorf("upstream path = %q (encoding must be preserved)", got.URL.EscapedPath())
	}
	if got.URL.RawQuery != "x=1&y=two" {
		t.Errorf("upstream query = %q", got.URL.RawQuery)
	}
	if got.Header.Get("Authorization") != "Bearer abc" {
		t.Error("Authorization not forwarded")
	}
	if got.Header.Get("User-Agent") != "PrismLauncher/test" {
		t.Errorf("User-Agent = %q", got.Header.Get("User-Agent"))
	}
	if got.Header.Get(TokenHeader) != "" {
		t.Error("relay token leaked to upstream")
	}
	if got.Header.Get("X-Forwarded-For") != "" {
		t.Error("X-Forwarded-For leaked to upstream")
	}
	if got.Host != hostOf(up) {
		t.Errorf("upstream Host = %q, want %q", got.Host, hostOf(up))
	}
}

func TestForwardsPOSTBody(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Method", r.Method)
		w.Header().Set("X-Ctype", r.Header.Get("Content-Type"))
		w.Write(b)
	}))
	defer up.Close()
	relay := newTestRelay(t, hostOf(up))

	resp, body := do(t, "POST", relay.URL+"/r/"+hostOf(up)+"/login", testToken,
		strings.NewReader(`{"platform":"PC_LAUNCHER"}`), map[string]string{"Content-Type": "application/json"})
	if body != `{"platform":"PC_LAUNCHER"}` {
		t.Errorf("body = %q", body)
	}
	if resp.Header.Get("X-Method") != "POST" || resp.Header.Get("X-Ctype") != "application/json" {
		t.Errorf("method/content-type not forwarded: %v", resp.Header)
	}
}

func TestPassesThroughUpstreamErrorStatus(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"authorization_pending"}`)
	}))
	defer up.Close()
	relay := newTestRelay(t, hostOf(up))

	resp, body := do(t, "POST", relay.URL+"/r/"+hostOf(up)+"/token", testToken, strings.NewReader("x"), nil)
	if resp.StatusCode != 400 || !strings.Contains(body, "authorization_pending") {
		t.Errorf("got %d %q; upstream 4xx must reach the client unchanged", resp.StatusCode, body)
	}
}

func TestFollowsRedirectToAllowedHost(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "final:"+r.URL.Path) }))
	defer final.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/landed", http.StatusFound)
	}))
	defer first.Close()
	relay := newTestRelay(t, hostOf(first), hostOf(final))

	resp, body := do(t, "GET", relay.URL+"/r/"+hostOf(first)+"/start", testToken, nil, nil)
	if resp.StatusCode != 200 || body != "final:/landed" {
		t.Errorf("got %d %q; redirect should be followed by the relay", resp.StatusCode, body)
	}
}

func TestRefusesRedirectToDisallowedHost(t *testing.T) {
	hit := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/", http.StatusFound)
	}))
	defer first.Close()
	relay := newTestRelay(t, hostOf(first)) // evil is not allowed

	resp, body := do(t, "GET", relay.URL+"/r/"+hostOf(first)+"/start", testToken, nil, nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d, want 502", resp.StatusCode)
	}
	if !strings.Contains(body, "allowlist") {
		t.Errorf("error should explain the allowlist, got %q", body)
	}
	if hit {
		t.Error("relay followed a redirect to a host that is not allowed")
	}
}

func TestRefusesPrivateAddressesByDefault(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "lan secret") }))
	defer up.Close()
	s, err := NewServer(Config{
		Token:  testToken,
		Allow:  NewAllowlist([]string{hostOf(up)}),
		Scheme: "http",
		// AllowPrivate left false: a name that resolves to the LAN must not be reachable.
	})
	if err != nil {
		t.Fatal(err)
	}
	relay := httptest.NewServer(s)
	defer relay.Close()

	resp, body := do(t, "GET", relay.URL+"/r/"+hostOf(up)+"/", testToken, nil, nil)
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(body, "lan secret") {
		t.Errorf("got %d %q; loopback upstream should have been refused", resp.StatusCode, body)
	}
}

func TestLocksOutAfterRepeatedBadTokens(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer up.Close()
	relay := newTestRelay(t, hostOf(up))

	for i := 0; i < maxAuthFailures; i++ {
		resp, _ := do(t, "GET", relay.URL+"/r/"+hostOf(up)+"/", "bad-token-0123456789abcdefgh", nil, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i, resp.StatusCode)
		}
	}
	// Now even the correct token is refused until the lockout expires.
	resp, _ := do(t, "GET", relay.URL+"/r/"+hostOf(up)+"/", testToken, nil, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status %d, want 429 during lockout", resp.StatusCode)
	}
}

func TestBadRoutes(t *testing.T) {
	relay := newTestRelay(t, "example.com")
	for _, p := range []string{"/", "/foo", "/r/", "/r//x", "/r/exa mple.com/x", "/r/user@example.com/x"} {
		resp, _ := do(t, "GET", relay.URL+strings.ReplaceAll(p, " ", "%20"), testToken, nil, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", p, resp.StatusCode)
		}
	}
}

func TestHealthz(t *testing.T) {
	relay := newTestRelay(t, "example.com")
	resp, body := do(t, "GET", relay.URL+"/healthz", testToken, nil, nil)
	if resp.StatusCode != 200 || strings.TrimSpace(body) != "ok" {
		t.Errorf("got %d %q", resp.StatusCode, body)
	}
	resp, _ = do(t, "GET", relay.URL+"/healthz", "", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("healthz without token: %d, want 401", resp.StatusCode)
	}
}

func TestAllowlistMatching(t *testing.T) {
	a := NewAllowlist([]string{"Libraries.Minecraft.net", "*.forgecdn.net", "example.com:8443", "  ", "# not an entry is handled by ReadEntries"})
	cases := map[string]bool{
		"libraries.minecraft.net":      true,
		"LIBRARIES.MINECRAFT.NET":      true,
		"libraries.minecraft.net.":     true,
		"edge.forgecdn.net":            true,
		"forgecdn.net":                 false, // wildcard excludes the apex
		"evilforgecdn.net":             false,
		"edge.forgecdn.net.evil.com":   false,
		"edge.forgecdn.net:8080":       false, // wildcard only matches the default port
		"example.com:8443":             true,
		"example.com":                  false,
		"":                             false,
		"libraries.minecraft.net:8080": false,
	}
	for host, want := range cases {
		if got := a.Match(host); got != want {
			t.Errorf("Match(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestReadEntries(t *testing.T) {
	got, err := ReadEntries(strings.NewReader("a.com\n# comment\n\n  b.com  # trailing\n*.c.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.com", "b.com", "*.c.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestDefaultAllowlistCoversPrismHosts(t *testing.T) {
	a := NewAllowlist(DefaultHosts)
	// every host from the blocked-links report must be reachable through the relay
	for _, h := range []string{
		"libraries.minecraft.net", "piston-meta.mojang.com", "api.minecraftservices.com",
		"login.microsoftonline.com", "user.auth.xboxlive.com", "xsts.auth.xboxlive.com",
		"api.curseforge.com", "api.modrinth.com", "meta.prismlauncher.org",
		"maven.minecraftforge.net", "resources.download.minecraft.net", "piston-data.mojang.com",
	} {
		if !a.Match(h) {
			t.Errorf("%s missing from DefaultHosts", h)
		}
	}
}

func TestNewServerRejectsWeakToken(t *testing.T) {
	if _, err := NewServer(Config{Token: "short", Allow: NewAllowlist(nil)}); err == nil {
		t.Error("expected error for short token")
	}
}

func TestEmitsEventsForEveryOutcome(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello") }))
	defer up.Close()
	var events []Event
	s, err := NewServer(Config{
		Token: testToken, Allow: NewAllowlist([]string{hostOf(up)}), Scheme: "http", AllowPrivate: true,
		OnEvent: func(e Event) { events = append(events, e) },
	})
	if err != nil {
		t.Fatal(err)
	}
	relay := httptest.NewServer(s)
	defer relay.Close()

	do(t, "GET", relay.URL+"/r/"+hostOf(up)+"/a/b?secret=1", testToken, nil, nil)
	do(t, "GET", relay.URL+"/r/nope.example.com/x", testToken, nil, nil)
	do(t, "GET", relay.URL+"/r/"+hostOf(up)+"/", "bad-token-0123456789abcdefgh", nil, nil)
	do(t, "GET", relay.URL+"/nonsense", testToken, nil, nil)

	kinds := []string{}
	for _, e := range events {
		kinds = append(kinds, e.Kind)
		if strings.Contains(e.Line(), "secret=1") || strings.Contains(e.Path, "secret") {
			t.Errorf("query string leaked into event: %+v", e)
		}
	}
	want := []string{KindOK, KindDeny, KindAuth, KindBad}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("event kinds = %v, want %v", kinds, want)
	}
	if events[0].Host != hostOf(up) || events[0].Status != 200 || events[0].Bytes != 5 || events[0].Path != "/a/b" {
		t.Errorf("ok event wrong: %+v", events[0])
	}
}

func TestTokenAndAllowlistCanChangeWhileServing(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer up.Close()
	s, _ := NewServer(Config{Token: testToken, Allow: NewAllowlist(nil), Scheme: "http", AllowPrivate: true})
	relay := httptest.NewServer(s)
	defer relay.Close()
	url := relay.URL + "/r/" + hostOf(up) + "/"

	if resp, _ := do(t, "GET", url, testToken, nil, nil); resp.StatusCode != 403 {
		t.Fatalf("before allowing: %d, want 403", resp.StatusCode)
	}
	s.SetAllowlist(NewAllowlist([]string{hostOf(up)}))
	if resp, _ := do(t, "GET", url, testToken, nil, nil); resp.StatusCode != 200 {
		t.Fatalf("after allowing: %d, want 200", resp.StatusCode)
	}

	const newToken = "another-token-0123456789abcdef"
	if err := s.SetToken(newToken); err != nil {
		t.Fatal(err)
	}
	if resp, _ := do(t, "GET", url, testToken, nil, nil); resp.StatusCode != 401 {
		t.Errorf("old token after change: %d, want 401", resp.StatusCode)
	}
	if resp, _ := do(t, "GET", url, newToken, nil, nil); resp.StatusCode != 200 {
		t.Errorf("new token: %d, want 200", resp.StatusCode)
	}
	if err := s.SetToken("short"); err == nil {
		t.Error("a short token must be refused")
	}
}
