package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// TLS modes.
const (
	TLSAuto  = "auto"  // Let's Encrypt certificate for Domain, port 443
	TLSFiles = "files" // certificate and key files supplied by the user
	TLSPlain = "plain" // no TLS: for testing, or behind a TLS-terminating proxy
)

// DefaultAdminAddr is where the admin interface listens unless told otherwise (-admin-addr or "adminAddr").
// It is always loopback or a private network address, never a public one.
const DefaultAdminAddr = "127.0.0.1:9777"

// Settings is everything the admin interface edits. It is stored as JSON.
type Settings struct {
	Domain             string   `json:"domain"`
	TLSMode            string   `json:"tlsMode"`
	Listen             string   `json:"listen"` // "" = the default for the TLS mode
	CertFile           string   `json:"certFile"`
	KeyFile            string   `json:"keyFile"`
	LetsEncryptStaging bool     `json:"letsEncryptStaging"`
	Token              string   `json:"token"`
	ExtraHosts         []string `json:"extraHosts"`
	DisabledHosts      []string `json:"disabledHosts"` // built-in hosts that are switched off
	RelayEnabled       bool     `json:"relayEnabled"`  // start the relay when the app starts
	AdminAddr          string   `json:"adminAddr"`
	AdminKey           string   `json:"adminKey"`
}

// DefaultListen returns the listen address used when Settings.Listen is empty.
func DefaultListen(mode string) string {
	switch mode {
	case TLSFiles:
		return ":8443"
	case TLSPlain:
		return "127.0.0.1:8080"
	default:
		return ":443"
	}
}

// ListenAddr is the effective listen address.
func (s Settings) ListenAddr() string {
	if s.Listen != "" {
		return s.Listen
	}
	return DefaultListen(s.TLSMode)
}

// ListenPort is the effective TCP port, or 0 if it cannot be parsed.
func (s Settings) ListenPort() int {
	_, p, err := net.SplitHostPort(s.ListenAddr())
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// PrismURL is the address to type into the launcher's Relay Server box.
func (s Settings) PrismURL() string {
	switch s.TLSMode {
	case TLSPlain:
		host := hostOrLoopback(s.ListenAddr())
		if s.Domain != "" && host == "127.0.0.1" && !strings.HasPrefix(s.ListenAddr(), "127.") {
			host = s.Domain // listening on all addresses: reachable by the domain name
		}
		return "http://" + net.JoinHostPort(host, strconv.Itoa(s.ListenPort()))
	default:
		if s.Domain == "" {
			return ""
		}
		if p := s.ListenPort(); p != 443 && p != 0 {
			return "https://" + net.JoinHostPort(s.Domain, strconv.Itoa(p))
		}
		return "https://" + s.Domain
	}
}

func hostOrLoopback(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil || h == "" || h == "0.0.0.0" || h == "::" {
		return "127.0.0.1"
	}
	return h
}

// Allowlist builds the effective allowlist: built-in hosts minus disabled ones, plus extras.
func (s Settings) Allowlist() *Allowlist {
	off := map[string]bool{}
	for _, h := range s.DisabledHosts {
		off[normalizeHost(h)] = true
	}
	a := NewAllowlist(nil)
	for _, h := range DefaultHosts {
		if !off[normalizeHost(h)] {
			a.Add(h)
		}
	}
	for _, h := range s.ExtraHosts {
		a.Add(h)
	}
	return a
}

// Validate reports the first problem with s.
func (s Settings) Validate() error {
	switch s.TLSMode {
	case TLSAuto, TLSFiles, TLSPlain:
	default:
		return fmt.Errorf("unknown TLS mode %q", s.TLSMode)
	}
	if s.Domain != "" && !validDomain(s.Domain) {
		return fmt.Errorf("%q is not a valid domain name (use just the name, like relay.example.com)", s.Domain)
	}
	if s.Listen != "" {
		_, p, err := net.SplitHostPort(s.Listen)
		if err != nil {
			return fmt.Errorf("listen address %q must look like :443 or 0.0.0.0:443", s.Listen)
		}
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("port %q is not between 1 and 65535", p)
		}
	}
	if len(s.Token) < MinTokenLen {
		return fmt.Errorf("token must be at least %d characters", MinTokenLen)
	}
	for _, h := range s.ExtraHosts {
		if !ValidEntry(h) {
			return fmt.Errorf("%q is not a valid host entry (examples: cdn.example.org, *.example.net)", h)
		}
	}
	if err := checkAdminAddr(s.AdminAddr); err != nil {
		return fmt.Errorf("admin address: %w", err)
	}
	return nil
}

func validDomain(d string) bool {
	return validHostname(strings.ToLower(d)) && net.ParseIP(d) == nil
}

// privateOrLoopback reports whether ip is this computer or an address that only exists inside a home or office
// network (192.168.x.x, 10.x.x.x, 172.16-31.x.x, fe80::, fc00::/7).
func privateOrLoopback(ip net.IP) bool {
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

// checkAdminAddr accepts only an address that cannot be reached from the internet: loopback, or one specific
// private address of this computer (for example 192.168.0.127:9777). 0.0.0.0, public addresses and names are refused.
func checkAdminAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q must look like 127.0.0.1:9777 or 192.168.0.10:9777", addr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || !privateOrLoopback(ip) {
		return fmt.Errorf("%q is not a loopback or private network address (such as 192.168.0.10); the admin interface must not be reachable from the internet", addr)
	}
	return nil
}

func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Store loads and saves Settings.
type Store struct {
	path string
	mu   sync.Mutex
	s    Settings
}

// OpenStore reads path, creating it with fresh secrets if it does not exist yet.
func OpenStore(path string) (*Store, error) {
	st := &Store{path: path}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &st.s); err != nil {
			return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, err
	}

	changed := errors.Is(err, os.ErrNotExist)
	if st.s.TLSMode == "" {
		st.s.TLSMode, changed = TLSAuto, true
	}
	if st.s.AdminAddr == "" {
		st.s.AdminAddr, changed = DefaultAdminAddr, true
	}
	if st.s.Token == "" {
		if st.s.Token, err = newSecret(); err != nil {
			return nil, err
		}
		changed = true
	}
	if st.s.AdminKey == "" {
		if st.s.AdminKey, err = newSecret(); err != nil {
			return nil, err
		}
		changed = true
	}
	if changed {
		if err := st.save(); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// Path is where the settings file lives.
func (st *Store) Path() string { return st.path }

// Get returns a copy of the current settings.
func (st *Store) Get() Settings {
	st.mu.Lock()
	defer st.mu.Unlock()
	return clone(st.s)
}

// Update applies fn to a copy, validates, saves and returns the result. On error nothing changes.
func (st *Store) Update(fn func(*Settings)) (Settings, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	next := clone(st.s)
	fn(&next)
	next.ExtraHosts = cleanList(next.ExtraHosts)
	next.DisabledHosts = cleanList(next.DisabledHosts)
	next.Domain = strings.ToLower(strings.TrimSpace(next.Domain))
	if err := next.Validate(); err != nil {
		return clone(st.s), err
	}
	old := st.s
	st.s = next
	if err := st.save(); err != nil {
		st.s = old
		return clone(old), err
	}
	return clone(next), nil
}

func clone(s Settings) Settings {
	// never nil: the admin page expects lists, and nil would be sent as JSON null
	s.ExtraHosts = append([]string{}, s.ExtraHosts...)
	s.DisabledHosts = append([]string{}, s.DisabledHosts...)
	return s
}

// cleanList lowercases, trims, removes blanks and duplicates, and sorts.
func cleanList(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, e := range in {
		e = normalizeHost(e)
		if e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}

func (st *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(st.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st.s, "", "  ")
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}
