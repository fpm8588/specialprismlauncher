package main

import (
	"bufio"
	"io"
	"strings"
)

// DefaultHosts are the upstream hosts Prism Launcher talks to. The relay only
// forwards to hosts on this list (plus anything added with -allow/-allow-file),
// so that the port-forwarded relay is not an open proxy.
//
// An entry is either an exact host ("api.modrinth.com") or a wildcard
// ("*.forgecdn.net", which matches subdomains but not the bare domain).
// An entry may include a port ("example.com:8443"); entries without a port
// only match the default port.
var DefaultHosts = []string{
	// Mojang / Minecraft
	"libraries.minecraft.net",
	"resources.download.minecraft.net",
	"textures.minecraft.net",
	"session.minecraft.net",
	"piston-meta.mojang.com",
	"piston-data.mojang.com",
	"launchermeta.mojang.com",
	"launcher.mojang.com",
	"api.mojang.com",
	"sessionserver.mojang.com",
	"authserver.mojang.com",
	"api.minecraftservices.com",

	// Microsoft / Xbox sign-in
	"login.microsoftonline.com",
	"login.live.com",
	"user.auth.xboxlive.com",
	"xsts.auth.xboxlive.com",
	"device.auth.xboxlive.com",
	"title.auth.xboxlive.com",

	// Prism Launcher
	"meta.prismlauncher.org",
	"files.prismlauncher.org",
	"i18n.prismlauncher.org",
	"prismlauncher.org",

	// GitHub (releases, raw files, redirect targets)
	"github.com",
	"api.github.com",
	"raw.githubusercontent.com",
	"objects.githubusercontent.com",
	"release-assets.githubusercontent.com",
	"codeload.github.com",

	// Mod loaders and Maven repositories
	"maven.minecraftforge.net",
	"files.minecraftforge.net",
	"maven.neoforged.net",
	"maven.fabricmc.net",
	"meta.fabricmc.net",
	"maven.quiltmc.org",
	"meta.quiltmc.org",
	"repo1.maven.org",

	// Mod platforms
	"api.curseforge.com",
	"edge.forgecdn.net",
	"mediafilez.forgecdn.net",
	"media.forgecdn.net",
	"api.modrinth.com",
	"cdn.modrinth.com",
}

// Allowlist decides which upstream hosts the relay may contact.
type Allowlist struct {
	exact    map[string]struct{}
	suffixes []string // stored as ".example.com"
}

// NewAllowlist builds an Allowlist from host entries. Blank entries are skipped.
func NewAllowlist(entries []string) *Allowlist {
	a := &Allowlist{exact: make(map[string]struct{})}
	for _, e := range entries {
		a.Add(e)
	}
	return a
}

// Add adds one entry (exact host or "*.suffix").
func (a *Allowlist) Add(entry string) {
	entry = normalizeHost(entry)
	if entry == "" {
		return
	}
	if strings.HasPrefix(entry, "*.") {
		a.suffixes = append(a.suffixes, entry[1:])
		return
	}
	a.exact[entry] = struct{}{}
}

// Match reports whether host (optionally with ":port") is allowed.
func (a *Allowlist) Match(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	if _, ok := a.exact[host]; ok {
		return true
	}
	for _, s := range a.suffixes {
		// The wildcard applies to the host name; compare without a port so
		// "*.example.com" matches "a.example.com" but not "a.example.com:8080".
		if strings.HasSuffix(host, s) && !strings.Contains(host, ":") {
			return true
		}
	}
	return false
}

// ReadEntries parses a host list: one entry per line, '#' starts a comment.
func ReadEntries(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	return strings.TrimSuffix(h, ".")
}
