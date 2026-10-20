package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// autocert reports every failed validation as the same generic sentence ("no viable challenge type found"),
// which hides why Let's Encrypt really refused. The failure message does name the authorization, and Let's
// Encrypt records the reason for each challenge it tried on that authorization, so it can be asked afterwards.
var authzRe = regexp.MustCompile(`unable to satisfy "([^"]+)"`)

// letsEncryptReason asks the CA why the authorization named in failure did not validate. The reason is "" when
// the failure is of another kind or the CA recorded none; err says why the question could not be asked.
func letsEncryptReason(ctx context.Context, cacheDir string, staging bool, failure error) (string, error) {
	m := authzRe.FindStringSubmatch(failure.Error())
	if m == nil {
		return "", nil // not a validation failure: nothing to look up
	}
	data, err := autocert.DirCache(cacheDir).Get(ctx, "acme_account+key")
	if err != nil {
		return "", fmt.Errorf("account key not found in %s: %w", cacheDir, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("account key is not valid PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("account key unreadable: %w", err)
	}
	directory := acme.LetsEncryptURL
	if staging {
		directory = letsEncryptStagingURL
	}
	client := &acme.Client{Key: key, DirectoryURL: directory}
	authz, err := client.GetAuthorization(ctx, m[1])
	if err != nil {
		return "", fmt.Errorf("asking Let's Encrypt failed: %w", err)
	}
	return describeAuthorization(authz), nil
}

// describeAuthorization lists, for each challenge that failed, its type and the CA's own explanation.
func describeAuthorization(a *acme.Authorization) string {
	var parts []string
	for _, c := range a.Challenges {
		if c == nil || c.Error == nil {
			continue
		}
		detail := c.Error.Error()
		var ae *acme.Error
		if errors.As(c.Error, &ae) && ae.Detail != "" {
			detail = ae.Detail
		}
		parts = append(parts, c.Type+": "+detail)
	}
	return strings.Join(parts, " | ")
}

// reasonHint turns the CA's wording into what to do about it.
func reasonHint(reason string) string {
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "caa"):
		return "A CAA record on your domain does not allow Let's Encrypt to issue. In Netlify's DNS records, remove or edit the CAA record (it must allow letsencrypt.org)."
	case strings.Contains(r, "no valid a or aaaa"), strings.Contains(r, "nxdomain"), strings.Contains(r, "dns problem"):
		return "Let's Encrypt cannot find the address of your domain. Check the A record for prism in Netlify's DNS, and that it has no AAAA (IPv6) record pointing somewhere else."
	case strings.Contains(r, "timeout"):
		return "Let's Encrypt could not connect at all: the connection timed out. Port 80 and port 443 are not reachable from the internet. Check the router's port forwarding and the Windows firewall, and that the router's WAN address is your public address."
	case strings.Contains(r, "connection refused"):
		return "Let's Encrypt reached your address but nothing accepted the connection. The router is forwarding to the wrong PC or port, or the relay is not running."
	case strings.Contains(r, "connection reset"), strings.Contains(r, "eof"):
		return "The connection was cut off on the way. A router or provider filter may be interfering with ports 80 and 443."
	case strings.Contains(r, "invalid response"), strings.Contains(r, "unauthorized"), strings.Contains(r, "404"), strings.Contains(r, "403"):
		return "Something answered, but it was not this relay. Another device or a router web page is answering on that port; check where the port forward points."
	case strings.Contains(r, "firewall"):
		return "Let's Encrypt suspects a firewall. Check the router's port forwarding and the Windows firewall for ports 80 and 443."
	}
	return ""
}

// certFailure builds the message shown on the Server tab.
func certFailure(reason string, lookupErr, original error) error {
	if reason == "" {
		base := explainCertError(original)
		if lookupErr != nil {
			return fmt.Errorf("%w [could not fetch Let's Encrypt's reason: %v]", base, lookupErr)
		}
		return fmt.Errorf("%w [Let's Encrypt recorded no reason; watch the Activity tab for its connection attempts]", base)
	}
	msg := "Let's Encrypt tried to verify your domain and reported: " + reason
	if hint := reasonHint(reason); hint != "" {
		msg += ". " + hint
	}
	return fmt.Errorf("%s", msg)
}
