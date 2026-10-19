// prism-relay is a small authenticated HTTPS relay for a Prism Launcher fork.
//
// The launcher rewrites every outgoing request to
//
//	https://<relay>/r/<upstream-host>/<path>?<query>
//
// with an X-Relay-Token header. The relay checks the token, checks that the
// upstream host is on its allowlist, makes the real request from this machine,
// follows redirects itself, and streams the response back.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	var (
		listen    = flag.String("listen", "", "address to listen on (default :443 with -domain, :8443 with -cert, 127.0.0.1:8080 with -plain-http)")
		domain    = flag.String("domain", "", "public DNS name of this machine; enables automatic Let's Encrypt certificates (needs port 443 reachable from the internet)")
		cacheDir  = flag.String("cache-dir", "certs", "where -domain stores certificates")
		certFile  = flag.String("cert", "", "TLS certificate file (PEM), used together with -key")
		keyFile   = flag.String("key", "", "TLS private key file (PEM), used together with -cert")
		plainHTTP = flag.Bool("plain-http", false, "serve plain HTTP; only for use behind a TLS-terminating reverse proxy or for local testing")
		tokenFile = flag.String("token-file", "", "file containing the shared secret (alternatively set RELAY_TOKEN)")
		allowCSV  = flag.String("allow", "", "extra upstream hosts to allow, comma separated (supports *.example.com)")
		allowFile = flag.String("allow-file", "", "file with extra allowed upstream hosts, one per line")
		genToken  = flag.Bool("gen-token", false, "print a new random token and exit")
		printList = flag.Bool("print-allowlist", false, "print the built-in allowlist and exit")
	)
	flag.Parse()

	if *genToken {
		tok, err := newToken()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(tok)
		return
	}
	if *printList {
		fmt.Println(strings.Join(DefaultHosts, "\n"))
		return
	}

	token, err := loadToken(*tokenFile)
	if err != nil {
		log.Fatalf("token: %v\n(generate one with: prism-relay -gen-token)", err)
	}

	allow := NewAllowlist(DefaultHosts)
	for _, h := range strings.Split(*allowCSV, ",") {
		allow.Add(h)
	}
	if *allowFile != "" {
		f, err := os.Open(*allowFile)
		if err != nil {
			log.Fatalf("allow-file: %v", err)
		}
		entries, err := ReadEntries(f)
		f.Close()
		if err != nil {
			log.Fatalf("allow-file: %v", err)
		}
		for _, e := range entries {
			allow.Add(e)
		}
	}

	relay, err := NewServer(Config{Token: token, Allow: allow})
	if err != nil {
		log.Fatal(err)
	}

	modes := 0
	for _, on := range []bool{*domain != "", *certFile != "" || *keyFile != "", *plainHTTP} {
		if on {
			modes++
		}
	}
	if modes != 1 {
		log.Fatal("choose exactly one of: -domain, -cert with -key, or -plain-http")
	}

	srv := &http.Server{
		Handler:           relay,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		// No Read/WriteTimeout: large downloads and uploads must be able to run.
	}

	errc := make(chan error, 1)
	switch {
	case *domain != "":
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*domain),
			Cache:      autocert.DirCache(*cacheDir),
		}
		srv.Addr = orDefault(*listen, ":443")
		srv.TLSConfig = m.TLSConfig() // TLS-ALPN-01 challenge: only port 443 is needed
		log.Printf("prism-relay listening on %s for https://%s (certificates cached in %s)", srv.Addr, *domain, *cacheDir)
		go func() { errc <- srv.ListenAndServeTLS("", "") }()
	case *certFile != "" || *keyFile != "":
		if *certFile == "" || *keyFile == "" {
			log.Fatal("-cert and -key must be given together")
		}
		srv.Addr = orDefault(*listen, ":8443")
		log.Printf("prism-relay listening on %s (TLS)", srv.Addr)
		go func() { errc <- srv.ListenAndServeTLS(*certFile, *keyFile) }()
	default:
		srv.Addr = orDefault(*listen, "127.0.0.1:8080")
		log.Printf("prism-relay listening on %s (PLAIN HTTP: the token is sent unencrypted unless a TLS proxy is in front)", srv.Addr)
		go func() { errc <- srv.ListenAndServe() }()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case <-stop:
		log.Print("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func loadToken(path string) (string, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return validateToken(strings.TrimSpace(string(b)))
	}
	return validateToken(strings.TrimSpace(os.Getenv("RELAY_TOKEN")))
}

func validateToken(t string) (string, error) {
	if t == "" {
		return "", errors.New("no token set: use -token-file or RELAY_TOKEN")
	}
	if len(t) < 24 {
		return "", errors.New("token is too short (need at least 24 characters)")
	}
	return t, nil
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
