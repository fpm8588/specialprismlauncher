// prism-relay is a relay for a Prism Launcher fork, with a built-in admin interface.
//
// The launcher rewrites every outgoing request to
//
//	https://<relay>/r/<upstream-host>/<path>?<query>
//
// with an X-Relay-Token header. The relay checks the token, checks that the upstream host is on its
// allowlist, makes the real request from this machine, follows redirects itself, and streams the
// response back. Run the program and use the page it opens in your browser to set everything up.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		dataDir    = flag.String("data-dir", "", "where settings, certificates and the log are kept (default: your user settings folder)")
		noBrowser  = flag.Bool("no-browser", false, "do not open the admin page in the browser")
		background = flag.Bool("background", false, "run without a console window (used by 'start with Windows')")
		genToken   = flag.Bool("gen-token", false, "print a new random token and exit")
		printList  = flag.Bool("print-allowlist", false, "print the built-in allowlist and exit")
		showVer    = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	switch {
	case *showVer:
		fmt.Println("prism-relay", version)
		return
	case *genToken:
		tok, err := newSecret()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(tok)
		return
	case *printList:
		fmt.Println(strings.Join(DefaultHosts, "\n"))
		return
	}

	dir := *dataDir
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			base = "."
		}
		dir = filepath.Join(base, "PrismRelay")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Fatalf("cannot create %s: %v", dir, err)
	}

	m, err := NewManager(dir, version)
	if err != nil {
		log.Fatalf("cannot start: %v", err)
	}
	s := m.Store.Get()

	quit := make(chan struct{})
	var once = make(chan struct{}, 1)
	requestQuit := func() {
		select {
		case once <- struct{}{}:
			close(quit)
		default:
		}
	}
	admin := NewAdmin(m, executablePath(), s.AdminAddr, requestQuit)

	ln, err := net.Listen("tcp", s.AdminAddr)
	if err != nil {
		// Most likely another copy is already running: just open its page.
		fmt.Printf("The admin page address %s is busy; assuming prism-relay is already running.\n", s.AdminAddr)
		if !*noBrowser && !*background {
			_ = openBrowser(admin.LoginURL())
		}
		return
	}
	adminSrv := &http.Server{Handler: admin.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := adminSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("admin interface stopped: %v", err)
		}
	}()

	if s.RelayEnabled {
		if err := m.Start(); err != nil {
			log.Printf("relay did not start: %v", err)
		}
	}

	if *background {
		hideConsole()
	} else {
		fmt.Printf("prism-relay %s\n\nAdmin page: %s\n(Keep this window open while the relay is running. Close it, or press Quit on the page, to stop.)\n\n",
			version, admin.LoginURL())
		if !*noBrowser {
			_ = openBrowser(admin.LoginURL())
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case <-quit:
	}

	m.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = adminSrv.Shutdown(ctx)
}
