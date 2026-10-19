//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
)

func hideConsole() {}

func autostartSupported() bool { return false }

func autostartEnabled() bool { return false }

func setAutostart(bool, string) error {
	return errors.New("starting at sign-in is only built in for Windows")
}

func firewallSupported() bool { return false }

func firewallCommand(port int) string {
	return fmt.Sprintf("allow TCP port %d in this computer's firewall", port)
}

func addFirewallRule(int) (string, error) {
	return "", errors.New("the firewall helper only exists on Windows")
}

func openBrowser(url string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("open", url).Start()
	}
	return exec.Command("xdg-open", url).Start()
}

func openFolder(path string) error { return openBrowser(path) }
