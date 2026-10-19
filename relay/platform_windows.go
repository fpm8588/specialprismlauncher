//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const (
	runKey         = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	runValue       = "PrismRelay"
	ruleName       = "Prism Relay"
	createNoWindow = 0x08000000
)

// hideConsole detaches from the console window so the relay can run in the background.
func hideConsole() {
	if p := syscall.NewLazyDLL("kernel32.dll").NewProc("FreeConsole"); p.Find() == nil {
		_, _, _ = p.Call()
	}
}

// run starts prog with the command line exactly as given (Go's usual argument quoting does not suit reg.exe
// and netsh), without a console window. cmdLine must begin with the quoted path of prog.
func run(prog, cmdLine string) (string, error) {
	cmd := exec.Command(prog)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: cmdLine, HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func regExe() string { return os.Getenv("SystemRoot") + `\System32\reg.exe` }

func autostartSupported() bool { return true }

func autostartEnabled() bool {
	out, err := run(regExe(), fmt.Sprintf(`"%s" query "%s" /v %s`, regExe(), runKey, runValue))
	return err == nil && strings.Contains(out, runValue)
}

// setAutostart adds or removes the per-user "start when I sign in" entry. It needs no administrator rights.
func setAutostart(enabled bool, exe string) error {
	var line string
	if enabled {
		// The stored command is: "C:\path\prism-relay.exe" -background
		line = fmt.Sprintf(`"%s" add "%s" /v %s /t REG_SZ /d "\"%s\" -background" /f`, regExe(), runKey, runValue, exe)
	} else {
		// reg.exe fails when there is nothing to delete, and its message is translated, so
		// look first instead of interpreting the error text.
		if !autostartEnabled() {
			return nil
		}
		line = fmt.Sprintf(`"%s" delete "%s" /v %s /f`, regExe(), runKey, runValue)
	}
	if out, err := run(regExe(), line); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func firewallSupported() bool { return true }

func firewallCommand(port int) string {
	return fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=in action=allow protocol=TCP localport=%d`, ruleName, port)
}

// addFirewallRule opens the port in Windows Defender Firewall. It only works from an administrator session.
func addFirewallRule(port int) (string, error) {
	netsh := os.Getenv("SystemRoot") + `\System32\netsh.exe`
	_, _ = run(netsh, fmt.Sprintf(`"%s" advfirewall firewall delete rule name="%s"`, netsh, ruleName))
	out, err := run(netsh, fmt.Sprintf(`"%s" advfirewall firewall add rule name="%s" dir=in action=allow protocol=TCP localport=%d`, netsh, ruleName, port))
	if err != nil {
		return out, fmt.Errorf("Windows refused (this needs an administrator): %s", out)
	}
	return out, nil
}

func openBrowser(url string) error {
	cmd := exec.Command(os.Getenv("SystemRoot")+`\System32\rundll32.exe`, "url.dll,FileProtocolHandler", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd.Start()
}

func openFolder(path string) error {
	return exec.Command(os.Getenv("SystemRoot")+`\explorer.exe`, path).Start()
}
