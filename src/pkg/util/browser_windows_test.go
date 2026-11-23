//go:build windows

package util

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// browserPayload ends in what cmd.exe runs as a second command: & starts it,
// and cmd reads the comma as a space, so it makes a folder named by the test.
const browserPayload = "https://console.phase.invalid/org/apps/x&md,phase-browser-ran"

// The test binary stands in for rundll32: it is started exactly as OpenBrowser
// starts the opener, and reports the command line it received the way
// rundll32 reads it, as the raw text after url.dll,FileProtocolHandler.
func TestBrowserArgvHelper(t *testing.T) {
	out := os.Getenv("PHASE_BROWSER_ARGV_OUT")
	if out == "" {
		t.Skip("helper process for TestOpeningAURLOnWindowsPassesItWholeAndRunsNoShell")
	}
	raw := windows.UTF16PtrToString(windows.GetCommandLine())
	_, tail, found := strings.Cut(raw, "url.dll,FileProtocolHandler")
	if !found {
		t.Fatalf("command line %q has no handler", raw)
	}
	if err := os.WriteFile(out, []byte(strings.TrimSpace(tail)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpeningAURLOnWindowsPassesItWholeAndRunsNoShell(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "phase-browser-ran")

	// The payload is real: through cmd.exe, as the CLI used to open URLs, it
	// runs its second command.
	shell := exec.Command("cmd", "/c", "echo", browserPayload)
	shell.Dir = dir
	if err := shell.Run(); err != nil {
		t.Fatalf("cmd: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("cmd.exe did not run the payload, so this test proves nothing: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	name, args, err := browserCommand("windows", browserPayload)
	if err != nil {
		t.Fatal(err)
	}
	if name != "rundll32" {
		t.Fatalf("opener is %s, want rundll32", name)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	got := filepath.Join(dir, "argv")
	opener := exec.Command(self, append([]string{"-test.run=^TestBrowserArgvHelper$", "--"}, args...)...)
	opener.Dir = dir
	opener.Env = append(os.Environ(), "PHASE_BROWSER_ARGV_OUT="+got)
	if out, err := opener.CombinedOutput(); err != nil {
		t.Fatalf("opener stand-in: %v\n%s", err, out)
	}
	received, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(received) != browserPayload {
		t.Fatalf("the opener received %q, want the URL unchanged", received)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("opening the URL ran its second command")
	}
}
