package util

import (
	"slices"
	"testing"
)

// Windows opens a URL through its protocol handler with the URL as one
// argument, never through cmd.exe, which runs what follows &.
func TestBrowserCommandOnWindowsAvoidsTheShell(t *testing.T) {
	const target = "https://console.phase.invalid/org/apps/x&calc.exe/environments/y&z"
	name, args, err := browserCommand("windows", target)
	if err != nil {
		t.Fatal(err)
	}
	if name != "rundll32" || !slices.Equal(args, []string{"url.dll,FileProtocolHandler", target}) {
		t.Fatalf("got %s %q", name, args)
	}
}

func TestBrowserCommandRefusesUnsafeURLs(t *testing.T) {
	for _, target := range []string{
		"",
		"file:///etc/passwd",
		"C:\\Windows\\System32\\calc.exe",
		"--help",
		"javascript:alert(1)",
		"https://",
		"https://console.phase.invalid/a b",
		"https://console.phase.invalid/a\"&calc",
		"https://console.phase.invalid/a\r\ncalc",
		"https://console.phase.invalid/a^&calc",
	} {
		for _, goos := range []string{"windows", "darwin", "linux"} {
			if name, args, err := browserCommand(goos, target); err == nil {
				t.Errorf("%s: %q accepted as %s %q", goos, target, name, args)
			}
		}
	}
	for _, target := range []string{"https://console.phase.dev", "http://localhost:8080/webauth/abc%2Bdef", "https://docs.phase.dev/cli/commands"} {
		if _, _, err := browserCommand("windows", target); err != nil {
			t.Errorf("%q refused: %v", target, err)
		}
	}
}
