package cmd

import (
	"strings"
	"testing"

	"github.com/phasehq/cli/pkg/config"
)

// The app and environment ids come from the checkout, so each stays one path
// segment: no separator, space or quote reaches the URL the browser opens.
func TestConsoleURLEscapesCheckoutIDs(t *testing.T) {
	got := consoleURL("https://console.phase.invalid", "Acme Org", &config.PhaseJSONConfig{
		Version: "2",
		AppID:   `x" & calc.exe`,
		EnvID:   "../../admin?y=1",
	})
	want := "https://console.phase.invalid/Acme%20Org/apps/x%22%20&%20calc.exe/environments/..%2F..%2Fadmin%3Fy=1"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if strings.ContainsAny(got, " \"") {
		t.Fatalf("unescaped characters in %s", got)
	}
}

func TestConsoleURLWithoutACheckout(t *testing.T) {
	if got := consoleURL("https://console.phase.invalid", "acme", nil); got != "https://console.phase.invalid" {
		t.Fatalf("got %s", got)
	}
	got := consoleURL("https://console.phase.invalid", "acme", &config.PhaseJSONConfig{AppID: "app-1", EnvID: "env-1"})
	if got != "https://console.phase.invalid/acme/apps/app-1" {
		t.Fatalf("a version 1 config: %s", got)
	}
}
