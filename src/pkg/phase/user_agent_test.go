package phase

import (
	"strings"
	"testing"

	"github.com/phasehq/cli/pkg/version"
	"github.com/phasehq/golang-sdk/v2/phase/network"
)

func TestConfigureUserAgentUsesCanonicalCLIIdentity(t *testing.T) {
	for _, key := range []string{"CLAUDECODE", "CURSOR_AGENT", "OPENCODE", "AGENT"} {
		t.Setenv(key, "")
	}
	t.Setenv("CODEX", "1")
	previousUserAgent := network.GetUserAgent()
	t.Cleanup(func() { network.SetUserAgent(previousUserAgent) })

	wantPrefix := "phase-cli/" + version.Version + " "
	userAgent := UserAgent()
	if !strings.HasPrefix(userAgent, wantPrefix) || !strings.HasSuffix(userAgent, " (ai-agent/codex)") {
		t.Fatalf("UserAgent() = %q", userAgent)
	}
	ConfigureUserAgent()
	if got := network.GetUserAgent(); got != userAgent {
		t.Fatalf("configured User-Agent = %q, want %q", got, userAgent)
	}
}
