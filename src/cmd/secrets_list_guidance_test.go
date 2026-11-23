package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// An Agent login sees masked values wherever it runs, so it is not told to
// run the command in a terminal.
func TestSecretsListGuidanceFitsTheLogin(t *testing.T) {
	for name, test := range map[string]struct {
		aiHarness, agentLogin bool
		want, forbidden       string
	}{
		"Agent login":       {false, true, "[REDACTED] for Agents on purpose. A person can see them with their own login or in the Phase Console.", "run this command directly"},
		"Agent login in AI": {true, true, "for Agents on purpose", "run this command directly"},
		"member in AI tool": {true, false, "the user should run this command directly in their terminal", "Agent login"},
		"member":            {false, false, "", "REDACTED"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			writeSecretsListGuidance(&stdout, &stderr, false, test.aiHarness, test.agentLogin)
			if !strings.Contains(stderr.String(), test.want) || strings.Contains(stderr.String(), test.forbidden) {
				t.Fatalf("stderr = %q", stderr.String())
			}
			// --show does not unmask for an Agent, so it is not offered.
			if strings.Contains(stdout.String(), "--show") == test.agentLogin {
				t.Fatalf("stdout = %q", stdout.String())
			}
		})
	}
}
