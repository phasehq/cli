package ai

import "testing"

func TestIsAIAgentDetectsCodexPrefixedEnvVars(t *testing.T) {
	t.Setenv("CODEX_CI", "1")
	t.Setenv("AGENT", "")
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CURSOR_AGENT", "")
	t.Setenv("CODEX", "")
	t.Setenv("OPENCODE", "")

	if !IsAIAgent() {
		t.Fatal("expected CODEX_* environment variables to be detected as AI agent")
	}
}

func TestIsAIAgentDetectsOpenCodeEnvVar(t *testing.T) {
	t.Setenv("OPENCODE", "1")
	t.Setenv("AGENT", "")
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CURSOR_AGENT", "")
	t.Setenv("CODEX", "")

	if !IsAIAgent() {
		t.Fatal("expected OPENCODE=1 to be detected as AI agent")
	}
}
