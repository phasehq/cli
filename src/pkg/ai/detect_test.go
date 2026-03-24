package ai

import "testing"

func TestDetectAIAgent(t *testing.T) {
	allKeys := []string{"CLAUDECODE", "CURSOR_AGENT", "CODEX", "OPENCODE", "AGENT"}
	clearAll := func(t *testing.T) {
		for _, k := range allKeys {
			t.Setenv(k, "")
		}
	}

	tests := []struct {
		name string
		key  string
		val  string
		want string
	}{
		{"claude-code", "CLAUDECODE", "1", "claude-code"},
		{"cursor", "CURSOR_AGENT", "1", "cursor"},
		{"codex", "CODEX", "1", "codex"},
		{"opencode", "OPENCODE", "1", "opencode"},
		{"agent-convention", "AGENT", "goose", "goose"},
		{"none", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearAll(t)
			if tt.key != "" {
				t.Setenv(tt.key, tt.val)
			}
			if got := DetectAIAgent(); got != tt.want {
				t.Fatalf("DetectAIAgent() = %q, want %q", got, tt.want)
			}
		})
	}
}
