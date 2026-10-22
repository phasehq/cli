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

func TestDetectAIAgentCommandPrefersChildExecutable(t *testing.T) {
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CURSOR_AGENT", "")
	t.Setenv("CODEX", "1")
	t.Setenv("OPENCODE", "")
	t.Setenv("AGENT", "")

	for _, test := range []struct {
		command []string
		want    string
	}{
		{[]string{"/usr/local/bin/claude", "--print"}, "claude-code"},
		{[]string{"/usr/local/bin/devin"}, "devin"},
		{[]string{`C:\\Tools\\codex.exe`}, "codex"},
		{[]string{"cursor-agent"}, "cursor"},
		{[]string{"opencode"}, "opencode"},
		{[]string{"unknown-harness"}, "codex"},
		{nil, "codex"},
	} {
		if got := DetectAIAgentCommand(test.command); got != test.want {
			t.Fatalf("DetectAIAgentCommand(%q) = %q, want %q", test.command, got, test.want)
		}
	}
}
