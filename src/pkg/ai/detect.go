package ai

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/phasehq/cli/pkg/config"
)

// agentLogin is set when this process acts with an Agent token. An Agent is
// the AI tool by definition, so its output is masked whether or not a harness
// was detected.
var agentLogin atomic.Bool

// SetAgentLogin records whether this process acts with an Agent token.
func SetAgentLogin(active bool) { agentLogin.Store(active) }

// AgentLogin reports whether this process acts with an Agent token.
func AgentLogin() bool { return agentLogin.Load() }

// IsAIAgent returns true if the CLI is being invoked by a known AI coding agent.
// WARNING: This is not a realiable way to detect if an AI is calling the CLI. Certain AI agents like VSCode don't seem to be wrapping. Inside threats could easily bypass this by stripping execution env var configs.
// https://x.com/nimishkarmali/status/2035246459290099876
// Checks for:
//   - CLAUDECODE=1 (Claude Code)
//   - CURSOR_AGENT=1 (Cursor)
//   - CODEX=1 (Codex)
//   - OPENCODE=1 (OpenCode)
//   - AGENT env var (emerging convention: Codex sets "codex", Goose sets "goose", Amp sets "amp")
func IsAIAgent() bool {
	return DetectAIAgent() != ""
}

// DetectAIAgent returns the name of the AI coding agent invoking the CLI,
// or an empty string if none is detected.
func DetectAIAgent() string {
	agentEnvVars := []struct {
		key  string
		name string
	}{
		{"CLAUDECODE", "claude-code"},
		{"CURSOR_AGENT", "cursor"},
		{"CODEX", "codex"},
		{"OPENCODE", "opencode"},
	}

	for _, a := range agentEnvVars {
		if os.Getenv(a.key) == "1" {
			return a.name
		}
	}

	// AGENT=<name> is the emerging cross-tool convention
	// (Codex, Goose, Amp, etc.)
	if agent := os.Getenv("AGENT"); agent != "" {
		return agent
	}

	return ""
}

// DetectAIAgentCommand identifies a supported Agent harness from the child
// executable launched by `phase ai run`. The explicit child wins over ambient
// detection because users commonly start Phase from an ordinary terminal.
func DetectAIAgentCommand(command []string) string {
	if detected := DetectAIAgentExecutable(command); detected != "" {
		return detected
	}
	return DetectAIAgent()
}

// DetectAIAgentExecutable identifies only the explicitly launched executable.
// Callers that mutate harness arguments must use this stricter form so an
// ambient Agent marker never causes flags to be added to an unrelated child.
func DetectAIAgentExecutable(command []string) string {
	if len(command) > 0 {
		executable := strings.ReplaceAll(strings.TrimSpace(command[0]), `\`, "/")
		name := strings.ToLower(filepath.Base(executable))
		name = strings.TrimSuffix(name, ".exe")
		switch name {
		case "claude", "claude-code":
			return "claude-code"
		case "cursor", "cursor-agent":
			return "cursor"
		case "codex":
			return "codex"
		case "opencode":
			return "opencode"
		case "goose":
			return "goose"
		case "amp":
			return "amp"
		}
	}
	return ""
}

// ShouldRedact returns whether a secret of the given type should have its value
// redacted from CLI output. Requires both AI agent detection AND an enabled
// ai.json config.
//
// Rules:
//   - sealed and secret: redacted when AI detected + AI mode enabled
//   - config: never redacted
//   - no ai.json or AI mode disabled: no redaction
//   - an ai.json that exists but cannot be read: sealed and secret redacted
//   - an Agent login: sealed and secret always redacted
func ShouldRedact(secretType string) bool {
	if AgentLogin() {
		return secretType == "sealed" || secretType == "secret"
	}
	if !IsAIAgent() {
		return false
	}
	cfg := config.LoadAIConfig()
	if cfg == nil {
		if _, err := os.Stat(config.AIConfigPath); err != nil {
			return false
		}
	} else if !cfg.Enabled {
		return false
	}
	return secretType == "sealed" || secretType == "secret"
}
