package ai

import (
	"os"

	"github.com/phasehq/cli/pkg/config"
)

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
	for _, key := range []string{"CLAUDECODE", "CURSOR_AGENT", "CODEX", "OPENCODE"} {
		if os.Getenv(key) == "1" {
			return true
		}
	}
	// AGENT=<name> is the emerging cross-tool convention
	// (Codex, Goose, Amp, etc.)
	if os.Getenv("AGENT") != "" {
		return true
	}
	return false
}

// ShouldRedact returns whether a secret of the given type should have its value
// redacted from CLI output. Requires both AI agent detection AND ai.json config.
//
// Rules:
//   - sealed: ALWAYS redacted when AI detected + ai.json exists
//   - secret: redacted when ai.json maskSecretValues is true
//   - config: NEVER redacted
//   - no ai.json: no redaction (AI feature not enabled)
func ShouldRedact(secretType string) bool {
	if !IsAIAgent() {
		return false
	}
	cfg := config.LoadAIConfig()
	if cfg == nil {
		return false
	}
	switch secretType {
	case "sealed":
		return true
	case "secret":
		return cfg.MaskSecretValues
	default:
		return false
	}
}
