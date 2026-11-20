package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/spf13/cobra"
)

// OpenCode's adapter: the commands its Phase plugin calls for a session and
// for each shell command.

var aiOpenCodeCommandCmd = &cobra.Command{
	Use:           "__opencode-command",
	Hidden:        true,
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runAIOpenCodeCommand,
}

// aiOpenCodeSessionCmd is called by the OpenCode plugin before shell commands.
// It starts or repairs the hook-owned proxy within a bounded wait and renews the
// plugin process's session lease; the plugin then reads the published
// environment file itself. It always exits 0 so ordinary work is never blocked.
var aiOpenCodeSessionCmd = &cobra.Command{
	Use:           "__opencode-session",
	Hidden:        true,
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runAIOpenCodeSession,
}

type openCodeCommandResponse struct {
	SchemaVersion int    `json:"schemaVersion"`
	Managed       bool   `json:"managed"`
	Command       string `json:"command,omitempty"`
	Error         string `json:"error,omitempty"`
}

func runAIOpenCodeCommand(cmd *cobra.Command, _ []string) error {
	encodedCommand, _ := cmd.Flags().GetString("command")
	commandBytes, err := base64.RawURLEncoding.DecodeString(encodedCommand)
	if err != nil || len(commandBytes) == 0 || len(commandBytes) > maxHarnessCommandBytes {
		return emitOpenCodeCommandResponse(cmd, openCodeCommandResponse{
			SchemaVersion: 1, Managed: true, Error: harnessFailureMessage("OpenCode"),
		})
	}
	original := string(commandBytes)
	if shellCommandUsesPowerShellWeb(original) {
		return emitOpenCodeCommandResponse(cmd, openCodeCommandResponse{
			SchemaVersion: 1, Managed: true, Error: harnessPowerShellWebMessage(),
		})
	}
	if shellCommandMixesPhase(original) {
		return emitOpenCodeCommandResponse(cmd, openCodeCommandResponse{
			SchemaVersion: 1, Managed: true, Error: harnessMixedCommandMessage(),
		})
	}
	if !shellCommandRequiresPhase(original) {
		return emitOpenCodeCommandResponse(cmd, openCodeCommandResponse{SchemaVersion: 1})
	}
	sessionID, _ := cmd.Flags().GetString("session")
	sessionID = strings.TrimSpace(sessionID)
	if len(sessionID) > 512 {
		return emitOpenCodeCommandResponse(cmd, openCodeCommandResponse{
			SchemaVersion: 1, Managed: true, Error: harnessFailureMessage("OpenCode"),
		})
	}
	if sessionID == "" {
		sessionID = "tool"
	}

	if os.Getenv("PHASE_AI_ENABLED") == "1" {
		if err := probeInheritedPhaseRuntime(cmd.Context()); err != nil {
			return emitOpenCodeCommandResponse(cmd, openCodeCommandResponse{
				SchemaVersion: 1, Managed: true, Error: harnessFailureMessage("OpenCode"),
			})
		}
		return emitOpenCodeCommandResponse(cmd, openCodeCommandResponse{
			SchemaVersion: 1, Managed: true, Command: original,
		})
	}
	if disabled, configErr := automaticHarnessDisabled(ai.HarnessOpenCode); disabled || configErr != nil {
		return emitOpenCodeCommandResponse(cmd, openCodeCommandResponse{
			SchemaVersion: 1, Managed: true, Error: harnessFailureMessage("OpenCode"),
		})
	}
	if err := ensureHarnessRuntimeReady(cmd.Context()); err != nil {
		message := harnessFailureMessage("OpenCode")
		if errors.Is(err, errHookRuntimeRefreshing) {
			message = harnessRefreshMessage("OpenCode")
		}
		return emitOpenCodeCommandResponse(cmd, openCodeCommandResponse{
			SchemaVersion: 1, Managed: true, Error: message,
		})
	}
	if err := registerHarnessLease(ai.HarnessOpenCode, sessionID, time.Now().UTC().Add(openCodeLeaseTTL)); err != nil {
		return emitOpenCodeCommandResponse(cmd, openCodeCommandResponse{
			SchemaVersion: 1, Managed: true, Error: harnessFailureMessage("OpenCode"),
		})
	}
	leaseID := harnessLeaseID(ai.HarnessOpenCode, sessionID)
	wrapped, err := buildHarnessWrapperCommand(ai.HarnessOpenCode, leaseID, original)
	if err != nil {
		return emitOpenCodeCommandResponse(cmd, openCodeCommandResponse{
			SchemaVersion: 1, Managed: true, Error: harnessFailureMessage("OpenCode"),
		})
	}
	return emitOpenCodeCommandResponse(cmd, openCodeCommandResponse{
		SchemaVersion: 1, Managed: true, Command: wrapped,
	})
}

func runAIOpenCodeSession(cmd *cobra.Command, _ []string) error {
	if os.Getenv("PHASE_AI_ENABLED") == "1" {
		return nil
	}
	sessionID, _ := cmd.Flags().GetString("session")
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || len(sessionID) > 512 {
		sessionID = "tool"
	}
	if disabled, err := automaticHarnessDisabled(ai.HarnessOpenCode); disabled || err != nil {
		return nil
	}
	directory, err := hookRuntimeDir()
	if err != nil {
		return nil
	}
	kickHarnessRuntime(cmd.Context(), directory, ai.HarnessOpenCode, sessionID, hookKickBudget)
	return nil
}

func emitOpenCodeCommandResponse(cmd *cobra.Command, response openCodeCommandResponse) error {
	return json.NewEncoder(cmd.OutOrStdout()).Encode(response)
}

func init() {
	aiOpenCodeCommandCmd.Flags().String("session", "", "")
	aiOpenCodeCommandCmd.Flags().String("command", "", "")
	aiOpenCodeSessionCmd.Flags().String("session", "", "")
	aiCmd.AddCommand(aiOpenCodeCommandCmd, aiOpenCodeSessionCmd)
}
