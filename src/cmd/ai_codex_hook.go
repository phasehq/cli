package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/spf13/cobra"
)

// Codex's adapter: its SessionStart context and the PreToolUse hook that
// wraps shell commands in the shared runtime.

type codexSessionOutput struct {
	Continue           *bool  `json:"continue,omitempty"`
	StopReason         string `json:"stopReason,omitempty"`
	HookSpecificOutput *struct {
		HookEventName     string `json:"hookEventName"`
		AdditionalContext string `json:"additionalContext,omitempty"`
	} `json:"hookSpecificOutput,omitempty"`
}

type codexToolOutput struct {
	HookSpecificOutput struct {
		HookEventName            string           `json:"hookEventName"`
		PermissionDecision       string           `json:"permissionDecision"`
		PermissionDecisionReason string           `json:"permissionDecisionReason,omitempty"`
		UpdatedInput             harnessToolInput `json:"updatedInput,omitempty"`
	} `json:"hookSpecificOutput"`
}

var aiCodexHookCmd = &cobra.Command{
	Use:          "__codex-hook",
	Hidden:       true,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runAICodexHook,
}

var aiCodexEventCmd = &cobra.Command{
	Use:          "__codex-event [guard|heartbeat|session-end]",
	Hidden:       true,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runAICodexEvent,
}

func runAICodexHook(cmd *cobra.Command, _ []string) error {
	input, err := readHarnessHookInput(cmd.InOrStdin())
	if err != nil || strings.TrimSpace(input.SessionID) == "" {
		return emitCodexBootstrapFailure(cmd)
	}
	if disabled, err := automaticHarnessDisabled(ai.HarnessCodex); disabled || err != nil {
		if err != nil {
			return emitCodexBootstrapFailure(cmd)
		}
		return nil
	}
	if err := refreshConfiguredAISkill(); err != nil {
		return emitCodexBootstrapFailure(cmd)
	}
	return emitCodexContext(cmd)
}

func runAICodexEvent(cmd *cobra.Command, args []string) error {
	input, err := readHarnessHookInput(cmd.InOrStdin())
	action := args[0]
	original := ""
	if action == "guard" {
		if err != nil || !strings.EqualFold(strings.TrimSpace(input.ToolName), "Bash") {
			return denyCodexShell(cmd)
		}
		original, err = input.ToolInput.command()
		if err != nil || strings.TrimSpace(original) == "" {
			return denyCodexShell(cmd)
		}
		if shellCommandUsesPowerShellWeb(original) {
			return denyCodexShellWithReason(cmd, harnessPowerShellWebMessage())
		}
		if shellCommandMixesPhase(original) {
			return denyCodexShellWithReason(cmd, harnessMixedCommandMessage())
		}
		if !shellCommandRequiresPhase(original) {
			return nil
		}
		if len(original) > maxHarnessCommandBytes {
			return denyCodexShell(cmd)
		}
	}
	if err != nil || strings.TrimSpace(input.SessionID) == "" {
		if action == "guard" {
			return denyCodexShell(cmd)
		}
		return nil
	}
	if disabled, configErr := automaticHarnessDisabled(ai.HarnessCodex); disabled || configErr != nil {
		if action == "guard" && configErr != nil {
			return denyCodexShell(cmd)
		}
		return nil
	}
	leaseID := harnessLeaseID(ai.HarnessCodex, input.SessionID)
	switch action {
	case "guard":
		if os.Getenv("PHASE_AI_ENABLED") == "1" {
			if probeInheritedPhaseRuntime(cmd.Context()) != nil {
				return denyCodexShell(cmd)
			}
			return nil
		}
		if err := ensureHarnessRuntimeReady(cmd.Context()); err != nil {
			if errors.Is(err, errHookRuntimeRefreshing) {
				return denyCodexShellForPendingRefresh(cmd)
			}
			return denyCodexShellWithReason(cmd, harnessRuntimeFailureMessage("Codex", err))
		}
		if err := registerHarnessLease(ai.HarnessCodex, input.SessionID, time.Time{}); err != nil {
			return denyCodexShell(cmd)
		}
		wrapped, err := buildHarnessWrapperCommand(ai.HarnessCodex, leaseID, original)
		if err != nil {
			return denyCodexShell(cmd)
		}
		updatedInput, err := input.ToolInput.withCommand(wrapped)
		if err != nil {
			return denyCodexShell(cmd)
		}
		output := codexToolOutput{}
		output.HookSpecificOutput.HookEventName = "PreToolUse"
		output.HookSpecificOutput.PermissionDecision = "allow"
		output.HookSpecificOutput.UpdatedInput = updatedInput
		return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
	case "heartbeat":
		return touchSessionLease(leaseID)
	case "session-end":
		return removeSessionLease(leaseID)
	default:
		return errors.New("unsupported Codex lifecycle event")
	}
}

func emitCodexContext(cmd *cobra.Command) error {
	output := codexSessionOutput{}
	output.HookSpecificOutput = &struct {
		HookEventName     string `json:"hookEventName"`
		AdditionalContext string `json:"additionalContext,omitempty"`
	}{HookEventName: "SessionStart", AdditionalContext: codexPhaseAIHarnessContext}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
}

func emitCodexBootstrapFailure(cmd *cobra.Command) error {
	output := codexSessionOutput{}
	output.HookSpecificOutput = &struct {
		HookEventName     string `json:"hookEventName"`
		AdditionalContext string `json:"additionalContext,omitempty"`
	}{HookEventName: "SessionStart", AdditionalContext: harnessUnavailableContext("Codex")}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
}

func denyCodexShell(cmd *cobra.Command) error {
	return denyCodexShellWithReason(cmd, harnessFailureMessage("Codex"))
}

func denyCodexShellForPendingRefresh(cmd *cobra.Command) error {
	return denyCodexShellWithReason(cmd, harnessRefreshMessage("Codex"))
}

func denyCodexShellWithReason(cmd *cobra.Command, reason string) error {
	output := codexToolOutput{}
	output.HookSpecificOutput.HookEventName = "PreToolUse"
	output.HookSpecificOutput.PermissionDecision = "deny"
	output.HookSpecificOutput.PermissionDecisionReason = reason
	return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
}

func init() {
	aiCmd.AddCommand(aiCodexHookCmd, aiCodexEventCmd)
}
