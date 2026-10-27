package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

const (
	maxHarnessHookInputBytes = 2 << 20
	// The command is base64-encoded into the helper argv. Keep the encoded
	// wrapper comfortably below Windows' 32,767-character command-line limit.
	maxHarnessCommandBytes     = 16 << 10
	cursorFallbackLeaseTTL     = 4 * time.Hour
	harnessSessionLeaseTTL     = 4 * time.Hour
	openCodeLeaseTTL           = 4 * time.Hour
	harnessCommandLeaseTTL     = 2 * time.Minute
	harnessCommandLeaseRenew   = 30 * time.Second
	harnessCommandLeasePurpose = "command"
)

var errActiveHookRuntimeUnavailable = errors.New("active Phase AI hook runtime is unavailable")

var (
	harnessRuntimeCycleWait = claudeHookRecycleTimeout
	harnessRuntimeCyclePoll = 50 * time.Millisecond
)

type harnessHookInput struct {
	SessionID     string           `json:"session_id"`
	HookEventName string           `json:"hook_event_name"`
	ToolName      string           `json:"tool_name"`
	ToolUseID     string           `json:"tool_use_id"`
	ToolInput     harnessToolInput `json:"tool_input"`
}

type harnessToolInput map[string]json.RawMessage

func (input harnessToolInput) command() (string, error) {
	raw, present := input["command"]
	if !present {
		return "", errors.New("shell command is unavailable")
	}
	var command string
	if err := json.Unmarshal(raw, &command); err != nil {
		return "", errors.New("shell command is invalid")
	}
	return command, nil
}

func (input harnessToolInput) withCommand(command string) (harnessToolInput, error) {
	raw, err := json.Marshal(command)
	if err != nil {
		return nil, err
	}
	updated := make(harnessToolInput, len(input))
	for key, value := range input {
		updated[key] = append(json.RawMessage(nil), value...)
	}
	updated["command"] = raw
	return updated, nil
}

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

type cursorSessionOutput struct {
	Environment       map[string]string `json:"env,omitempty"`
	AdditionalContext string            `json:"additional_context,omitempty"`
}

type cursorToolOutput struct {
	Permission   string           `json:"permission"`
	UserMessage  string           `json:"user_message,omitempty"`
	AgentMessage string           `json:"agent_message,omitempty"`
	UpdatedInput harnessToolInput `json:"updated_input,omitempty"`
}

type devinHookOutput struct {
	Decision           string `json:"decision,omitempty"`
	Reason             string `json:"reason,omitempty"`
	HookSpecificOutput *struct {
		HookEventName     string           `json:"hookEventName"`
		AdditionalContext string           `json:"additionalContext,omitempty"`
		UpdatedInput      harnessToolInput `json:"updatedInput,omitempty"`
	} `json:"hookSpecificOutput,omitempty"`
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

var aiCursorHookCmd = &cobra.Command{
	Use:          "__cursor-hook",
	Hidden:       true,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runAICursorHook,
}

var aiCursorEventCmd = &cobra.Command{
	Use:          "__cursor-event [guard|heartbeat|session-end]",
	Hidden:       true,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runAICursorEvent,
}

var aiHarnessExecCmd = &cobra.Command{
	Use:           "__harness-exec",
	Hidden:        true,
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runAIHarnessExec,
}

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

var aiDevinHookCmd = &cobra.Command{
	Use:          "__devin-hook",
	Hidden:       true,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runAIDevinHook,
}

var aiDevinEventCmd = &cobra.Command{
	Use:          "__devin-event [guard|heartbeat|context|session-end]",
	Hidden:       true,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runAIDevinEvent,
}

func readHarnessHookInput(reader io.Reader) (harnessHookInput, error) {
	var input harnessHookInput
	if reader == nil {
		return input, errors.New("hook input is unavailable")
	}
	decoder := json.NewDecoder(io.LimitReader(reader, maxHarnessHookInputBytes))
	if err := decoder.Decode(&input); err != nil {
		return input, err
	}
	return input, nil
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
		if !shellCommandRequiresPhase(original) {
			return nil
		}
		if len(original) > maxHarnessCommandBytes {
			return denyCodexShell(cmd)
		}
		if shellCommandMixesPhase(original) {
			return denyCodexShellWithReason(cmd, harnessMixedCommandMessage())
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
			if errors.Is(err, errClaudeRuntimeRefreshing) {
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
		return touchClaudeSessionLease(leaseID)
	case "session-end":
		return removeClaudeSessionLease(leaseID)
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

func runAICursorHook(cmd *cobra.Command, _ []string) error {
	input, err := readHarnessHookInput(cmd.InOrStdin())
	if err != nil || strings.TrimSpace(input.SessionID) == "" {
		return emitCursorBootstrapFailure(cmd)
	}
	if disabled, err := automaticHarnessDisabled(ai.HarnessCursor); disabled || err != nil {
		if err != nil {
			return emitCursorBootstrapFailure(cmd)
		}
		return nil
	}
	if err := refreshConfiguredAISkill(); err != nil {
		return emitCursorBootstrapFailure(cmd)
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(cursorSessionOutput{
		Environment:       map[string]string{"PHASE_CURSOR_SESSION_ID": input.SessionID},
		AdditionalContext: phaseAIHarnessContext,
	})
}

func runAICursorEvent(cmd *cobra.Command, args []string) error {
	input, inputErr := readHarnessHookInput(cmd.InOrStdin())
	action := args[0]
	original := ""
	if action == "guard" {
		var commandErr error
		original, commandErr = input.ToolInput.command()
		if inputErr != nil || commandErr != nil || !strings.EqualFold(strings.TrimSpace(input.ToolName), "Shell") ||
			strings.TrimSpace(original) == "" {
			return denyCursorShell(cmd)
		}
		if shellCommandUsesPowerShellWeb(original) {
			return denyCursorShellWithReason(cmd, harnessPowerShellWebMessage())
		}
		if !shellCommandRequiresPhase(original) {
			return nil
		}
		if len(original) > maxHarnessCommandBytes {
			return denyCursorShell(cmd)
		}
		if shellCommandMixesPhase(original) {
			return denyCursorShellWithReason(cmd, harnessMixedCommandMessage())
		}
	}
	if disabled, configErr := automaticHarnessDisabled(ai.HarnessCursor); disabled || configErr != nil {
		if action == "guard" && configErr != nil {
			return denyCursorShell(cmd)
		}
		return nil
	}
	sessionID := strings.TrimSpace(input.SessionID)
	if sessionID == "" {
		sessionID = strings.TrimSpace(os.Getenv("PHASE_CURSOR_SESSION_ID"))
	}
	switch action {
	case "guard":
		if os.Getenv("PHASE_AI_ENABLED") == "1" {
			if probeInheritedPhaseRuntime(cmd.Context()) != nil {
				return denyCursorShell(cmd)
			}
			return nil
		}
		if err := ensureHarnessRuntimeReady(cmd.Context()); err != nil {
			if errors.Is(err, errClaudeRuntimeRefreshing) {
				return denyCursorShellForPendingRefresh(cmd)
			}
			return denyCursorShell(cmd)
		}
		expiresAt := time.Time{}
		if sessionID == "" {
			// sessionStart is fire-and-forget. A first tool call may win that
			// race, so bind a bounded fallback lease to this tool invocation.
			sessionID = "tool:" + strings.TrimSpace(input.ToolUseID)
			expiresAt = time.Now().UTC().Add(cursorFallbackLeaseTTL)
		}
		if strings.TrimSpace(sessionID) == "" {
			return denyCursorShell(cmd)
		}
		if err := registerHarnessLease(ai.HarnessCursor, sessionID, expiresAt); err != nil {
			return denyCursorShell(cmd)
		}
		leaseID := harnessLeaseID(ai.HarnessCursor, sessionID)
		wrapped, err := buildHarnessWrapperCommand(ai.HarnessCursor, leaseID, original)
		if err != nil {
			return denyCursorShell(cmd)
		}
		updatedInput, err := input.ToolInput.withCommand(wrapped)
		if err != nil {
			return denyCursorShell(cmd)
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(cursorToolOutput{
			Permission: "allow", UpdatedInput: updatedInput,
		})
	case "heartbeat":
		if sessionID != "" {
			return touchClaudeSessionLease(harnessLeaseID(ai.HarnessCursor, sessionID))
		}
		return nil
	case "session-end":
		if sessionID != "" {
			return removeClaudeSessionLease(harnessLeaseID(ai.HarnessCursor, sessionID))
		}
		return nil
	default:
		return errors.New("unsupported Cursor lifecycle event")
	}
}

func emitCursorBootstrapFailure(cmd *cobra.Command) error {
	return json.NewEncoder(cmd.OutOrStdout()).Encode(cursorSessionOutput{
		AdditionalContext: harnessUnavailableContext("Cursor"),
	})
}

func denyCursorShell(cmd *cobra.Command) error {
	return denyCursorShellWithReason(cmd, harnessFailureMessage("Cursor"))
}

func denyCursorShellForPendingRefresh(cmd *cobra.Command) error {
	return denyCursorShellWithReason(cmd, harnessRefreshMessage("Cursor"))
}

func denyCursorShellWithReason(cmd *cobra.Command, reason string) error {
	return json.NewEncoder(cmd.OutOrStdout()).Encode(cursorToolOutput{
		Permission: "deny", UserMessage: reason, AgentMessage: reason,
	})
}

func runAIDevinHook(cmd *cobra.Command, _ []string) error {
	input, err := readHarnessHookInput(cmd.InOrStdin())
	if err != nil || strings.TrimSpace(input.SessionID) == "" {
		return emitDevinBootstrapFailure(cmd)
	}
	if disabled, err := automaticHarnessDisabled(ai.HarnessDevin); disabled || err != nil {
		if err != nil {
			return emitDevinBootstrapFailure(cmd)
		}
		return nil
	}
	if err := refreshConfiguredAISkill(); err != nil {
		return emitDevinBootstrapFailure(cmd)
	}
	return emitDevinContext(cmd, "SessionStart")
}

func runAIDevinEvent(cmd *cobra.Command, args []string) error {
	input, err := readHarnessHookInput(cmd.InOrStdin())
	action := args[0]
	original := ""
	if action == "guard" {
		if err != nil || !strings.EqualFold(strings.TrimSpace(input.ToolName), "exec") {
			return denyDevin(cmd, harnessFailureMessage("Devin"))
		}
		original, err = input.ToolInput.command()
		if err != nil || strings.TrimSpace(original) == "" {
			return denyDevin(cmd, harnessFailureMessage("Devin"))
		}
		if shellCommandUsesPowerShellWeb(original) {
			return denyDevin(cmd, harnessPowerShellWebMessage())
		}
		if !shellCommandRequiresPhase(original) {
			return nil
		}
		if len(original) > maxHarnessCommandBytes {
			return denyDevin(cmd, harnessFailureMessage("Devin"))
		}
		if shellCommandMixesPhase(original) {
			return denyDevin(cmd, harnessMixedCommandMessage())
		}
	}
	if err != nil || strings.TrimSpace(input.SessionID) == "" {
		if action == "guard" {
			return denyDevin(cmd, harnessFailureMessage("Devin"))
		}
		return nil
	}
	if disabled, configErr := automaticHarnessDisabled(ai.HarnessDevin); disabled || configErr != nil {
		if action == "guard" && configErr != nil {
			return denyDevin(cmd, harnessFailureMessage("Devin"))
		}
		return nil
	}
	leaseID := harnessLeaseID(ai.HarnessDevin, input.SessionID)
	switch action {
	case "guard":
		if os.Getenv("PHASE_AI_ENABLED") == "1" {
			if probeInheritedPhaseRuntime(cmd.Context()) != nil {
				return denyDevin(cmd, harnessFailureMessage("Devin"))
			}
			return nil
		}
		if err := ensureHarnessRuntimeReady(cmd.Context()); err != nil {
			if errors.Is(err, errClaudeRuntimeRefreshing) {
				return denyDevin(cmd, harnessRefreshMessage("Devin"))
			}
			return denyDevin(cmd, harnessFailureMessage("Devin"))
		}
		if err := registerHarnessLease(ai.HarnessDevin, input.SessionID, time.Time{}); err != nil {
			return denyDevin(cmd, harnessFailureMessage("Devin"))
		}
		wrapped, err := buildHarnessWrapperCommand(ai.HarnessDevin, leaseID, original)
		if err != nil {
			return denyDevin(cmd, harnessFailureMessage("Devin"))
		}
		updatedInput, err := input.ToolInput.withCommand(wrapped)
		if err != nil {
			return denyDevin(cmd, harnessFailureMessage("Devin"))
		}
		output := devinHookOutput{}
		output.HookSpecificOutput = &struct {
			HookEventName     string           `json:"hookEventName"`
			AdditionalContext string           `json:"additionalContext,omitempty"`
			UpdatedInput      harnessToolInput `json:"updatedInput,omitempty"`
		}{HookEventName: "PreToolUse", UpdatedInput: updatedInput}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
	case "heartbeat":
		// Runtime startup is deliberately lazy. Prompt submission must never
		// stall unrelated work; the first managed command owns the ensure path.
		_ = touchClaudeSessionLease(leaseID)
		return emitDevinContext(cmd, "UserPromptSubmit")
	case "context":
		_ = touchClaudeSessionLease(leaseID)
		return emitDevinContext(cmd, "PostCompaction")
	case "session-end":
		return removeClaudeSessionLease(leaseID)
	default:
		return errors.New("unsupported Devin lifecycle event")
	}
}

func emitDevinContext(cmd *cobra.Command, event string) error {
	output := devinHookOutput{}
	output.HookSpecificOutput = &struct {
		HookEventName     string           `json:"hookEventName"`
		AdditionalContext string           `json:"additionalContext,omitempty"`
		UpdatedInput      harnessToolInput `json:"updatedInput,omitempty"`
	}{HookEventName: event, AdditionalContext: phaseAIHarnessContext}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
}

func emitDevinBootstrapFailure(cmd *cobra.Command) error {
	return emitDevinUnavailableContext(cmd, "SessionStart")
}

func emitDevinUnavailableContext(cmd *cobra.Command, event string) error {
	output := devinHookOutput{}
	output.HookSpecificOutput = &struct {
		HookEventName     string           `json:"hookEventName"`
		AdditionalContext string           `json:"additionalContext,omitempty"`
		UpdatedInput      harnessToolInput `json:"updatedInput,omitempty"`
	}{HookEventName: event, AdditionalContext: harnessUnavailableContext("Devin")}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
}

func denyDevin(cmd *cobra.Command, reason string) error {
	return json.NewEncoder(cmd.OutOrStdout()).Encode(devinHookOutput{Decision: "block", Reason: reason})
}

func automaticHarnessDisabled(harness string) (bool, error) {
	cfg := config.LoadAIConfig()
	if cfg == nil {
		return false, errors.New("Phase AI configuration is unavailable")
	}
	return !cfg.HarnessEnabled(harness), nil
}

func harnessFailureMessage(name string) string {
	return "This explicit Phase control call could not reach a healthy authenticated proxy for this " + name + " session. Only the Phase call was blocked; ordinary ambient tools remain available. Do not silently change credential source. A later direct request from the human may choose ambient execution."
}

func harnessRuntimeFailureMessage(name string, err error) string {
	if errors.Is(err, errClaudeRuntimeAuthenticationRequired) || errors.Is(err, airuntime.ErrAuthenticationRequired) {
		return "Phase authentication is invalid or no longer active for this " + name + " session. The human must authenticate with a current token using phase auth --mode token. Only this explicit Phase call was blocked; ordinary ambient tools remain available. After authentication, retry the same explicit Phase call."
	}
	return harnessFailureMessage(name)
}

func harnessRefreshMessage(name string) string {
	return "Phase AI is recycling its authenticated session for this " + name + " session. Retry the same explicit Phase call shortly as a new tool call. Do not silently change credential source; a later direct request from the human may choose ambient execution."
}

func harnessMixedCommandMessage() string {
	return "This shell call mixes a proxy-local Phase control request with ordinary work. Split it into separate tool calls so the Phase control request can be handled independently."
}

func harnessPowerShellWebMessage() string {
	return "PowerShell's Invoke-WebRequest and Invoke-RestMethod do not use the Phase AI proxy, so they cannot reach phase.invalid. Send the same Phase control request with curl in its own tool call instead, for example: curl.exe -sS http://phase.invalid/v1/status"
}

func harnessUnavailableContext(name string) string {
	return "Phase AI credentials are currently unavailable in this " + name + " session. Ordinary tools, including git and gh, remain available. Commands that need Phase-managed credentials stay blocked until the authenticated proxy recovers."
}

func harnessRuntimePlanError(harness string, err error) error {
	if harness == ai.HarnessCodex && (errors.Is(err, errPhaseProxyNotReachable) || errors.Is(err, errPhaseAgentManifestNotReachable)) {
		return errors.New("phase_ai_codex_sandbox_network_required: the Codex shell sandbox blocked this explicit request to the authenticated local Phase proxy. Retry the same Phase control request once using Codex's normal sandbox escalation; ordinary ambient tools remain independent")
	}
	return err
}

func harnessLeaseID(harness, sessionID string) string {
	return harness + ":" + strings.TrimSpace(sessionID)
}

// ensureHarnessRuntimeReady keeps wrapped harness hooks' steady-state validation
// local to the authenticated proxy. The wrapped command remains responsible
// for fetching the fresh manifest exactly once immediately before execution.
// Fall back to the full ensure path when the runtime is absent, stale, or
// unhealthy so startup and replacement semantics remain unchanged.
func ensureHarnessRuntimeReady(ctx context.Context) error {
	directory, err := claudeHookRuntimeDir()
	if err == nil {
		fingerprint, fingerprintErr := claudeHookFingerprint()
		scopeFingerprint, scopeFingerprintErr := claudeHookScopeFingerprint()
		state, stateErr := readClaudeRuntimeState(filepath.Join(directory, claudeRuntimeStateFile))
		if fingerprintErr == nil && scopeFingerprintErr == nil && stateErr == nil &&
			state.RuntimeFingerprint == fingerprint && state.RuntimeScopeFingerprint == scopeFingerprint &&
			probeClaudeRuntimeState(ctx, state, fingerprint) == nil {
			return nil
		}
	}
	_, err = claudeHookEnsureRuntime(ctx)
	return err
}

func registerHarnessLease(harness, sessionID string, expiresAt time.Time) error {
	directory, err := claudeHookRuntimeDir()
	if err != nil {
		return err
	}
	leaseID := harnessLeaseID(harness, sessionID)
	path, err := claudeSessionLeasePath(directory, leaseID)
	if err != nil {
		return err
	}
	return withClaudeLeaseRegistryLock(context.Background(), directory, func() error {
		return withClaudeLeaseMutationLock(context.Background(), path, func() error {
			state, err := readClaudeRuntimeState(filepath.Join(directory, claudeRuntimeStateFile))
			if err != nil {
				return err
			}
			return writeOwnerOnlyJSON(path, claudeSessionLease{
				Version: claudeRuntimeStateVersion, Generation: state.Generation,
				UpdatedAt: time.Now().UTC(), ExpiresAt: expiresAt,
			})
		})
	})
}

func buildHarnessWrapperCommand(harness, leaseID, original string) (string, error) {
	if strings.TrimSpace(original) == "" || len(original) > maxHarnessCommandBytes {
		return "", errors.New("shell command is invalid")
	}
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		return "", errors.New("Phase hook executable is unavailable")
	}
	encodedLease := base64.RawURLEncoding.EncodeToString([]byte(leaseID))
	encodedCommand := base64.RawURLEncoding.EncodeToString([]byte(original))
	arguments := []string{executable, "ai", "__harness-exec", "--harness", harness, "--lease", encodedLease, "--command", encodedCommand}
	return harnessWrapperCommandLine(runtime.GOOS, harness, arguments), nil
}

// harnessWrapperCommandLine quotes the wrapper for the shell the harness runs
// it in. On Windows, Codex uses PowerShell, which needs the call operator to
// run a quoted executable path; Cursor uses its default terminal profile.
// Other harnesses may run it in PowerShell too, so they get the unquoted form
// every Windows shell runs, and the double-quoted cmd form only when the path
// cannot be written unquoted.
func harnessWrapperCommandLine(goos, harness string, arguments []string) string {
	if goos == "windows" {
		if harness == ai.HarnessCodex || (harness == ai.HarnessCursor && !cursorWindowsShellIsBashOrCmd(cursorWindowsSettings())) {
			return quotePowerShellCommand(arguments)
		}
		if line, ok := ai.WindowsPlainCommand(arguments); ok {
			return line
		}
		return quoteWindowsCommand(arguments)
	}
	quoted := make([]string, len(arguments))
	for index, argument := range arguments {
		quoted[index] = quotePOSIXShellValue(argument)
	}
	return strings.Join(quoted, " ")
}

// cursorWindowsSettings returns Cursor's user settings.json, or nil.
var cursorWindowsSettings = func() []byte {
	directory, err := os.UserConfigDir()
	if err != nil {
		return nil
	}
	settings, err := os.ReadFile(filepath.Join(directory, "Cursor", "User", "settings.json"))
	if err != nil {
		return nil
	}
	return settings
}

// cursorWindowsShellIsBashOrCmd reports whether Cursor's default Windows
// terminal profile is a POSIX shell or cmd, which cannot parse the PowerShell
// call operator; the double-quoted form works in both. Unset or unreadable
// settings mean PowerShell, Cursor's default.
func cursorWindowsShellIsBashOrCmd(settings []byte) bool {
	var parsed map[string]json.RawMessage
	if len(settings) == 0 || json.Unmarshal(stripJSONComments(settings), &parsed) != nil {
		return false
	}
	var name string
	if json.Unmarshal(parsed["terminal.integrated.defaultProfile.windows"], &name) != nil || name == "" {
		return false
	}
	var profiles map[string]struct {
		Path   json.RawMessage `json:"path"`
		Source string          `json:"source"`
	}
	_ = json.Unmarshal(parsed["terminal.integrated.profiles.windows"], &profiles)
	if profile, defined := profiles[name]; defined {
		if path := cursorProfileExecutable(profile.Path); path != "" {
			shell := strings.TrimSuffix(strings.ToLower(filepath.Base(strings.ReplaceAll(path, `\`, "/"))), ".exe")
			return shell != "pwsh" && shell != "powershell"
		}
		switch strings.ToLower(strings.TrimSpace(profile.Source)) {
		case "git bash":
			return true
		case "powershell":
			return false
		}
	}
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.Contains(name, "bash") || name == "command prompt" || name == "cmd"
}

var cursorProfileVariable = regexp.MustCompile(`\$\{(env:[A-Za-z_][A-Za-z0-9_]*|userHome)\}`)

// cursorProfileExecutable resolves a profile's path like the terminal does:
// ${env:NAME} and ${userHome} are substituted, and from a list of candidates
// the first one that exists wins. "" means it cannot be resolved here.
func cursorProfileExecutable(raw json.RawMessage) string {
	var candidates []string
	var single string
	if json.Unmarshal(raw, &single) == nil {
		candidates = []string{single}
	} else if json.Unmarshal(raw, &candidates) != nil {
		return ""
	}
	resolved := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = cursorProfileVariable.ReplaceAllStringFunc(candidate, func(variable string) string {
			name := strings.TrimSuffix(strings.TrimPrefix(variable, "${"), "}")
			if name == "userHome" {
				home, _ := os.UserHomeDir()
				return home
			}
			return os.Getenv(strings.TrimPrefix(name, "env:"))
		})
		if candidate == "" || strings.Contains(candidate, "${") {
			continue
		}
		if len(candidates) == 1 {
			return candidate
		}
		resolved = append(resolved, candidate)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if len(resolved) > 0 {
		return resolved[0]
	}
	return ""
}

// stripJSONComments turns JSONC (comments, trailing commas) into JSON.
// Comments go first so a comment after a trailing comma cannot hide it.
func stripJSONComments(source []byte) []byte {
	return stripJSONTrailingCommas(stripJSONCommentText(source))
}

func stripJSONCommentText(source []byte) []byte {
	out := make([]byte, 0, len(source))
	inString := false
	for index := 0; index < len(source); index++ {
		character := source[index]
		if inString {
			out = append(out, character)
			if character == '\\' && index+1 < len(source) {
				index++
				out = append(out, source[index])
			} else if character == '"' {
				inString = false
			}
			continue
		}
		switch {
		case character == '"':
			inString = true
			out = append(out, character)
		case character == '/' && index+1 < len(source) && source[index+1] == '/':
			for index < len(source) && source[index] != '\n' {
				index++
			}
			index--
		case character == '/' && index+1 < len(source) && source[index+1] == '*':
			index += 2
			for index+1 < len(source) && !(source[index] == '*' && source[index+1] == '/') {
				index++
			}
			index++
			out = append(out, ' ')
		default:
			out = append(out, character)
		}
	}
	return out
}

func stripJSONTrailingCommas(source []byte) []byte {
	out := make([]byte, 0, len(source))
	inString := false
	for index := 0; index < len(source); index++ {
		character := source[index]
		if inString {
			out = append(out, character)
			if character == '\\' && index+1 < len(source) {
				index++
				out = append(out, source[index])
			} else if character == '"' {
				inString = false
			}
			continue
		}
		if character == '"' {
			inString = true
		}
		if character == ',' {
			next := index + 1
			for next < len(source) && (source[next] == ' ' || source[next] == '\t' || source[next] == '\n' || source[next] == '\r') {
				next++
			}
			if next < len(source) && (source[next] == '}' || source[next] == ']') {
				continue
			}
		}
		out = append(out, character)
	}
	return out
}

// quotePowerShellCommand renders `& 'exe' 'arg' ...`. PowerShell treats the
// typographic single quotes as quote characters too, so each is doubled.
func quotePowerShellCommand(arguments []string) string {
	quoted := make([]string, len(arguments))
	for index, argument := range arguments {
		var builder strings.Builder
		builder.WriteByte('\'')
		for _, character := range argument {
			if character == '\'' || character == '\u2018' || character == '\u2019' || character == '\u201A' || character == '\u201B' {
				builder.WriteRune(character)
			}
			builder.WriteRune(character)
		}
		builder.WriteByte('\'')
		quoted[index] = builder.String()
	}
	return "& " + strings.Join(quoted, " ")
}

func quoteWindowsCommand(arguments []string) string {
	quoted := make([]string, len(arguments))
	for index, argument := range arguments {
		quoted[index] = `"` + strings.ReplaceAll(argument, `"`, `\"`) + `"`
	}
	return strings.Join(quoted, " ")
}

type harnessRuntimeBinding struct {
	directory string
	leasePath string
	lease     claudeSessionLease
	lock      claudeRuntimeLock
}

func loadHarnessRuntimePlan(ctx context.Context, leaseID string) (phaseproxy.ProcessEnvironmentPlan, error) {
	binding, err := readHarnessRuntimeBinding(leaseID)
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase AI session is not authorized")
	}
	statePath := filepath.Join(binding.directory, claudeRuntimeStateFile)
	state, err := readClaudeRuntimeState(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return waitForHarnessRuntimeCycle(ctx, binding, nil, fmt.Errorf("%w: runtime state is cycling", errClaudeRuntimeRefreshing))
	}
	if err != nil || !harnessStateMatchesBinding(state, binding) {
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase AI session is not authorized")
	}
	plan, err := loadAndConfirmHarnessRuntimePlan(ctx, binding, state)
	if err == nil {
		return plan, nil
	}
	if !harnessManifestFailureMayBeCycle(err) {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	return waitForHarnessRuntimeCycle(ctx, binding, &state, err)
}

func readHarnessRuntimeBinding(leaseID string) (harnessRuntimeBinding, error) {
	var binding harnessRuntimeBinding
	directory, err := claudeHookRuntimeDir()
	if err != nil {
		return binding, err
	}
	leasePath, err := claudeSessionLeasePath(directory, leaseID)
	if err != nil {
		return binding, err
	}
	var lease claudeSessionLease
	if err := readOwnerOnlyJSON(leasePath, &lease); err != nil || !validHarnessRuntimeLease(lease, time.Now().UTC()) {
		return binding, errors.New("Phase AI harness lease is unavailable")
	}
	lock, err := readClaudeRuntimeLock(filepath.Join(directory, claudeRuntimeLockFile))
	if err != nil || lock.Version != claudeRuntimeStateVersion || lock.Generation != lease.Generation ||
		lock.PID <= 0 || lock.CreatedAt.IsZero() || !processIsAlive(lock.PID) {
		return binding, errors.New("Phase AI runtime ownership is unavailable")
	}
	return harnessRuntimeBinding{directory: directory, leasePath: leasePath, lease: lease, lock: lock}, nil
}

func validHarnessRuntimeLease(lease claudeSessionLease, now time.Time) bool {
	return lease.Version == claudeRuntimeStateVersion && lease.Generation != "" &&
		!lease.UpdatedAt.IsZero() && !lease.UpdatedAt.After(now) &&
		now.Sub(lease.UpdatedAt) <= claudeHookLeaseMaxAge &&
		(lease.ExpiresAt.IsZero() || now.Before(lease.ExpiresAt)) &&
		(lease.Purpose == "" || lease.Purpose == harnessCommandLeasePurpose)
}

func validateHarnessRuntimeBinding(binding harnessRuntimeBinding) error {
	var lease claudeSessionLease
	if err := readOwnerOnlyJSON(binding.leasePath, &lease); err != nil ||
		lease.Generation != binding.lease.Generation || !validHarnessRuntimeLease(lease, time.Now().UTC()) {
		return errors.New("Phase AI harness lease changed during runtime refresh")
	}
	lock, err := readClaudeRuntimeLock(filepath.Join(binding.directory, claudeRuntimeLockFile))
	if err != nil || lock.Version != binding.lock.Version || lock.Generation != binding.lock.Generation ||
		lock.PID != binding.lock.PID || !lock.CreatedAt.Equal(binding.lock.CreatedAt) || !processIsAlive(lock.PID) {
		return errors.New("Phase AI runtime ownership changed during refresh")
	}
	return nil
}

func harnessStateMatchesBinding(state claudeRuntimeState, binding harnessRuntimeBinding) bool {
	return state.Version == claudeRuntimeStateVersion && state.Generation == binding.lock.Generation &&
		state.PID == binding.lock.PID && state.RuntimeFingerprint != "" && state.ProxyURL != "" &&
		!state.StartedAt.IsZero() && processIsAlive(state.PID)
}

func sameHarnessRuntimeState(left, right claudeRuntimeState) bool {
	return left.Version == right.Version && left.Generation == right.Generation &&
		left.RuntimeFingerprint == right.RuntimeFingerprint && left.PID == right.PID &&
		left.StartedAt.Equal(right.StartedAt) && left.ProxyURL == right.ProxyURL
}

func loadAndConfirmHarnessRuntimePlan(ctx context.Context, binding harnessRuntimeBinding, state claudeRuntimeState) (phaseproxy.ProcessEnvironmentPlan, error) {
	plan, err := loadClaudeRuntimePlan(ctx, state, state.RuntimeFingerprint)
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	if err := validateHarnessRuntimeBinding(binding); err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	current, err := readClaudeRuntimeState(filepath.Join(binding.directory, claudeRuntimeStateFile))
	if err != nil || !sameHarnessRuntimeState(current, state) {
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase AI runtime changed while loading its environment")
	}
	return plan, nil
}

func harnessManifestFailureMayBeCycle(err error) bool {
	var failure *phaseAgentManifestFailure
	if !errors.As(err, &failure) {
		return false
	}
	if failure.StatusCode == 407 {
		return true
	}
	return harnessExplicitManifestRefresh(err)
}

func waitForHarnessRuntimeCycle(ctx context.Context, binding harnessRuntimeBinding, previous *claudeRuntimeState, initialErr error) (phaseproxy.ProcessEnvironmentPlan, error) {
	waitContext, cancel := context.WithTimeout(ctx, harnessRuntimeCycleWait)
	defer cancel()
	ticker := time.NewTicker(harnessRuntimeCyclePoll)
	defer ticker.Stop()
	statePath := filepath.Join(binding.directory, claudeRuntimeStateFile)
	for {
		if err := validateHarnessRuntimeBinding(binding); err != nil {
			return phaseproxy.ProcessEnvironmentPlan{}, initialErr
		}
		state, err := readClaudeRuntimeState(statePath)
		if err == nil {
			if !harnessStateMatchesBinding(state, binding) {
				return phaseproxy.ProcessEnvironmentPlan{}, initialErr
			}
			// A new cycle of the same daemon publishes a newer start time. The
			// proxy capability itself is stable across cycles (one Engine serves
			// them all), so it cannot tell cycles apart.
			refreshed := previous == nil
			if previous != nil {
				refreshed = state.RuntimeFingerprint == previous.RuntimeFingerprint &&
					state.StartedAt.After(previous.StartedAt)
			}
			if refreshed {
				return loadAndConfirmHarnessRuntimePlan(waitContext, binding, state)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return phaseproxy.ProcessEnvironmentPlan{}, initialErr
		}
		select {
		case <-waitContext.Done():
			if ctx.Err() != nil {
				return phaseproxy.ProcessEnvironmentPlan{}, ctx.Err()
			}
			if errors.Is(initialErr, errClaudeRuntimeRefreshing) || harnessExplicitManifestRefresh(initialErr) {
				return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase AI is still refreshing after credential fulfillment; retry the same explicit Phase call shortly. The command was not started")
			}
			return phaseproxy.ProcessEnvironmentPlan{}, initialErr
		case <-ticker.C:
		}
	}
}

func harnessExplicitManifestRefresh(err error) bool {
	var failure *phaseAgentManifestFailure
	return errors.As(err, &failure) && failure.StatusCode == 503 && failure.Structured && failure.Canonical && failure.Retryable &&
		failure.Code == aiproxy.ManifestRefreshRequiredCode
}

func runAIHarnessExec(cmd *cobra.Command, _ []string) error {
	harness, _ := cmd.Flags().GetString("harness")
	encodedLease, _ := cmd.Flags().GetString("lease")
	encodedCommand, _ := cmd.Flags().GetString("command")
	if harness != ai.HarnessClaudeCode && harness != ai.HarnessCodex && harness != ai.HarnessCursor && harness != ai.HarnessDevin && harness != ai.HarnessOpenCode {
		return errors.New("unsupported Phase AI harness")
	}
	leaseBytes, err := base64.RawURLEncoding.DecodeString(encodedLease)
	if err != nil || len(leaseBytes) == 0 || len(leaseBytes) > 1024 {
		return errors.New("Phase AI harness lease is invalid")
	}
	commandBytes, err := base64.RawURLEncoding.DecodeString(encodedCommand)
	if err != nil || len(commandBytes) == 0 || len(commandBytes) > maxHarnessCommandBytes {
		return errors.New("Phase AI wrapped command is invalid")
	}
	if disabled, err := automaticHarnessDisabled(harness); disabled || err != nil {
		return errors.New("Phase AI is not enabled")
	}
	leaseID := string(leaseBytes)
	if !strings.HasPrefix(leaseID, harness+":") {
		return errors.New("Phase AI harness lease does not match the caller")
	}

	environment := os.Environ()
	releaseCommandLease := func() {}
	if os.Getenv("PHASE_AI_ENABLED") == "1" {
		if err := probeInheritedPhaseRuntime(cmd.Context()); err != nil {
			return errors.New("Phase AI inherited proxy is not healthy")
		}
	} else {
		// PreToolUse already fingerprint-validates the managed runtime before
		// minting this generation-bound lease. Do not re-read the keyring from
		// the sandboxed child. The wrapper validates the owner-only lease and
		// daemon lock, then fetches the short-lived plan from that exact runtime.
		// A pre-execution manifest refresh may rotate the proxy capability; wait
		// for that same daemon cycle without ever replaying the child command.
		plan, err := loadHarnessRuntimePlan(cmd.Context(), leaseID)
		if err != nil {
			return harnessRuntimePlanError(harness, err)
		}
		environment, err = phaseproxy.ApplyProcessEnvironment(environment, plan)
		if err != nil {
			return errors.New("Phase AI environment could not be applied")
		}
		releaseCommandLease, err = holdHarnessCommandLease(harness)
		if err != nil {
			return errors.New("Phase AI could not retain the proxy for this command")
		}
	}
	err = executeHarnessShell(cmd.Context(), string(commandBytes), environment, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
	releaseCommandLease()
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		code := exitError.ExitCode()
		if code < 1 || code > 255 {
			code = 1
		}
		os.Exit(code)
	}
	return err
}

func holdHarnessCommandLease(harness string) (func(), error) {
	_, release, err := holdHarnessCommandLeaseWithID(harness, "")
	return release, err
}

// holdHarnessCommandLeaseWithID creates a command lease while holding the
// lease registry lock, then pins every renewal to that exact daemon owner.
// requiredScope is used by a plaintext `phase ai exec` attach; wrapped hook
// commands have already validated their own generation-bound caller lease.
func holdHarnessCommandLeaseWithID(harness, requiredScope string) (string, func(), error) {
	random, err := randomClaudeGeneration()
	if err != nil {
		return "", nil, err
	}
	sessionID := "command:" + random
	leaseID := harnessLeaseID(harness, sessionID)
	directory, err := claudeHookRuntimeDir()
	if err != nil {
		return "", nil, err
	}
	path, err := claudeSessionLeasePath(directory, leaseID)
	if err != nil {
		return "", nil, err
	}

	var generation string
	var ownerPID int
	var ownerCreatedAt time.Time
	register := func(initial bool) error {
		return withClaudeLeaseRegistryLock(context.Background(), directory, func() error {
			state, err := readClaudeRuntimeState(filepath.Join(directory, claudeRuntimeStateFile))
			if err != nil || state.RuntimeFingerprint == "" || state.StartedAt.IsZero() ||
				validateClaudeRuntimeState(state, state.RuntimeFingerprint) != nil {
				return errActiveHookRuntimeUnavailable
			}
			if requiredScope != "" && state.RuntimeScopeFingerprint != requiredScope {
				return errActiveHookRuntimeUnavailable
			}
			lock, err := readClaudeRuntimeLock(filepath.Join(directory, claudeRuntimeLockFile))
			if err != nil || lock.Version != claudeRuntimeStateVersion || lock.Generation != state.Generation ||
				lock.PID != state.PID || lock.CreatedAt.IsZero() || !processIsAlive(lock.PID) {
				return errActiveHookRuntimeUnavailable
			}
			if !initial && (state.Generation != generation || lock.PID != ownerPID || !lock.CreatedAt.Equal(ownerCreatedAt)) {
				return errActiveHookRuntimeUnavailable
			}
			if initial {
				generation, ownerPID, ownerCreatedAt = state.Generation, lock.PID, lock.CreatedAt
			}
			return withClaudeLeaseMutationLock(context.Background(), path, func() error {
				if !initial {
					var current claudeSessionLease
					if err := readOwnerOnlyJSON(path, &current); err != nil ||
						current.Generation != generation || current.Purpose != harnessCommandLeasePurpose {
						return errActiveHookRuntimeUnavailable
					}
				}
				return writeOwnerOnlyJSON(path, claudeSessionLease{
					Version: claudeRuntimeStateVersion, Generation: generation,
					UpdatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(harnessCommandLeaseTTL),
					Purpose: harnessCommandLeasePurpose,
				})
			})
		})
	}
	if err := register(true); err != nil {
		return "", nil, err
	}
	done := make(chan struct{})
	waitForRenewal := startHarnessCommandLeaseRenewal(done, harnessCommandLeaseRenew, func() error { return register(false) })
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(done)
			waitForRenewal()
			_ = withClaudeLeaseRegistryLock(context.Background(), directory, func() error {
				return withClaudeLeaseMutationLock(context.Background(), path, func() error {
					var current claudeSessionLease
					if err := readOwnerOnlyJSON(path, &current); err != nil {
						return nil
					}
					if current.Generation == generation && current.Purpose == harnessCommandLeasePurpose {
						_ = os.Remove(path)
					}
					return nil
				})
			})
		})
	}
	return leaseID, release, nil
}

func startHarnessCommandLeaseRenewal(done <-chan struct{}, interval time.Duration, register func() error) func() {
	var renewal sync.WaitGroup
	renewal.Add(1)
	go func() {
		defer renewal.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				_ = register()
			}
		}
	}()
	return renewal.Wait
}

// windowsPowerShellPrelude makes curl and wget run the real executables.
// Windows PowerShell aliases both to Invoke-WebRequest, which ignores
// HTTP(S)_PROXY, so a wrapped phase.invalid call would miss the Phase proxy.
const windowsPowerShellPrelude = "Remove-Item -Path Alias:curl, Alias:wget -Force -ErrorAction SilentlyContinue; "

func executeHarnessShell(ctx context.Context, command string, environment []string, stdin io.Reader, stdout, stderr io.Writer) error {
	shell := util.GetDefaultShell()
	if len(shell) == 0 {
		return errors.New("default shell is unavailable")
	}
	arguments := []string{"-c", command}
	if runtime.GOOS == "windows" {
		base := strings.ToLower(shell[0])
		if strings.Contains(base, "powershell") || strings.Contains(base, "pwsh") {
			arguments = []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", windowsPowerShellPrelude + command}
		} else {
			arguments = []string{"/D", "/S", "/C", command}
		}
	}
	child := exec.CommandContext(ctx, shell[0], arguments...)
	child.Env = environment
	child.Stdin = stdin
	child.Stdout = stdout
	child.Stderr = stderr
	if err := child.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return fmt.Errorf("wrapped command exited with status %d: %w", exitError.ExitCode(), err)
		}
		return err
	}
	return nil
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
		if errors.Is(err, errClaudeRuntimeRefreshing) {
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
	directory, err := claudeHookRuntimeDir()
	if err != nil {
		return nil
	}
	kickHarnessRuntime(cmd.Context(), directory, ai.HarnessOpenCode, sessionID, claudeHookKickBudget)
	return nil
}

func emitOpenCodeCommandResponse(cmd *cobra.Command, response openCodeCommandResponse) error {
	return json.NewEncoder(cmd.OutOrStdout()).Encode(response)
}

func init() {
	aiHarnessExecCmd.Flags().String("harness", "", "")
	aiHarnessExecCmd.Flags().String("lease", "", "")
	aiHarnessExecCmd.Flags().String("command", "", "")
	aiOpenCodeCommandCmd.Flags().String("session", "", "")
	aiOpenCodeCommandCmd.Flags().String("command", "", "")
	aiOpenCodeSessionCmd.Flags().String("session", "", "")
	aiCmd.AddCommand(
		aiCodexHookCmd, aiCodexEventCmd,
		aiCursorHookCmd, aiCursorEventCmd,
		aiDevinHookCmd, aiDevinEventCmd,
		aiHarnessExecCmd, aiOpenCodeCommandCmd, aiOpenCodeSessionCmd,
	)
}
