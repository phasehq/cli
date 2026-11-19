package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	"github.com/spf13/cobra"
)

// Claude Code's adapter: its hook commands, the context its SessionStart hook
// injects, and the loader line written into CLAUDE_ENV_FILE.

type claudeHookInput struct {
	SessionID string `json:"session_id"`
}

type claudeSessionStartOutput struct {
	HookSpecificOutput struct {
		HookEventName     string `json:"hookEventName"`
		AdditionalContext string `json:"additionalContext"`
		ReloadSkills      bool   `json:"reloadSkills"`
	} `json:"hookSpecificOutput"`
}

type claudePromptSubmitOutput struct {
	HookSpecificOutput struct {
		HookEventName     string `json:"hookEventName"`
		AdditionalContext string `json:"additionalContext,omitempty"`
	} `json:"hookSpecificOutput"`
}

// claudePhaseAIHarnessContext is the session context for Claude Code, whose
// shell sources the Phase AI environment before every command.
const claudePhaseAIHarnessContext = `Phase AI is enabled on this machine: the human chose Phase-managed execution by running phase ai enable. While the Phase proxy is running, every Bash command starts with the Phase AI environment, so provider CLIs and HTTP clients for this Workflow's Connections use Phase-managed credentials automatically, with no wrapper. http://phase.invalid/v1/status lists the Connections. If Phase is unavailable, Phase-managed commands fail with credential or connection errors while everything else is unaffected: tell the human and continue other work. ` + claudePhaseAIRules

// claudeNoLoaderPhaseAIContext replaces it when the session's shell could not
// be set up to load the Phase AI environment.
const claudeNoLoaderPhaseAIContext = `Phase AI is enabled on this machine: the human chose Phase-managed execution by running phase ai enable. Phase could not set up this session's shell, so Bash commands here do not start with the Phase AI environment and use ambient credentials. For a command that needs this Workflow's Connections, run it as phase ai exec -- <command>. http://phase.invalid/v1/status lists the Connections. If Phase is unavailable, phase ai exec fails while everything else is unaffected: tell the human and continue other work. ` + claudePhaseAIRules

const claudePhaseAIRules = `Never unset, override, print, or copy PHASE_AI_*, HTTPS_PROXY, or provider credential variables, and never substitute other credentials. Values Phase shows masked are hidden on purpose: never try to recover, decode, or work around them, and tell the human if the task needs one. Load the phase-cli skill for Connections, access requests, and app secrets.`

const claudeInheritedPhaseAIContext = `Phase AI is active through the environment inherited from phase ai run: provider CLIs and HTTP clients for this Workflow's Connections already use Phase-managed credentials. http://phase.invalid/v1/status lists them. Never unset, override, print, or copy PHASE_AI_*, HTTPS_PROXY, or provider credential variables, and never substitute other credentials. Values Phase shows masked are hidden on purpose: never try to recover, decode, or work around them, and tell the human if the task needs one. Load the phase-cli skill for Connections, access requests, and app secrets.`

var aiClaudeHookCmd = &cobra.Command{
	Use:          "__claude-hook",
	Hidden:       true,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runAIClaudeHook,
}

var aiClaudeEventCmd = &cobra.Command{
	Use:          "__claude-event [heartbeat|session-end]",
	Hidden:       true,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runAIClaudeEvent,
}

func runAIClaudeHook(cmd *cobra.Command, args []string) error {
	hookInput, _ := readClaudeHookInput(cmd.InOrStdin())
	aiConfig := config.LoadAIConfig()
	if aiConfig == nil {
		return emitClaudeHookFailure(cmd)
	}
	if !aiConfig.HarnessEnabled(ai.HarnessClaudeCode) {
		return nil
	}
	if err := refreshConfiguredAISkill(); err != nil {
		return emitClaudeHookFailure(cmd)
	}

	if strings.TrimSpace(hookInput.SessionID) == "" {
		return emitClaudeHookFailure(cmd)
	}
	if claudeLauncherEnvironment() {
		// phase ai run already gave this harness a complete environment; the
		// loader defers to it and no second runtime is started.
		return emitClaudeHookContext(cmd, claudeInheritedPhaseAIContext)
	}
	directory, err := hookRuntimeDir()
	if err != nil {
		// No runtime directory means no loader either.
		return emitClaudeHookContext(cmd, claudeNoLoaderPhaseAIContext+"\n"+runtimeStatusLine(hookRuntimeHealth{}))
	}
	// The harness-owned env file only ever receives a line that sources the
	// daemon-maintained file, so this hook never writes a secret anywhere the
	// harness reads directly. Startup is bounded and best effort: a slow or
	// unreachable Console must not delay ordinary work, and the next prompt
	// retries.
	loaderPath := strings.TrimSpace(os.Getenv("CLAUDE_ENV_FILE"))
	sessionContext := claudePhaseAIHarnessContext
	if loaderPath == "" || installClaudeEnvironmentLoader(loaderPath, runtimeEnvironmentPath(directory)) != nil {
		sessionContext = claudeNoLoaderPhaseAIContext
	}
	health := kickClaudeRuntime(cmd.Context(), directory, hookInput.SessionID, hookKickBudget)
	return emitClaudeHookContext(cmd, sessionContext+"\n"+runtimeStatusLine(health))
}

// claudeLauncherEnvironment reports whether Claude inherited a complete Phase
// environment from a launcher such as phase ai run. One copied from the shared
// hook daemon (Claude started from an OpenCode shell) is adopted instead: it
// needs the loader and a lease to follow that daemon's restarts.
func claudeLauncherEnvironment() bool {
	if os.Getenv("PHASE_AI_ENABLED") != "1" {
		return false
	}
	proxyURL := firstEnvironmentValue("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")
	return proxyURL == "" || os.Getenv(hookRuntimeMarker) != hookRuntimeMarkerValue(proxyURL)
}

func emitClaudeHookFailure(cmd *cobra.Command) error {
	return emitClaudeHookContext(cmd, harnessUnavailableContext("Claude"))
}

func emitClaudeHookContext(cmd *cobra.Command, additionalContext string) error {
	output := claudeSessionStartOutput{}
	output.HookSpecificOutput.HookEventName = "SessionStart"
	output.HookSpecificOutput.AdditionalContext = additionalContext
	output.HookSpecificOutput.ReloadSkills = true
	return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
}

func runAIClaudeEvent(cmd *cobra.Command, args []string) error {
	action := args[0]
	input, inputErr := readClaudeHookInput(cmd.InOrStdin())
	aiConfig := config.LoadAIConfig()
	if aiConfig == nil || !aiConfig.HarnessEnabled(ai.HarnessClaudeCode) {
		return nil
	}
	if inputErr != nil || strings.TrimSpace(input.SessionID) == "" {
		return nil
	}
	switch action {
	case "heartbeat":
		return runClaudeHeartbeat(cmd, input.SessionID)
	case "session-end":
		return removeSessionLease(harnessLeaseID(ai.HarnessClaudeCode, input.SessionID))
	default:
		return errors.New("unsupported Claude lifecycle event")
	}
}

// runClaudeHeartbeat runs once per prompt. It keeps the session lease fresh,
// restarts a daemon that is gone within a bounded budget, retires stale proxy
// routing, and tells the Agent whether Phase is ready. Nothing here touches
// the network while the daemon is healthy.
func runClaudeHeartbeat(cmd *cobra.Command, sessionID string) error {
	leaseID := harnessLeaseID(ai.HarnessClaudeCode, sessionID)
	_ = touchSessionLease(leaseID)
	if claudeLauncherEnvironment() {
		return nil
	}
	directory, err := hookRuntimeDir()
	if err != nil {
		return nil
	}
	// Repairs a session whose SessionStart could not install the loader.
	_ = installClaudeEnvironmentLoader(os.Getenv("CLAUDE_ENV_FILE"), runtimeEnvironmentPath(directory))
	health := inspectHookRuntime(directory)
	if health.ready {
		if _, statErr := os.Stat(mustSessionLeasePath(directory, leaseID)); statErr != nil {
			_ = registerHarnessLease(ai.HarnessClaudeCode, sessionID, time.Now().UTC().Add(harnessSessionLeaseTTL))
		}
	} else {
		health = kickClaudeRuntime(cmd.Context(), directory, sessionID, hookKickBudget)
	}
	output := claudePromptSubmitOutput{}
	output.HookSpecificOutput.HookEventName = "UserPromptSubmit"
	output.HookSpecificOutput.AdditionalContext = runtimeStatusLine(health)
	return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
}

func readClaudeHookInput(reader io.Reader) (claudeHookInput, error) {
	var input claudeHookInput
	if reader == nil {
		return input, errors.New("Claude hook input is unavailable")
	}
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	if err := decoder.Decode(&input); err != nil {
		return input, err
	}
	return input, nil
}

func init() {
	aiCmd.AddCommand(aiClaudeHookCmd, aiClaudeEventCmd)
}

const claudeEnvironmentLoaderMark = "# phase-ai-env-loader v1"

// claudeEnvironmentLoaderSnippet is the only content Phase writes into the
// harness-owned environment file. It names a path; no Phase value enters that
// file. An environment inherited from `phase ai run` (PHASE_AI_ENABLED=1) wins
// unless it was copied from this file, and a missing or unreadable file is a
// silent no-op.
func claudeEnvironmentLoaderSnippet(environmentPath string) string {
	quoted := ai.QuotePOSIXShell(environmentPath)
	return claudeEnvironmentLoaderMark + "\n" +
		`if { [ "${PHASE_AI_ENABLED:-}" != 1 ] || [ -n "${` + hookRuntimeMarker + `:-}" ]; } && [ -r ` + quoted + ` ]; then . ` + quoted + `; fi` + "\n"
}

// installClaudeEnvironmentLoader appends the loader snippet to loaderPath once.
func installClaudeEnvironmentLoader(loaderPath, environmentPath string) error {
	loaderPath = strings.TrimSpace(loaderPath)
	if loaderPath == "" {
		return nil
	}
	if !filepath.IsAbs(environmentPath) || strings.ContainsAny(environmentPath, "\x00\r\n") {
		return errors.New("Phase AI environment path is invalid")
	}
	existing, err := os.ReadFile(loaderPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if bytes.Contains(existing, []byte(claudeEnvironmentLoaderMark)) {
		return nil
	}
	file, err := openRuntimeEnvironmentFile(loaderPath)
	if err != nil {
		return err
	}
	defer file.Close()
	snippet := claudeEnvironmentLoaderSnippet(environmentPath)
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		snippet = "\n" + snippet
	}
	_, err = file.WriteString(snippet)
	return err
}

// kickClaudeRuntime starts or repairs the hook-owned daemon with a bounded wait
// and never fails the calling hook. When the runtime is ready it registers the
// session lease so the daemon keeps running between prompts.
func kickClaudeRuntime(ctx context.Context, directory, sessionID string, budget time.Duration) hookRuntimeHealth {
	return kickHarnessRuntime(ctx, directory, ai.HarnessClaudeCode, sessionID, budget)
}
