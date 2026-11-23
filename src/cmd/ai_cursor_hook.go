package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/spf13/cobra"
)

// Cursor's adapter: its session hook, the shell hook that wraps commands in
// the shared runtime, and reading Cursor's Windows terminal settings.

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
		if shellCommandMixesPhase(original) {
			return denyCursorShellWithReason(cmd, harnessMixedCommandMessage())
		}
		if !shellCommandRequiresPhase(original) {
			return nil
		}
		if len(original) > maxHarnessCommandBytes {
			return denyCursorShell(cmd)
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
			if errors.Is(err, errHookRuntimeRefreshing) {
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
			return touchSessionLease(harnessLeaseID(ai.HarnessCursor, sessionID))
		}
		return nil
	case "session-end":
		if sessionID != "" {
			return removeSessionLease(harnessLeaseID(ai.HarnessCursor, sessionID))
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

func init() {
	aiCmd.AddCommand(aiCursorHookCmd, aiCursorEventCmd)
}
