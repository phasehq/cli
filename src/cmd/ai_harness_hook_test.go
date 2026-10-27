package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/spf13/cobra"
)

func withHarnessHookConfig(t *testing.T, harness string) {
	t.Helper()
	originalPath := config.AIConfigPath
	config.AIConfigPath = filepath.Join(t.TempDir(), "ai.json")
	t.Cleanup(func() { config.AIConfigPath = originalPath })
	if err := config.SaveAIConfig(&config.AIConfig{
		Enabled: true, ProxyMode: config.AIProxyModeLocal, HarnessID: harness,
	}); err != nil {
		t.Fatal(err)
	}
}

func prepareHarnessHookRuntime(t *testing.T) string {
	t.Helper()
	directory := withClaudeHookRuntimeDirectory(t)
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one",
		RuntimeFingerprint: "fingerprint-one", PID: os.Getpid(),
		ProxyURL: "http://phase:capability@127.0.0.1:9543",
	}); err != nil {
		t.Fatal(err)
	}
	originalEnsure := claudeHookEnsureRuntime
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		return phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{
			"PHASE_AI_ENABLED": "1", "AWS_SECRET_ACCESS_KEY": "decoy-never-print",
		}}, nil
	}
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })
	return directory
}

func newHarnessHookCommand(input string) (*cobra.Command, *bytes.Buffer) {
	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.SetIn(strings.NewReader(input))
	output := &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(&bytes.Buffer{})
	return command, output
}

func harnessUpdatedCommand(t *testing.T, input harnessToolInput) string {
	t.Helper()
	command, err := input.command()
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func assertHarnessToolInputMetadataPreserved(t *testing.T, input harnessToolInput) {
	t.Helper()
	expected := map[string]string{
		"sandbox_permissions": `"require_escalated"`,
		"justification":       `"Allow the authenticated local Phase proxy"`,
		"prefix_rule":         `["aws","sts"]`,
		"working_directory":   `"/workspace/phase"`,
	}
	for key, value := range expected {
		if !bytes.Equal(input[key], []byte(value)) {
			t.Fatalf("updated tool input %s = %s, want exact %s", key, input[key], value)
		}
	}
}

func TestCodexGuardWrapsCommandWithoutExposingRuntimePlan(t *testing.T) {
	withHarnessHookConfig(t, ai.HarnessCodex)
	prepareHarnessHookRuntime(t)
	t.Setenv("PHASE_AI_ENABLED", "")

	command, output := newHarnessHookCommand(`{
        "session_id":"codex-session","hook_event_name":"PreToolUse","tool_name":"Bash",
		"tool_input":{"command":"curl http://phase.invalid/v1/status","sandbox_permissions":"require_escalated",
		"justification":"Allow the authenticated local Phase proxy","prefix_rule":["aws","sts"],
		"working_directory":"/workspace/phase"},"tool_use_id":"tool-one"
    }`)
	if err := runAICodexEvent(command, []string{"guard"}); err != nil {
		t.Fatal(err)
	}
	var result codexToolOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	wrapped := harnessUpdatedCommand(t, result.HookSpecificOutput.UpdatedInput)
	if result.HookSpecificOutput.PermissionDecision != "allow" || !strings.Contains(wrapped, "__harness-exec") {
		t.Fatalf("unexpected Codex guard output: %#v", result)
	}
	assertHarnessToolInputMetadataPreserved(t, result.HookSpecificOutput.UpdatedInput)
	if strings.Contains(output.String(), "decoy-never-print") || strings.Contains(output.String(), "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("Codex hook exposed runtime material: %s", output.String())
	}
	if strings.Contains(wrapped, "curl http://phase.invalid/v1/status") {
		t.Fatalf("wrapped command should carry the original command as bounded base64: %s", wrapped)
	}
}

func TestCodexGuardExplainsAuthenticationRecoveryWithoutBlockingAmbientTools(t *testing.T) {
	withHarnessHookConfig(t, ai.HarnessCodex)
	withClaudeHookRuntimeDirectory(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	originalEnsure := claudeHookEnsureRuntime
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		return phaseproxy.ProcessEnvironmentPlan{}, airuntime.ErrAuthenticationRequired
	}
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })

	command, output := newHarnessHookCommand(`{
		"session_id":"codex-session","hook_event_name":"PreToolUse","tool_name":"Bash",
		"tool_input":{"command":"curl http://phase.invalid/v1/status"},"tool_use_id":"tool-one"
	}`)
	if err := runAICodexEvent(command, []string{"guard"}); err != nil {
		t.Fatal(err)
	}
	var result codexToolOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	reason := result.HookSpecificOutput.PermissionDecisionReason
	if result.HookSpecificOutput.PermissionDecision != "deny" ||
		!strings.Contains(reason, "phase auth --mode token") ||
		!strings.Contains(reason, "ordinary ambient tools remain available") ||
		strings.Contains(reason, "phase ai enable") || strings.Contains(strings.ToLower(reason), "restart") {
		t.Fatalf("unexpected authentication denial: %#v", result)
	}
}

func TestAutomaticHarnessGuardsLeaveOrdinaryCommandsAloneWithUnhealthyInheritedRuntime(t *testing.T) {
	t.Setenv("PHASE_AI_ENABLED", "1")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("http_proxy", "")

	tests := []struct {
		name, harness, input string
		run                  func(*cobra.Command) error
	}{
		{
			name: "codex", harness: ai.HarnessCodex,
			input: `{"session_id":"codex-session","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status && gh pr create --fill"},"tool_use_id":"tool-one"}`,
			run:   func(command *cobra.Command) error { return runAICodexEvent(command, []string{"guard"}) },
		},
		{
			name: "cursor", harness: ai.HarnessCursor,
			input: `{"session_id":"cursor-session","hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"git status && gh pr create --fill"},"tool_use_id":"tool-two"}`,
			run:   func(command *cobra.Command) error { return runAICursorEvent(command, []string{"guard"}) },
		},
		{
			name: "devin", harness: ai.HarnessDevin,
			input: `{"session_id":"devin-session","hook_event_name":"PreToolUse","tool_name":"exec","tool_input":{"command":"git status && gh pr create --fill"},"tool_use_id":"tool-three"}`,
			run:   func(command *cobra.Command) error { return runAIDevinEvent(command, []string{"guard"}) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withHarnessHookConfig(t, test.harness)
			command, output := newHarnessHookCommand(test.input)
			if err := test.run(command); err != nil {
				t.Fatal(err)
			}
			if output.Len() != 0 {
				t.Fatalf("ordinary command was intercepted with inherited Phase environment: %s", output.String())
			}
		})
	}
}

func TestAutomaticHarnessGuardsLeaveLargeOrdinaryCommandsAlone(t *testing.T) {
	largeCommand, err := json.Marshal("gh pr create --body " + strings.Repeat("ordinary release notes ", maxHarnessCommandBytes/8))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, harness, toolName string
		run                     func(*cobra.Command) error
	}{
		{name: "codex", harness: ai.HarnessCodex, toolName: "Bash", run: func(command *cobra.Command) error {
			return runAICodexEvent(command, []string{"guard"})
		}},
		{name: "cursor", harness: ai.HarnessCursor, toolName: "Shell", run: func(command *cobra.Command) error {
			return runAICursorEvent(command, []string{"guard"})
		}},
		{name: "devin", harness: ai.HarnessDevin, toolName: "exec", run: func(command *cobra.Command) error {
			return runAIDevinEvent(command, []string{"guard"})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withHarnessHookConfig(t, test.harness)
			input := fmt.Sprintf(`{"session_id":"large-session","hook_event_name":"PreToolUse","tool_name":%q,"tool_input":{"command":%s}}`, test.toolName, largeCommand)
			command, output := newHarnessHookCommand(input)
			if err := test.run(command); err != nil {
				t.Fatal(err)
			}
			if output.Len() != 0 {
				t.Fatalf("large ordinary command was intercepted: %s", output.String())
			}
		})
	}
}

func TestAutomaticHarnessGuardsRejectMixedManagedAndOrdinaryCommands(t *testing.T) {
	tests := []struct {
		name, harness, input string
		run                  func(*cobra.Command) error
	}{
		{
			name: "codex", harness: ai.HarnessCodex,
			input: `{"session_id":"codex-session","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh pr create --fill && curl http://phase.invalid/v1/status"},"tool_use_id":"tool-one"}`,
			run:   func(command *cobra.Command) error { return runAICodexEvent(command, []string{"guard"}) },
		},
		{
			name: "cursor", harness: ai.HarnessCursor,
			input: `{"session_id":"cursor-session","hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"gh pr create --fill && curl http://phase.invalid/v1/status"},"tool_use_id":"tool-two"}`,
			run:   func(command *cobra.Command) error { return runAICursorEvent(command, []string{"guard"}) },
		},
		{
			name: "devin", harness: ai.HarnessDevin,
			input: `{"session_id":"devin-session","hook_event_name":"PreToolUse","tool_name":"exec","tool_input":{"command":"gh pr create --fill && curl http://phase.invalid/v1/status"},"tool_use_id":"tool-three"}`,
			run:   func(command *cobra.Command) error { return runAIDevinEvent(command, []string{"guard"}) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withHarnessHookConfig(t, test.harness)
			command, output := newHarnessHookCommand(test.input)
			if err := test.run(command); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "Split it into separate tool calls") {
				t.Fatalf("mixed command was not rejected at the credential boundary: %s", output.String())
			}
		})
	}
}

func TestWrappedHarnessGuardsLeaveManifestFetchToExactlyOnceWrapperBoundary(t *testing.T) {
	tests := []struct {
		name, harness, sessionID, input string
		run                             func(*cobra.Command) error
	}{
		{
			name: "codex", harness: ai.HarnessCodex, sessionID: "codex-session",
			input: `{"session_id":"codex-session","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl http://phase.invalid/v1/status"},"tool_use_id":"tool-one"}`,
			run:   func(command *cobra.Command) error { return runAICodexEvent(command, []string{"guard"}) },
		},
		{
			name: "cursor", harness: ai.HarnessCursor, sessionID: "cursor-session",
			input: `{"session_id":"cursor-session","hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"curl http://phase.invalid/v1/status"},"tool_use_id":"tool-two"}`,
			run:   func(command *cobra.Command) error { return runAICursorEvent(command, []string{"guard"}) },
		},
		{
			name: "devin", harness: ai.HarnessDevin, sessionID: "devin-session",
			input: `{"session_id":"devin-session","hook_event_name":"PreToolUse","tool_name":"exec","tool_input":{"command":"curl http://phase.invalid/v1/status"},"tool_use_id":"tool-three"}`,
			run:   func(command *cobra.Command) error { return runAIDevinEvent(command, []string{"guard"}) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withHarnessHookConfig(t, test.harness)
			directory := withClaudeHookRuntimeDirectory(t)
			t.Setenv("PHASE_AI_ENABLED", "")

			var statusCalls atomic.Int32
			var manifestCalls atomic.Int32
			var proxyURL string
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				switch request.URL.Path {
				case "/v1/status":
					statusCalls.Add(1)
					_, _ = writer.Write([]byte(`{"schemaVersion":1,"kind":"phase.ai.status","safeToPrint":true,"connections":[]}`))
				case "/.well-known/agents":
					manifestCalls.Add(1)
					_ = json.NewEncoder(writer).Encode(map[string]any{
						"schemaVersion": 1, "sessionUid": "session-one",
						"processEnvironment": map[string]any{
							"set": map[string]string{"PHASE_AI_ENABLED": "1", "HTTP_PROXY": proxyURL},
						},
					})
				default:
					writer.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			parsed, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			parsed.User = url.UserPassword("phase", "runtime-capability")
			proxyURL = parsed.String()

			originalFingerprint := claudeHookFingerprint
			originalScopeFingerprint := claudeHookScopeFingerprint
			claudeHookFingerprint = func() (string, error) { return "binding-one", nil }
			claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
			t.Cleanup(func() {
				claudeHookFingerprint = originalFingerprint
				claudeHookScopeFingerprint = originalScopeFingerprint
			})
			now := time.Now().UTC()
			if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), claudeRuntimeState{
				Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one", RuntimeScopeFingerprint: "scope-one",
				PID: os.Getpid(), StartedAt: now, ProxyURL: proxyURL,
			}); err != nil {
				t.Fatal(err)
			}
			if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
				Version: claudeRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(), CreatedAt: now,
			}); err != nil {
				t.Fatal(err)
			}

			command, output := newHarnessHookCommand(test.input)
			if err := test.run(command); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "__harness-exec") {
				t.Fatalf("guard did not wrap the command: %s", output.String())
			}
			if got := manifestCalls.Load(); got != 0 {
				t.Fatalf("guard fetched the Agent manifest %d times, want 0", got)
			}
			if got := statusCalls.Load(); got != 1 {
				t.Fatalf("guard health probes = %d, want 1", got)
			}

			plan, err := loadHarnessRuntimePlan(context.Background(), harnessLeaseID(test.harness, test.sessionID))
			if err != nil {
				t.Fatal(err)
			}
			if plan.Set["HTTP_PROXY"] != proxyURL {
				t.Fatalf("wrapper plan proxy = %q, want %q", plan.Set["HTTP_PROXY"], proxyURL)
			}
			if got := manifestCalls.Load(); got != 1 {
				t.Fatalf("wrapper manifest fetches = %d, want exactly 1", got)
			}
		})
	}
}

func TestWrappedHarnessSessionStartsAreLazyAndDoNotTouchRuntime(t *testing.T) {
	tests := []struct {
		name, harness, sessionID string
		run                      func(*cobra.Command) error
	}{
		{
			name: "codex", harness: ai.HarnessCodex, sessionID: "codex-session",
			run: func(command *cobra.Command) error { return runAICodexHook(command, nil) },
		},
		{
			name: "cursor", harness: ai.HarnessCursor, sessionID: "cursor-session",
			run: func(command *cobra.Command) error { return runAICursorHook(command, nil) },
		},
		{
			name: "devin", harness: ai.HarnessDevin, sessionID: "devin-session",
			run: func(command *cobra.Command) error { return runAIDevinHook(command, nil) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withHarnessHookConfig(t, test.harness)
			directory := withClaudeHookRuntimeDirectory(t)
			t.Setenv("PHASE_AI_ENABLED", "")

			var statusCalls atomic.Int32
			var manifestCalls atomic.Int32
			var proxyURL string
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				switch request.URL.Path {
				case "/v1/status":
					statusCalls.Add(1)
					_, _ = writer.Write([]byte(`{"schemaVersion":1,"kind":"phase.ai.status","safeToPrint":true,"connections":[]}`))
				case "/.well-known/agents":
					manifestCalls.Add(1)
					_ = json.NewEncoder(writer).Encode(map[string]any{
						"schemaVersion": 1, "sessionUid": "session-one",
						"processEnvironment": map[string]any{
							"set": map[string]string{"PHASE_AI_ENABLED": "1", "HTTP_PROXY": proxyURL},
						},
					})
				default:
					writer.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			parsed, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			parsed.User = url.UserPassword("phase", "runtime-capability")
			proxyURL = parsed.String()

			originalFingerprint := claudeHookFingerprint
			originalScopeFingerprint := claudeHookScopeFingerprint
			claudeHookFingerprint = func() (string, error) { return "binding-one", nil }
			claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
			t.Cleanup(func() {
				claudeHookFingerprint = originalFingerprint
				claudeHookScopeFingerprint = originalScopeFingerprint
			})
			now := time.Now().UTC()
			if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), claudeRuntimeState{
				Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one", RuntimeScopeFingerprint: "scope-one",
				PID: os.Getpid(), StartedAt: now, ProxyURL: proxyURL,
			}); err != nil {
				t.Fatal(err)
			}
			if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
				Version: claudeRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(), CreatedAt: now,
			}); err != nil {
				t.Fatal(err)
			}

			command, _ := newHarnessHookCommand(`{"session_id":"` + test.sessionID + `","hook_event_name":"SessionStart"}`)
			if err := test.run(command); err != nil {
				t.Fatal(err)
			}
			if got := statusCalls.Load(); got != 0 {
				t.Fatalf("SessionStart health probes = %d, want 0", got)
			}
			if got := manifestCalls.Load(); got != 0 {
				t.Fatalf("SessionStart fetched the Agent manifest %d times, want 0", got)
			}
			leasePath, err := claudeSessionLeasePath(directory, harnessLeaseID(test.harness, test.sessionID))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(leasePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("SessionStart registered a runtime lease: %v", err)
			}
		})
	}
}

func TestEnsureHarnessRuntimeReadyColdFallbackFailsClosed(t *testing.T) {
	withClaudeHookRuntimeDirectory(t)
	expected := errors.New("cold runtime failed")
	var ensureCalls atomic.Int32
	originalEnsure := claudeHookEnsureRuntime
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		ensureCalls.Add(1)
		return phaseproxy.ProcessEnvironmentPlan{}, expected
	}
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })

	err := ensureHarnessRuntimeReady(context.Background())
	if !errors.Is(err, expected) || ensureCalls.Load() != 1 {
		t.Fatalf("cold fallback error=%v full ensure calls=%d", err, ensureCalls.Load())
	}
}

func TestDevinHeartbeatTouchesExistingLeaseWithoutRuntimeProbe(t *testing.T) {
	withHarnessHookConfig(t, ai.HarnessDevin)
	directory := withClaudeHookRuntimeDirectory(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	now := time.Now().UTC()
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(), StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	leasePath, err := claudeSessionLeasePath(directory, harnessLeaseID(ai.HarnessDevin, "devin-session"))
	if err != nil {
		t.Fatal(err)
	}
	originalUpdatedAt := now.Add(-time.Minute)
	if err := writeOwnerOnlyJSON(leasePath, claudeSessionLease{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", UpdatedAt: originalUpdatedAt,
	}); err != nil {
		t.Fatal(err)
	}
	originalEnsure := claudeHookEnsureRuntime
	var ensureCalls atomic.Int32
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		ensureCalls.Add(1)
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("heartbeat must not start the runtime")
	}
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })

	command, _ := newHarnessHookCommand(`{"session_id":"devin-session","hook_event_name":"UserPromptSubmit"}`)
	if err := runAIDevinEvent(command, []string{"heartbeat"}); err != nil {
		t.Fatal(err)
	}
	if ensureCalls.Load() != 0 {
		t.Fatalf("heartbeat started or probed the managed runtime %d times", ensureCalls.Load())
	}
	var lease claudeSessionLease
	if err := readOwnerOnlyJSON(leasePath, &lease); err != nil || lease.Generation != "generation-one" || !lease.UpdatedAt.After(originalUpdatedAt) {
		t.Fatalf("heartbeat lease was not renewed for the active generation: %#v, %v", lease, err)
	}
}

func TestDevinHeartbeatFailureDoesNotBlockOrdinaryWork(t *testing.T) {
	withHarnessHookConfig(t, ai.HarnessDevin)
	withClaudeHookRuntimeDirectory(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	originalEnsure := claudeHookEnsureRuntime
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("runtime unavailable")
	}
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })

	command, output := newHarnessHookCommand(`{"session_id":"devin-session","hook_event_name":"UserPromptSubmit"}`)
	if err := runAIDevinEvent(command, []string{"heartbeat"}); err != nil {
		t.Fatal(err)
	}
	var result devinHookOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Decision == "block" || result.HookSpecificOutput == nil ||
		result.HookSpecificOutput.HookEventName != "UserPromptSubmit" ||
		!strings.Contains(result.HookSpecificOutput.AdditionalContext, "Plain shell and provider commands") {
		t.Fatalf("runtime failure blocked Devin prompt: %#v", result)
	}
}

func TestCodexGuardReportsManagedRuntimeRecycle(t *testing.T) {
	withHarnessHookConfig(t, ai.HarnessCodex)
	t.Setenv("PHASE_AI_ENABLED", "")
	originalEnsure := claudeHookEnsureRuntime
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		return phaseproxy.ProcessEnvironmentPlan{}, fmt.Errorf("%w: test recycle", errClaudeRuntimeRefreshing)
	}
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })

	command, output := newHarnessHookCommand(`{
		"session_id":"codex-session","hook_event_name":"PreToolUse","tool_name":"Bash",
		"tool_input":{"command":"curl http://phase.invalid/v1/status"},"tool_use_id":"tool-one"
	}`)
	if err := runAICodexEvent(command, []string{"guard"}); err != nil {
		t.Fatal(err)
	}
	var result codexToolOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	reason := result.HookSpecificOutput.PermissionDecisionReason
	if result.HookSpecificOutput.PermissionDecision != "deny" ||
		!strings.Contains(reason, "recycling") || !strings.Contains(reason, "Retry the same explicit Phase call") ||
		strings.Contains(reason, "phase ai enable") {
		t.Fatalf("unexpected transient Codex denial: %#v", result)
	}
}

func TestCodexContextExplainsSandboxNetworkApproval(t *testing.T) {
	command, output := newHarnessHookCommand("")
	if err := emitCodexContext(command); err != nil {
		t.Fatal(err)
	}
	var result codexSessionOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.HookSpecificOutput == nil ||
		!strings.Contains(result.HookSpecificOutput.AdditionalContext, "normal Codex network approval") ||
		!strings.Contains(result.HookSpecificOutput.AdditionalContext, "authenticated local Phase proxy") ||
		!strings.Contains(result.HookSpecificOutput.AdditionalContext, "separate from Connection approval") ||
		!strings.Contains(result.HookSpecificOutput.AdditionalContext, "Unrelated commands do not need Phase recovery") ||
		strings.Contains(result.HookSpecificOutput.AdditionalContext, "phase ai disable") ||
		len(result.HookSpecificOutput.AdditionalContext) > 1200 {
		t.Fatalf("Codex context does not explain the safe sandbox recovery: %#v", result)
	}
}

func TestCodexProxyReachabilityFailureRequestsNormalSandboxEscalation(t *testing.T) {
	for _, err := range []error{errPhaseProxyNotReachable, fmt.Errorf("runtime plan: %w", errPhaseAgentManifestNotReachable)} {
		result := harnessRuntimePlanError(ai.HarnessCodex, err)
		if !strings.Contains(result.Error(), "phase_ai_codex_sandbox_network_required") ||
			!strings.Contains(result.Error(), "Codex shell sandbox blocked") ||
			!strings.Contains(result.Error(), "same Phase control request once") ||
			!strings.Contains(result.Error(), "ordinary ambient tools remain independent") {
			t.Fatalf("unexpected Codex sandbox error: %v", result)
		}
	}
	if got := harnessRuntimePlanError(ai.HarnessCursor, errPhaseProxyNotReachable); !errors.Is(got, errPhaseProxyNotReachable) {
		t.Fatalf("non-Codex reachability error changed: %v", got)
	}
}

func TestAutomaticHarnessConfigAllowsConcurrentIntegrations(t *testing.T) {
	originalPath := config.AIConfigPath
	config.AIConfigPath = filepath.Join(t.TempDir(), "ai.json")
	t.Cleanup(func() { config.AIConfigPath = originalPath })
	if err := config.SaveAIConfig(&config.AIConfig{
		Enabled: true, ProxyMode: config.AIProxyModeLocal,
		HarnessIDs: []string{ai.HarnessCodex, ai.HarnessCursor},
	}); err != nil {
		t.Fatal(err)
	}

	for _, harness := range []string{ai.HarnessCodex, ai.HarnessCursor} {
		disabled, err := automaticHarnessDisabled(harness)
		if err != nil || disabled {
			t.Fatalf("%s integration disabled=%v err=%v", harness, disabled, err)
		}
	}
	disabled, err := automaticHarnessDisabled(ai.HarnessClaudeCode)
	if err != nil || !disabled {
		t.Fatalf("unconfigured Claude integration disabled=%v err=%v", disabled, err)
	}
}

func TestHarnessWrapperCommandEnforcesCrossPlatformArgumentLimit(t *testing.T) {
	if _, err := buildHarnessWrapperCommand(ai.HarnessCodex, "codex:session", strings.Repeat("x", maxHarnessCommandBytes)); err != nil {
		t.Fatalf("maximum supported command was rejected: %v", err)
	}
	if _, err := buildHarnessWrapperCommand(ai.HarnessCodex, "codex:session", strings.Repeat("x", maxHarnessCommandBytes+1)); err == nil {
		t.Fatal("oversized command should be rejected before base64 expansion")
	}
}

func TestHarnessGuardsRejectPowerShellWebCallsToPhase(t *testing.T) {
	const call = "Invoke-RestMethod http://phase.invalid/v1/status"
	t.Setenv("PHASE_AI_ENABLED", "")
	t.Run("codex", func(t *testing.T) {
		withHarnessHookConfig(t, ai.HarnessCodex)
		command, output := newHarnessHookCommand(`{"session_id":"codex-session","hook_event_name":"PreToolUse","tool_name":"Bash",
			"tool_input":{"command":"` + call + `"},"tool_use_id":"tool-one"}`)
		if err := runAICodexEvent(command, []string{"guard"}); err != nil {
			t.Fatal(err)
		}
		var result codexToolOutput
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.HookSpecificOutput.PermissionDecision != "deny" || result.HookSpecificOutput.PermissionDecisionReason != harnessPowerShellWebMessage() {
			t.Fatalf("Codex guard output = %#v", result)
		}
	})
	t.Run("cursor", func(t *testing.T) {
		withHarnessHookConfig(t, ai.HarnessCursor)
		command, output := newHarnessHookCommand(`{"hook_event_name":"preToolUse","tool_name":"Shell",
			"tool_input":{"command":"` + call + `"},"tool_use_id":"tool-two"}`)
		if err := runAICursorEvent(command, []string{"guard"}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "do not use the Phase AI proxy") || strings.Contains(output.String(), "__harness-exec") {
			t.Fatalf("Cursor guard output = %s", output.String())
		}
	})
	t.Run("devin", func(t *testing.T) {
		withHarnessHookConfig(t, ai.HarnessDevin)
		command, output := newHarnessHookCommand(`{"session_id":"devin-session","hook_event_name":"PreToolUse","tool_name":"exec",
			"tool_input":{"command":"` + call + `"},"tool_use_id":"devin-tool"}`)
		if err := runAIDevinEvent(command, []string{"guard"}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "do not use the Phase AI proxy") || strings.Contains(output.String(), "__harness-exec") {
			t.Fatalf("Devin guard output = %s", output.String())
		}
	})
	t.Run("opencode", func(t *testing.T) {
		withHarnessHookConfig(t, ai.HarnessOpenCode)
		if response := runOpenCodeCommandForTest(t, call); !response.Managed || response.Error != harnessPowerShellWebMessage() {
			t.Fatalf("OpenCode command response = %#v", response)
		}
	})
}

func TestCursorGuardUsesSessionEnvironmentAndCursorSchema(t *testing.T) {
	withHarnessHookConfig(t, ai.HarnessCursor)
	prepareHarnessHookRuntime(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	t.Setenv("PHASE_CURSOR_SESSION_ID", "cursor-session")

	command, output := newHarnessHookCommand(`{
        "hook_event_name":"preToolUse","tool_name":"Shell",
		"tool_input":{"command":"curl http://phase.invalid/v1/status","sandbox_permissions":"require_escalated",
		"justification":"Allow the authenticated local Phase proxy","prefix_rule":["aws","sts"],
		"working_directory":"/workspace/phase"},"tool_use_id":"tool-two"
    }`)
	if err := runAICursorEvent(command, []string{"guard"}); err != nil {
		t.Fatal(err)
	}
	var result cursorToolOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Permission != "allow" || !strings.Contains(harnessUpdatedCommand(t, result.UpdatedInput), "__harness-exec") {
		t.Fatalf("unexpected Cursor guard output: %#v", result)
	}
	assertHarnessToolInputMetadataPreserved(t, result.UpdatedInput)
}

func TestCursorGuardCreatesBoundedFallbackLease(t *testing.T) {
	withHarnessHookConfig(t, ai.HarnessCursor)
	directory := prepareHarnessHookRuntime(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	t.Setenv("PHASE_CURSOR_SESSION_ID", "")

	command, _ := newHarnessHookCommand(`{
        "hook_event_name":"preToolUse","tool_name":"Shell",
		"tool_input":{"command":"curl http://phase.invalid/v1/status"},"tool_use_id":"race-tool"
    }`)
	if err := runAICursorEvent(command, []string{"guard"}); err != nil {
		t.Fatal(err)
	}
	leasePath, err := claudeSessionLeasePath(directory, harnessLeaseID(ai.HarnessCursor, "tool:race-tool"))
	if err != nil {
		t.Fatal(err)
	}
	var lease claudeSessionLease
	if err := readOwnerOnlyJSON(leasePath, &lease); err != nil {
		t.Fatal(err)
	}
	if lease.ExpiresAt.IsZero() || time.Until(lease.ExpiresAt) > cursorFallbackLeaseTTL+time.Minute {
		t.Fatalf("unexpected fallback lease expiry: %s", lease.ExpiresAt)
	}
}

func TestDevinGuardUsesUpdatedInputWithoutRuntimeMaterial(t *testing.T) {
	withHarnessHookConfig(t, ai.HarnessDevin)
	prepareHarnessHookRuntime(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	command, output := newHarnessHookCommand(`{
        "session_id":"devin-session","hook_event_name":"PreToolUse","tool_name":"exec",
		"tool_input":{"command":"curl http://phase.invalid/v1/status","sandbox_permissions":"require_escalated",
		"justification":"Allow the authenticated local Phase proxy","prefix_rule":["aws","sts"],
		"working_directory":"/workspace/phase"},"tool_use_id":"devin-tool"
    }`)
	if err := runAIDevinEvent(command, []string{"guard"}); err != nil {
		t.Fatal(err)
	}
	var result devinHookOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.HookSpecificOutput == nil || !strings.Contains(harnessUpdatedCommand(t, result.HookSpecificOutput.UpdatedInput), "__harness-exec") {
		t.Fatalf("unexpected Devin guard output: %#v", result)
	}
	assertHarnessToolInputMetadataPreserved(t, result.HookSpecificOutput.UpdatedInput)
	if strings.Contains(output.String(), "decoy-never-print") {
		t.Fatalf("Devin hook exposed runtime material: %s", output.String())
	}
}

func runOpenCodeCommandForTest(t *testing.T, original string) openCodeCommandResponse {
	t.Helper()
	command, output := newHarnessHookCommand("")
	command.Flags().String("session", "", "")
	command.Flags().String("command", "", "")
	if err := command.Flags().Set("session", "opencode-session"); err != nil {
		t.Fatal(err)
	}
	if err := command.Flags().Set("command", base64.RawURLEncoding.EncodeToString([]byte(original))); err != nil {
		t.Fatal(err)
	}
	if err := runAIOpenCodeCommand(command, nil); err != nil {
		t.Fatal(err)
	}
	var response openCodeCommandResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestOpenCodeCommandLeavesOrdinaryToolsAloneWithoutRuntime(t *testing.T) {
	withHarnessHookConfig(t, ai.HarnessOpenCode)
	t.Setenv("PHASE_AI_ENABLED", "")
	originalEnsure := claudeHookEnsureRuntime
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		t.Fatal("ordinary OpenCode command attempted to start the Phase runtime")
		return phaseproxy.ProcessEnvironmentPlan{}, nil
	}
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })
	response := runOpenCodeCommandForTest(t, "git status && gh pr create --fill")
	if response.SchemaVersion != 1 || response.Managed || response.Command != "" || response.Error != "" {
		t.Fatalf("ordinary OpenCode command was intercepted: %#v", response)
	}
}

func TestOpenCodeCommandWrapsOnlyManagedToolsWithoutReturningRuntimeMaterial(t *testing.T) {
	withHarnessHookConfig(t, ai.HarnessOpenCode)
	directory := prepareHarnessHookRuntime(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	response := runOpenCodeCommandForTest(t, "curl http://phase.invalid/v1/status")
	if response.SchemaVersion != 1 || !response.Managed || !strings.Contains(response.Command, "__harness-exec") || response.Error != "" {
		t.Fatalf("unexpected managed OpenCode command response: %#v", response)
	}
	if strings.Contains(response.Command, "curl http://phase.invalid/v1/status") || strings.Contains(response.Command, "decoy-never-print") {
		t.Fatalf("OpenCode wrapper exposed the original command or runtime material: %s", response.Command)
	}
	leasePath, err := claudeSessionLeasePath(directory, harnessLeaseID(ai.HarnessOpenCode, "opencode-session"))
	if err != nil {
		t.Fatal(err)
	}
	var lease claudeSessionLease
	if err := readOwnerOnlyJSON(leasePath, &lease); err != nil {
		t.Fatal(err)
	}
	if lease.ExpiresAt.IsZero() || time.Until(lease.ExpiresAt) > openCodeLeaseTTL+time.Minute {
		t.Fatalf("unexpected OpenCode lease expiry: %s", lease.ExpiresAt)
	}
}

func TestOpenCodeCommandFailsClosedOnlyForManagedToolsWhenRuntimeIsUnavailable(t *testing.T) {
	withHarnessHookConfig(t, ai.HarnessOpenCode)
	t.Setenv("PHASE_AI_ENABLED", "")
	originalEnsure := claudeHookEnsureRuntime
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("runtime unavailable")
	}
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })
	response := runOpenCodeCommandForTest(t, "curl http://phase.invalid/v1/status")
	if !response.Managed || response.Command != "" || !strings.Contains(response.Error, "ordinary ambient tools remain available") {
		t.Fatalf("managed OpenCode command did not fail closed: %#v", response)
	}
}

func TestExpiredHarnessLeaseIsRemoved(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	path, err := claudeSessionLeasePath(directory, "cursor:expired")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyJSON(path, claudeSessionLease{
		Version: claudeRuntimeStateVersion, Generation: "generation-one",
		UpdatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	active, err := hasActiveClaudeSessionLease(directory, "generation-one", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("expired harness lease remained active")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expired harness lease was not removed: %v", err)
	}
}

func TestMalformedHarnessLeaseDoesNotPinRuntime(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	malformedPath, err := claudeSessionLeasePath(directory, "cursor:malformed")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(malformedPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	validPath, err := claudeSessionLeasePath(directory, "cursor:valid")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyJSON(validPath, claudeSessionLease{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	active, err := hasActiveClaudeSessionLease(directory, "generation-one", time.Now().UTC())
	if err != nil || !active {
		t.Fatalf("active=%v err=%v", active, err)
	}
	if _, err := os.Stat(malformedPath); !os.IsNotExist(err) {
		t.Fatalf("malformed harness lease was not removed: %v", err)
	}
}

func TestHarnessCommandLeaseIsHeldAndReleased(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	now := time.Now().UTC()
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one",
		PID: os.Getpid(), StartedAt: now, ProxyURL: "http://phase:capability@127.0.0.1:9543",
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: state.Generation, PID: state.PID, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	release, err := holdHarnessCommandLease(ai.HarnessCodex)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(directory, claudeSessionLeasePrefix+"*"+claudeSessionLeaseSuffix))
	if err != nil || len(paths) != 1 {
		t.Fatalf("command lease paths=%v err=%v", paths, err)
	}
	var lease claudeSessionLease
	if err := readOwnerOnlyJSON(paths[0], &lease); err != nil {
		t.Fatal(err)
	}
	if lease.ExpiresAt.IsZero() || time.Until(lease.ExpiresAt) > harnessCommandLeaseTTL+time.Minute {
		t.Fatalf("unexpected command lease expiry: %s", lease.ExpiresAt)
	}
	if lease.Purpose != harnessCommandLeasePurpose {
		t.Fatalf("command lease purpose = %q", lease.Purpose)
	}
	release()
	if _, err := os.Stat(paths[0]); !os.IsNotExist(err) {
		t.Fatalf("command lease remains after release: %v", err)
	}
}

func TestHarnessCommandLeaseRenewalJoinsInFlightWrite(t *testing.T) {
	done := make(chan struct{})
	started := make(chan struct{})
	unblock := make(chan struct{})
	var startedOnce sync.Once
	waitForRenewal := startHarnessCommandLeaseRenewal(done, time.Millisecond, func() error {
		startedOnce.Do(func() { close(started) })
		<-unblock
		return nil
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("lease renewal did not start")
	}
	close(done)
	joined := make(chan struct{})
	go func() {
		waitForRenewal()
		close(joined)
	}()
	select {
	case <-joined:
		t.Fatal("lease renewal returned while a write was in flight")
	case <-time.After(20 * time.Millisecond):
	}
	close(unblock)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("lease renewal did not join after the write completed")
	}
}

func harnessTestProxyURL(t *testing.T, rawURL, capability string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword("phase", capability)
	return parsed.String()
}

func writeHarnessRuntimeFixture(t *testing.T, directory, leaseID string, state *claudeRuntimeState) harnessRuntimeBinding {
	t.Helper()
	createdAt := time.Now().UTC().Add(-time.Minute)
	lock := claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(), CreatedAt: createdAt,
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), lock); err != nil {
		t.Fatal(err)
	}
	leasePath, err := claudeSessionLeasePath(directory, leaseID)
	if err != nil {
		t.Fatal(err)
	}
	lease := claudeSessionLease{
		Version: claudeRuntimeStateVersion, Generation: lock.Generation, UpdatedAt: time.Now().UTC(),
	}
	if err := writeOwnerOnlyJSON(leasePath, lease); err != nil {
		t.Fatal(err)
	}
	if state != nil {
		if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), *state); err != nil {
			t.Fatal(err)
		}
	}
	return harnessRuntimeBinding{directory: directory, leasePath: leasePath, lease: lease, lock: lock}
}

func runHarnessExecTest(t *testing.T, leaseID, shellCommand string) (string, error) {
	t.Helper()
	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.SetIn(strings.NewReader(""))
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&bytes.Buffer{})
	command.Flags().String("harness", "", "")
	command.Flags().String("lease", "", "")
	command.Flags().String("command", "", "")
	for flag, value := range map[string]string{
		"harness": ai.HarnessCodex,
		"lease":   base64.RawURLEncoding.EncodeToString([]byte(leaseID)),
		"command": base64.RawURLEncoding.EncodeToString([]byte(shellCommand)),
	} {
		if err := command.Flags().Set(flag, value); err != nil {
			t.Fatal(err)
		}
	}
	err := runAIHarnessExec(command, nil)
	return output.String(), err
}

func manifestSuccessResponse(proxyURL string) remoteapi.ManifestResponse {
	return remoteapi.ManifestResponse{
		SchemaVersion: agentapi.SchemaVersion,
		SessionUID:    "session-refreshed",
		ProcessEnvironment: phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{
			"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": proxyURL, "HTTP_PROXY": proxyURL,
		}},
	}
}

func TestHarnessExecWaitsForManifestRefreshAndExecutesCommandOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell execution assertion uses printf")
	}
	withHarnessHookConfig(t, ai.HarnessCodex)
	directory := withClaudeHookRuntimeDirectory(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	originalWait, originalPoll := harnessRuntimeCycleWait, harnessRuntimeCyclePoll
	harnessRuntimeCycleWait, harnessRuntimeCyclePoll = 2*time.Second, 5*time.Millisecond
	t.Cleanup(func() { harnessRuntimeCycleWait, harnessRuntimeCyclePoll = originalWait, originalPoll })

	var refreshedProxyURL string
	var refreshedRequests atomic.Int32
	refreshedServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		refreshedRequests.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(manifestSuccessResponse(refreshedProxyURL))
	}))
	defer refreshedServer.Close()
	refreshedProxyURL = harnessTestProxyURL(t, refreshedServer.URL, "refreshed-capability")

	oldStartedAt := time.Now().UTC().Add(-time.Minute)
	refreshedState := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one",
		PID: os.Getpid(), StartedAt: time.Now().UTC(), ProxyURL: refreshedProxyURL,
	}
	rotationResult := make(chan error, 1)
	var rotateOnce sync.Once
	var oldRequests atomic.Int32
	oldServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		oldRequests.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Phase-Error-Code", aiproxy.ManifestRefreshRequiredCode)
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`{"error":{"code":"agent_manifest_refresh_required","message":"The Phase AI session is refreshing.","retryable":true,"details":{}}}`))
		rotateOnce.Do(func() {
			go func() {
				time.Sleep(20 * time.Millisecond)
				rotationResult <- writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), refreshedState)
			}()
		})
	}))
	defer oldServer.Close()
	oldState := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one",
		PID: os.Getpid(), StartedAt: oldStartedAt, ProxyURL: harnessTestProxyURL(t, oldServer.URL, "old-capability"),
	}
	const leaseID = "codex:session-one"
	writeHarnessRuntimeFixture(t, directory, leaseID, &oldState)

	output, err := runHarnessExecTest(t, leaseID, "printf x")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-rotationResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime state did not rotate")
	}
	if output != "x" {
		t.Fatalf("wrapped command output = %q; command must execute exactly once", output)
	}
	if oldRequests.Load() != 1 || refreshedRequests.Load() != 1 {
		t.Fatalf("manifest requests old=%d refreshed=%d", oldRequests.Load(), refreshedRequests.Load())
	}
}

func TestHarnessExecWaitsForRuntimeStateGapAndExecutesCommandOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell execution assertion uses printf")
	}
	withHarnessHookConfig(t, ai.HarnessCodex)
	directory := withClaudeHookRuntimeDirectory(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	originalWait, originalPoll := harnessRuntimeCycleWait, harnessRuntimeCyclePoll
	harnessRuntimeCycleWait, harnessRuntimeCyclePoll = 2*time.Second, 5*time.Millisecond
	t.Cleanup(func() { harnessRuntimeCycleWait, harnessRuntimeCyclePoll = originalWait, originalPoll })

	var proxyURL string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(manifestSuccessResponse(proxyURL))
	}))
	defer server.Close()
	proxyURL = harnessTestProxyURL(t, server.URL, "gap-capability")
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one",
		PID: os.Getpid(), StartedAt: time.Now().UTC(), ProxyURL: proxyURL,
	}
	const leaseID = "codex:state-gap"
	writeHarnessRuntimeFixture(t, directory, leaseID, nil)
	publishResult := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		publishResult <- writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), state)
	}()

	output, err := runHarnessExecTest(t, leaseID, "printf x")
	if err != nil {
		t.Fatal(err)
	}
	if publishErr := <-publishResult; publishErr != nil {
		t.Fatal(publishErr)
	}
	if output != "x" {
		t.Fatalf("wrapped command output = %q; command must execute exactly once", output)
	}
}

func TestHarnessExecDoesNotRunCommandWhenRuntimeLockChangesDuringRefresh(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell execution assertion uses printf")
	}
	withHarnessHookConfig(t, ai.HarnessCodex)
	directory := withClaudeHookRuntimeDirectory(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	originalWait, originalPoll := harnessRuntimeCycleWait, harnessRuntimeCyclePoll
	harnessRuntimeCycleWait, harnessRuntimeCyclePoll = 2*time.Second, 5*time.Millisecond
	t.Cleanup(func() { harnessRuntimeCycleWait, harnessRuntimeCyclePoll = originalWait, originalPoll })

	lockChange := make(chan error, 1)
	var changeOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Phase-Error-Code", aiproxy.ManifestRefreshRequiredCode)
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`{"error":{"code":"agent_manifest_refresh_required","message":"The Phase AI session is refreshing.","retryable":true,"details":{}}}`))
		changeOnce.Do(func() {
			go func() {
				time.Sleep(20 * time.Millisecond)
				lockChange <- writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
					Version: claudeRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(), CreatedAt: time.Now().UTC(),
				})
			}()
		})
	}))
	defer server.Close()
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one",
		PID: os.Getpid(), StartedAt: time.Now().UTC(), ProxyURL: harnessTestProxyURL(t, server.URL, "old-capability"),
	}
	const leaseID = "codex:lock-change"
	writeHarnessRuntimeFixture(t, directory, leaseID, &state)

	output, err := runHarnessExecTest(t, leaseID, "printf x")
	if err == nil {
		t.Fatal("runtime lock change should fail closed")
	}
	if changeErr := <-lockChange; changeErr != nil {
		t.Fatal(changeErr)
	}
	if output != "" {
		t.Fatalf("command executed after runtime ownership changed: %q", output)
	}
}

func TestHarnessExecDoesNotRunCommandForUnchangedManifestFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell execution assertion uses printf")
	}
	tests := []struct {
		name       string
		status     int
		header     string
		body       string
		wantReason string
	}{
		{
			name: "refresh timeout", status: http.StatusServiceUnavailable,
			header:     aiproxy.ManifestRefreshRequiredCode,
			body:       `{"error":{"code":"agent_manifest_refresh_required","message":"The Phase AI session is refreshing.","retryable":true,"details":{}}}`,
			wantReason: "command was not started",
		},
		{name: "proxy authentication unchanged", status: http.StatusProxyAuthRequired, body: `{`, wantReason: "authentication failed"},
		{name: "malformed service unavailable", status: http.StatusServiceUnavailable, body: `{`, wantReason: "failure response is invalid"},
		{
			name: "unknown service unavailable", status: http.StatusServiceUnavailable,
			header: "unknown", body: `{"error":{"code":"unknown","retryable":true}}`, wantReason: "request failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withHarnessHookConfig(t, ai.HarnessCodex)
			directory := withClaudeHookRuntimeDirectory(t)
			t.Setenv("PHASE_AI_ENABLED", "")
			originalWait, originalPoll := harnessRuntimeCycleWait, harnessRuntimeCyclePoll
			harnessRuntimeCycleWait, harnessRuntimeCyclePoll = 40*time.Millisecond, 5*time.Millisecond
			t.Cleanup(func() { harnessRuntimeCycleWait, harnessRuntimeCyclePoll = originalWait, originalPoll })

			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				if test.header != "" {
					writer.Header().Set("X-Phase-Error-Code", test.header)
				}
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			state := claudeRuntimeState{
				Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one",
				PID: os.Getpid(), StartedAt: time.Now().UTC(), ProxyURL: harnessTestProxyURL(t, server.URL, "unchanged-capability"),
			}
			const leaseID = "codex:unchanged-session"
			writeHarnessRuntimeFixture(t, directory, leaseID, &state)

			output, err := runHarnessExecTest(t, leaseID, "printf x")
			if err == nil || !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf("error = %v, want %q", err, test.wantReason)
			}
			if output != "" {
				t.Fatalf("command executed despite hard manifest failure: %q", output)
			}
		})
	}
}

func TestExecuteHarnessShellAppliesOnlyProvidedEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell assertion")
	}
	var output bytes.Buffer
	err := executeHarnessShell(context.Background(), `printf '%s' "$PHASE_HOOK_TEST"`, []string{"PHASE_HOOK_TEST=applied"}, strings.NewReader(""), &output, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if output.String() != "applied" {
		t.Fatalf("wrapped environment output = %q", output.String())
	}
}

func TestHarnessHookCommandsStayHidden(t *testing.T) {
	for _, command := range []*cobra.Command{
		aiCodexHookCmd, aiCodexEventCmd,
		aiCursorHookCmd, aiCursorEventCmd,
		aiDevinHookCmd, aiDevinEventCmd,
		aiHarnessExecCmd, aiOpenCodeCommandCmd, aiOpenCodeSessionCmd,
	} {
		if !command.Hidden {
			t.Fatalf("internal harness command %q is public", command.Use)
		}
	}
}

func TestOpenCodeSessionKickRegistersLeaseAndNeverFails(t *testing.T) {
	withHarnessHookConfig(t, ai.HarnessOpenCode)
	directory := prepareHarnessHookRuntime(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	command, output := newHarnessHookCommand("")
	command.Flags().String("session", "", "")
	if err := command.Flags().Set("session", "pid-4242"); err != nil {
		t.Fatal(err)
	}
	if err := runAIOpenCodeSession(command, nil); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("session kick printed output: %q", output.String())
	}
	leasePath, err := claudeSessionLeasePath(directory, harnessLeaseID(ai.HarnessOpenCode, "pid-4242"))
	if err != nil {
		t.Fatal(err)
	}
	var lease claudeSessionLease
	if err := readOwnerOnlyJSON(leasePath, &lease); err != nil {
		t.Fatalf("OpenCode session lease was not registered: %v", err)
	}
	if lease.ExpiresAt.IsZero() || time.Until(lease.ExpiresAt) > harnessSessionLeaseTTL+time.Minute {
		t.Fatalf("unexpected OpenCode lease expiry: %s", lease.ExpiresAt)
	}

	// Disabled integrations and inherited environments are silent no-ops.
	t.Setenv("PHASE_AI_ENABLED", "1")
	originalEnsure := claudeHookEnsureRuntime
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		t.Fatal("inherited environment attempted to start the Phase runtime")
		return phaseproxy.ProcessEnvironmentPlan{}, nil
	}
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })
	if err := runAIOpenCodeSession(command, nil); err != nil {
		t.Fatal(err)
	}
}

func TestHarnessWrapperCommandLineMatchesTheHarnessShell(t *testing.T) {
	originalSettings := cursorWindowsSettings
	t.Cleanup(func() { cursorWindowsSettings = originalSettings })
	cursorWindowsSettings = func() []byte { return nil }
	arguments := []string{`C:\Users\O'Brien Ann\.phase\ai\bin\phase-hook-v1.exe`, "ai", "__harness-exec", "--lease", "Y29kZXg6YQ"}
	for _, harness := range []string{ai.HarnessCodex, ai.HarnessCursor} {
		got := harnessWrapperCommandLine("windows", harness, arguments)
		want := `& 'C:\Users\O''Brien Ann\.phase\ai\bin\phase-hook-v1.exe' 'ai' '__harness-exec' '--lease' 'Y29kZXg6YQ'`
		if got != want {
			t.Fatalf("%s on Windows:\n got %s\nwant %s", harness, got, want)
		}
	}
	if got := ai.PowerShellCallCommand([]string{"a\u2019b"}); got != "& 'a\u2019\u2019b'" {
		t.Fatalf("typographic quote not doubled: %s", got)
	}
	if got := harnessWrapperCommandLine("windows", ai.HarnessDevin, arguments); !strings.HasPrefix(got, `"C:\Users`) {
		t.Fatalf("Devin falls back to the cmd form for a path that needs quoting: %s", got)
	}
	plain := []string{`C:\Users\dev\.phase\ai\bin\phase-hook-v1.exe`, "ai", "__harness-exec", "--lease", "Y29kZXg6YQ"}
	for _, harness := range []string{ai.HarnessDevin, ai.HarnessOpenCode} {
		if got, want := harnessWrapperCommandLine("windows", harness, plain), "C:/Users/dev/.phase/ai/bin/phase-hook-v1.exe ai __harness-exec --lease Y29kZXg6YQ"; got != want {
			t.Fatalf("%s on Windows:\n got %s\nwant %s", harness, got, want)
		}
	}
	if got := harnessWrapperCommandLine("linux", ai.HarnessCodex, []string{"/home/o'brien/phase", "ai"}); got != `'/home/o'"'"'brien/phase' 'ai'` {
		t.Fatalf("POSIX form = %s", got)
	}
}

func TestCursorWrapperFollowsItsWindowsTerminalProfile(t *testing.T) {
	for name, test := range map[string]struct {
		settings  string
		bashOrCmd bool
	}{
		"unset":          {``, false},
		"powershell":     {`{"terminal.integrated.defaultProfile.windows": "PowerShell"}`, false},
		"git bash":       {`{"terminal.integrated.defaultProfile.windows": "Git Bash"}`, true},
		"command prompt": {`{"terminal.integrated.defaultProfile.windows": "Command Prompt"}`, true},
		"commented default": {`{
			// "terminal.integrated.defaultProfile.windows": "Git Bash",
			/* "terminal.integrated.defaultProfile.windows": "Command Prompt", */
			"terminal.integrated.defaultProfile.windows": "PowerShell",
		}`, false},
		"custom bash source": {`{
			"terminal.integrated.profiles.windows": {"Development": {"source": "Git Bash"}},
			"terminal.integrated.defaultProfile.windows": "Development"
		}`, true},
		"misleading name, PowerShell source": {`{
			"terminal.integrated.profiles.windows": {"Bash Migration": {"source": "PowerShell"}},
			"terminal.integrated.defaultProfile.windows": "Bash Migration"
		}`, false},
		"custom path": {`{
			"terminal.integrated.profiles.windows": {"Work": {"path": ["C:\\Program Files\\PowerShell\\7\\pwsh.exe"]}},
			"terminal.integrated.defaultProfile.windows": "Work"
		}`, false},
		"custom bash path": {`{
			"terminal.integrated.profiles.windows": {"MSYS": {"path": "C:\\msys64\\usr\\bin\\bash.exe", "args": ["--login"]}},
			"terminal.integrated.defaultProfile.windows": "MSYS",
		}`, true},
		"escaped value":                      {`{"terminal.integrated.defaultProfile.windows": "Git \u0042ash"}`, true},
		"url in a string":                    {`{"a": "http://x/y", "terminal.integrated.defaultProfile.windows": "Git Bash"}`, true},
		"line comment after trailing comma":  {"{\"terminal.integrated.defaultProfile.windows\": \"Git Bash\", // keep\n}", true},
		"block comment after trailing comma": {`{"terminal.integrated.defaultProfile.windows": "Git Bash", /* keep */}`, true},
		"array with trailing comment":        {`{"terminal.integrated.defaultProfile.windows": "Git Bash", "x": ["y", /* note */]}`, true},
	} {
		if got := cursorWindowsShellIsBashOrCmd([]byte(test.settings)); got != test.bashOrCmd {
			t.Errorf("%s: bash or cmd = %v, want %v", name, got, test.bashOrCmd)
		}
	}

	originalSettings := cursorWindowsSettings
	t.Cleanup(func() { cursorWindowsSettings = originalSettings })
	arguments := []string{`C:\\Users\\phase\\phase-hook-v1.exe`, "ai"}
	cursorWindowsSettings = func() []byte { return []byte(`{"terminal.integrated.defaultProfile.windows": "Git Bash"}`) }
	if got := harnessWrapperCommandLine("windows", ai.HarnessCursor, arguments); strings.HasPrefix(got, "& ") {
		t.Fatalf("Cursor on Git Bash got the PowerShell form: %s", got)
	}
	if got := harnessWrapperCommandLine("windows", ai.HarnessCodex, arguments); !strings.HasPrefix(got, "& ") {
		t.Fatalf("Codex must keep the PowerShell form: %s", got)
	}
	cursorWindowsSettings = func() []byte { return nil }
	if got := harnessWrapperCommandLine("windows", ai.HarnessCursor, arguments); !strings.HasPrefix(got, "& ") {
		t.Fatalf("Cursor defaults to the PowerShell form: %s", got)
	}
}

func TestCursorProfileExecutableResolvesVariablesAndFallbacks(t *testing.T) {
	directory := t.TempDir()
	powershell := filepath.Join(directory, "pwsh.exe")
	bash := filepath.Join(directory, "bash.exe")
	for _, path := range []string{powershell, bash} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PHASE_TEST_SHELL", powershell)
	t.Setenv("PHASE_TEST_DIR", directory)
	missing := filepath.Join(directory, "missing", "bash.exe")
	for name, test := range map[string]struct {
		path string
		want string
	}{
		"whole path variable":           {mustJSON(t, "${env:PHASE_TEST_SHELL}"), powershell},
		"directory variable":            {mustJSON(t, "${env:PHASE_TEST_DIR}/bash.exe"), directory + "/bash.exe"},
		"missing candidate falls back":  {mustJSON(t, []string{missing, powershell}), powershell},
		"first existing candidate wins": {mustJSON(t, []string{bash, powershell}), bash},
		"unresolved variable":           {mustJSON(t, "${env:PHASE_TEST_UNSET_VARIABLE}"), ""},
	} {
		if got := cursorProfileExecutable(json.RawMessage(test.path)); got != test.want {
			t.Errorf("%s: resolved %q, want %q", name, got, test.want)
		}
	}
	settings := `{"terminal.integrated.profiles.windows": {"Work": {"path": "${env:PHASE_TEST_SHELL}"}}, "terminal.integrated.defaultProfile.windows": "Work"}`
	if cursorWindowsShellIsBashOrCmd([]byte(settings)) {
		t.Fatal("a variable pointing at pwsh must keep the PowerShell form")
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
