package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/spf13/cobra"
)

func TestAIRuntimeCommandsAreRegistered(t *testing.T) {
	for _, name := range []string{"serve", "run", "exec"} {
		command, _, err := aiCmd.Find([]string{name})
		if err != nil || command == nil || command.Name() != name {
			t.Fatalf("phase ai %s is not registered: command=%v err=%v", name, command, err)
		}
	}
	for _, removed := range []string{"context", "request"} {
		for _, command := range aiCmd.Commands() {
			if command.Name() == removed {
				t.Fatalf("phase ai %s must remain a proxy API, not a CLI command", removed)
			}
		}
	}
}

func TestRemoteModeLivesOnlyUnderRelayStart(t *testing.T) {
	for _, command := range []*cobra.Command{aiServeCmd, aiRunCmd, aiExecCmd} {
		for _, name := range []string{"remote", "advertise-host", "tls-cert", "tls-key", "postgres-listen"} {
			if command.Flags().Lookup(name) != nil {
				t.Fatalf("phase ai %s unexpectedly exposes --%s; remote mode is phase relay start", command.Name(), name)
			}
		}
	}
	for _, name := range []string{"advertise-host", "tls-cert", "tls-key", "listen", "lockdown"} {
		if relayStartCmd.Flags().Lookup(name) == nil {
			t.Fatalf("phase relay start is missing --%s", name)
		}
	}
	if relayStartCmd.Flags().Lookup("postgres-listen") != nil {
		t.Fatal("phase relay start must derive the PostgreSQL listener instead of taking --postgres-listen")
	}
}

func TestAIRuntimeUsesFixedDefaultProxyPort(t *testing.T) {
	for _, command := range []*cobra.Command{aiRunCmd, aiServeCmd, aiExecCmd} {
		flag := command.Flags().Lookup("listen")
		if flag == nil || flag.DefValue != aiproxy.DefaultProxyListenAddress {
			t.Fatalf("phase ai %s listen default = %v", command.Name(), flag)
		}
	}
}

func TestAIRuntimeRejectsRandomPortAllocation(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("listen", "127.0.0.1:0", "")
	if err := validateAIRuntimePorts(command); err == nil || !strings.Contains(err.Error(), "port 0/random") {
		t.Fatalf("random port validation error = %v", err)
	}
	_ = command.Flags().Set("listen", "127.0.0.1:9543")
	if err := validateAIRuntimePorts(command); err != nil {
		t.Fatalf("fixed port rejected: %v", err)
	}
}

func TestManualAIRuntimeRejectsActiveClaudeHookLease(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	state := writeHealthyManualHandoffState(t, directory)
	if err := registerHarnessLease(ai.HarnessClaudeCode, "active-claude-session", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	stopCalls := 0
	err := prepareManualAIRuntimeWithStop(
		context.Background(),
		func(context.Context, string, claudeRuntimeState) error {
			stopCalls++
			return nil
		},
		func(context.Context) error {
			stopCalls++
			return nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "active Agent sessions") {
		t.Fatalf("active lease conflict error = %v", err)
	}
	if stopCalls != 0 {
		t.Fatalf("active Claude runtime was stopped %d times", stopCalls)
	}
	if _, err := os.Stat(filepath.Join(directory, claudeRuntimeStateFile)); err != nil {
		t.Fatalf("active runtime state was changed: %v (state=%#v)", err, state)
	}
}

func TestManualAIRuntimeStopsAuthenticatedIdleClaudeHookRuntime(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	wantState := writeHealthyManualHandoffState(t, directory)
	stopCalls := 0
	err := prepareManualAIRuntimeWithStop(
		context.Background(),
		func(_ context.Context, gotDirectory string, gotState claudeRuntimeState) error {
			stopCalls++
			if gotDirectory != directory || gotState.Generation != wantState.Generation || gotState.ProxyURL != wantState.ProxyURL {
				t.Fatalf("idle runtime handoff = directory %q state %#v", gotDirectory, gotState)
			}
			return nil
		},
		func(context.Context) error {
			t.Fatal("healthy published runtime used startup-lock cleanup")
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stopCalls != 1 {
		t.Fatalf("idle runtime stop calls = %d, want 1", stopCalls)
	}
}

func TestManualAIRuntimeCleansDeadGenerationWithoutSignallingPID(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "dead-generation", PID: -1,
		RuntimeFingerprint: "binding", ProxyURL: "http://phase:capability@127.0.0.1:9543",
	}
	statePath := filepath.Join(directory, claudeRuntimeStateFile)
	lockPath := filepath.Join(directory, claudeRuntimeLockFile)
	if err := writeOwnerOnlyJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyJSON(lockPath, claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: state.Generation, PID: state.PID, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := registerHarnessLease(ai.HarnessClaudeCode, "dead-session", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	stopStateCalls, startupCleanupCalls := 0, 0
	err := prepareManualAIRuntimeWithStop(
		context.Background(),
		func(context.Context, string, claudeRuntimeState) error {
			stopStateCalls++
			return nil
		},
		func(context.Context) error {
			startupCleanupCalls++
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stopStateCalls != 0 || startupCleanupCalls != 1 {
		t.Fatalf("dead runtime cleanup stop=%d startup=%d", stopStateCalls, startupCleanupCalls)
	}
	for _, path := range []string{statePath, lockPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("stale artifact %q remains: %v", path, err)
		}
	}
	leasePath, err := claudeSessionLeasePath(directory, "dead-session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leasePath); !os.IsNotExist(err) {
		t.Fatalf("stale lease remains: %v", err)
	}
}

func TestManualAIRuntimeFailsClosedOnUnreadableOwnedState(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	if err := os.WriteFile(filepath.Join(directory, claudeRuntimeStateFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	stopCalls := 0
	err := prepareManualAIRuntimeWithStop(
		context.Background(),
		func(context.Context, string, claudeRuntimeState) error { stopCalls++; return nil },
		func(context.Context) error { stopCalls++; return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "inspect hook-managed") {
		t.Fatalf("unreadable state error = %v", err)
	}
	if stopCalls != 0 {
		t.Fatalf("unreadable state triggered %d unsafe stop calls", stopCalls)
	}
}

func writeHealthyManualHandoffState(t *testing.T, directory string) claudeRuntimeState {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"schemaVersion":1,"kind":"phase.ai.status","safeToPrint":true,"connections":[]}`))
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword("phase", "runtime-capability")
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "healthy-generation", PID: os.Getpid(),
		RuntimeFingerprint: "binding", StartedAt: time.Now().UTC(), ProxyURL: parsed.String(),
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestAIServeHandoffPrintsExactCompiledEnvironmentAndAuthenticatedManifest(t *testing.T) {
	const proxyURL = "https://phase:runtime-capability@agent.example:9543"
	handoff := formatAIServeHandoff(aiproxy.Endpoints{
		ProxyURL: agentapi.SensitiveString(proxyURL),
		ProcessEnvironment: phaseproxy.ProcessEnvironmentPlan{
			Set: map[string]string{
				"HTTP_PROXY": proxyURL, "HTTPS_PROXY": proxyURL, "http_proxy": proxyURL, "https_proxy": proxyURL,
				"PHASE_AI_CA_BUNDLE": "/stable/phase ca.pem", "AWS_SECRET_ACCESS_KEY": "decoy```'$(touch /tmp/never)",
			},
			Unset: []string{"AWS_SESSION_TOKEN", "AWS_PROFILE"},
		},
	})
	for _, required := range []string{
		"## Sensitive harness environment",
		"Do not paste this block into a chat",
		"export HTTP_PROXY='" + proxyURL + "'",
		"export HTTPS_PROXY='" + proxyURL + "'",
		"export http_proxy='" + proxyURL + "'",
		"export https_proxy='" + proxyURL + "'",
		"export PHASE_AI_CA_BUNDLE='/stable/phase ca.pem'",
		"export AWS_SECRET_ACCESS_KEY='decoy```'\"'\"'$(touch /tmp/never)'",
		"````sh\n",
		"unset AWS_PROFILE AWS_SESSION_TOKEN",
		"http://phase.invalid/.well-known/agents",
		"## Safe Agent context",
		"http://phase.invalid/v1/status",
		"credential-free block may be pasted",
	} {
		if !strings.Contains(handoff, required) {
			t.Fatalf("handoff missing %q: %s", required, handoff)
		}
	}
	for _, forbidden := range []string{
		"ALL_PROXY=", "PHASE_AI_PROXY_URL=", "PHASE_AI_SESSION_UID=",
		"PHASE_AI_SESSION_CREDENTIAL=", "PGPASSWORD=", "UNRELATED=",
	} {
		if strings.Contains(handoff, forbidden) {
			t.Fatalf("handoff contains redundant or unsafe key %q: %s", forbidden, handoff)
		}
	}
}

func TestPrepareAIChildCommandInjectsClaudeContext(t *testing.T) {
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CODEX", "")
	t.Setenv("AGENT", "")

	prepared := prepareAIChildCommand([]string{"/usr/local/bin/claude", "--print", "hello"})
	if len(prepared) < 3 || prepared[1] != "--append-system-prompt" || prepared[2] != phaseAIHarnessContext {
		t.Fatalf("Claude command did not receive Phase context: %#v", prepared)
	}

	prepared = prepareAIChildCommand([]string{"claude", "--append-system-prompt", "existing", "--print"})
	if got := prepared[2]; got != "existing\n\n"+phaseAIHarnessContext {
		t.Fatalf("existing Claude prompt was clobbered: %q", got)
	}

	prepared = prepareAIChildCommand([]string{"claude", "--append-system-prompt=existing"})
	if got := prepared[1]; got != "--append-system-prompt=existing\n\n"+phaseAIHarnessContext {
		t.Fatalf("existing inline Claude prompt was clobbered: %q", got)
	}
}

func TestPrepareAIChildCommandDoesNotInjectUnsupportedHarness(t *testing.T) {
	t.Setenv("CLAUDECODE", "1")
	t.Setenv("CODEX", "")
	t.Setenv("AGENT", "")
	command := []string{"codex", "exec", "hello"}
	prepared := prepareAIChildCommand(command)
	if strings.Join(prepared, "\x00") != strings.Join(command, "\x00") {
		t.Fatalf("Codex command received undocumented arguments: %#v", prepared)
	}
	if prepared := prepareAIChildCommand(nil); prepared != nil {
		t.Fatalf("empty child command changed: %#v", prepared)
	}
}

func TestAIExecCommandRemainsRaw(t *testing.T) {
	command := []string{"claude", "--print", "hello"}
	prepared := prepareAIRuntimeChild(aiRuntimeOneOffChild, command)
	if strings.Join(prepared, "\x00") != strings.Join(command, "\x00") {
		t.Fatalf("one-off command received harness preparation: %#v", prepared)
	}
	prepared = prepareAIRuntimeChild(aiRuntimeHarnessChild, command)
	if len(prepared) < 3 || prepared[1] != "--append-system-prompt" {
		t.Fatalf("Agent harness did not receive harness preparation: %#v", prepared)
	}
}

func TestAIRunRequiresHarnessOrExplicitOverride(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().String("harness", "", "")
	if _, err := resolveAIRunHarness(command, []string{"aws", "sts", "get-caller-identity"}); err == nil || !strings.Contains(err.Error(), "phase ai exec") {
		t.Fatalf("non-harness run error = %v", err)
	}
	if got, err := resolveAIRunHarness(command, []string{"/usr/local/bin/claude"}); err != nil || got != "claude-code" {
		t.Fatalf("detected harness = %q, err=%v", got, err)
	}
	if err := command.Flags().Set("harness", "custom-desktop-agent"); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveAIRunHarness(command, []string{"open", "-a", "Agent Desktop"}); err != nil || got != "custom-desktop-agent" {
		t.Fatalf("overridden harness = %q, err=%v", got, err)
	}
	if err := command.Flags().Set("harness", strings.Repeat("x", 129)); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAIRunHarness(command, []string{"open"}); err == nil || !strings.Contains(err.Error(), "128") {
		t.Fatalf("oversized harness override error = %v", err)
	}
}

func TestAIExecUsesHealthyInheritedRuntimeWithoutStartingAnotherProxy(t *testing.T) {
	t.Setenv("PHASE_AI_ENABLED", "1")
	originalProbe, originalRun, originalHook := aiExecProbeInherited, aiExecRunInherited, aiExecTryHookRuntime
	t.Cleanup(func() {
		aiExecProbeInherited, aiExecRunInherited = originalProbe, originalRun
		aiExecTryHookRuntime = originalHook
	})

	probeCalls, runCalls := 0, 0
	aiExecProbeInherited = func(context.Context) error {
		probeCalls++
		return nil
	}
	want := []string{"aws", "sts", "get-caller-identity"}
	aiExecRunInherited = func(_ *cobra.Command, got []string) error {
		runCalls++
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("inherited exec command = %#v, want %#v", got, want)
		}
		return nil
	}
	aiExecTryHookRuntime = func(*cobra.Command, []string) (bool, error) {
		t.Fatal("inherited Phase environment should not inspect the hook runtime")
		return false, nil
	}

	if err := executeAIRuntimeCommand(&cobra.Command{}, want, aiRuntimeOneOffChild); err != nil {
		t.Fatal(err)
	}
	if probeCalls != 1 || runCalls != 1 {
		t.Fatalf("inherited exec probe calls=%d run calls=%d", probeCalls, runCalls)
	}
}

func TestAIExecUsesActiveHookRuntimeBeforeStartingAnotherProxy(t *testing.T) {
	t.Setenv("PHASE_AI_ENABLED", "")
	originalHook := aiExecTryHookRuntime
	t.Cleanup(func() { aiExecTryHookRuntime = originalHook })

	want := []string{"aws", "sts", "get-caller-identity"}
	calls := 0
	aiExecTryHookRuntime = func(_ *cobra.Command, got []string) (bool, error) {
		calls++
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("hook runtime command = %#v, want %#v", got, want)
		}
		return true, nil
	}
	if err := executeAIRuntimeCommand(&cobra.Command{}, want, aiRuntimeOneOffChild); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("hook runtime attach calls = %d, want 1", calls)
	}
}

func TestAIExecAttachesToAuthenticatedActiveHookRuntime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("child environment assertion uses a POSIX shell")
	}
	directory := withClaudeHookRuntimeDirectory(t)
	withClaudeHookTestConfig(t, true)
	t.Setenv("PHASE_AI_ENABLED", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient")
	originalScopeFingerprint := claudeHookScopeFingerprint
	claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() { claudeHookScopeFingerprint = originalScopeFingerprint })

	var runtimeProxyURL, selectedProxyURL string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case phaseproxy.ManifestPath:
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "session-one",
				"processEnvironment": phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{
					"PHASE_AI_ENABLED": "1", "HTTP_PROXY": runtimeProxyURL, "http_proxy": runtimeProxyURL,
					"HTTPS_PROXY": runtimeProxyURL, "https_proxy": runtimeProxyURL,
					"AWS_ACCESS_KEY_ID": "managed-default",
					"PGPASSWORD":        "managed-postgres-must-be-removed",
				}},
			})
		case "/v1/connections/aws-two/environment":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"schemaVersion": 1, "connectionId": "aws-two", "configGeneration": 1,
				"processEnvironment": phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{
					"PHASE_AI_ENABLED": "1", "HTTP_PROXY": selectedProxyURL, "http_proxy": selectedProxyURL,
					"HTTPS_PROXY": selectedProxyURL, "https_proxy": selectedProxyURL,
					"AWS_ACCESS_KEY_ID": "managed-selected",
				}},
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
	runtimeProxyURL = parsed.String()
	parsed.User = url.UserPassword("phase.aws-two", "runtime-capability")
	selectedProxyURL = parsed.String()

	now := time.Now().UTC()
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one", RuntimeScopeFingerprint: "scope-one",
		PID: os.Getpid(), StartedAt: now, ProxyURL: runtimeProxyURL,
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: state.Generation, PID: state.PID, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := registerHarnessLease(ai.HarnessClaudeCode, "session-one", time.Time{}); err != nil {
		t.Fatal(err)
	}

	command := &cobra.Command{}
	command.SetContext(t.Context())
	command.Flags().String("connection", "aws-two", "")
	if err := command.Flags().Set("connection", "aws-two"); err != nil {
		t.Fatal(err)
	}
	handled, err := runAIExecThroughActiveHookRuntime(command, []string{
		"/bin/sh", "-c", `test "$PHASE_AI_ENABLED" = 1 && test "$AWS_ACCESS_KEY_ID" = managed-selected && test -z "$PGPASSWORD"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("active authenticated hook runtime was not reused")
	}
	active, err := hasActiveClaudeSessionLease(directory, state.Generation, time.Now().UTC())
	if err != nil || !active {
		t.Fatalf("original harness lease was not preserved: active=%v err=%v", active, err)
	}
}

func TestAIExecDoesNotAttachToOutOfScopeHookRuntime(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	withClaudeHookTestConfig(t, true)
	originalScopeFingerprint := claudeHookScopeFingerprint
	claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() { claudeHookScopeFingerprint = originalScopeFingerprint })
	now := time.Now().UTC()
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one", RuntimeScopeFingerprint: "old-scope",
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
	handled, err := runAIExecThroughActiveHookRuntime(&cobra.Command{}, []string{"must-not-run"})
	if err != nil || handled {
		t.Fatalf("out-of-scope hook runtime attach = handled %v err %v", handled, err)
	}
}

func TestAIExecDoesNotIgnoreExplicitRuntimeFlagsWhenAttaching(t *testing.T) {
	for _, name := range []string{"workflow", "listen", "lockdown"} {
		t.Run(name, func(t *testing.T) {
			command := &cobra.Command{}
			switch name {
			case "lockdown":
				command.Flags().Bool(name, false, "")
				if err := command.Flags().Set(name, "true"); err != nil {
					t.Fatal(err)
				}
			default:
				command.Flags().String(name, "", "")
				if err := command.Flags().Set(name, "explicit"); err != nil {
					t.Fatal(err)
				}
			}
			handled, err := runAIExecThroughActiveHookRuntime(command, []string{"must-not-run"})
			if err != nil || handled {
				t.Fatalf("explicit --%s attach = handled %v err %v", name, handled, err)
			}
		})
	}
}

func TestAIExecRejectsExplicitRuntimeFlagsInInheritedEnvironment(t *testing.T) {
	t.Setenv("PHASE_AI_ENABLED", "1")
	originalProbe, originalRun := aiExecProbeInherited, aiExecRunInherited
	t.Cleanup(func() { aiExecProbeInherited, aiExecRunInherited = originalProbe, originalRun })
	aiExecProbeInherited = func(context.Context) error {
		t.Fatal("explicit runtime flag should be rejected before probing the inherited runtime")
		return nil
	}
	aiExecRunInherited = func(*cobra.Command, []string) error {
		t.Fatal("explicit runtime flag should not execute against the inherited runtime")
		return nil
	}
	for _, name := range []string{"workflow", "listen", "lockdown"} {
		t.Run(name, func(t *testing.T) {
			command := &cobra.Command{}
			switch name {
			case "lockdown":
				command.Flags().Bool(name, false, "")
				_ = command.Flags().Set(name, "true")
			default:
				command.Flags().String(name, "", "")
				_ = command.Flags().Set(name, "explicit")
			}
			err := executeAIRuntimeCommand(command, []string{"must-not-run"}, aiRuntimeOneOffChild)
			if err == nil || !strings.Contains(err.Error(), "cannot change the inherited") {
				t.Fatalf("inherited --%s error = %v", name, err)
			}
		})
	}
}

func TestAIExecFailsClosedForUnhealthyInheritedRuntime(t *testing.T) {
	t.Setenv("PHASE_AI_ENABLED", "1")
	originalProbe, originalRun := aiExecProbeInherited, aiExecRunInherited
	t.Cleanup(func() {
		aiExecProbeInherited, aiExecRunInherited = originalProbe, originalRun
	})
	aiExecProbeInherited = func(context.Context) error { return errors.New("proxy unavailable") }
	aiExecRunInherited = func(*cobra.Command, []string) error {
		t.Fatal("unhealthy inherited runtime executed the child")
		return nil
	}

	err := executeAIRuntimeCommand(&cobra.Command{}, []string{"aws", "sts", "get-caller-identity"}, aiRuntimeOneOffChild)
	if err == nil || !strings.Contains(err.Error(), "inherited proxy is not healthy") {
		t.Fatalf("unhealthy inherited runtime error = %v", err)
	}
}

func TestAIExecInheritedChildExitCodeReachesRoot(t *testing.T) {
	t.Setenv("PHASE_AI_ENABLED", "1")
	originalProbe, originalRun := aiExecProbeInherited, aiExecRunInherited
	t.Cleanup(func() {
		aiExecProbeInherited, aiExecRunInherited = originalProbe, originalRun
	})
	aiExecProbeInherited = func(context.Context) error { return nil }
	aiExecRunInherited = func(*cobra.Command, []string) error { return testProcessExitError{code: 42} }

	err := executeAIRuntimeCommand(&cobra.Command{}, []string{"provider-command"}, aiRuntimeOneOffChild)
	if code, ok := phaseCLIExitCode(err); !ok || code != 42 {
		t.Fatalf("inherited child root exit = %d, ok=%v, err=%v", code, ok, err)
	}
}

func TestAITransientChildExitCodeReachesRootWithoutChangingNormalErrors(t *testing.T) {
	err := preserveAIChildExitCode(testProcessExitError{code: 42})
	if code, ok := phaseCLIExitCode(err); !ok || code != 42 {
		t.Fatalf("transient child root exit = %d, ok=%v, err=%v", code, ok, err)
	}

	want := errors.New("ordinary Phase failure")
	if got := preserveAIChildExitCode(want); !errors.Is(got, want) || got != want {
		t.Fatalf("ordinary error changed: %v", got)
	}
	if code, ok := phaseCLIExitCode(want); ok || code != 0 {
		t.Fatalf("ordinary error became exit status %d, ok=%v", code, ok)
	}
}

type testProcessExitError struct{ code int }

func (e testProcessExitError) Error() string { return "exit status" }
func (e testProcessExitError) ExitCode() int { return e.code }

func TestAIServeClipboardSeparatesSafeContextFromSensitiveEnvironment(t *testing.T) {
	originalCopy := copyAIServeHandoff
	t.Cleanup(func() { copyAIServeHandoff = originalCopy })

	var copied []string
	copyAIServeHandoff = func(content string) error {
		copied = append(copied, content)
		return nil
	}
	command := &cobra.Command{}
	command.SetIn(strings.NewReader("c\ne\n"))
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&bytes.Buffer{})
	listenForAIServeCopy(command, "safe context", "export HTTPS_PROXY='sensitive'\n")
	want := []string{"safe context", "export HTTPS_PROXY='sensitive'\n"}
	if len(copied) != len(want) {
		t.Fatalf("copied %d values, want %d: %#v", len(copied), len(want), copied)
	}
	for index := range want {
		if copied[index] != want[index] {
			t.Fatalf("copy %d = %q, want %q", index, copied[index], want[index])
		}
	}
	for _, message := range []string{"Safe Phase AI Agent context copied.", "Sensitive Phase AI launcher environment copied."} {
		if !strings.Contains(output.String(), message) {
			t.Fatalf("clipboard output missing %q: %s", message, output.String())
		}
	}
}

func TestAIServeClipboardListenerStopsOnContextCancellation(t *testing.T) {
	reader, writer := io.Pipe()
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	ctx, cancel := context.WithCancel(context.Background())
	command := &cobra.Command{}
	command.SetContext(ctx)
	command.SetIn(reader)
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	done := make(chan struct{})
	go func() {
		listenForAIServeCopy(command, "safe context", "sensitive environment")
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("clipboard listener did not stop after context cancellation")
	}
}

func TestRefreshConfiguredAISkillPreservesUnrecognizedTarget(t *testing.T) {
	originalConfigPath := config.AIConfigPath
	config.AIConfigPath = filepath.Join(t.TempDir(), "ai.json")
	t.Cleanup(func() { config.AIConfigPath = originalConfigPath })

	skillPath := filepath.Join(t.TempDir(), "phase-cli", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(skillPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(skillPath, []byte("stale skill"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveAIConfig(&config.AIConfig{
		Enabled: true, ProxyMode: config.AIProxyModeLocal, SkillInstallPath: skillPath,
	}); err != nil {
		t.Fatal(err)
	}

	if err := refreshConfiguredAISkill(); err == nil {
		t.Fatal("refresh accepted an unrecognized skill")
	}
	installed, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(installed) != "stale skill" {
		t.Fatal("unrecognized configured skill was overwritten")
	}
}

func TestRefreshConfiguredAISkillUpdatesEveryConfiguredTarget(t *testing.T) {
	originalConfigPath := config.AIConfigPath
	config.AIConfigPath = filepath.Join(t.TempDir(), "ai.json")
	t.Cleanup(func() { config.AIConfigPath = originalConfigPath })

	first := filepath.Join(t.TempDir(), "first", "SKILL.md")
	second := filepath.Join(t.TempDir(), "second", "SKILL.md")
	for _, path := range []string{first, second} {
		if err := ai.InstallSkillTo(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := config.SaveAIConfig(&config.AIConfig{
		Enabled: true, ProxyMode: config.AIProxyModeLocal,
		SkillInstallPaths: []string{first, second},
	}); err != nil {
		t.Fatal(err)
	}

	if err := refreshConfiguredAISkill(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{first, second} {
		installed, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(installed), "<!-- phase-cli-skill-owner: phase-cli; kind: agent-runtime;") {
			t.Fatalf("configured Phase AI skill was not refreshed at %s", path)
		}
	}
}

func TestAgentLocalAccountIDIsStableAndDoesNotContainLookup(t *testing.T) {
	lookup := strings.Repeat("a", 64)
	first := agentLocalAccountID(lookup)
	second := agentLocalAccountID(lookup)
	if first != second || !strings.HasPrefix(first, "agent-") {
		t.Fatalf("unexpected local ID: %q %q", first, second)
	}
	if strings.Contains(first, lookup) || len(first) != len("agent-")+24 {
		t.Fatalf("local ID exposes token lookup or has unstable shape: %q", first)
	}
}

func TestSetupStopsHookRuntimeDespiteStaleSessionLeases(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	state := writeHealthyManualHandoffState(t, directory)
	// A session that ended without SessionEnd leaves an unbounded lease behind.
	if err := registerHarnessLease(ai.HarnessClaudeCode, "quit-without-session-end", time.Time{}); err != nil {
		t.Fatal(err)
	}
	stopCalls := 0
	stopped, err := prepareHookRuntime(
		context.Background(),
		func(_ context.Context, gotDirectory string, gotState claudeRuntimeState) error {
			stopCalls++
			if gotDirectory != directory || gotState.Generation != state.Generation {
				t.Fatalf("setup stop handoff = directory %q state %#v", gotDirectory, gotState)
			}
			return nil
		},
		func(context.Context) error {
			t.Fatal("healthy published runtime used startup-lock cleanup")
			return nil
		},
		true,
	)
	if err != nil || !stopped || stopCalls != 1 {
		t.Fatalf("setup with session leases: stopped=%v stopCalls=%d err=%v", stopped, stopCalls, err)
	}
}

func TestSetupRefusesWhileWrappedCommandIsInFlight(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	state := writeHealthyManualHandoffState(t, directory)
	path, err := claudeSessionLeasePath(directory, harnessLeaseID(ai.HarnessCodex, "command:in-flight"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := writeOwnerOnlyJSON(path, claudeSessionLease{
		Version: claudeRuntimeStateVersion, Generation: state.Generation, UpdatedAt: now,
		ExpiresAt: now.Add(harnessCommandLeaseTTL), Purpose: harnessCommandLeasePurpose,
	}); err != nil {
		t.Fatal(err)
	}
	stopCalls := 0
	stopped, err := prepareHookRuntime(
		context.Background(),
		func(context.Context, string, claudeRuntimeState) error {
			stopCalls++
			return nil
		},
		func(context.Context) error {
			stopCalls++
			return nil
		},
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "active Agent sessions") || stopped || stopCalls != 0 {
		t.Fatalf("setup during a wrapped command: stopped=%v stopCalls=%d err=%v", stopped, stopCalls, err)
	}
}
