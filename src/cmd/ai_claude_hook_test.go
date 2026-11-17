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
	"testing"
	"time"

	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/spf13/cobra"
)

func setClaudeHookInput(command *cobra.Command, event string) {
	command.SetContext(context.Background())
	command.SetIn(strings.NewReader(`{"session_id":"session-one","hook_event_name":"` + event + `"}`))
}

func TestClaudeHookDisabledIsNoop(t *testing.T) {
	withHookTestConfig(t, false)
	environmentPath := filepath.Join(t.TempDir(), "claude.env")
	t.Setenv("CLAUDE_ENV_FILE", environmentPath)
	command := &cobra.Command{}
	setClaudeHookInput(command, "SessionStart")
	var output bytes.Buffer
	command.SetOut(&output)
	if err := runAIClaudeHook(command, nil); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("disabled hook produced context: %s", output.String())
	}
	if _, err := os.Stat(environmentPath); !os.IsNotExist(err) {
		t.Fatalf("disabled hook created an environment file: %v", err)
	}
}

func TestClaudeHooksDegradeWithoutBlockingOrdinaryTools(t *testing.T) {
	originalPath := config.AIConfigPath
	config.AIConfigPath = filepath.Join(t.TempDir(), "missing-ai.json")
	t.Cleanup(func() { config.AIConfigPath = originalPath })
	t.Setenv("PHASE_AI_ENABLED", "")

	start := &cobra.Command{}
	setClaudeHookInput(start, "SessionStart")
	var startOutput bytes.Buffer
	start.SetOut(&startOutput)
	if err := runAIClaudeHook(start, nil); err != nil {
		t.Fatal(err)
	}
	var started claudeSessionStartOutput
	if err := json.Unmarshal(startOutput.Bytes(), &started); err != nil || !strings.Contains(started.HookSpecificOutput.AdditionalContext, "Ordinary tools") {
		t.Fatalf("invalid-config SessionStart did not degrade cleanly: %#v err=%v", started, err)
	}

	for _, event := range []string{"heartbeat", "session-end"} {
		command := &cobra.Command{}
		setClaudeHookInput(command, "UserPromptSubmit")
		var output bytes.Buffer
		command.SetOut(&output)
		if err := runAIClaudeEvent(command, []string{event}); err != nil || output.Len() != 0 {
			t.Fatalf("invalid-config %s interfered: output=%q err=%v", event, output.String(), err)
		}
	}
}

func TestClaudeHookReusesInheritedPhaseEnvironment(t *testing.T) {
	withHookTestConfig(t, true)
	t.Setenv("PHASE_AI_ENABLED", "1")
	// phase ai run started from a shell that carries the hook daemon's
	// environment: its own proxy replaced the daemon's.
	t.Setenv("HTTPS_PROXY", "http://phase:run-capability@127.0.0.1:9600")
	t.Setenv(hookRuntimeMarker, hookRuntimeMarkerValue("http://phase:daemon-capability@127.0.0.1:9543"))
	t.Setenv("CLAUDE_ENV_FILE", filepath.Join(t.TempDir(), "claude.env"))
	originalEnsure := hookEnsureRuntime
	t.Cleanup(func() { hookEnsureRuntime = originalEnsure })
	ensureCalls := 0
	hookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		ensureCalls++
		return phaseproxy.ProcessEnvironmentPlan{}, nil
	}
	command := &cobra.Command{}
	setClaudeHookInput(command, "SessionStart")
	var output bytes.Buffer
	command.SetOut(&output)
	if err := runAIClaudeHook(command, nil); err != nil {
		t.Fatal(err)
	}
	if ensureCalls != 0 {
		t.Fatalf("inherited flow started a second runtime: ensure calls=%d", ensureCalls)
	}
	if _, err := os.Stat(os.Getenv("CLAUDE_ENV_FILE")); !os.IsNotExist(err) {
		t.Fatalf("inherited flow rewrote Claude environment: %v", err)
	}
	if !strings.Contains(output.String(), "inherited from phase ai run") {
		t.Fatalf("inherited flow context = %s", output.String())
	}
}

func TestClaudeHookAdoptsAnEnvironmentInheritedFromTheHookDaemon(t *testing.T) {
	withHookTestConfig(t, true)
	directory := withHookRuntimeDirectory(t)
	withHookFingerprints(t)
	plan := phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{
		"PHASE_AI_ENABLED": "1", "PHASE_AI_RESERVED_ENV": "", "HTTPS_PROXY": "http://phase:capability@127.0.0.1:9543", "AWS_ACCESS_KEY_ID": "AKIADECOY",
	}}
	if err := writeRuntimeEnvironment(directory, os.Getpid(), "generation-one", time.Now().UTC(), plan, nil, true); err != nil {
		t.Fatal(err)
	}
	// Claude launched from an OpenCode shell inherits what the plugin exported.
	var published runtimeEnvironmentJSON
	if err := readOwnerOnlyJSON(runtimeEnvironmentJSONPath(directory), &published); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookRuntimeMarker, "")
	for key, value := range published.Set {
		t.Setenv(key, value)
	}
	for key, value := range published.Proxy {
		t.Setenv(key, value)
	}
	loaderPath := filepath.Join(t.TempDir(), "claude.env")
	t.Setenv("CLAUDE_ENV_FILE", loaderPath)
	originalEnsure := hookEnsureRuntime
	t.Cleanup(func() { hookEnsureRuntime = originalEnsure })
	ensureCalls := 0
	hookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		ensureCalls++
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("runtime unavailable")
	}

	command := &cobra.Command{}
	setClaudeHookInput(command, "SessionStart")
	var output bytes.Buffer
	command.SetOut(&output)
	if err := runAIClaudeHook(command, nil); err != nil {
		t.Fatal(err)
	}
	if ensureCalls != 1 || strings.Contains(output.String(), "inherited from phase ai run") {
		t.Fatalf("SessionStart treated the hook daemon's environment as a launcher's: ensure calls=%d output=%s", ensureCalls, output.String())
	}
	if loader, err := os.ReadFile(loaderPath); err != nil || !strings.Contains(string(loader), claudeEnvironmentLoaderMark) {
		t.Fatalf("SessionStart did not install the loader: %q err=%v", loader, err)
	}
	command = &cobra.Command{}
	setClaudeHookInput(command, "UserPromptSubmit")
	command.SetOut(io.Discard)
	if err := runAIClaudeEvent(command, []string{"heartbeat"}); err != nil {
		t.Fatal(err)
	}
	if ensureCalls != 2 {
		t.Fatalf("heartbeat did not repair the runtime for an adopted session: ensure calls=%d", ensureCalls)
	}
}

func TestClaudeHeartbeatDoesNotModifyWatchedRuntimeState(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	statePath := filepath.Join(directory, hookRuntimeStateFile)
	state := hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(),
		StartedAt: time.Now().UTC(), ProxyURL: "http://phase:capability@127.0.0.1:9543",
	}
	if err := writeOwnerOnlyJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	if err := registerHarnessLease(ai.HarnessClaudeCode, "session-one", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := touchSessionLease(harnessLeaseID(ai.HarnessClaudeCode, "session-one")); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatal("Claude heartbeat modified the watched runtime state")
	}
}

func TestClaudeHookCommandsStayHidden(t *testing.T) {
	if !aiClaudeHookCmd.Hidden || !aiRuntimeDaemonCmd.Hidden || !aiClaudeEventCmd.Hidden {
		t.Fatal("Claude runtime internals must not be advertised as public AI subcommands")
	}
}

func TestClaudeHookSessionStartInstallsLoaderAndKicksRuntimeWithoutBlocking(t *testing.T) {
	withHookTestConfig(t, true)
	directory := withHookRuntimeDirectory(t)
	withHookFingerprints(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	loaderPath := filepath.Join(t.TempDir(), "claude.env")
	t.Setenv("CLAUDE_ENV_FILE", loaderPath)
	originalEnsure := hookEnsureRuntime
	t.Cleanup(func() { hookEnsureRuntime = originalEnsure })
	ensureCalls := 0
	hookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		ensureCalls++
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("contains-sensitive-backend-detail runtime-secret")
	}

	run := func() claudeSessionStartOutput {
		t.Helper()
		command := &cobra.Command{}
		setClaudeHookInput(command, "SessionStart")
		var output bytes.Buffer
		command.SetOut(&output)
		if err := runAIClaudeHook(command, nil); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "contains-sensitive") || strings.Contains(output.String(), "runtime-secret") {
			t.Fatalf("hook stdout exposed runtime failure detail: %s", output.String())
		}
		var result claudeSessionStartOutput
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	result := run()
	if ensureCalls != 1 {
		t.Fatalf("SessionStart kicked the runtime %d times", ensureCalls)
	}
	additional := result.HookSpecificOutput.AdditionalContext
	if result.HookSpecificOutput.HookEventName != "SessionStart" || !result.HookSpecificOutput.ReloadSkills ||
		!strings.Contains(additional, "Phase AI is enabled on this machine") || !strings.Contains(additional, "Phase AI: proxy unavailable") {
		t.Fatalf("unexpected SessionStart output: %#v", result)
	}
	loader, err := os.ReadFile(loaderPath)
	if err != nil {
		t.Fatal(err)
	}
	expectedSnippet := claudeEnvironmentLoaderSnippet(runtimeEnvironmentPath(directory))
	if string(loader) != expectedSnippet || !strings.Contains(string(loader), runtimeEnvironmentPath(directory)) ||
		strings.Contains(string(loader), "PROXY=") || strings.Contains(string(loader), "export ") {
		t.Fatalf("loader file must contain only the source line:\n%s", loader)
	}
	leasePath, err := sessionLeasePath(directory, harnessLeaseID(ai.HarnessClaudeCode, "session-one"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leasePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("SessionStart registered a lease without a runtime: %v", err)
	}

	run()
	loader, err = os.ReadFile(loaderPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(loader), claudeEnvironmentLoaderMark) != 1 {
		t.Fatalf("repeated SessionStart duplicated the loader:\n%s", loader)
	}
}

func TestClaudeHookSessionStartReportsReadyRuntimeAndRegistersLease(t *testing.T) {
	withHookTestConfig(t, true)
	directory := withHookRuntimeDirectory(t)
	withHookFingerprints(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	t.Setenv("CLAUDE_ENV_FILE", filepath.Join(t.TempDir(), "claude.env"))
	originalEnsure := hookEnsureRuntime
	t.Cleanup(func() { hookEnsureRuntime = originalEnsure })
	hookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		return phaseproxy.ProcessEnvironmentPlan{}, nil
	}
	state := hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one",
		RuntimeScopeFingerprint: "scope-one", PID: os.Getpid(), StartedAt: time.Now().UTC(),
		ProxyURL: "http://phase:capability@127.0.0.1:1",
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	plan := phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{"HTTPS_PROXY": state.ProxyURL, "AWS_ACCESS_KEY_ID": "AKIADECOY"}}
	connections := []aiproxy.EndpointConnection{{ConnectionID: "conn-1", Name: "aws-prod", ServiceType: "aws", Protocol: "http"}}
	if err := writeRuntimeEnvironment(directory, os.Getpid(), "generation-one", state.StartedAt, plan, connections, true); err != nil {
		t.Fatal(err)
	}

	command := &cobra.Command{}
	setClaudeHookInput(command, "SessionStart")
	var output bytes.Buffer
	command.SetOut(&output)
	if err := runAIClaudeHook(command, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "capability") || strings.Contains(output.String(), "AKIADECOY") {
		t.Fatalf("SessionStart context leaked runtime material: %s", output.String())
	}
	var result claudeSessionStartOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.HookSpecificOutput.AdditionalContext, "Phase AI: proxy ready") ||
		!strings.Contains(result.HookSpecificOutput.AdditionalContext, "aws-prod (aws)") {
		t.Fatalf("unexpected ready context: %#v", result)
	}
	leasePath, err := sessionLeasePath(directory, harnessLeaseID(ai.HarnessClaudeCode, "session-one"))
	if err != nil {
		t.Fatal(err)
	}
	var lease sessionLease
	if err := readOwnerOnlyJSON(leasePath, &lease); err != nil || lease.Generation != "generation-one" {
		t.Fatalf("ready SessionStart did not register the session lease: %#v err=%v", lease, err)
	}
}

func TestClaudeHeartbeatReportsStatusAndRetiresStaleRouting(t *testing.T) {
	withHookTestConfig(t, true)
	directory := withHookRuntimeDirectory(t)
	withHookFingerprints(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	originalEnsure := hookEnsureRuntime
	t.Cleanup(func() { hookEnsureRuntime = originalEnsure })
	ensureCalls := 0
	hookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		ensureCalls++
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("runtime unavailable")
	}
	const deadPID = 1 << 30
	plan := phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{"HTTPS_PROXY": "http://phase:capability@127.0.0.1:1", "AWS_ACCESS_KEY_ID": "AKIADECOY"}}
	if err := writeRuntimeEnvironment(directory, deadPID, "generation-gone", time.Now().UTC(), plan, nil, true); err != nil {
		t.Fatal(err)
	}

	command := &cobra.Command{}
	setClaudeHookInput(command, "UserPromptSubmit")
	var output bytes.Buffer
	command.SetOut(&output)
	if err := runAIClaudeEvent(command, []string{"heartbeat"}); err != nil {
		t.Fatal(err)
	}
	var result claudePromptSubmitOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if ensureCalls != 1 || result.HookSpecificOutput.HookEventName != "UserPromptSubmit" ||
		!strings.Contains(result.HookSpecificOutput.AdditionalContext, "Phase AI: proxy unavailable") {
		t.Fatalf("heartbeat ensure calls=%d output=%#v", ensureCalls, result)
	}
	environment, err := os.ReadFile(runtimeEnvironmentPath(directory))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(environment), proxyBlockBegin) || strings.Contains(string(environment), "HTTPS_PROXY") ||
		!strings.Contains(string(environment), "export AWS_ACCESS_KEY_ID='AKIADECOY'") {
		t.Fatalf("heartbeat left routing for a dead proxy:\n%s", environment)
	}
	var status runtimeEnvironmentStatus
	if err := readOwnerOnlyJSON(runtimeEnvironmentStatusPath(directory), &status); err != nil || status.ProxyLive {
		t.Fatalf("heartbeat status = %#v err=%v", status, err)
	}
}

func TestClaudeHeartbeatStaysLocalWhileRuntimeIsHealthy(t *testing.T) {
	withHookTestConfig(t, true)
	directory := withHookRuntimeDirectory(t)
	withHookFingerprints(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	originalEnsure := hookEnsureRuntime
	t.Cleanup(func() { hookEnsureRuntime = originalEnsure })
	hookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		t.Fatal("healthy heartbeat must not touch the runtime")
		return phaseproxy.ProcessEnvironmentPlan{}, nil
	}
	state := hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one",
		RuntimeScopeFingerprint: "scope-one", PID: os.Getpid(), StartedAt: time.Now().UTC(),
		ProxyURL: "http://phase:capability@127.0.0.1:1",
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	connections := []aiproxy.EndpointConnection{{ConnectionID: "conn-1", Name: "analytics", ServiceType: "postgres", Protocol: "postgres"}}
	if err := writeRuntimeEnvironment(directory, os.Getpid(), "generation-one", state.StartedAt, phaseproxy.ProcessEnvironmentPlan{}, connections, true); err != nil {
		t.Fatal(err)
	}
	command := &cobra.Command{}
	setClaudeHookInput(command, "UserPromptSubmit")
	var output bytes.Buffer
	command.SetOut(&output)
	if err := runAIClaudeEvent(command, []string{"heartbeat"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Phase AI: proxy ready") || !strings.Contains(output.String(), "analytics (postgres)") {
		t.Fatalf("healthy heartbeat output = %s", output.String())
	}
	leasePath, err := sessionLeasePath(directory, harnessLeaseID(ai.HarnessClaudeCode, "session-one"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leasePath); err != nil {
		t.Fatalf("healthy heartbeat did not register the missing session lease: %v", err)
	}
}

func TestClaudeHeartbeatInstallsAMissingLoader(t *testing.T) {
	withHookTestConfig(t, true)
	directory := withHookRuntimeDirectory(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	loaderPath := filepath.Join(t.TempDir(), "claude.env")
	t.Setenv("CLAUDE_ENV_FILE", loaderPath)
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(),
		StartedAt: time.Now().UTC(), ProxyURL: "http://phase:capability@127.0.0.1:1",
	}); err != nil {
		t.Fatal(err)
	}
	command := &cobra.Command{}
	setClaudeHookInput(command, "UserPromptSubmit")
	command.SetOut(io.Discard)
	if err := runAIClaudeEvent(command, []string{"heartbeat"}); err != nil {
		t.Fatal(err)
	}
	loader, err := os.ReadFile(loaderPath)
	if err != nil || string(loader) != claudeEnvironmentLoaderSnippet(runtimeEnvironmentPath(directory)) {
		t.Fatalf("heartbeat did not repair a session that missed its loader: %q err=%v", loader, err)
	}
}
