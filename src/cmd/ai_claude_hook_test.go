package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/spf13/cobra"
)

type claudeFailingWriter struct{}

func (claudeFailingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

type claudeFailingManagedRuntime struct {
	err error
}

func (runtime claudeFailingManagedRuntime) ServeManaged(context.Context, airuntime.Engine) error {
	return runtime.err
}

var errClaudeRecycleTestComplete = errors.New("Claude recycle test complete")

type claudeRecycleTestRuntime struct {
	directory    string
	generation   string
	engines      []*aiproxy.Engine
	states       []claudeRuntimeState
	environments []string
}

func (runtime *claudeRecycleTestRuntime) ServeManaged(_ context.Context, engine airuntime.Engine) error {
	proxyEngine, ok := engine.(*aiproxy.Engine)
	if !ok {
		return fmt.Errorf("unexpected proxy engine %T", engine)
	}
	runtime.engines = append(runtime.engines, proxyEngine)
	cycle := len(runtime.engines)
	proxyURL := fmt.Sprintf("http://phase:cycle-%d@127.0.0.1:9543", cycle)
	proxyEngine.OnStarted(aiproxy.Endpoints{ProcessEnvironment: phaseproxy.ProcessEnvironmentPlan{
		Set: map[string]string{"PHASE_AI_ENABLED": "1", "HTTP_PROXY": proxyURL, "AWS_ACCESS_KEY_ID": "AKIADECOY"},
	}, Connections: []aiproxy.EndpointConnection{{ConnectionID: "conn-1", Name: "aws-prod", ServiceType: "aws", Protocol: "http"}}})
	state, err := readClaudeRuntimeState(filepath.Join(runtime.directory, claudeRuntimeStateFile))
	if err != nil {
		return err
	}
	runtime.states = append(runtime.states, state)
	environment, err := os.ReadFile(claudeEnvironmentPath(runtime.directory))
	if err != nil {
		return err
	}
	runtime.environments = append(runtime.environments, string(environment))
	if cycle == 1 {
		return fmt.Errorf("first managed cycle: %w", airuntime.ErrSessionReprovisionRequired)
	}
	return errClaudeRecycleTestComplete
}

func withClaudeHookTestConfig(t *testing.T, enabled bool) {
	t.Helper()
	originalPath := config.AIConfigPath
	config.AIConfigPath = filepath.Join(t.TempDir(), "ai.json")
	t.Cleanup(func() { config.AIConfigPath = originalPath })
	if err := config.SaveAIConfig(&config.AIConfig{
		Enabled: enabled, ProxyMode: config.AIProxyModeLocal,
		HarnessIDs: []string{ai.HarnessClaudeCode},
	}); err != nil {
		t.Fatal(err)
	}
}

func withClaudeHookRuntimeDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	// Hooks append a loader to this file; never touch a real harness session's.
	t.Setenv("CLAUDE_ENV_FILE", "")
	originalDirectory := claudeHookRuntimeDir
	claudeHookRuntimeDir = func() (string, error) { return directory, nil }
	t.Cleanup(func() { claudeHookRuntimeDir = originalDirectory })
	return directory
}

func setClaudeHookInput(command *cobra.Command, event string) {
	command.SetContext(context.Background())
	command.SetIn(strings.NewReader(`{"session_id":"session-one","hook_event_name":"` + event + `"}`))
}

func setClaudeToolHookInput(command *cobra.Command, toolName string) {
	setClaudeToolHookCommand(command, toolName, "curl http://phase.invalid/v1/status")
}

func setClaudeToolHookCommand(command *cobra.Command, toolName, shellCommand string) {
	command.SetContext(context.Background())
	payload, _ := json.Marshal(map[string]any{
		"session_id": "session-one", "hook_event_name": "PreToolUse", "tool_name": toolName,
		"tool_use_id": "tool-one", "tool_input": map[string]any{
			"command": shellCommand, "description": "preserve normal permission evaluation",
		},
	})
	command.SetIn(bytes.NewReader(payload))
}

func TestClaudeHookDisabledIsNoop(t *testing.T) {
	withClaudeHookTestConfig(t, false)
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

	for _, shellCommand := range []string{"curl http://phase.invalid/v1/status", "git status && gh pr view", "aws s3 ls"} {
		guard := &cobra.Command{}
		setClaudeToolHookCommand(guard, "Bash", shellCommand)
		var guardOutput bytes.Buffer
		guard.SetOut(&guardOutput)
		if err := runAIClaudeEvent(guard, []string{"guard"}); err != nil || guardOutput.Len() != 0 {
			t.Fatalf("invalid-config guard interfered with %q: output=%q err=%v", shellCommand, guardOutput.String(), err)
		}
	}
}

func TestRequestClaudeRuntimeShutdownUsesAuthenticatedLocalControl(t *testing.T) {
	const capability = "runtime-shutdown-capability"
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		called = true
		if request.Method != http.MethodPost || request.URL.String() != phaseproxy.ControlURL+"/v1/revoke" {
			t.Errorf("shutdown request = %s %s", request.Method, request.URL.String())
		}
		expectedAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("phase:"+capability))
		if actual := request.Header.Get("Proxy-Authorization"); actual != expectedAuthorization {
			t.Errorf("shutdown proxy authorization = %q", actual)
		}
		if request.Header.Get("Authorization") != "" {
			t.Error("runtime capability was reused as origin authorization")
		}
		_ = json.NewEncoder(w).Encode(agentapi.RevokeResponse{
			SchemaVersion: agentapi.SchemaVersion,
			SessionUID:    "session-one",
			RevokedAt:     time.Now().UTC(),
		})
	}))
	defer server.Close()

	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("phase", capability)
	if err := requestClaudeRuntimeShutdown(context.Background(), proxyURL.String()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("authenticated shutdown control was not called")
	}
}

func TestRequestClaudeRuntimeShutdownRejectsInvalidAcknowledgement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"session-one"}`))
	}))
	defer server.Close()

	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("phase", "runtime-shutdown-capability")
	if err := requestClaudeRuntimeShutdown(context.Background(), proxyURL.String()); err == nil ||
		!strings.Contains(err.Error(), "response is invalid") {
		t.Fatalf("invalid shutdown acknowledgement error = %v", err)
	}
}

func TestClaudeDaemonRecyclesSameProcessAndGenerationOnOneEngine(t *testing.T) {
	withClaudeHookTestConfig(t, true)
	directory := withClaudeHookRuntimeDirectory(t)
	const generation = "generation-one"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: generation, PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	managed := &claudeRecycleTestRuntime{directory: directory, generation: generation}
	originalRuntime := claudeHookNewRuntime
	originalEngine := claudeHookNewProxyEngine
	originalFingerprint := claudeHookFingerprint
	originalScopeFingerprint := claudeHookScopeFingerprint
	runtimeCreations := 0
	claudeHookNewRuntime = func() (claudeManagedRuntime, error) {
		runtimeCreations++
		return managed, nil
	}
	claudeHookNewProxyEngine = aiproxy.New
	claudeHookFingerprint = func() (string, error) { return "binding-one", nil }
	claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		claudeHookNewRuntime = originalRuntime
		claudeHookNewProxyEngine = originalEngine
		claudeHookFingerprint = originalFingerprint
		claudeHookScopeFingerprint = originalScopeFingerprint
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("generation", "", "")
	if err := command.Flags().Set("generation", generation); err != nil {
		t.Fatal(err)
	}
	if err := runAIClaudeDaemon(command, nil); !errors.Is(err, errClaudeRecycleTestComplete) {
		t.Fatalf("daemon recycle result = %v", err)
	}
	if runtimeCreations != 1 || len(managed.engines) != 2 || len(managed.states) != 2 {
		t.Fatalf("runtime creations=%d engines=%d states=%d", runtimeCreations, len(managed.engines), len(managed.states))
	}
	// One Engine serves every cycle: it keeps the proxy capability and the
	// memory of earlier decoy generations, so shells and processes provisioned
	// before a recycle keep working through the new session.
	if managed.engines[0] != managed.engines[1] {
		t.Fatal("managed recycle replaced the proxy Engine and lost the decoy history")
	}
	for index, state := range managed.states {
		if state.Generation != generation || state.PID != os.Getpid() || state.RuntimeFingerprint != "binding-one" || state.RuntimeScopeFingerprint != "scope-one" {
			t.Fatalf("cycle %d state = %#v", index+1, state)
		}
	}
	if !managed.states[1].StartedAt.After(managed.states[0].StartedAt) {
		t.Fatalf("managed recycle did not publish a newer cycle start: %v then %v", managed.states[0].StartedAt, managed.states[1].StartedAt)
	}
	for index, environment := range managed.environments {
		guard, err := claudeProxyLivenessGuard(os.Getpid(), phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{"HTTP_PROXY": managed.states[index].ProxyURL}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(environment, "if "+guard+"; then") ||
			!strings.Contains(environment, "export HTTP_PROXY='"+managed.states[index].ProxyURL+"'") ||
			!strings.Contains(environment, "export AWS_ACCESS_KEY_ID='AKIADECOY'") {
			t.Fatalf("cycle %d did not publish a live sourced environment:\n%s", index+1, environment)
		}
	}
	final, err := os.ReadFile(claudeEnvironmentPath(directory))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(final), claudeProxyBlockBegin) || strings.Contains(string(final), "HTTP_PROXY") ||
		!strings.Contains(string(final), "export AWS_ACCESS_KEY_ID='AKIADECOY'") {
		t.Fatalf("daemon exit left proxy routing in the sourced environment:\n%s", final)
	}
	var status claudeEnvironmentStatus
	if err := readOwnerOnlyJSON(claudeEnvironmentStatusPath(directory), &status); err != nil || status.ProxyLive || len(status.Connections) != 1 || status.Connections[0].Name != "aws-prod" {
		t.Fatalf("daemon exit status = %#v err=%v", status, err)
	}
}

type claudeStopDuringRecycleRuntime struct {
	cycles  int
	stopErr error
}

func (runtime *claudeStopDuringRecycleRuntime) ServeManaged(ctx context.Context, engine airuntime.Engine) error {
	runtime.cycles++
	if runtime.cycles == 2 {
		// The session is recycling: the daemon's state is withdrawn.
		runtime.stopErr = stopClaudeHookRuntime(ctx)
	}
	engine.(*aiproxy.Engine).OnStarted(aiproxy.Endpoints{ProcessEnvironment: phaseproxy.ProcessEnvironmentPlan{
		Set: map[string]string{"PHASE_AI_ENABLED": "1", "HTTP_PROXY": "http://phase:capability@127.0.0.1:9543"},
	}})
	if runtime.cycles == 1 {
		return fmt.Errorf("first managed cycle: %w", airuntime.ErrSessionExpired)
	}
	return errClaudeRecycleTestComplete
}

func TestSetupCanStopAnEstablishedDaemonWhileItRecycles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX sleep process as the daemon PID")
	}
	withClaudeHookTestConfig(t, true)
	directory := withClaudeHookRuntimeDirectory(t)
	withClaudeHookFingerprints(t)
	daemon := exec.Command("sleep", "60")
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = daemon.Wait(); close(exited) }()
	t.Cleanup(func() { _ = daemon.Process.Kill() })
	const generation = "generation-established"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: generation, PID: daemon.Process.Pid,
		CreatedAt: time.Now().Add(-10 * time.Minute).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	managed := &claudeStopDuringRecycleRuntime{}
	originalRuntime := claudeHookNewRuntime
	claudeHookNewRuntime = func() (claudeManagedRuntime, error) { return managed, nil }
	t.Cleanup(func() { claudeHookNewRuntime = originalRuntime })

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("generation", "", "")
	if err := command.Flags().Set("generation", generation); err != nil {
		t.Fatal(err)
	}
	if err := runAIClaudeDaemon(command, nil); !errors.Is(err, errClaudeRecycleTestComplete) {
		t.Fatalf("daemon recycle result = %v", err)
	}
	if managed.cycles != 2 || managed.stopErr != nil {
		t.Fatalf("setup could not stop the recycling daemon: cycles=%d err=%v", managed.cycles, managed.stopErr)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the recycling daemon was not stopped")
	}
}

func TestClaudeDaemonPublishesAuthenticationFailure(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	const generation = "generation-authentication-failure"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: generation, PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	originalRuntime := claudeHookNewRuntime
	originalFingerprint := claudeHookFingerprint
	originalScopeFingerprint := claudeHookScopeFingerprint
	claudeHookNewRuntime = func() (claudeManagedRuntime, error) {
		return claudeFailingManagedRuntime{err: airuntime.ErrAuthenticationRequired}, nil
	}
	claudeHookFingerprint = func() (string, error) { return "binding-one", nil }
	claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		claudeHookNewRuntime = originalRuntime
		claudeHookFingerprint = originalFingerprint
		claudeHookScopeFingerprint = originalScopeFingerprint
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("generation", "", "")
	if err := command.Flags().Set("generation", generation); err != nil {
		t.Fatal(err)
	}
	if err := runAIClaudeDaemon(command, nil); !errors.Is(err, airuntime.ErrAuthenticationRequired) {
		t.Fatalf("daemon result = %v", err)
	}
	failure, err := readClaudeRuntimeFailure(claudeRuntimeFailurePath(directory, generation))
	if err != nil {
		t.Fatal(err)
	}
	if failure.Generation != generation || failure.Reason != "authentication" {
		t.Fatalf("runtime failure = %#v", failure)
	}
	if !errors.Is(claudeRuntimeFailureError(failure.Reason), errClaudeRuntimeAuthenticationRequired) {
		t.Fatalf("authentication failure was not preserved: %v", claudeRuntimeFailureError(failure.Reason))
	}
}

func TestClaudeDaemonPublishesAuthenticationFailureFromRuntimeConstruction(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	const generation = "generation-authentication-construction-failure"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: generation, PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	originalRuntime := claudeHookNewRuntime
	originalFingerprint := claudeHookFingerprint
	originalScopeFingerprint := claudeHookScopeFingerprint
	claudeHookNewRuntime = func() (claudeManagedRuntime, error) {
		return nil, airuntime.ErrAuthenticationRequired
	}
	claudeHookFingerprint = func() (string, error) { return "binding-one", nil }
	claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		claudeHookNewRuntime = originalRuntime
		claudeHookFingerprint = originalFingerprint
		claudeHookScopeFingerprint = originalScopeFingerprint
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("generation", "", "")
	if err := command.Flags().Set("generation", generation); err != nil {
		t.Fatal(err)
	}
	if err := runAIClaudeDaemon(command, nil); !errors.Is(err, airuntime.ErrAuthenticationRequired) {
		t.Fatalf("daemon result = %v", err)
	}
	failure, err := readClaudeRuntimeFailure(claudeRuntimeFailurePath(directory, generation))
	if err != nil {
		t.Fatal(err)
	}
	if failure.Generation != generation || failure.Reason != "authentication" {
		t.Fatalf("runtime failure = %#v", failure)
	}
}

func TestClaudeHookReusesInheritedPhaseEnvironment(t *testing.T) {
	withClaudeHookTestConfig(t, true)
	t.Setenv("PHASE_AI_ENABLED", "1")
	// phase ai run started from a shell that carries the hook daemon's
	// environment: its own proxy replaced the daemon's.
	t.Setenv("HTTPS_PROXY", "http://phase:run-capability@127.0.0.1:9600")
	t.Setenv(claudeHookRuntimeMarker, claudeHookRuntimeMarkerValue("http://phase:daemon-capability@127.0.0.1:9543"))
	t.Setenv("CLAUDE_ENV_FILE", filepath.Join(t.TempDir(), "claude.env"))
	originalEnsure := claudeHookEnsureRuntime
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })
	ensureCalls := 0
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
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
	withClaudeHookTestConfig(t, true)
	directory := withClaudeHookRuntimeDirectory(t)
	withClaudeHookFingerprints(t)
	plan := phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{
		"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": "http://phase:capability@127.0.0.1:9543", "AWS_ACCESS_KEY_ID": "AKIADECOY",
	}}
	if err := writeClaudeEnvironment(directory, os.Getpid(), "generation-one", time.Now().UTC(), plan, nil, true); err != nil {
		t.Fatal(err)
	}
	// Claude launched from an OpenCode shell inherits what the plugin exported.
	var published claudeEnvironmentJSON
	if err := readOwnerOnlyJSON(claudeEnvironmentJSONPath(directory), &published); err != nil {
		t.Fatal(err)
	}
	t.Setenv(claudeHookRuntimeMarker, "")
	for key, value := range published.Set {
		t.Setenv(key, value)
	}
	for key, value := range published.Proxy {
		t.Setenv(key, value)
	}
	loaderPath := filepath.Join(t.TempDir(), "claude.env")
	t.Setenv("CLAUDE_ENV_FILE", loaderPath)
	originalEnsure := claudeHookEnsureRuntime
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })
	ensureCalls := 0
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
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

func TestClaudeRuntimeFingerprintMismatchIsRejected(t *testing.T) {
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "old-binding",
		PID: os.Getpid(), ProxyURL: "http://phase:capability@127.0.0.1:9543",
	}
	err := probeClaudeRuntimeState(context.Background(), state, "new-binding")
	if err == nil || !strings.Contains(err.Error(), "binding changed") {
		t.Fatalf("fingerprint mismatch error = %v", err)
	}
}

func TestClaudeRuntimeStateRejectsLegacyV1(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	statePath := filepath.Join(directory, claudeRuntimeStateFile)
	if err := writeOwnerOnlyJSON(statePath, map[string]any{
		"version": 1, "generation": "legacy-generation", "pid": os.Getpid(),
		"processEnvironment": map[string]any{
			"set": map[string]string{"HTTP_PROXY": "http://phase:legacy-capability@127.0.0.1:9543"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := readClaudeRuntimeState(statePath); err == nil || !strings.Contains(err.Error(), "version is unsupported") {
		t.Fatalf("legacy v1 runtime state error = %v", err)
	}
}
func TestClaudeLeaseFileLockIsReleasedWhenOwnerExits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.lock")
	owner, acquired, err := tryLockClaudeLeaseFile(path)
	if err != nil || !acquired {
		t.Fatalf("initial lease lock acquired=%v err=%v", acquired, err)
	}
	contender, acquired, err := tryLockClaudeLeaseFile(path)
	if err != nil || acquired || contender != nil {
		t.Fatalf("contended lease lock acquired=%v file=%v err=%v", acquired, contender, err)
	}
	// Closing without the explicit unlock models process teardown: the OS lock
	// must be released without stale-owner pathname deletion.
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, acquired, err := tryLockClaudeLeaseFile(path)
	if err != nil || !acquired {
		t.Fatalf("replacement lease lock acquired=%v err=%v", acquired, err)
	}
	if err := unlockClaudeLeaseFile(replacement); err != nil {
		t.Fatal(err)
	}
}

func TestClaudeRuntimeLockStaleRecoveryGrantsOneOwner(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	lockPath := filepath.Join(directory, claudeRuntimeLockFile)
	if err := writeOwnerOnlyJSON(lockPath, claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: "generation-stale", CreatedAt: time.Now().Add(-time.Hour).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	const claimers = 32
	results := make(chan string, claimers)
	start := make(chan struct{})
	for index := range claimers {
		go func() {
			<-start
			generation := fmt.Sprintf("generation-%d", index)
			claimed, err := claimClaudeRuntimeLock(lockPath, generation)
			switch {
			case err != nil:
				results <- "error: " + err.Error()
			case claimed:
				results <- generation
			default:
				results <- ""
			}
		}()
	}
	close(start)
	var owners []string
	for range claimers {
		result := <-results
		if strings.HasPrefix(result, "error: ") {
			t.Fatal(result)
		}
		if result != "" {
			owners = append(owners, result)
		}
	}
	lock, err := readClaudeRuntimeLock(lockPath)
	if err != nil || len(owners) != 1 || lock.Generation != owners[0] {
		t.Fatalf("stale lock recovery granted owners %v; recorded %q err=%v", owners, lock.Generation, err)
	}
}

func TestHookDaemonStartWaitsForSetupToFinish(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	lockPath := filepath.Join(directory, claudeRuntimeLockFile)
	release, err := lockClaudeHookSetup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := claimClaudeRuntimeLock(lockPath, "generation-during-setup")
	if claimed || !errors.Is(err, errClaudeHookSetupInProgress) {
		t.Fatalf("a daemon start during setup: claimed=%v err=%v", claimed, err)
	}
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a daemon start during setup left a lock: %v", err)
	}
	release()
	if claimed, err := claimClaudeRuntimeLock(lockPath, "generation-after-setup"); !claimed || err != nil {
		t.Fatalf("a daemon start after setup: claimed=%v err=%v", claimed, err)
	}
}

func TestClaudeRuntimeLockRecoversAnInterruptedWrite(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	lockPath := filepath.Join(directory, claudeRuntimeLockFile)
	writeEmptyLock := func(age time.Duration) {
		t.Helper()
		if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		modified := time.Now().Add(-age)
		if err := os.Chtimes(lockPath, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	writeEmptyLock(0)
	if claimed, err := claimClaudeRuntimeLock(lockPath, "generation-new"); claimed || err == nil {
		t.Fatalf("a lock still being written was replaced: claimed=%v err=%v", claimed, err)
	}
	writeEmptyLock(time.Hour)
	if claimed, err := claimClaudeRuntimeLock(lockPath, "generation-new"); !claimed || err != nil {
		t.Fatalf("an abandoned lock blocked recovery: claimed=%v err=%v", claimed, err)
	}
	writeEmptyLock(time.Hour)
	if err := stopClaudeHookRuntime(context.Background()); err != nil {
		t.Fatalf("stop could not clear an abandoned lock: %v", err)
	}
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned lock survived stop: %v", err)
	}
}

func TestProcessIsAliveRejectsAZombie(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("zombie detection reads /proc")
	}
	child := exec.Command("/bin/sh", "-c", "exit 0")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	// Left unreaped, the exited child stays a zombie as under a non-reaping init.
	t.Cleanup(func() { _ = child.Wait() })
	statPath := fmt.Sprintf("/proc/%d/stat", child.Process.Pid)
	deadline := time.Now().Add(5 * time.Second)
	for {
		stat, err := os.ReadFile(statPath)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(stat), ") Z ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child never became a zombie: %s", stat)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if processIsAlive(child.Process.Pid) {
		t.Fatal("an exited zombie process was reported alive")
	}
	if !processIsAlive(os.Getpid()) {
		t.Fatal("the running test process was reported dead")
	}
}

func TestClaudeHeartbeatDoesNotModifyWatchedRuntimeState(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	statePath := filepath.Join(directory, claudeRuntimeStateFile)
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(),
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
	if err := touchClaudeSessionLease(harnessLeaseID(ai.HarnessClaudeCode, "session-one")); err != nil {
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

func TestEnsureClaudeHookRuntimeReusesAuthenticatedManagedProxy(t *testing.T) {
	var proxyURL string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/status":
			_, _ = writer.Write([]byte(`{"schemaVersion":1,"kind":"phase.ai.status","safeToPrint":true,"connections":[]}`))
		case "/.well-known/agents":
			payload := map[string]any{
				"schemaVersion": 1, "sessionUid": "session",
				"processEnvironment": map[string]any{
					"set":   map[string]string{"PHASE_AI_ENABLED": "1", "HTTP_PROXY": proxyURL},
					"unset": []string{"PHASE_AGENT_TOKEN"},
				},
				"discover": map[string]any{"schemaVersion": 1, "sessionUid": "session", "connections": []any{}},
			}
			_ = json.NewEncoder(writer).Encode(payload)
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

	directory := withClaudeHookRuntimeDirectory(t)
	originalFingerprint := claudeHookFingerprint
	originalScopeFingerprint := claudeHookScopeFingerprint
	claudeHookFingerprint = func() (string, error) { return "binding-one", nil }
	claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		claudeHookFingerprint = originalFingerprint
		claudeHookScopeFingerprint = originalScopeFingerprint
	})
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(),
		RuntimeFingerprint: "binding-one", RuntimeScopeFingerprint: "scope-one", ProxyURL: proxyURL,
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	plan, err := ensureClaudeHookRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Set["HTTP_PROXY"] != proxyURL {
		t.Fatalf("reused proxy = %q", plan.Set["HTTP_PROXY"])
	}
}

func TestEnsureClaudeHookRuntimeReplacesCurrentSchemaStateWithoutScope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owned-process replacement uses POSIX interrupt semantics")
	}

	oldProcess := exec.Command("sleep", "30")
	if err := oldProcess.Start(); err != nil {
		t.Fatal(err)
	}
	processDone := make(chan struct{})
	go func() {
		_ = oldProcess.Wait()
		close(processDone)
	}()
	t.Cleanup(func() {
		select {
		case <-processDone:
		default:
			_ = oldProcess.Process.Kill()
			<-processDone
		}
	})

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/status" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"schemaVersion":1,"kind":"phase.ai.status","safeToPrint":true,"connections":[]}`))
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword("phase", "old-runtime-capability")

	directory := withClaudeHookRuntimeDirectory(t)
	now := time.Now().UTC()
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-without-scope",
		RuntimeFingerprint: "binding-one", PID: oldProcess.Process.Pid,
		StartedAt: now, ProxyURL: parsed.String(),
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: state.Generation,
		PID: state.PID, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	originalFingerprint := claudeHookFingerprint
	originalScopeFingerprint := claudeHookScopeFingerprint
	originalExecutable := claudeHookExecutable
	replacementErr := errors.New("replacement daemon requested")
	replacementCalls := 0
	claudeHookFingerprint = func() (string, error) { return "binding-one", nil }
	claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	claudeHookExecutable = func() (string, error) {
		replacementCalls++
		return "", replacementErr
	}
	t.Cleanup(func() {
		claudeHookFingerprint = originalFingerprint
		claudeHookScopeFingerprint = originalScopeFingerprint
		claudeHookExecutable = originalExecutable
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ensureClaudeHookRuntime(ctx); !errors.Is(err, replacementErr) {
		t.Fatalf("missing-scope replacement error = %v", err)
	}
	if replacementCalls != 1 {
		t.Fatalf("replacement daemon requests = %d, want 1", replacementCalls)
	}
	select {
	case <-processDone:
	case <-time.After(time.Second):
		t.Fatal("outdated current-schema runtime process was not stopped")
	}
	for _, path := range []string{
		filepath.Join(directory, claudeRuntimeStateFile),
		filepath.Join(directory, claudeRuntimeLockFile),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("outdated runtime artifact remains at %s: %v", path, err)
		}
	}
}

func TestEnsureClaudeHookRuntimeClassifiesLiveLockWaitTimeoutAsRefresh(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	lock := claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: "generation-recycling",
		PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), lock); err != nil {
		t.Fatal(err)
	}
	originalFingerprint := claudeHookFingerprint
	originalScopeFingerprint := claudeHookScopeFingerprint
	originalStartTimeout := claudeHookStartTimeout
	originalPollInterval := claudeHookPollInterval
	claudeHookFingerprint = func() (string, error) { return "binding-one", nil }
	claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	claudeHookStartTimeout = 25 * time.Millisecond
	claudeHookPollInterval = time.Millisecond
	t.Cleanup(func() {
		claudeHookFingerprint = originalFingerprint
		claudeHookScopeFingerprint = originalScopeFingerprint
		claudeHookStartTimeout = originalStartTimeout
		claudeHookPollInterval = originalPollInterval
	})

	_, err := ensureClaudeHookRuntime(context.Background())
	if !errors.Is(err, errClaudeRuntimeRefreshing) {
		t.Fatalf("live-lock wait timeout error = %v, want managed refresh", err)
	}
}

func TestPhaseAgentManifestFailureClassification(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		header     string
		body       string
		structured bool
		canonical  bool
		retryable  bool
		mayCycle   bool
	}{
		{
			name: "refresh contract", status: http.StatusServiceUnavailable,
			header:     aiproxy.ManifestRefreshRequiredCode,
			body:       `{"error":{"code":"agent_manifest_refresh_required","message":"refreshing","retryable":true,"details":{}}}`,
			structured: true, canonical: true, retryable: true, mayCycle: true,
		},
		{
			name: "refresh code wrong status", status: http.StatusBadGateway,
			header:     aiproxy.ManifestRefreshRequiredCode,
			body:       `{"error":{"code":"agent_manifest_refresh_required","message":"refreshing","retryable":true,"details":{}}}`,
			structured: true, canonical: true, retryable: true,
		},
		{
			name: "refresh not retryable", status: http.StatusServiceUnavailable,
			header:     aiproxy.ManifestRefreshRequiredCode,
			body:       `{"error":{"code":"agent_manifest_refresh_required","message":"refreshing","retryable":false,"details":{}}}`,
			structured: true, canonical: true,
		},
		{
			name: "unknown service unavailable", status: http.StatusServiceUnavailable,
			header: "unknown", body: `{"error":{"code":"unknown","message":"unknown","retryable":true,"details":{}}}`,
			structured: true, canonical: true, retryable: true,
		},
		{name: "malformed service unavailable", status: http.StatusServiceUnavailable, body: `{`},
		{name: "proxy auth cycle gap", status: http.StatusProxyAuthRequired, body: `{`, mayCycle: true},
		{name: "legacy bad gateway", status: http.StatusBadGateway, body: `{`},
		{
			name: "header body mismatch", status: http.StatusServiceUnavailable,
			header: aiproxy.ManifestRefreshRequiredCode,
			body:   `{"error":{"code":"different","retryable":true}}`,
		},
		{
			name: "trailing payload", status: http.StatusServiceUnavailable,
			header: aiproxy.ManifestRefreshRequiredCode,
			body:   `{"error":{"code":"agent_manifest_refresh_required","retryable":true}} {}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{
				StatusCode: test.status, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(test.body)),
			}
			if test.header != "" {
				response.Header.Set("X-Phase-Error-Code", test.header)
			}
			err := decodePhaseAgentManifestFailure(response)
			var failure *phaseAgentManifestFailure
			if !errors.As(err, &failure) {
				t.Fatalf("failure type = %T", err)
			}
			if failure.StatusCode != test.status || failure.Structured != test.structured ||
				failure.Canonical != test.canonical || failure.Retryable != test.retryable {
				t.Fatalf("failure = %#v", failure)
			}
			if got := harnessManifestFailureMayBeCycle(err); got != test.mayCycle {
				t.Fatalf("may cycle = %v, want %v", got, test.mayCycle)
			}
		})
	}
}

func TestClaudeHookCommandsStayHidden(t *testing.T) {
	if !aiClaudeHookCmd.Hidden || !aiClaudeDaemonCmd.Hidden || !aiClaudeEventCmd.Hidden {
		t.Fatal("Claude runtime internals must not be advertised as public AI subcommands")
	}
}

func withClaudeHookFingerprints(t *testing.T) {
	t.Helper()
	originalFingerprint := claudeHookFingerprint
	originalScopeFingerprint := claudeHookScopeFingerprint
	claudeHookFingerprint = func() (string, error) { return "binding-one", nil }
	claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		claudeHookFingerprint = originalFingerprint
		claudeHookScopeFingerprint = originalScopeFingerprint
	})
}

func TestClaudeHookSessionStartInstallsLoaderAndKicksRuntimeWithoutBlocking(t *testing.T) {
	withClaudeHookTestConfig(t, true)
	directory := withClaudeHookRuntimeDirectory(t)
	withClaudeHookFingerprints(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	loaderPath := filepath.Join(t.TempDir(), "claude.env")
	t.Setenv("CLAUDE_ENV_FILE", loaderPath)
	originalEnsure := claudeHookEnsureRuntime
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })
	ensureCalls := 0
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
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
	expectedSnippet := claudeEnvironmentLoaderSnippet(claudeEnvironmentPath(directory))
	if string(loader) != expectedSnippet || !strings.Contains(string(loader), claudeEnvironmentPath(directory)) ||
		strings.Contains(string(loader), "PROXY=") || strings.Contains(string(loader), "export ") {
		t.Fatalf("loader file must contain only the source line:\n%s", loader)
	}
	leasePath, err := claudeSessionLeasePath(directory, harnessLeaseID(ai.HarnessClaudeCode, "session-one"))
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
	withClaudeHookTestConfig(t, true)
	directory := withClaudeHookRuntimeDirectory(t)
	withClaudeHookFingerprints(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	t.Setenv("CLAUDE_ENV_FILE", filepath.Join(t.TempDir(), "claude.env"))
	originalEnsure := claudeHookEnsureRuntime
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		return phaseproxy.ProcessEnvironmentPlan{}, nil
	}
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one",
		RuntimeScopeFingerprint: "scope-one", PID: os.Getpid(), StartedAt: time.Now().UTC(),
		ProxyURL: "http://phase:capability@127.0.0.1:1",
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	plan := phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{"HTTPS_PROXY": state.ProxyURL, "AWS_ACCESS_KEY_ID": "AKIADECOY"}}
	connections := []aiproxy.EndpointConnection{{ConnectionID: "conn-1", Name: "aws-prod", ServiceType: "aws", Protocol: "http"}}
	if err := writeClaudeEnvironment(directory, os.Getpid(), "generation-one", state.StartedAt, plan, connections, true); err != nil {
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
	leasePath, err := claudeSessionLeasePath(directory, harnessLeaseID(ai.HarnessClaudeCode, "session-one"))
	if err != nil {
		t.Fatal(err)
	}
	var lease claudeSessionLease
	if err := readOwnerOnlyJSON(leasePath, &lease); err != nil || lease.Generation != "generation-one" {
		t.Fatalf("ready SessionStart did not register the session lease: %#v err=%v", lease, err)
	}
}

func TestClaudeHeartbeatReportsStatusAndRetiresStaleRouting(t *testing.T) {
	withClaudeHookTestConfig(t, true)
	directory := withClaudeHookRuntimeDirectory(t)
	withClaudeHookFingerprints(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	originalEnsure := claudeHookEnsureRuntime
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })
	ensureCalls := 0
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		ensureCalls++
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("runtime unavailable")
	}
	const deadPID = 1 << 30
	plan := phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{"HTTPS_PROXY": "http://phase:capability@127.0.0.1:1", "AWS_ACCESS_KEY_ID": "AKIADECOY"}}
	if err := writeClaudeEnvironment(directory, deadPID, "generation-gone", time.Now().UTC(), plan, nil, true); err != nil {
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
	environment, err := os.ReadFile(claudeEnvironmentPath(directory))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(environment), claudeProxyBlockBegin) || strings.Contains(string(environment), "HTTPS_PROXY") ||
		!strings.Contains(string(environment), "export AWS_ACCESS_KEY_ID='AKIADECOY'") {
		t.Fatalf("heartbeat left routing for a dead proxy:\n%s", environment)
	}
	var status claudeEnvironmentStatus
	if err := readOwnerOnlyJSON(claudeEnvironmentStatusPath(directory), &status); err != nil || status.ProxyLive {
		t.Fatalf("heartbeat status = %#v err=%v", status, err)
	}
}

func TestClaudeHeartbeatStaysLocalWhileRuntimeIsHealthy(t *testing.T) {
	withClaudeHookTestConfig(t, true)
	directory := withClaudeHookRuntimeDirectory(t)
	withClaudeHookFingerprints(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	originalEnsure := claudeHookEnsureRuntime
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		t.Fatal("healthy heartbeat must not touch the runtime")
		return phaseproxy.ProcessEnvironmentPlan{}, nil
	}
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one",
		RuntimeScopeFingerprint: "scope-one", PID: os.Getpid(), StartedAt: time.Now().UTC(),
		ProxyURL: "http://phase:capability@127.0.0.1:1",
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	connections := []aiproxy.EndpointConnection{{ConnectionID: "conn-1", Name: "analytics", ServiceType: "postgres", Protocol: "postgres"}}
	if err := writeClaudeEnvironment(directory, os.Getpid(), "generation-one", state.StartedAt, phaseproxy.ProcessEnvironmentPlan{}, connections, true); err != nil {
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
	leasePath, err := claudeSessionLeasePath(directory, harnessLeaseID(ai.HarnessClaudeCode, "session-one"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leasePath); err != nil {
		t.Fatalf("healthy heartbeat did not register the missing session lease: %v", err)
	}
}

func TestKickLeasesASessionToADaemonStillStarting(t *testing.T) {
	withClaudeHookTestConfig(t, true)
	directory := withClaudeHookRuntimeDirectory(t)
	originalEnsure := claudeHookEnsureRuntime
	t.Cleanup(func() { claudeHookEnsureRuntime = originalEnsure })
	claudeHookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase AI automatic proxy did not become ready")
	}
	const generation = "generation-starting"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: generation, PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if health := kickClaudeRuntime(context.Background(), directory, "session-one", time.Millisecond); !health.starting {
		t.Fatalf("kick health = %+v, want starting", health)
	}
	// The daemon publishes after the hook's wait ended; the session must still
	// keep it from idling out.
	active, err := hasActiveClaudeSessionLease(directory, generation, time.Now())
	if err != nil || !active {
		t.Fatalf("a session waiting on a slow startup has no lease: active=%v err=%v", active, err)
	}
}

func TestClaudeHeartbeatInstallsAMissingLoader(t *testing.T) {
	withClaudeHookTestConfig(t, true)
	directory := withClaudeHookRuntimeDirectory(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	loaderPath := filepath.Join(t.TempDir(), "claude.env")
	t.Setenv("CLAUDE_ENV_FILE", loaderPath)
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(),
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
	if err != nil || string(loader) != claudeEnvironmentLoaderSnippet(claudeEnvironmentPath(directory)) {
		t.Fatalf("heartbeat did not repair a session that missed its loader: %q err=%v", loader, err)
	}
}

func TestClaudeGuardIsSilentForEveryCommand(t *testing.T) {
	withClaudeHookTestConfig(t, true)
	withClaudeHookRuntimeDirectory(t)
	t.Setenv("PHASE_AI_ENABLED", "")
	for _, shellCommand := range []string{"aws s3 ls", "curl http://phase.invalid/v1/status", "git status && curl http://phase.invalid/v1/status"} {
		command := &cobra.Command{}
		setClaudeToolHookCommand(command, "Bash", shellCommand)
		var output bytes.Buffer
		command.SetOut(&output)
		if err := runAIClaudeEvent(command, []string{"guard"}); err != nil || output.Len() != 0 {
			t.Fatalf("guard interfered with %q: output=%q err=%v", shellCommand, output.String(), err)
		}
	}
}

func TestClaudeSessionLeasesAreBoundedAndExtendedByActivity(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(),
		StartedAt: time.Now().UTC(), ProxyURL: "http://phase:capability@127.0.0.1:1",
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	leaseID := harnessLeaseID(ai.HarnessClaudeCode, "session-one")
	soon := time.Now().UTC().Add(time.Minute)
	if err := registerHarnessLease(ai.HarnessClaudeCode, "session-one", soon); err != nil {
		t.Fatal(err)
	}
	if err := touchClaudeSessionLease(leaseID); err != nil {
		t.Fatal(err)
	}
	path, err := claudeSessionLeasePath(directory, leaseID)
	if err != nil {
		t.Fatal(err)
	}
	var lease claudeSessionLease
	if err := readOwnerOnlyJSON(path, &lease); err != nil {
		t.Fatal(err)
	}
	if lease.ExpiresAt.Before(time.Now().UTC().Add(harnessSessionLeaseTTL-time.Minute)) || lease.ExpiresAt.After(time.Now().UTC().Add(harnessSessionLeaseTTL+time.Minute)) {
		t.Fatalf("heartbeat did not extend the bounded lease: expires %v", lease.ExpiresAt)
	}
	expired := claudeSessionLease{Version: claudeRuntimeStateVersion, Generation: "generation-one", UpdatedAt: time.Now().UTC().Add(-5 * time.Hour), ExpiresAt: time.Now().UTC().Add(-time.Hour)}
	if err := writeOwnerOnlyJSON(path, expired); err != nil {
		t.Fatal(err)
	}
	if active, err := hasActiveClaudeSessionLease(directory, "generation-one", time.Now().UTC()); err != nil || active {
		t.Fatalf("expired lease still counts as active: active=%v err=%v", active, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expired lease was not pruned: %v", err)
	}
}

// disablingRecycleRuntime publishes one session, then runs phase ai disable
// (config saved disabled, environment files removed) before the session
// recycles, the window in which a daemon used to reopen and republish.
type disablingRecycleRuntime struct {
	directory string
	calls     int
}

func (runtime *disablingRecycleRuntime) ServeManaged(_ context.Context, engine airuntime.Engine) error {
	runtime.calls++
	proxyEngine := engine.(*aiproxy.Engine)
	proxyEngine.OnStarted(aiproxy.Endpoints{ProcessEnvironment: phaseproxy.ProcessEnvironmentPlan{
		Set: map[string]string{"PHASE_AI_ENABLED": "1", "HTTP_PROXY": "http://phase:cycle@127.0.0.1:9543", "AWS_ACCESS_KEY_ID": "AKIADECOY"},
	}, Connections: []aiproxy.EndpointConnection{{ConnectionID: "conn-1", Name: "aws-prod", ServiceType: "aws", Protocol: "http"}}})
	if runtime.calls > 1 {
		return errors.New("a disabled daemon opened another session")
	}
	cfg := config.LoadAIConfig()
	cfg.Enabled = false
	if err := config.SaveAIConfig(cfg); err != nil {
		return err
	}
	if err := removeClaudeEnvironmentFiles(); err != nil {
		return err
	}
	return fmt.Errorf("first cycle: %w", airuntime.ErrSessionReprovisionRequired)
}

func TestClaudeDaemonStopsInsteadOfRecyclingAfterDisable(t *testing.T) {
	withClaudeHookTestConfig(t, true)
	directory := withClaudeHookRuntimeDirectory(t)
	const generation = "generation-disable"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: generation, PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	managed := &disablingRecycleRuntime{directory: directory}
	originalRuntime, originalEngine := claudeHookNewRuntime, claudeHookNewProxyEngine
	originalFingerprint, originalScopeFingerprint := claudeHookFingerprint, claudeHookScopeFingerprint
	claudeHookNewRuntime = func() (claudeManagedRuntime, error) { return managed, nil }
	claudeHookNewProxyEngine = aiproxy.New
	claudeHookFingerprint = func() (string, error) { return "binding-one", nil }
	claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		claudeHookNewRuntime, claudeHookNewProxyEngine = originalRuntime, originalEngine
		claudeHookFingerprint, claudeHookScopeFingerprint = originalFingerprint, originalScopeFingerprint
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("generation", "", "")
	if err := command.Flags().Set("generation", generation); err != nil {
		t.Fatal(err)
	}
	if err := runAIClaudeDaemon(command, nil); err != nil {
		t.Fatalf("daemon result = %v", err)
	}
	if managed.calls != 1 {
		t.Fatalf("sessions opened = %d, want 1", managed.calls)
	}
	for _, path := range []string{claudeEnvironmentPath(directory), claudeEnvironmentJSONPath(directory), claudeEnvironmentStatusPath(directory)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("disabled daemon recreated %s (stat err %v)", path, err)
		}
	}
}

func TestClaudeDaemonPublishesNothingWhenAlreadyDisabled(t *testing.T) {
	withClaudeHookTestConfig(t, false)
	directory := withClaudeHookRuntimeDirectory(t)
	const generation = "generation-disabled-start"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: generation, PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	managed := &claudeRecycleTestRuntime{directory: directory, generation: generation}
	originalRuntime, originalEngine := claudeHookNewRuntime, claudeHookNewProxyEngine
	originalFingerprint, originalScopeFingerprint := claudeHookFingerprint, claudeHookScopeFingerprint
	claudeHookNewRuntime = func() (claudeManagedRuntime, error) { return managed, nil }
	claudeHookNewProxyEngine = aiproxy.New
	claudeHookFingerprint = func() (string, error) { return "binding-one", nil }
	claudeHookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		claudeHookNewRuntime, claudeHookNewProxyEngine = originalRuntime, originalEngine
		claudeHookFingerprint, claudeHookScopeFingerprint = originalFingerprint, originalScopeFingerprint
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("generation", "", "")
	if err := command.Flags().Set("generation", generation); err != nil {
		t.Fatal(err)
	}
	if err := runAIClaudeDaemon(command, nil); err != nil {
		t.Fatalf("daemon result = %v", err)
	}
	if _, err := os.Stat(claudeEnvironmentPath(directory)); !os.IsNotExist(err) {
		t.Fatalf("a disabled daemon published an environment (stat err %v)", err)
	}
}

func TestActiveClaudeLeasesKeepsLeaseRenewedAfterTheScanTime(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	path, err := claudeSessionLeasePath(directory, "codex:renewed-after-tick")
	if err != nil {
		t.Fatal(err)
	}
	scanTime := time.Now().UTC()
	renewed := claudeSessionLease{
		Version: claudeRuntimeStateVersion, Generation: "generation-one",
		UpdatedAt: scanTime.Add(50 * time.Millisecond), ExpiresAt: scanTime.Add(time.Minute), Purpose: harnessCommandLeasePurpose,
	}
	if err := writeOwnerOnlyJSON(path, renewed); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_, commands, err := activeClaudeLeases(directory, "generation-one", scanTime)
	if err != nil || !commands {
		t.Fatalf("a lease renewed after the scan time was dropped: commands=%v err=%v", commands, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("renewed lease was pruned: %v", err)
	}
}
