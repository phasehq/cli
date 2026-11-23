package cmd

import (
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

type failingLifecycleWriter struct{}

func (failingLifecycleWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

type failingManagedRuntime struct {
	err error
}

func (runtime failingManagedRuntime) ServeManaged(context.Context, airuntime.Engine) error {
	return runtime.err
}

var errRecycleTestComplete = errors.New("recycle test complete")

type recycleTestRuntime struct {
	directory    string
	generation   string
	engines      []*aiproxy.Engine
	states       []hookRuntimeState
	environments []string
}

func (runtime *recycleTestRuntime) ServeManaged(_ context.Context, engine airuntime.Engine) error {
	proxyEngine, ok := engine.(*aiproxy.Engine)
	if !ok {
		return fmt.Errorf("unexpected proxy engine %T", engine)
	}
	runtime.engines = append(runtime.engines, proxyEngine)
	cycle := len(runtime.engines)
	proxyURL := fmt.Sprintf("http://phase:cycle-%d@127.0.0.1:9543", cycle)
	proxyEngine.OnStarted(aiproxy.Endpoints{ProcessEnvironment: phaseproxy.ProcessEnvironmentPlan{
		Set: map[string]string{"PHASE_AI_ENABLED": "1", "PHASE_AI_RESERVED_ENV": "", "HTTP_PROXY": proxyURL, "AWS_ACCESS_KEY_ID": "AKIADECOY"},
	}, Connections: []aiproxy.EndpointConnection{{ConnectionID: "conn-1", Name: "aws-prod", ServiceType: "aws", Protocol: "http"}}})
	state, err := readHookRuntimeState(filepath.Join(runtime.directory, hookRuntimeStateFile))
	if err != nil {
		return err
	}
	runtime.states = append(runtime.states, state)
	environment, err := os.ReadFile(runtimeEnvironmentPath(runtime.directory))
	if err != nil {
		return err
	}
	runtime.environments = append(runtime.environments, string(environment))
	if cycle == 1 {
		return fmt.Errorf("first managed cycle: %w", airuntime.ErrSessionReprovisionRequired)
	}
	return errRecycleTestComplete
}

func withHookTestConfig(t *testing.T, enabled bool) {
	t.Helper()
	originalPath := config.AIConfigPath
	config.AIConfigPath = filepath.Join(t.TempDir(), "ai.json")
	t.Cleanup(func() { config.AIConfigPath = originalPath })
	if err := config.SaveAIConfig(&config.AIConfig{
		Enabled:    enabled,
		HarnessIDs: []string{ai.HarnessClaudeCode},
	}); err != nil {
		t.Fatal(err)
	}
}

func withHookRuntimeDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	// Hooks append a loader to this file; never touch a real harness session's.
	t.Setenv("CLAUDE_ENV_FILE", "")
	originalDirectory := hookRuntimeDir
	hookRuntimeDir = func() (string, error) { return directory, nil }
	t.Cleanup(func() { hookRuntimeDir = originalDirectory })
	return directory
}

func TestRequestHookRuntimeShutdownUsesAuthenticatedLocalControl(t *testing.T) {
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
		// The proxy refuses a revoke without it (a followed redirect would not carry it).
		if request.Header.Get(phaseproxy.ControlIntentHeader) != "1" {
			t.Errorf("shutdown request lacks %s", phaseproxy.ControlIntentHeader)
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
	if err := requestHookRuntimeShutdown(context.Background(), proxyURL.String()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("authenticated shutdown control was not called")
	}
}

func TestRequestHookRuntimeShutdownRejectsInvalidAcknowledgement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"session-one"}`))
	}))
	defer server.Close()

	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("phase", "runtime-shutdown-capability")
	if err := requestHookRuntimeShutdown(context.Background(), proxyURL.String()); err == nil ||
		!strings.Contains(err.Error(), "response is invalid") {
		t.Fatalf("invalid shutdown acknowledgement error = %v", err)
	}
}

func TestRuntimeDaemonRecyclesSameProcessAndGenerationOnOneEngine(t *testing.T) {
	withHookTestConfig(t, true)
	directory := withHookRuntimeDirectory(t)
	const generation = "generation-one"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: generation, PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	managed := &recycleTestRuntime{directory: directory, generation: generation}
	originalRuntime := hookNewRuntime
	originalEngine := hookNewProxyEngine
	originalFingerprint := hookFingerprint
	originalScopeFingerprint := hookScopeFingerprint
	runtimeCreations := 0
	hookNewRuntime = func() (hookManagedRuntime, error) {
		runtimeCreations++
		return managed, nil
	}
	hookNewProxyEngine = aiproxy.New
	hookFingerprint = func() (string, error) { return "binding-one", nil }
	hookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		hookNewRuntime = originalRuntime
		hookNewProxyEngine = originalEngine
		hookFingerprint = originalFingerprint
		hookScopeFingerprint = originalScopeFingerprint
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("generation", "", "")
	if err := command.Flags().Set("generation", generation); err != nil {
		t.Fatal(err)
	}
	if err := runAIRuntimeDaemon(command, nil); !errors.Is(err, errRecycleTestComplete) {
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
		guard, err := proxyLivenessGuard(os.Getpid(), phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{"HTTP_PROXY": managed.states[index].ProxyURL}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(environment, "if "+guard+"; then") ||
			!strings.Contains(environment, "export HTTP_PROXY='"+managed.states[index].ProxyURL+"'") ||
			!strings.Contains(environment, "export AWS_ACCESS_KEY_ID='AKIADECOY'") {
			t.Fatalf("cycle %d did not publish a live sourced environment:\n%s", index+1, environment)
		}
	}
	final, err := os.ReadFile(runtimeEnvironmentPath(directory))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(final), proxyBlockBegin) || strings.Contains(string(final), "HTTP_PROXY") ||
		!strings.Contains(string(final), "export AWS_ACCESS_KEY_ID='AKIADECOY'") {
		t.Fatalf("daemon exit left proxy routing in the sourced environment:\n%s", final)
	}
	var status runtimeEnvironmentStatus
	if err := readOwnerOnlyJSON(runtimeEnvironmentStatusPath(directory), &status); err != nil || status.ProxyLive || len(status.Connections) != 1 || status.Connections[0].Name != "aws-prod" {
		t.Fatalf("daemon exit status = %#v err=%v", status, err)
	}
}

type stopDuringRecycleRuntime struct {
	cycles  int
	stopErr error
}

func (runtime *stopDuringRecycleRuntime) ServeManaged(ctx context.Context, engine airuntime.Engine) error {
	runtime.cycles++
	if runtime.cycles == 2 {
		// The session is recycling: the daemon's state is withdrawn.
		runtime.stopErr = stopHookRuntime(ctx)
	}
	engine.(*aiproxy.Engine).OnStarted(aiproxy.Endpoints{ProcessEnvironment: phaseproxy.ProcessEnvironmentPlan{
		Set: map[string]string{"PHASE_AI_ENABLED": "1", "PHASE_AI_RESERVED_ENV": "", "HTTP_PROXY": "http://phase:capability@127.0.0.1:9543"},
	}})
	if runtime.cycles == 1 {
		return fmt.Errorf("first managed cycle: %w", airuntime.ErrSessionExpired)
	}
	return errRecycleTestComplete
}

func TestSetupCanStopAnEstablishedDaemonWhileItRecycles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX sleep process as the daemon PID")
	}
	withHookTestConfig(t, true)
	directory := withHookRuntimeDirectory(t)
	withHookFingerprints(t)
	daemon := exec.Command("sleep", "60")
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = daemon.Wait(); close(exited) }()
	t.Cleanup(func() { _ = daemon.Process.Kill() })
	const generation = "generation-established"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: generation, PID: daemon.Process.Pid,
		CreatedAt: time.Now().Add(-10 * time.Minute).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	managed := &stopDuringRecycleRuntime{}
	originalRuntime := hookNewRuntime
	hookNewRuntime = func() (hookManagedRuntime, error) { return managed, nil }
	t.Cleanup(func() { hookNewRuntime = originalRuntime })

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("generation", "", "")
	if err := command.Flags().Set("generation", generation); err != nil {
		t.Fatal(err)
	}
	if err := runAIRuntimeDaemon(command, nil); !errors.Is(err, errRecycleTestComplete) {
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

func TestRuntimeDaemonPublishesAuthenticationFailure(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	const generation = "generation-authentication-failure"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: generation, PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	originalRuntime := hookNewRuntime
	originalFingerprint := hookFingerprint
	originalScopeFingerprint := hookScopeFingerprint
	hookNewRuntime = func() (hookManagedRuntime, error) {
		return failingManagedRuntime{err: airuntime.ErrAuthenticationRequired}, nil
	}
	hookFingerprint = func() (string, error) { return "binding-one", nil }
	hookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		hookNewRuntime = originalRuntime
		hookFingerprint = originalFingerprint
		hookScopeFingerprint = originalScopeFingerprint
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("generation", "", "")
	if err := command.Flags().Set("generation", generation); err != nil {
		t.Fatal(err)
	}
	if err := runAIRuntimeDaemon(command, nil); !errors.Is(err, airuntime.ErrAuthenticationRequired) {
		t.Fatalf("daemon result = %v", err)
	}
	failure, err := readHookRuntimeFailure(hookRuntimeFailurePath(directory, generation))
	if err != nil {
		t.Fatal(err)
	}
	if failure.Generation != generation || failure.Reason != "authentication" {
		t.Fatalf("runtime failure = %#v", failure)
	}
	if !errors.Is(hookRuntimeFailureError(failure.Reason), errRuntimeAuthenticationRequired) {
		t.Fatalf("authentication failure was not preserved: %v", hookRuntimeFailureError(failure.Reason))
	}
}

func TestRuntimeDaemonPublishesAuthenticationFailureFromRuntimeConstruction(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	const generation = "generation-authentication-construction-failure"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: generation, PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	originalRuntime := hookNewRuntime
	originalFingerprint := hookFingerprint
	originalScopeFingerprint := hookScopeFingerprint
	hookNewRuntime = func() (hookManagedRuntime, error) {
		return nil, airuntime.ErrAuthenticationRequired
	}
	hookFingerprint = func() (string, error) { return "binding-one", nil }
	hookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		hookNewRuntime = originalRuntime
		hookFingerprint = originalFingerprint
		hookScopeFingerprint = originalScopeFingerprint
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("generation", "", "")
	if err := command.Flags().Set("generation", generation); err != nil {
		t.Fatal(err)
	}
	if err := runAIRuntimeDaemon(command, nil); !errors.Is(err, airuntime.ErrAuthenticationRequired) {
		t.Fatalf("daemon result = %v", err)
	}
	failure, err := readHookRuntimeFailure(hookRuntimeFailurePath(directory, generation))
	if err != nil {
		t.Fatal(err)
	}
	if failure.Generation != generation || failure.Reason != "authentication" {
		t.Fatalf("runtime failure = %#v", failure)
	}
}

func TestHookRuntimeFingerprintMismatchIsRejected(t *testing.T) {
	state := hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "old-binding",
		PID: os.Getpid(), ProxyURL: "http://phase:capability@127.0.0.1:9543",
	}
	err := probeHookRuntimeState(context.Background(), state, "new-binding")
	if err == nil || !strings.Contains(err.Error(), "binding changed") {
		t.Fatalf("fingerprint mismatch error = %v", err)
	}
}

func TestHookRuntimeStateRejectsLegacyV1(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	statePath := filepath.Join(directory, hookRuntimeStateFile)
	if err := writeOwnerOnlyJSON(statePath, map[string]any{
		"version": 1, "generation": "legacy-generation", "pid": os.Getpid(),
		"processEnvironment": map[string]any{
			"set": map[string]string{"HTTP_PROXY": "http://phase:legacy-capability@127.0.0.1:9543"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := readHookRuntimeState(statePath); err == nil || !strings.Contains(err.Error(), "version is unsupported") {
		t.Fatalf("legacy v1 runtime state error = %v", err)
	}
}

func TestLeaseFileLockIsReleasedWhenOwnerExits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.lock")
	owner, acquired, err := tryLockLeaseFile(path)
	if err != nil || !acquired {
		t.Fatalf("initial lease lock acquired=%v err=%v", acquired, err)
	}
	contender, acquired, err := tryLockLeaseFile(path)
	if err != nil || acquired || contender != nil {
		t.Fatalf("contended lease lock acquired=%v file=%v err=%v", acquired, contender, err)
	}
	// Closing without the explicit unlock models process teardown: the OS lock
	// must be released without stale-owner pathname deletion.
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, acquired, err := tryLockLeaseFile(path)
	if err != nil || !acquired {
		t.Fatalf("replacement lease lock acquired=%v err=%v", acquired, err)
	}
	if err := unlockLeaseFile(replacement); err != nil {
		t.Fatal(err)
	}
}

func TestHookRuntimeLockStaleRecoveryGrantsOneOwner(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	lockPath := filepath.Join(directory, hookRuntimeLockFile)
	if err := writeOwnerOnlyJSON(lockPath, hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: "generation-stale", CreatedAt: time.Now().Add(-time.Hour).UTC(),
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
			claimed, err := claimHookRuntimeLock(lockPath, generation)
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
	lock, err := readHookRuntimeLock(lockPath)
	if err != nil || len(owners) != 1 || lock.Generation != owners[0] {
		t.Fatalf("stale lock recovery granted owners %v; recorded %q err=%v", owners, lock.Generation, err)
	}
}

func TestHookDaemonStartWaitsForSetupToFinish(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	lockPath := filepath.Join(directory, hookRuntimeLockFile)
	release, err := lockHookSetup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := claimHookRuntimeLock(lockPath, "generation-during-setup")
	if claimed || !errors.Is(err, errHookSetupInProgress) {
		t.Fatalf("a daemon start during setup: claimed=%v err=%v", claimed, err)
	}
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a daemon start during setup left a lock: %v", err)
	}
	release()
	if claimed, err := claimHookRuntimeLock(lockPath, "generation-after-setup"); !claimed || err != nil {
		t.Fatalf("a daemon start after setup: claimed=%v err=%v", claimed, err)
	}
}

func TestHookRuntimeLockRecoversAnInterruptedWrite(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	lockPath := filepath.Join(directory, hookRuntimeLockFile)
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
	if claimed, err := claimHookRuntimeLock(lockPath, "generation-new"); claimed || err == nil {
		t.Fatalf("a lock still being written was replaced: claimed=%v err=%v", claimed, err)
	}
	writeEmptyLock(time.Hour)
	if claimed, err := claimHookRuntimeLock(lockPath, "generation-new"); !claimed || err != nil {
		t.Fatalf("an abandoned lock blocked recovery: claimed=%v err=%v", claimed, err)
	}
	writeEmptyLock(time.Hour)
	if err := stopHookRuntime(context.Background()); err != nil {
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

func TestEnsureHookRuntimeReusesAuthenticatedManagedProxy(t *testing.T) {
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
					"set":   map[string]string{"PHASE_AI_ENABLED": "1", "PHASE_AI_RESERVED_ENV": "", "HTTP_PROXY": proxyURL},
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

	directory := withHookRuntimeDirectory(t)
	originalFingerprint := hookFingerprint
	originalScopeFingerprint := hookScopeFingerprint
	hookFingerprint = func() (string, error) { return "binding-one", nil }
	hookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		hookFingerprint = originalFingerprint
		hookScopeFingerprint = originalScopeFingerprint
	})
	state := hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(),
		RuntimeFingerprint: "binding-one", RuntimeScopeFingerprint: "scope-one", ProxyURL: proxyURL,
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	plan, err := ensureHookRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Set["HTTP_PROXY"] != proxyURL {
		t.Fatalf("reused proxy = %q", plan.Set["HTTP_PROXY"])
	}
}

func TestEnsureHookRuntimeReplacesCurrentSchemaStateWithoutScope(t *testing.T) {
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

	directory := withHookRuntimeDirectory(t)
	now := time.Now().UTC()
	state := hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: "generation-without-scope",
		RuntimeFingerprint: "binding-one", PID: oldProcess.Process.Pid,
		StartedAt: now, ProxyURL: parsed.String(),
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: state.Generation,
		PID: state.PID, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	originalFingerprint := hookFingerprint
	originalScopeFingerprint := hookScopeFingerprint
	originalExecutable := hookRuntimeExecutable
	replacementErr := errors.New("replacement daemon requested")
	replacementCalls := 0
	hookFingerprint = func() (string, error) { return "binding-one", nil }
	hookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	hookRuntimeExecutable = func() (string, error) {
		replacementCalls++
		return "", replacementErr
	}
	t.Cleanup(func() {
		hookFingerprint = originalFingerprint
		hookScopeFingerprint = originalScopeFingerprint
		hookRuntimeExecutable = originalExecutable
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ensureHookRuntime(ctx); !errors.Is(err, replacementErr) {
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
		filepath.Join(directory, hookRuntimeStateFile),
		filepath.Join(directory, hookRuntimeLockFile),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("outdated runtime artifact remains at %s: %v", path, err)
		}
	}
}

func TestEnsureHookRuntimeClassifiesLiveLockWaitTimeoutAsRefresh(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	lock := hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: "generation-recycling",
		PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), lock); err != nil {
		t.Fatal(err)
	}
	originalFingerprint := hookFingerprint
	originalScopeFingerprint := hookScopeFingerprint
	originalStartTimeout := hookStartTimeout
	originalPollInterval := hookPollInterval
	hookFingerprint = func() (string, error) { return "binding-one", nil }
	hookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	hookStartTimeout = 25 * time.Millisecond
	hookPollInterval = time.Millisecond
	t.Cleanup(func() {
		hookFingerprint = originalFingerprint
		hookScopeFingerprint = originalScopeFingerprint
		hookStartTimeout = originalStartTimeout
		hookPollInterval = originalPollInterval
	})

	_, err := ensureHookRuntime(context.Background())
	if !errors.Is(err, errHookRuntimeRefreshing) {
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

func withHookFingerprints(t *testing.T) {
	t.Helper()
	originalFingerprint := hookFingerprint
	originalScopeFingerprint := hookScopeFingerprint
	hookFingerprint = func() (string, error) { return "binding-one", nil }
	hookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		hookFingerprint = originalFingerprint
		hookScopeFingerprint = originalScopeFingerprint
	})
}

func TestKickLeasesASessionToADaemonStillStarting(t *testing.T) {
	withHookTestConfig(t, true)
	directory := withHookRuntimeDirectory(t)
	originalEnsure := hookEnsureRuntime
	t.Cleanup(func() { hookEnsureRuntime = originalEnsure })
	hookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase AI automatic proxy did not become ready")
	}
	const generation = "generation-starting"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: generation, PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if health := kickClaudeRuntime(context.Background(), directory, "session-one", time.Millisecond); !health.starting {
		t.Fatalf("kick health = %+v, want starting", health)
	}
	// The daemon publishes after the hook's wait ended; the session must still
	// keep it from idling out.
	active, err := hasActiveSessionLease(directory, generation, time.Now())
	if err != nil || !active {
		t.Fatalf("a session waiting on a slow startup has no lease: active=%v err=%v", active, err)
	}
}

func TestKickLeasesASessionToAnEstablishedDaemonWhileItRecycles(t *testing.T) {
	withHookTestConfig(t, true)
	directory := withHookRuntimeDirectory(t)
	originalEnsure := hookEnsureRuntime
	t.Cleanup(func() { hookEnsureRuntime = originalEnsure })
	hookEnsureRuntime = func(context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
		return phaseproxy.ProcessEnvironmentPlan{}, errHookRuntimeRefreshing
	}
	const generation = "generation-recycling"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: generation, PID: os.Getpid(),
		CreatedAt: time.Now().Add(-10 * time.Minute).UTC(), RecyclingAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if health := kickClaudeRuntime(context.Background(), directory, "session-one", time.Millisecond); !health.starting {
		t.Fatalf("kick health = %+v, want starting", health)
	}
	active, err := hasActiveSessionLease(directory, generation, time.Now())
	if err != nil || !active {
		t.Fatalf("a session started during a recycle has no lease: active=%v err=%v", active, err)
	}
}

func TestSessionLeasesAreBoundedAndExtendedByActivity(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	state := hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: "generation-one", PID: os.Getpid(),
		StartedAt: time.Now().UTC(), ProxyURL: "http://phase:capability@127.0.0.1:1",
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	leaseID := harnessLeaseID(ai.HarnessClaudeCode, "session-one")
	soon := time.Now().UTC().Add(time.Minute)
	if err := registerHarnessLease(ai.HarnessClaudeCode, "session-one", soon); err != nil {
		t.Fatal(err)
	}
	if err := touchSessionLease(leaseID); err != nil {
		t.Fatal(err)
	}
	path, err := sessionLeasePath(directory, leaseID)
	if err != nil {
		t.Fatal(err)
	}
	var lease sessionLease
	if err := readOwnerOnlyJSON(path, &lease); err != nil {
		t.Fatal(err)
	}
	if lease.ExpiresAt.Before(time.Now().UTC().Add(harnessSessionLeaseTTL-time.Minute)) || lease.ExpiresAt.After(time.Now().UTC().Add(harnessSessionLeaseTTL+time.Minute)) {
		t.Fatalf("heartbeat did not extend the bounded lease: expires %v", lease.ExpiresAt)
	}
	expired := sessionLease{Version: hookRuntimeStateVersion, Generation: "generation-one", UpdatedAt: time.Now().UTC().Add(-5 * time.Hour), ExpiresAt: time.Now().UTC().Add(-time.Hour)}
	if err := writeOwnerOnlyJSON(path, expired); err != nil {
		t.Fatal(err)
	}
	if active, err := hasActiveSessionLease(directory, "generation-one", time.Now().UTC()); err != nil || active {
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
		Set: map[string]string{"PHASE_AI_ENABLED": "1", "PHASE_AI_RESERVED_ENV": "", "HTTP_PROXY": "http://phase:cycle@127.0.0.1:9543", "AWS_ACCESS_KEY_ID": "AKIADECOY"},
	}, Connections: []aiproxy.EndpointConnection{{ConnectionID: "conn-1", Name: "aws-prod", ServiceType: "aws", Protocol: "http"}}})
	if runtime.calls > 1 {
		return errors.New("a disabled daemon opened another session")
	}
	cfg := config.LoadAIConfig()
	cfg.Enabled = false
	if err := config.SaveAIConfig(cfg); err != nil {
		return err
	}
	if err := removeRuntimeEnvironmentFiles(); err != nil {
		return err
	}
	return fmt.Errorf("first cycle: %w", airuntime.ErrSessionReprovisionRequired)
}

func TestRuntimeDaemonStopsInsteadOfRecyclingAfterDisable(t *testing.T) {
	withHookTestConfig(t, true)
	directory := withHookRuntimeDirectory(t)
	const generation = "generation-disable"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: generation, PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	managed := &disablingRecycleRuntime{directory: directory}
	originalRuntime, originalEngine := hookNewRuntime, hookNewProxyEngine
	originalFingerprint, originalScopeFingerprint := hookFingerprint, hookScopeFingerprint
	hookNewRuntime = func() (hookManagedRuntime, error) { return managed, nil }
	hookNewProxyEngine = aiproxy.New
	hookFingerprint = func() (string, error) { return "binding-one", nil }
	hookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		hookNewRuntime, hookNewProxyEngine = originalRuntime, originalEngine
		hookFingerprint, hookScopeFingerprint = originalFingerprint, originalScopeFingerprint
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("generation", "", "")
	if err := command.Flags().Set("generation", generation); err != nil {
		t.Fatal(err)
	}
	if err := runAIRuntimeDaemon(command, nil); err != nil {
		t.Fatalf("daemon result = %v", err)
	}
	if managed.calls != 1 {
		t.Fatalf("sessions opened = %d, want 1", managed.calls)
	}
	for _, path := range []string{runtimeEnvironmentPath(directory), runtimeEnvironmentJSONPath(directory), runtimeEnvironmentStatusPath(directory)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("disabled daemon recreated %s (stat err %v)", path, err)
		}
	}
}

func TestRuntimeDaemonPublishesNothingWhenAlreadyDisabled(t *testing.T) {
	withHookTestConfig(t, false)
	directory := withHookRuntimeDirectory(t)
	const generation = "generation-disabled-start"
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: generation, PID: os.Getpid(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	managed := &recycleTestRuntime{directory: directory, generation: generation}
	originalRuntime, originalEngine := hookNewRuntime, hookNewProxyEngine
	originalFingerprint, originalScopeFingerprint := hookFingerprint, hookScopeFingerprint
	hookNewRuntime = func() (hookManagedRuntime, error) { return managed, nil }
	hookNewProxyEngine = aiproxy.New
	hookFingerprint = func() (string, error) { return "binding-one", nil }
	hookScopeFingerprint = func() (string, error) { return "scope-one", nil }
	t.Cleanup(func() {
		hookNewRuntime, hookNewProxyEngine = originalRuntime, originalEngine
		hookFingerprint, hookScopeFingerprint = originalFingerprint, originalScopeFingerprint
	})

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.Flags().String("generation", "", "")
	if err := command.Flags().Set("generation", generation); err != nil {
		t.Fatal(err)
	}
	if err := runAIRuntimeDaemon(command, nil); err != nil {
		t.Fatalf("daemon result = %v", err)
	}
	if _, err := os.Stat(runtimeEnvironmentPath(directory)); !os.IsNotExist(err) {
		t.Fatalf("a disabled daemon published an environment (stat err %v)", err)
	}
}

func TestActiveSessionLeasesKeepsLeaseRenewedAfterTheScanTime(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	path, err := sessionLeasePath(directory, "codex:renewed-after-tick")
	if err != nil {
		t.Fatal(err)
	}
	scanTime := time.Now().UTC()
	renewed := sessionLease{
		Version: hookRuntimeStateVersion, Generation: "generation-one",
		UpdatedAt: scanTime.Add(50 * time.Millisecond), ExpiresAt: scanTime.Add(time.Minute), Purpose: harnessCommandLeasePurpose,
	}
	if err := writeOwnerOnlyJSON(path, renewed); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_, commands, err := activeSessionLeases(directory, "generation-one", scanTime)
	if err != nil || !commands {
		t.Fatalf("a lease renewed after the scan time was dropped: commands=%v err=%v", commands, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("renewed lease was pruned: %v", err)
	}
}

func TestLeaseSweepsKeepFilesPhaseDidNotName(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	foreign := filepath.Join(directory, "session-backup.lease.json")
	if err := os.WriteFile(foreign, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid, err := sessionLeasePath(directory, "claude:broken")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalid, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := activeSessionLeases(directory, "generation-one", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := removeLeasesForGeneration(directory, "generation-one"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("a file Phase did not write was removed: %v", err)
	}
	if _, err := os.Stat(invalid); !os.IsNotExist(err) {
		t.Fatalf("an unreadable Phase lease was kept: %v", err)
	}
}
