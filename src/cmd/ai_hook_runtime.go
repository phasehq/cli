package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/phasehq/cli/pkg/version"
	"github.com/spf13/cobra"
)

// The shared Phase AI runtime: one daemon per machine that every harness
// integration starts and keeps alive through session leases, with its state,
// lock, failure and lease files in ~/.phase/ai.

var (
	errPhaseProxyNotReachable         = errors.New("Phase proxy is not reachable")
	errPhaseAgentManifestNotReachable = errors.New("Phase Agent manifest is not reachable")
	errHookRuntimeRefreshing          = errors.New("Phase AI runtime is refreshing")
)

type phaseAgentManifestFailure struct {
	StatusCode int
	Code       string
	Structured bool
	Canonical  bool
	Retryable  bool
}

func (failure *phaseAgentManifestFailure) Error() string {
	if failure == nil {
		return "Phase Agent manifest request failed"
	}
	if failure.StatusCode == http.StatusProxyAuthRequired || failure.StatusCode == http.StatusUnauthorized {
		return "Phase Agent manifest authentication failed"
	}
	if failure.StatusCode == http.StatusServiceUnavailable && failure.Structured && failure.Canonical &&
		failure.Retryable && failure.Code == aiproxy.ManifestRefreshRequiredCode {
		return "Phase Agent manifest requires a refreshed runtime"
	}
	if !failure.Structured {
		return fmt.Sprintf("Phase Agent manifest failure response is invalid (HTTP %d)", failure.StatusCode)
	}
	return fmt.Sprintf("Phase Agent manifest request failed (HTTP %d)", failure.StatusCode)
}

const (
	hookRuntimeStateVersion = 2
	hookRuntimeStateFile    = "runtime.json"
	hookRuntimeLockFile     = "runtime.lock"
	hookSetupLockFile       = "runtime.setup.lock"
	sessionLeasePrefix      = "session-"
	sessionLeaseSuffix      = ".lease.json"
	leaseLockSuffix         = ".mutation.lock"
	leaseRegistryName       = "session-leases.registry"
	lifecycleLogFile        = "runtime.log"
	lifecycleLogMaxBytes    = 1 << 20
)

var (
	hookEnsureRuntime     = ensureHookRuntime
	hookFingerprint       = currentHookRuntimeFingerprint
	hookScopeFingerprint  = currentHookRuntimeScopeFingerprint
	hookRuntimeExecutable = os.Executable
	hookRuntimeDir        = phaseproxy.DefaultCADirectory
	hookStartTimeout      = 35 * time.Second
	hookPollInterval      = 100 * time.Millisecond
	hookIdleGrace         = 2 * time.Minute
	hookLeaseMaxAge       = 7 * 24 * time.Hour
	hookLeasePoll         = 15 * time.Second
	hookRecycleTimeout    = 35 * time.Second
	leaseLockWait         = 750 * time.Millisecond
	leaseLockPoll         = 10 * time.Millisecond
	hookNewRuntime        = func() (hookManagedRuntime, error) { return airuntime.New("") }
	hookNewProxyEngine    = aiproxy.New
)

type hookManagedRuntime interface {
	ServeManaged(context.Context, airuntime.Engine) error
}

type hookRuntimeState struct {
	Version                 int       `json:"version"`
	Generation              string    `json:"generation"`
	RuntimeFingerprint      string    `json:"runtimeFingerprint"`
	RuntimeScopeFingerprint string    `json:"runtimeScopeFingerprint,omitempty"`
	PID                     int       `json:"pid"`
	StartedAt               time.Time `json:"startedAt"`
	ProxyURL                string    `json:"proxyUrl"`
}

type hookRuntimeLock struct {
	Version    int       `json:"version"`
	Generation string    `json:"generation"`
	PID        int       `json:"pid,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	// RecyclingAt is when the daemon last withdrew its state to reopen its
	// session; setup may stop it then as during a startup.
	RecyclingAt time.Time `json:"recyclingAt,omitempty"`
}

type hookRuntimeFailure struct {
	Generation string `json:"generation"`
	Reason     string `json:"reason"`
}

type sessionLease struct {
	Version    int       `json:"version"`
	Generation string    `json:"generation"`
	UpdatedAt  time.Time `json:"updatedAt"`
	ExpiresAt  time.Time `json:"expiresAt,omitempty"`
	Purpose    string    `json:"purpose,omitempty"`
}

var aiRuntimeDaemonCmd = &cobra.Command{
	Use:          "__runtime-daemon",
	Hidden:       true,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runAIRuntimeDaemon,
}

func mustSessionLeasePath(directory, leaseID string) string {
	path, err := sessionLeasePath(directory, leaseID)
	if err != nil {
		return filepath.Join(directory, "missing")
	}
	return path
}

func ensureHookRuntime(ctx context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
	directory, err := hookRuntimeDir()
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	statePath := filepath.Join(directory, hookRuntimeStateFile)
	lockPath := filepath.Join(directory, hookRuntimeLockFile)
	fingerprint, err := hookFingerprint()
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	scopeFingerprint, err := hookScopeFingerprint()
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}

	if state, stateErr := readHookRuntimeState(statePath); stateErr == nil {
		if state.RuntimeFingerprint == fingerprint && state.RuntimeScopeFingerprint == scopeFingerprint {
			if plan, probeErr := loadHookRuntimePlan(ctx, state, fingerprint); probeErr == nil {
				return plan, nil
			}
		} else if probeErr := probeHookRuntimeState(ctx, state, ""); probeErr == nil {
			if stopErr := stopHookRuntimeState(ctx, directory, state); stopErr != nil {
				return phaseproxy.ProcessEnvironmentPlan{}, fmt.Errorf("replace outdated Phase AI runtime: %w", stopErr)
			}
		}
		if !processIsAlive(state.PID) {
			_ = removeStateIfGeneration(statePath, state.Generation)
			_ = releaseHookRuntimeLock(lockPath, state.Generation)
		} else if state.RuntimeFingerprint != fingerprint || state.RuntimeScopeFingerprint != scopeFingerprint {
			return phaseproxy.ProcessEnvironmentPlan{}, errors.New("an outdated Phase AI runtime could not be safely replaced")
		}
	} else if !errors.Is(stateErr, os.ErrNotExist) {
		return phaseproxy.ProcessEnvironmentPlan{}, stateErr
	}

	generation, err := randomRuntimeGeneration()
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	claimed, err := claimHookRuntimeLock(lockPath, generation)
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	var waitedLock hookRuntimeLock
	if !claimed {
		waitedLock, _ = readHookRuntimeLock(lockPath)
	}
	if claimed {
		executable, executableErr := hookRuntimeExecutable()
		if executableErr != nil {
			_ = releaseHookRuntimeLock(lockPath, generation)
			return phaseproxy.ProcessEnvironmentPlan{}, executableErr
		}
		pid, startErr := startHookDaemon(executable, generation)
		if startErr != nil {
			_ = releaseHookRuntimeLock(lockPath, generation)
			return phaseproxy.ProcessEnvironmentPlan{}, startErr
		}
		if err := updateHookRuntimeLock(lockPath, generation, func(lock *hookRuntimeLock) { lock.PID = pid }); err != nil {
			if process, findErr := os.FindProcess(pid); findErr == nil {
				_ = process.Kill()
			}
			_ = releaseHookRuntimeLock(lockPath, generation)
			return phaseproxy.ProcessEnvironmentPlan{}, err
		}
	}

	waitContext, cancel := context.WithTimeout(ctx, hookStartTimeout)
	defer cancel()
	ticker := time.NewTicker(hookPollInterval)
	defer ticker.Stop()
	for {
		if state, stateErr := readHookRuntimeState(statePath); stateErr == nil {
			if plan, probeErr := loadHookRuntimePlan(waitContext, state, fingerprint); probeErr == nil {
				return plan, nil
			}
		}
		if claimed {
			failurePath := hookRuntimeFailurePath(directory, generation)
			if failure, failureErr := readHookRuntimeFailure(failurePath); failureErr == nil && failure.Generation == generation {
				_ = os.Remove(failurePath)
				_ = releaseHookRuntimeLock(lockPath, generation)
				return phaseproxy.ProcessEnvironmentPlan{}, hookRuntimeFailureError(failure.Reason)
			}
		}
		select {
		case <-waitContext.Done():
			if claimed {
				if lock, lockErr := readHookRuntimeLock(lockPath); lockErr == nil && (lock.PID <= 0 || !processIsAlive(lock.PID)) {
					_ = releaseHookRuntimeLock(lockPath, generation)
				}
			} else if errors.Is(waitContext.Err(), context.DeadlineExceeded) &&
				waitedLock.Version == hookRuntimeStateVersion && waitedLock.Generation != "" && !waitedLock.CreatedAt.IsZero() {
				currentLock, lockErr := readHookRuntimeLock(lockPath)
				if lockErr == nil && currentLock.Version == waitedLock.Version &&
					currentLock.Generation == waitedLock.Generation && currentLock.CreatedAt.Equal(waitedLock.CreatedAt) &&
					currentLock.PID > 0 && processIsAlive(currentLock.PID) {
					return phaseproxy.ProcessEnvironmentPlan{}, fmt.Errorf("%w: managed session recycle did not complete", errHookRuntimeRefreshing)
				}
			}
			return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase AI automatic proxy did not become ready")
		case <-ticker.C:
		}
	}
}

func startHookDaemon(executable, generation string) (int, error) {
	name := strings.ToLower(filepath.Base(executable))
	if strings.HasSuffix(name, ".test") || strings.HasSuffix(name, ".test.exe") {
		return 0, errors.New("refusing to launch a Go test binary as the Phase hook daemon")
	}
	child := exec.Command(executable, "ai", "__runtime-daemon", "--generation", generation)
	child.Stdin = nil
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer null.Close()
	child.Stdout = null
	child.Stderr = null
	configureDetachedProcess(child)
	if err := child.Start(); err != nil {
		return 0, err
	}
	pid := child.Process.Pid
	// Reap the daemon if it exits while this process still runs.
	go func() { _ = child.Wait() }()
	return pid, nil
}

func runAIRuntimeDaemon(cmd *cobra.Command, args []string) error {
	generation, _ := cmd.Flags().GetString("generation")
	if generation == "" {
		return errors.New("Phase AI runtime generation is required")
	}
	directory, err := hookRuntimeDir()
	if err != nil {
		return err
	}
	statePath := filepath.Join(directory, hookRuntimeStateFile)
	lockPath := filepath.Join(directory, hookRuntimeLockFile)
	failurePath := hookRuntimeFailurePath(directory, generation)
	lock, err := readHookRuntimeLock(lockPath)
	if err != nil || lock.Generation != generation {
		appendLifecycleEvent(directory, "daemon_rejected", "ownership")
		return errors.New("Phase AI runtime ownership is unavailable")
	}
	appendLifecycleEvent(directory, "daemon_started", "")
	_ = sweepAIDirectory(directory, false)
	fingerprint, err := hookFingerprint()
	if err != nil {
		writeHookRuntimeFailure(failurePath, generation, "fingerprint")
		appendLifecycleEvent(directory, "startup_failed", "fingerprint")
		return err
	}
	scopeFingerprint, err := hookScopeFingerprint()
	if err != nil {
		writeHookRuntimeFailure(failurePath, generation, "fingerprint")
		appendLifecycleEvent(directory, "startup_failed", "fingerprint")
		return err
	}
	started := false
	stopReason := "fatal"
	defer func() {
		if started {
			_ = removeStateIfGeneration(statePath, generation)
		}
		_ = removeLeasesForGeneration(directory, generation)
		_ = releaseHookRuntimeLock(lockPath, generation)
		appendLifecycleEvent(directory, "daemon_stopped", stopReason)
	}()

	runtimeInstance, err := hookNewRuntime()
	if err != nil {
		reason := "runtime"
		if errors.Is(err, airuntime.ErrAuthenticationRequired) {
			reason = "authentication"
		}
		writeHookRuntimeFailure(failurePath, generation, reason)
		appendLifecycleEvent(directory, "startup_failed", reason)
		return err
	}
	serveContext, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	monitorStarted := false
	readyCycles := 0
	refreshDeadline := time.Time{}
	retryAttempt := 0
	var lastPlan phaseproxy.ProcessEnvironmentPlan
	var lastConnections []aiproxy.EndpointConnection

	// One Engine serves every session cycle of this daemon. It keeps the proxy
	// capability and the memory of earlier decoy generations, so a shell or a
	// long-running process provisioned before a recycle (a Connection or
	// credential edit in the Console) keeps working through the new session.
	engine := hookNewProxyEngine()
	engine.Stdout = io.Discard
	engine.Stderr = io.Discard
	for {
		if serveContext.Err() != nil {
			stopReason = "shutdown"
			return nil
		}
		cycleContext, cycleCancel := context.WithCancel(serveContext)
		cycleStarted := false
		var publishErr error
		engine.OnStarted = func(endpoints aiproxy.Endpoints) {
			if hookPhaseAIDisabled() {
				publishErr = errHookPhaseAIDisabled
				cycleCancel()
				return
			}
			proxyURL := firstMapValue(endpoints.ProcessEnvironment.Set, "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")
			if proxyURL == "" {
				publishErr = errors.New("Phase AI runtime proxy is unavailable")
				cycleCancel()
				return
			}
			state := hookRuntimeState{
				Version: hookRuntimeStateVersion, Generation: generation,
				RuntimeFingerprint: fingerprint, RuntimeScopeFingerprint: scopeFingerprint,
				PID: os.Getpid(), StartedAt: time.Now().UTC(), ProxyURL: proxyURL,
			}
			lastPlan, lastConnections = endpoints.ProcessEnvironment, endpoints.Connections
			if publishErr = publishHookRuntime(directory, state, lastPlan, lastConnections); publishErr != nil {
				cycleCancel()
				return
			}
			cycleStarted = true
			started = true
			readyCycles++
			refreshDeadline = time.Time{}
			retryAttempt = 0
			_ = os.Remove(failurePath)
			if !monitorStarted {
				monitorStarted = true
				go monitorSessionLeases(serveContext, cancel, directory, generation)
			}
			if readyCycles == 1 {
				appendLifecycleEvent(directory, "session_ready", "initial")
			} else {
				appendLifecycleEvent(directory, "session_ready", "recycled")
			}
		}

		err = runtimeInstance.ServeManaged(cycleContext, engine)
		cycleCancel()
		recycling := cycleStarted && (errors.Is(err, airuntime.ErrSessionReprovisionRequired) || errors.Is(err, airuntime.ErrSessionExpired))
		if recycling {
			_ = updateHookRuntimeLock(lockPath, generation, func(lock *hookRuntimeLock) { lock.RecyclingAt = time.Now().UTC() })
		}
		_ = removeStateIfGeneration(statePath, generation)
		disabled := hookPhaseAIDisabled()
		if cycleStarted {
			if disabled {
				// phase ai disable may already have removed these files; never
				// recreate them, or shells keep sourcing decoys.
				_ = removeRuntimeEnvironmentFiles()
			} else {
				// The listener is gone while this cycle recycles or the daemon exits.
				// Retire proxy routing immediately; decoys stay (see renderRuntimeEnvironment).
				_ = writeRuntimeEnvironment(directory, os.Getpid(), generation, time.Time{}, lastPlan, lastConnections, false)
				if hookPhaseAIDisabled() {
					disabled = true
					_ = removeRuntimeEnvironmentFiles()
				}
			}
		}
		if publishErr != nil {
			err = publishErr
		}
		if serveContext.Err() != nil || errors.Is(publishErr, errHookPhaseAIDisabled) {
			stopReason = "shutdown"
			return nil
		}
		if disabled && (cycleStarted || !refreshDeadline.IsZero()) {
			// Disabled while serving or recycling: do not open another session.
			stopReason = "shutdown"
			return nil
		}

		if recycling {
			reason := "environment_changed"
			if errors.Is(err, airuntime.ErrSessionExpired) {
				reason = "hard_expiry"
			}
			appendLifecycleEvent(directory, "session_recycle", reason)
			refreshDeadline = time.Now().Add(hookRecycleTimeout)
			retryAttempt = 0
			continue
		}

		if !cycleStarted && !refreshDeadline.IsZero() && time.Now().Before(refreshDeadline) && recycleRetryable(err) {
			delay := recycleRetryDelay(err, retryAttempt, time.Until(refreshDeadline))
			retryAttempt++
			appendLifecycleEvent(directory, "session_retry", "backend_unavailable")
			timer := time.NewTimer(delay)
			select {
			case <-serveContext.Done():
				if !timer.Stop() {
					<-timer.C
				}
				stopReason = "shutdown"
				return nil
			case <-timer.C:
				continue
			}
		}

		if !started && err != nil {
			reason := "runtime"
			if errors.Is(err, airuntime.ErrAuthenticationRequired) {
				reason = "authentication"
			} else if publishErr != nil {
				reason = "state_publish"
			}
			writeHookRuntimeFailure(failurePath, generation, reason)
			appendLifecycleEvent(directory, "startup_failed", reason)
		}
		return err
	}
}

// publishHookRuntime writes the runtime state and the live environment under
// the runtime lock, so a hook retiring a dead daemon's routing cannot
// interleave with it.
func publishHookRuntime(directory string, state hookRuntimeState, plan phaseproxy.ProcessEnvironmentPlan, connections []aiproxy.EndpointConnection) error {
	return withHookRuntimeLock(directory, func() error {
		if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), state); err != nil {
			return err
		}
		if err := writeRuntimeEnvironment(directory, state.PID, state.Generation, state.StartedAt, plan, connections, true); err != nil {
			return err
		}
		// disable may have run while the file was written; it removes
		// the files after saving the config, so a second look is enough.
		if hookPhaseAIDisabled() {
			_ = removeRuntimeEnvironmentFiles()
			return errHookPhaseAIDisabled
		}
		return nil
	})
}

func withHookRuntimeLock(directory string, mutate func() error) error {
	return withLeaseMutationLock(context.Background(), filepath.Join(directory, hookRuntimeLockFile), mutate)
}

func recycleRetryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var apiErr *agentapi.Error
	if errors.As(err, &apiErr) {
		if apiErr.Retryable || apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500 {
			return true
		}
		return false
	}
	return true
}

func recycleRetryDelay(err error, attempt int, remaining time.Duration) time.Duration {
	delay := 250 * time.Millisecond
	if attempt > 0 {
		shift := attempt
		if shift > 4 {
			shift = 4
		}
		delay *= time.Duration(1 << shift)
	}
	if delay > 3*time.Second {
		delay = 3 * time.Second
	}
	var apiErr *agentapi.Error
	if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
		delay = apiErr.RetryAfter
	}
	if remaining > 0 && delay > remaining {
		delay = remaining
	}
	if delay <= 0 {
		return time.Millisecond
	}
	return delay
}

func currentHookRuntimeFingerprint() (string, error) {
	values, _, err := currentHookRuntimeFingerprintValues()
	if err != nil {
		return "", err
	}
	return hashHookRuntimeFingerprint(values), nil
}

func currentHookRuntimeScopeFingerprint() (string, error) {
	_, values, err := currentHookRuntimeFingerprintValues()
	if err != nil {
		return "", err
	}
	return hashHookRuntimeFingerprint(values), nil
}

func currentHookRuntimeFingerprintValues() ([]string, []string, error) {
	aiConfig := config.LoadAIConfig()
	if aiConfig == nil || !aiConfig.Enabled {
		return nil, nil, errors.New("Phase AI is not enabled")
	}
	host, err := config.GetDefaultUserHost()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve Phase host: %w", err)
	}
	credential, err := keyring.GetCredentials()
	if err != nil || strings.TrimSpace(credential) == "" {
		return nil, nil, errors.New("Phase authentication is unavailable")
	}
	stat, err := os.Stat(config.AIConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read Phase AI config generation: %w", err)
	}
	generation := fmt.Sprintf("%d", stat.ModTime().UnixNano())
	runtimeValues := []string{host, credential, aiConfig.DefaultWorkflowID, version.Version, generation}
	scopeValues := []string{
		host, credential, aiConfig.DefaultWorkflowID, aiConfig.Version,
		strconv.FormatBool(aiConfig.Enabled), generation,
	}
	return runtimeValues, scopeValues, nil
}

func hashHookRuntimeFingerprint(values []string) string {
	hasher := sha256.New()
	for _, value := range values {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write([]byte(value))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func probeInheritedPhaseRuntime(ctx context.Context) error {
	proxyURL := firstEnvironmentValue("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")
	if proxyURL == "" {
		return errors.New("Phase proxy environment is incomplete")
	}
	return probePhaseProxy(ctx, proxyURL)
}

func probeHookRuntimeState(ctx context.Context, state hookRuntimeState, expectedFingerprint string) error {
	if err := validateHookRuntimeState(state, expectedFingerprint); err != nil {
		return err
	}
	return probePhaseProxy(ctx, state.ProxyURL)
}

func loadHookRuntimePlan(ctx context.Context, state hookRuntimeState, expectedFingerprint string) (phaseproxy.ProcessEnvironmentPlan, error) {
	if err := validateHookRuntimeState(state, expectedFingerprint); err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	return loadPhaseRuntimePlanFromProxy(ctx, state.ProxyURL)
}

func loadPhaseRuntimePlanFromProxy(ctx context.Context, rawProxyURL string) (phaseproxy.ProcessEnvironmentPlan, error) {
	client, err := phaseProxyHTTPClient(rawProxyURL)
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, aiproxy.ManifestURL, nil)
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, errPhaseAgentManifestNotReachable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return phaseproxy.ProcessEnvironmentPlan{}, decodePhaseAgentManifestFailure(response)
	}
	var manifest remoteapi.ManifestResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&manifest); err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase Agent manifest is invalid")
	}
	plan := manifest.ProcessEnvironment
	proxyURL := firstMapValue(plan.Set, "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")
	if manifest.SchemaVersion != agentapi.SchemaVersion || manifest.SessionUID == "" ||
		plan.Set["PHASE_AI_ENABLED"] != "1" || proxyURL != rawProxyURL {
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase Agent environment does not match the managed runtime")
	}
	if !phaseproxy.PlanCarriesReservedNames(plan) {
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase Agent environment does not name the variables phase run must keep")
	}
	for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		if value := plan.Set[key]; value != "" && value != rawProxyURL {
			return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase Agent proxy aliases disagree")
		}
	}
	for _, forbidden := range []string{
		"PHASE_SERVICE_TOKEN", "PHASE_AGENT_TOKEN",
	} {
		if _, present := plan.Set[forbidden]; present {
			return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase Agent environment contains a forbidden credential")
		}
	}
	for key, value := range plan.Set {
		if !phaseproxy.ValidShellEnvironmentKey(key) || strings.ContainsAny(value, "\x00\r\n") || len(value) > 64<<10 {
			return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase Agent environment is unsafe")
		}
	}
	for _, key := range plan.Unset {
		if !phaseproxy.ValidShellEnvironmentKey(key) {
			return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase Agent environment cleanup is unsafe")
		}
	}
	return plan, nil
}

func validateHookRuntimeState(state hookRuntimeState, expectedFingerprint string) error {
	if state.Version != hookRuntimeStateVersion || state.Generation == "" || state.PID <= 0 || state.ProxyURL == "" {
		return errors.New("Phase AI runtime state is invalid")
	}
	if expectedFingerprint != "" && state.RuntimeFingerprint != expectedFingerprint {
		return errors.New("Phase AI runtime binding changed")
	}
	if !processIsAlive(state.PID) {
		return errors.New("Phase AI runtime process is not running")
	}
	return nil
}

func decodePhaseAgentManifestFailure(response *http.Response) error {
	failure := &phaseAgentManifestFailure{}
	if response == nil {
		return failure
	}
	failure.StatusCode = response.StatusCode
	headerCode := strings.TrimSpace(response.Header.Get("X-Phase-Error-Code"))
	const maxManifestFailureBytes = 64 << 10
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxManifestFailureBytes+1))
	if err != nil || len(payload) > maxManifestFailureBytes {
		return failure
	}
	var envelope struct {
		Error struct {
			Code      string                     `json:"code"`
			Message   string                     `json:"message"`
			Retryable *bool                      `json:"retryable"`
			Details   map[string]json.RawMessage `json:"details"`
		} `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if decoder.Decode(&envelope) != nil {
		return failure
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return failure
	}
	bodyCode := strings.TrimSpace(envelope.Error.Code)
	if bodyCode == "" || headerCode == "" || bodyCode != headerCode || envelope.Error.Retryable == nil {
		return failure
	}
	failure.Code = bodyCode
	failure.Structured = true
	failure.Retryable = *envelope.Error.Retryable
	failure.Canonical = strings.TrimSpace(envelope.Error.Message) != "" && envelope.Error.Details != nil
	return failure
}

func probePhaseProxy(ctx context.Context, rawProxyURL string) error {
	client, err := phaseProxyHTTPClient(rawProxyURL)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://phase.invalid/v1/status", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return errPhaseProxyNotReachable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("Phase proxy authentication or discovery failed")
	}
	var status struct {
		SchemaVersion int    `json:"schemaVersion"`
		Kind          string `json:"kind"`
		SafeToPrint   bool   `json:"safeToPrint"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&status); err != nil ||
		status.SchemaVersion != agentapi.SchemaVersion || status.Kind != "phase.ai.status" || !status.SafeToPrint {
		return errors.New("Phase proxy status response is invalid")
	}
	return nil
}

// requestHookRuntimeShutdown uses the proxy's process-local capability to
// revoke the backend Agent session and trigger an orderly local daemon stop.
// It is the Windows equivalent of interrupting the detached Unix daemon.
func requestHookRuntimeShutdown(ctx context.Context, rawProxyURL string) error {
	client, err := phaseProxyHTTPClient(rawProxyURL)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, phaseproxy.ControlURL+"/v1/revoke", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("Phase runtime shutdown control is not reachable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("Phase runtime shutdown control was rejected")
	}
	var revoked agentapi.RevokeResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&revoked); err != nil ||
		revoked.SchemaVersion != agentapi.SchemaVersion || revoked.SessionUID == "" || revoked.RevokedAt.IsZero() {
		return errors.New("Phase runtime shutdown response is invalid")
	}
	return nil
}

func phaseProxyHTTPClient(rawProxyURL string) (*http.Client, error) {
	parsed, err := url.Parse(rawProxyURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User == nil {
		return nil, errors.New("Phase proxy URL is invalid")
	}
	if parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Phase proxy URL is invalid")
	}
	password, present := parsed.User.Password()
	if !phaseproxy.ValidProxyUsername(parsed.User.Username()) || !present || password == "" {
		return nil, errors.New("Phase proxy authentication is unavailable")
	}
	if !phaseproxy.IsLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("managed Phase proxy is not bound to loopback")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(parsed)
	transport.DialContext = (&net.Dialer{Timeout: 2 * time.Second}).DialContext
	return &http.Client{
		Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func firstEnvironmentValue(keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}

func firstMapValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := values[key]; value != "" {
			return value
		}
	}
	return ""
}

func randomRuntimeGeneration() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return hex.EncodeToString(random), nil
}

func sessionLeasePath(directory, sessionID string) (string, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || len(sessionID) > 512 {
		return "", errors.New("Phase AI session ID is invalid")
	}
	digest := sha256.Sum256([]byte(sessionID))
	return filepath.Join(directory, sessionLeasePrefix+hex.EncodeToString(digest[:16])+sessionLeaseSuffix), nil
}

func withLeaseMutationLock(ctx context.Context, leasePath string, mutate func() error) error {
	lockFile, err := acquireRuntimeFileLock(ctx, leasePath+leaseLockSuffix)
	if err != nil {
		return err
	}
	mutationErr := mutate()
	releaseErr := unlockLeaseFile(lockFile)
	if mutationErr != nil {
		return mutationErr
	}
	return releaseErr
}

// acquireRuntimeFileLock waits briefly for an exclusive OS lock on lockPath.
func acquireRuntimeFileLock(ctx context.Context, lockPath string) (*os.File, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, err
	}
	waitContext, cancel := context.WithTimeout(ctx, leaseLockWait)
	defer cancel()
	ticker := time.NewTicker(leaseLockPoll)
	defer ticker.Stop()
	for {
		lockFile, acquired, err := tryLockLeaseFile(lockPath)
		if err != nil {
			return nil, err
		}
		if acquired {
			return lockFile, nil
		}
		select {
		case <-waitContext.Done():
			return nil, errors.New("Phase AI session lease is busy")
		case <-ticker.C:
		}
	}
}

var errHookSetupInProgress = errors.New("Phase AI setup is in progress")

// lockHookSetup keeps hooks from starting a daemon until phase ai enable
// has saved the configuration that daemon must read.
func lockHookSetup(ctx context.Context) (func(), error) {
	directory, err := hookRuntimeDir()
	if err != nil {
		return nil, err
	}
	lockFile, err := acquireRuntimeFileLock(ctx, filepath.Join(directory, hookSetupLockFile))
	if err != nil {
		return nil, err
	}
	return func() { _ = unlockLeaseFile(lockFile) }, nil
}

// withLeaseRegistryLock serializes every lease read and write. One
// lock for all leases keeps the directory free of a lock file per session,
// which would otherwise outlive the lease it protected.
func withLeaseRegistryLock(ctx context.Context, directory string, mutate func() error) error {
	return withLeaseMutationLock(ctx, filepath.Join(directory, leaseRegistryName), mutate)
}

func touchSessionLease(sessionID string) error {
	directory, err := hookRuntimeDir()
	if err != nil {
		return nil
	}
	path, err := sessionLeasePath(directory, sessionID)
	if err != nil {
		return nil
	}
	_ = withLeaseRegistryLock(context.Background(), directory, func() error {
		var lease sessionLease
		if err := readOwnerOnlyJSON(path, &lease); err != nil {
			return nil
		}
		state, err := readHookRuntimeState(filepath.Join(directory, hookRuntimeStateFile))
		if err != nil || lease.Generation != state.Generation || lease.Version != hookRuntimeStateVersion {
			return nil
		}
		lease.UpdatedAt = time.Now().UTC()
		if !lease.ExpiresAt.IsZero() {
			// A bounded session lease is extended by activity and expires on
			// its own when the harness disappears without a SessionEnd.
			lease.ExpiresAt = lease.UpdatedAt.Add(harnessSessionLeaseTTL)
		}
		return writeOwnerOnlyJSON(path, lease)
	})
	return nil
}

func removeSessionLease(sessionID string) error {
	directory, err := hookRuntimeDir()
	if err != nil {
		return nil
	}
	path, err := sessionLeasePath(directory, sessionID)
	if err != nil {
		return nil
	}
	return withLeaseRegistryLock(context.Background(), directory, func() error {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	})
}

// errHookPhaseAIDisabled stops a daemon cycle that would publish an
// environment after phase ai disable.
var errHookPhaseAIDisabled = errors.New("Phase AI is disabled")

// hookPhaseAIDisabled reports whether phase ai disable has run (or the
// setup was removed). An unreadable or half-written config is not taken as
// disabled, so a concurrent enable cannot stop a healthy daemon.
func hookPhaseAIDisabled() bool {
	if _, err := os.Stat(config.AIConfigPath); errors.Is(err, os.ErrNotExist) {
		return true
	}
	cfg := config.LoadAIConfig()
	return cfg != nil && !cfg.Enabled
}

func monitorSessionLeases(ctx context.Context, cancel context.CancelFunc, directory, generation string) {
	ticker := time.NewTicker(hookLeasePoll)
	defer ticker.Stop()
	var emptySince time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if hookPhaseAIDisabled() {
				cancel()
				return
			}
			active, err := hasActiveSessionLease(directory, generation, now)
			if err != nil {
				emptySince = time.Time{}
				continue
			}
			if active {
				emptySince = time.Time{}
				continue
			}
			if emptySince.IsZero() {
				emptySince = now
				continue
			}
			if now.Sub(emptySince) >= hookIdleGrace {
				cancel()
				return
			}
		}
	}
}

func hasActiveSessionLease(directory, generation string, now time.Time) (bool, error) {
	sessions, commands, err := activeSessionLeases(directory, generation, now)
	return sessions || commands, err
}

// activeSessionLeases reports live session leases and live command leases
// (wrapped commands in flight) for one daemon generation, pruning every lease
// that is invalid, expired, or bound to another generation.
func activeSessionLeases(directory, generation string, now time.Time) (bool, bool, error) {
	sessions, commands := false, false
	err := withLeaseRegistryLock(context.Background(), directory, func() error {
		paths, err := filepath.Glob(filepath.Join(directory, sessionLeasePrefix+"*"+sessionLeaseSuffix))
		if err != nil {
			return err
		}
		for _, path := range paths {
			if err := func() error {
				var lease sessionLease
				if err := readOwnerOnlyJSON(path, &lease); err != nil {
					if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
						return fmt.Errorf("remove invalid Phase AI session lease: %w", removeErr)
					}
					return nil
				}
				// A lease renewed after the caller took now is legitimate; judge
				// it against the time the lock was actually acquired.
				checkedAt := now
				if current := time.Now(); current.After(checkedAt) {
					checkedAt = current
				}
				if lease.Version != hookRuntimeStateVersion || lease.UpdatedAt.IsZero() || lease.UpdatedAt.After(checkedAt) ||
					checkedAt.Sub(lease.UpdatedAt) > hookLeaseMaxAge ||
					(!lease.ExpiresAt.IsZero() && !checkedAt.Before(lease.ExpiresAt)) ||
					(lease.Purpose != "" && lease.Purpose != harnessCommandLeasePurpose) {
					_ = os.Remove(path)
					return nil
				}
				if lease.Generation == generation {
					if lease.Purpose == harnessCommandLeasePurpose {
						commands = true
					} else {
						sessions = true
					}
					return nil
				}
				_ = os.Remove(path)
				return nil
			}(); err != nil {
				return err
			}
		}
		return nil
	})
	return sessions, commands, err
}

func hookRuntimeFailurePath(directory, generation string) string {
	return filepath.Join(directory, "runtime-"+generation+".error.json")
}

// claimHookRuntimeLock, updateHookRuntimeLock and
// releaseHookRuntimeLock each run under an OS lock, so stale-owner recovery
// can never hand ownership to two starters.
func claimHookRuntimeLock(path, generation string) (bool, error) {
	claimed := false
	err := withLeaseMutationLock(context.Background(), path, func() error {
		existing, err := readHookRuntimeLock(path)
		switch {
		case err == nil:
			if existing.PID > 0 && processIsAlive(existing.PID) {
				return nil
			}
			if existing.PID == 0 && time.Since(existing.CreatedAt) < hookStartTimeout {
				return nil
			}
		case !errors.Is(err, os.ErrNotExist) && !abandonedHookRuntimeLock(path, err):
			return err
		}
		setup, free, err := tryLockLeaseFile(filepath.Join(filepath.Dir(path), hookSetupLockFile))
		if err != nil {
			return err
		}
		if !free {
			return errHookSetupInProgress
		}
		defer unlockLeaseFile(setup)
		claimed = true
		return writeOwnerOnlyJSON(path, hookRuntimeLock{
			Version: hookRuntimeStateVersion, Generation: generation, CreatedAt: time.Now().UTC(),
		})
	})
	return claimed && err == nil, err
}

// abandonedHookRuntimeLock reports a lock that cannot be parsed and is older
// than any startup: an earlier build was interrupted while writing it.
func abandonedHookRuntimeLock(path string, readErr error) bool {
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) &&
		!errors.As(readErr, &syntaxErr) && !errors.As(readErr, &typeErr) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && time.Since(info.ModTime()) > hookStartTimeout
}

func updateHookRuntimeLock(path, generation string, update func(*hookRuntimeLock)) error {
	return withLeaseMutationLock(context.Background(), path, func() error {
		lock, err := readHookRuntimeLock(path)
		if err != nil || lock.Generation != generation {
			return errors.New("Phase AI runtime lock ownership changed")
		}
		update(&lock)
		return writeOwnerOnlyJSON(path, lock)
	})
}

func releaseHookRuntimeLock(path, generation string) error {
	return withLeaseMutationLock(context.Background(), path, func() error {
		lock, err := readHookRuntimeLock(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil && !abandonedHookRuntimeLock(path, err) {
			return err
		}
		if err == nil && lock.Generation != generation {
			return nil
		}
		return os.Remove(path)
	})
}

func removeStateIfGeneration(path, generation string) error {
	state, err := readHookRuntimeState(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.Generation != generation {
		return nil
	}
	return os.Remove(path)
}

func readHookRuntimeState(path string) (hookRuntimeState, error) {
	var state hookRuntimeState
	err := readOwnerOnlyJSON(path, &state)
	if err == nil && state.Version != hookRuntimeStateVersion {
		return hookRuntimeState{}, errors.New("Phase AI runtime state version is unsupported")
	}
	return state, err
}

func readHookRuntimeLock(path string) (hookRuntimeLock, error) {
	var lock hookRuntimeLock
	err := readOwnerOnlyJSON(path, &lock)
	return lock, err
}

func readHookRuntimeFailure(path string) (hookRuntimeFailure, error) {
	var failure hookRuntimeFailure
	err := readOwnerOnlyJSON(path, &failure)
	if err == nil && !validLifecycleRecord("startup_failed", failure.Reason) {
		return hookRuntimeFailure{}, errors.New("Phase AI runtime failure state is invalid")
	}
	return failure, err
}

func readOwnerOnlyJSON(path string, value any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Phase AI runtime state must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("Phase AI runtime state must be owner-only")
	}
	file, err := openOwnerOnlyFile(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4<<20))
	if err := decoder.Decode(value); err != nil {
		return err
	}
	return nil
}

func writeOwnerOnlyJSON(path string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeOwnerOnlyBytes(path, payload)
}

func writeOwnerOnlyBytes(path string, payload []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".phase-runtime-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func stopHookRuntime(ctx context.Context) error {
	directory, err := hookRuntimeDir()
	if err != nil {
		return err
	}
	statePath := filepath.Join(directory, hookRuntimeStateFile)
	lockPath := filepath.Join(directory, hookRuntimeLockFile)
	state, err := readHookRuntimeState(statePath)
	if errors.Is(err, os.ErrNotExist) {
		lock, lockErr := readHookRuntimeLock(lockPath)
		if errors.Is(lockErr, os.ErrNotExist) {
			return nil
		}
		if lockErr != nil && !abandonedHookRuntimeLock(lockPath, lockErr) {
			return lockErr
		}
		if lock.PID > 0 && processIsAlive(lock.PID) {
			if time.Since(lock.CreatedAt) > 2*hookStartTimeout && time.Since(lock.RecyclingAt) > 2*hookStartTimeout {
				return errors.New("refusing to stop a live process from a stale Phase AI startup lock")
			}
			process, findErr := os.FindProcess(lock.PID)
			if findErr != nil {
				return findErr
			}
			if killErr := process.Kill(); killErr != nil {
				return killErr
			}
			if err := waitForRuntimeProcessExit(ctx, lock.PID, time.Second); err != nil {
				return err
			}
		}
		return releaseHookRuntimeLock(lockPath, lock.Generation)
	}
	if err != nil {
		return err
	}
	return stopHookRuntimeState(ctx, directory, state)
}

func stopHookRuntimeState(ctx context.Context, directory string, state hookRuntimeState) error {
	statePath := filepath.Join(directory, hookRuntimeStateFile)
	lockPath := filepath.Join(directory, hookRuntimeLockFile)
	lock, err := readHookRuntimeLock(lockPath)
	if err != nil || lock.Generation != state.Generation || lock.PID != state.PID {
		return errors.New("refusing to stop a Phase AI process without matching ownership state")
	}
	if err := probeHookRuntimeState(ctx, state, ""); err != nil {
		if !processIsAlive(state.PID) {
			_ = removeStateIfGeneration(statePath, state.Generation)
			_ = releaseHookRuntimeLock(lockPath, state.Generation)
			_ = removeLeasesForGeneration(directory, state.Generation)
			return nil
		}
		return errors.New("refusing to signal an owned PID whose authenticated Phase proxy is not healthy")
	}
	process, err := os.FindProcess(state.PID)
	if err != nil {
		return err
	}
	gracefulContext, gracefulCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	stopErr := stopRuntimeProcessGracefully(gracefulContext, process, state)
	gracefulCancel()
	if stopErr != nil {
		if killErr := process.Kill(); killErr != nil {
			return fmt.Errorf("stop managed Phase AI runtime: %w", stopErr)
		}
	}
	if err := waitForRuntimeProcessExit(ctx, state.PID, 2*time.Second); err != nil {
		if killErr := process.Kill(); killErr != nil {
			return err
		}
		if waitErr := waitForRuntimeProcessExit(ctx, state.PID, time.Second); waitErr != nil {
			return waitErr
		}
	}
	_ = removeStateIfGeneration(statePath, state.Generation)
	_ = releaseHookRuntimeLock(lockPath, state.Generation)
	_ = removeLeasesForGeneration(directory, state.Generation)
	return nil
}

func waitForRuntimeProcessExit(ctx context.Context, pid int, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for processIsAlive(pid) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("managed Phase AI runtime did not stop")
		case <-ticker.C:
		}
	}
	return nil
}

func removeLeasesForGeneration(directory, generation string) error {
	return withLeaseRegistryLock(context.Background(), directory, func() error {
		paths, err := filepath.Glob(filepath.Join(directory, sessionLeasePrefix+"*"+sessionLeaseSuffix))
		if err != nil {
			return err
		}
		for _, path := range paths {
			var lease sessionLease
			if err := readOwnerOnlyJSON(path, &lease); err == nil && lease.Generation == generation {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
		}
		return nil
	})
}

func init() {
	aiRuntimeDaemonCmd.Flags().String("generation", "", "")
	aiCmd.AddCommand(aiRuntimeDaemonCmd)
}
