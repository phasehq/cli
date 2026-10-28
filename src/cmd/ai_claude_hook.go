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
	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/phasehq/cli/pkg/version"
	"github.com/spf13/cobra"
)

var (
	errPhaseProxyNotReachable         = errors.New("Phase proxy is not reachable")
	errPhaseAgentManifestNotReachable = errors.New("Phase Agent manifest is not reachable")
	errClaudeRuntimeRefreshing        = errors.New("Claude Phase runtime is refreshing")
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
	claudeRuntimeStateVersion  = 2
	claudeRuntimeStateFile     = "claude-runtime.json"
	claudeRuntimeLockFile      = "claude-runtime.lock"
	claudeSessionLeasePrefix   = "claude-session-"
	claudeSessionLeaseSuffix   = ".lease.json"
	claudeLeaseLockSuffix      = ".mutation.lock"
	claudeLifecycleLogFile     = "claude-runtime.log"
	claudeLifecycleLogMaxBytes = 1 << 20
)

var (
	claudeHookEnsureRuntime    = ensureClaudeHookRuntime
	claudeHookFingerprint      = currentClaudeRuntimeFingerprint
	claudeHookScopeFingerprint = currentClaudeRuntimeScopeFingerprint
	claudeHookExecutable       = os.Executable
	claudeHookRuntimeDir       = phaseproxy.DefaultCADirectory
	claudeHookStartTimeout     = 35 * time.Second
	claudeHookPollInterval     = 100 * time.Millisecond
	claudeHookIdleGrace        = 2 * time.Minute
	claudeHookLeaseMaxAge      = 7 * 24 * time.Hour
	claudeHookLeasePoll        = 15 * time.Second
	claudeHookRecycleTimeout   = 35 * time.Second
	claudeLeaseLockWait        = 750 * time.Millisecond
	claudeLeaseLockPoll        = 10 * time.Millisecond
	claudeHookNewRuntime       = func() (claudeManagedRuntime, error) { return airuntime.New("") }
	claudeHookNewProxyEngine   = aiproxy.New
)

type claudeManagedRuntime interface {
	ServeManaged(context.Context, airuntime.Engine) error
}

type claudeRuntimeState struct {
	Version                 int       `json:"version"`
	Generation              string    `json:"generation"`
	RuntimeFingerprint      string    `json:"runtimeFingerprint"`
	RuntimeScopeFingerprint string    `json:"runtimeScopeFingerprint,omitempty"`
	PID                     int       `json:"pid"`
	StartedAt               time.Time `json:"startedAt"`
	ProxyURL                string    `json:"proxyUrl"`
}

type claudeRuntimeLock struct {
	Version    int       `json:"version"`
	Generation string    `json:"generation"`
	PID        int       `json:"pid,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	// RecyclingAt is when the daemon last withdrew its state to reopen its
	// session; setup may stop it then as during a startup.
	RecyclingAt time.Time `json:"recyclingAt,omitempty"`
}

type claudeRuntimeFailure struct {
	Generation string `json:"generation"`
	Reason     string `json:"reason"`
}

type claudeHookInput struct {
	SessionID string `json:"session_id"`
}

type claudeSessionLease struct {
	Version    int       `json:"version"`
	Generation string    `json:"generation"`
	UpdatedAt  time.Time `json:"updatedAt"`
	ExpiresAt  time.Time `json:"expiresAt,omitempty"`
	Purpose    string    `json:"purpose,omitempty"`
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
const claudePhaseAIHarnessContext = `Phase AI is enabled on this machine: the human chose Phase-managed execution by running phase ai enable. While the Phase proxy is running, every Bash command starts with the Phase AI environment, so provider CLIs and HTTP clients for this Workflow's Connections use Phase-managed credentials automatically with no wrapper, no phase ai exec, and no setup. http://phase.invalid/v1/status lists the Connections. If Phase is unavailable, Phase-managed provider commands fail with credential or connection errors while everything else is unaffected: tell the human and continue other work. Never unset, override, print, or copy PHASE_AI_*, HTTPS_PROXY, or provider credential variables, and never substitute other credentials or credential sources. Load the phase-cli-ai-relay skill to request a new or updated Connection.`

const claudeInheritedPhaseAIContext = `Phase AI is active through the environment inherited from phase ai run: provider CLIs and HTTP clients for this Workflow's Connections already use Phase-managed credentials. http://phase.invalid/v1/status lists them. Never unset, override, print, or copy PHASE_AI_*, HTTPS_PROXY, or provider credential variables, and never substitute other credentials.`

var aiClaudeHookCmd = &cobra.Command{
	Use:          "__claude-hook",
	Hidden:       true,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runAIClaudeHook,
}

var aiClaudeDaemonCmd = &cobra.Command{
	Use:          "__claude-daemon",
	Hidden:       true,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runAIClaudeDaemon,
}

var aiClaudeEventCmd = &cobra.Command{
	Use:          "__claude-event [guard|heartbeat|session-end]",
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
	if os.Getenv("PHASE_AI_ENABLED") == "1" {
		// phase ai run already gave this harness a complete environment; the
		// loader defers to it and no second runtime is started.
		return emitClaudeHookContext(cmd, claudeInheritedPhaseAIContext)
	}
	directory, err := claudeHookRuntimeDir()
	if err != nil {
		return emitClaudeHookContext(cmd, claudePhaseAIHarnessContext+"\n"+claudeEnvironmentStatusLine(claudeRuntimeHealth{}))
	}
	// The harness-owned env file only ever receives a line that sources the
	// daemon-maintained file, so this hook never writes a secret anywhere the
	// harness reads directly. Startup is bounded and best effort: a slow or
	// unreachable Console must not delay ordinary work, and the next prompt
	// retries.
	_ = installClaudeEnvironmentLoader(os.Getenv("CLAUDE_ENV_FILE"), claudeEnvironmentPath(directory))
	health := kickClaudeRuntime(cmd.Context(), directory, hookInput.SessionID, claudeHookKickBudget)
	return emitClaudeHookContext(cmd, claudePhaseAIHarnessContext+"\n"+claudeEnvironmentStatusLine(health))
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
	if action == "guard" {
		// Transparent mode needs no per-command hook: the shell sources the Phase
		// environment itself and every command keeps normal permission
		// evaluation. Hook configurations written before this change still
		// invoke the guard until phase ai enable rewrites them; stay silent.
		return nil
	}
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
		return removeClaudeSessionLease(harnessLeaseID(ai.HarnessClaudeCode, input.SessionID))
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
	_ = touchClaudeSessionLease(leaseID)
	if os.Getenv("PHASE_AI_ENABLED") == "1" {
		return nil
	}
	directory, err := claudeHookRuntimeDir()
	if err != nil {
		return nil
	}
	// Repairs a session whose SessionStart could not install the loader.
	_ = installClaudeEnvironmentLoader(os.Getenv("CLAUDE_ENV_FILE"), claudeEnvironmentPath(directory))
	health := inspectClaudeRuntime(directory)
	if health.ready {
		if _, statErr := os.Stat(mustClaudeLeasePath(directory, leaseID)); statErr != nil {
			_ = registerHarnessLease(ai.HarnessClaudeCode, sessionID, time.Now().UTC().Add(harnessSessionLeaseTTL))
		}
	} else {
		health = kickClaudeRuntime(cmd.Context(), directory, sessionID, claudeHookKickBudget)
	}
	output := claudePromptSubmitOutput{}
	output.HookSpecificOutput.HookEventName = "UserPromptSubmit"
	output.HookSpecificOutput.AdditionalContext = claudeEnvironmentStatusLine(health)
	return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
}

func mustClaudeLeasePath(directory, leaseID string) string {
	path, err := claudeSessionLeasePath(directory, leaseID)
	if err != nil {
		return filepath.Join(directory, "missing")
	}
	return path
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

func ensureClaudeHookRuntime(ctx context.Context) (phaseproxy.ProcessEnvironmentPlan, error) {
	directory, err := claudeHookRuntimeDir()
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	statePath := filepath.Join(directory, claudeRuntimeStateFile)
	lockPath := filepath.Join(directory, claudeRuntimeLockFile)
	fingerprint, err := claudeHookFingerprint()
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	scopeFingerprint, err := claudeHookScopeFingerprint()
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}

	if state, stateErr := readClaudeRuntimeState(statePath); stateErr == nil {
		if state.RuntimeFingerprint == fingerprint && state.RuntimeScopeFingerprint == scopeFingerprint {
			if plan, probeErr := loadClaudeRuntimePlan(ctx, state, fingerprint); probeErr == nil {
				return plan, nil
			}
		} else if probeErr := probeClaudeRuntimeState(ctx, state, ""); probeErr == nil {
			if stopErr := stopClaudeRuntimeState(ctx, directory, state); stopErr != nil {
				return phaseproxy.ProcessEnvironmentPlan{}, fmt.Errorf("replace outdated Phase AI runtime: %w", stopErr)
			}
		}
		if !processIsAlive(state.PID) {
			_ = removeClaudeStateIfGeneration(statePath, state.Generation)
			_ = releaseClaudeRuntimeLock(lockPath, state.Generation)
		} else if state.RuntimeFingerprint != fingerprint || state.RuntimeScopeFingerprint != scopeFingerprint {
			return phaseproxy.ProcessEnvironmentPlan{}, errors.New("an outdated Phase AI runtime could not be safely replaced")
		}
	} else if !errors.Is(stateErr, os.ErrNotExist) {
		return phaseproxy.ProcessEnvironmentPlan{}, stateErr
	}

	generation, err := randomClaudeGeneration()
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	claimed, err := claimClaudeRuntimeLock(lockPath, generation)
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	var waitedLock claudeRuntimeLock
	if !claimed {
		waitedLock, _ = readClaudeRuntimeLock(lockPath)
	}
	if claimed {
		executable, executableErr := claudeHookExecutable()
		if executableErr != nil {
			_ = releaseClaudeRuntimeLock(lockPath, generation)
			return phaseproxy.ProcessEnvironmentPlan{}, executableErr
		}
		pid, startErr := startClaudeHookDaemon(executable, generation)
		if startErr != nil {
			_ = releaseClaudeRuntimeLock(lockPath, generation)
			return phaseproxy.ProcessEnvironmentPlan{}, startErr
		}
		if err := updateClaudeRuntimeLock(lockPath, generation, func(lock *claudeRuntimeLock) { lock.PID = pid }); err != nil {
			if process, findErr := os.FindProcess(pid); findErr == nil {
				_ = process.Kill()
			}
			_ = releaseClaudeRuntimeLock(lockPath, generation)
			return phaseproxy.ProcessEnvironmentPlan{}, err
		}
	}

	waitContext, cancel := context.WithTimeout(ctx, claudeHookStartTimeout)
	defer cancel()
	ticker := time.NewTicker(claudeHookPollInterval)
	defer ticker.Stop()
	for {
		if state, stateErr := readClaudeRuntimeState(statePath); stateErr == nil {
			if plan, probeErr := loadClaudeRuntimePlan(waitContext, state, fingerprint); probeErr == nil {
				return plan, nil
			}
		}
		if claimed {
			failurePath := claudeRuntimeFailurePath(directory, generation)
			if failure, failureErr := readClaudeRuntimeFailure(failurePath); failureErr == nil && failure.Generation == generation {
				_ = os.Remove(failurePath)
				_ = releaseClaudeRuntimeLock(lockPath, generation)
				return phaseproxy.ProcessEnvironmentPlan{}, claudeRuntimeFailureError(failure.Reason)
			}
		}
		select {
		case <-waitContext.Done():
			if claimed {
				if lock, lockErr := readClaudeRuntimeLock(lockPath); lockErr == nil && (lock.PID <= 0 || !processIsAlive(lock.PID)) {
					_ = releaseClaudeRuntimeLock(lockPath, generation)
				}
			} else if errors.Is(waitContext.Err(), context.DeadlineExceeded) &&
				waitedLock.Version == claudeRuntimeStateVersion && waitedLock.Generation != "" && !waitedLock.CreatedAt.IsZero() {
				currentLock, lockErr := readClaudeRuntimeLock(lockPath)
				if lockErr == nil && currentLock.Version == waitedLock.Version &&
					currentLock.Generation == waitedLock.Generation && currentLock.CreatedAt.Equal(waitedLock.CreatedAt) &&
					currentLock.PID > 0 && processIsAlive(currentLock.PID) {
					return phaseproxy.ProcessEnvironmentPlan{}, fmt.Errorf("%w: managed session recycle did not complete", errClaudeRuntimeRefreshing)
				}
			}
			return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase AI automatic proxy did not become ready")
		case <-ticker.C:
		}
	}
}

func startClaudeHookDaemon(executable, generation string) (int, error) {
	name := strings.ToLower(filepath.Base(executable))
	if strings.HasSuffix(name, ".test") || strings.HasSuffix(name, ".test.exe") {
		return 0, errors.New("refusing to launch a Go test binary as the Phase hook daemon")
	}
	child := exec.Command(executable, "ai", "__claude-daemon", "--generation", generation)
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
	_ = child.Process.Release()
	return pid, nil
}

func runAIClaudeDaemon(cmd *cobra.Command, args []string) error {
	generation, _ := cmd.Flags().GetString("generation")
	if generation == "" {
		return errors.New("Claude runtime generation is required")
	}
	directory, err := claudeHookRuntimeDir()
	if err != nil {
		return err
	}
	statePath := filepath.Join(directory, claudeRuntimeStateFile)
	lockPath := filepath.Join(directory, claudeRuntimeLockFile)
	failurePath := claudeRuntimeFailurePath(directory, generation)
	lock, err := readClaudeRuntimeLock(lockPath)
	if err != nil || lock.Generation != generation {
		appendClaudeLifecycleEvent(directory, "daemon_rejected", "ownership")
		return errors.New("Claude runtime ownership is unavailable")
	}
	appendClaudeLifecycleEvent(directory, "daemon_started", "")
	fingerprint, err := claudeHookFingerprint()
	if err != nil {
		writeClaudeRuntimeFailure(failurePath, generation, "fingerprint")
		appendClaudeLifecycleEvent(directory, "startup_failed", "fingerprint")
		return err
	}
	scopeFingerprint, err := claudeHookScopeFingerprint()
	if err != nil {
		writeClaudeRuntimeFailure(failurePath, generation, "fingerprint")
		appendClaudeLifecycleEvent(directory, "startup_failed", "fingerprint")
		return err
	}
	started := false
	stopReason := "fatal"
	defer func() {
		if started {
			_ = removeClaudeStateIfGeneration(statePath, generation)
		}
		_ = removeClaudeLeasesForGeneration(directory, generation)
		_ = releaseClaudeRuntimeLock(lockPath, generation)
		appendClaudeLifecycleEvent(directory, "daemon_stopped", stopReason)
	}()

	runtimeInstance, err := claudeHookNewRuntime()
	if err != nil {
		reason := "runtime"
		if errors.Is(err, airuntime.ErrAuthenticationRequired) {
			reason = "authentication"
		}
		writeClaudeRuntimeFailure(failurePath, generation, reason)
		appendClaudeLifecycleEvent(directory, "startup_failed", reason)
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
	engine := claudeHookNewProxyEngine()
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
			if claudeHookPhaseAIDisabled() {
				publishErr = errClaudeHookPhaseAIDisabled
				cycleCancel()
				return
			}
			proxyURL := firstMapValue(endpoints.ProcessEnvironment.Set, "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")
			if proxyURL == "" {
				publishErr = errors.New("Phase AI runtime proxy is unavailable")
				cycleCancel()
				return
			}
			state := claudeRuntimeState{
				Version: claudeRuntimeStateVersion, Generation: generation,
				RuntimeFingerprint: fingerprint, RuntimeScopeFingerprint: scopeFingerprint,
				PID: os.Getpid(), StartedAt: time.Now().UTC(), ProxyURL: proxyURL,
			}
			lastPlan, lastConnections = endpoints.ProcessEnvironment, endpoints.Connections
			if publishErr = publishClaudeRuntime(directory, state, lastPlan, lastConnections); publishErr != nil {
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
				go monitorClaudeSessionLeases(serveContext, cancel, directory, generation)
			}
			if readyCycles == 1 {
				appendClaudeLifecycleEvent(directory, "session_ready", "initial")
			} else {
				appendClaudeLifecycleEvent(directory, "session_ready", "recycled")
			}
		}

		err = runtimeInstance.ServeManaged(cycleContext, engine)
		cycleCancel()
		recycling := cycleStarted && (errors.Is(err, airuntime.ErrSessionReprovisionRequired) || errors.Is(err, airuntime.ErrSessionExpired))
		if recycling {
			_ = updateClaudeRuntimeLock(lockPath, generation, func(lock *claudeRuntimeLock) { lock.RecyclingAt = time.Now().UTC() })
		}
		_ = removeClaudeStateIfGeneration(statePath, generation)
		disabled := claudeHookPhaseAIDisabled()
		if cycleStarted {
			if disabled {
				// phase ai disable may already have removed these files; never
				// recreate them, or shells keep sourcing decoys.
				_ = removeClaudeEnvironmentFiles()
			} else {
				// The listener is gone while this cycle recycles or the daemon exits.
				// Retire proxy routing immediately; decoys stay (see renderClaudeEnvironment).
				_ = writeClaudeEnvironment(directory, os.Getpid(), generation, time.Time{}, lastPlan, lastConnections, false)
				if claudeHookPhaseAIDisabled() {
					disabled = true
					_ = removeClaudeEnvironmentFiles()
				}
			}
		}
		if publishErr != nil {
			err = publishErr
		}
		if serveContext.Err() != nil || errors.Is(publishErr, errClaudeHookPhaseAIDisabled) {
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
			appendClaudeLifecycleEvent(directory, "session_recycle", reason)
			refreshDeadline = time.Now().Add(claudeHookRecycleTimeout)
			retryAttempt = 0
			continue
		}

		if !cycleStarted && !refreshDeadline.IsZero() && time.Now().Before(refreshDeadline) && claudeRecycleRetryable(err) {
			delay := claudeRecycleRetryDelay(err, retryAttempt, time.Until(refreshDeadline))
			retryAttempt++
			appendClaudeLifecycleEvent(directory, "session_retry", "backend_unavailable")
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
			writeClaudeRuntimeFailure(failurePath, generation, reason)
			appendClaudeLifecycleEvent(directory, "startup_failed", reason)
		}
		return err
	}
}

// publishClaudeRuntime writes the runtime state and the live environment under
// the runtime lock, so a hook retiring a dead daemon's routing cannot
// interleave with it.
func publishClaudeRuntime(directory string, state claudeRuntimeState, plan phaseproxy.ProcessEnvironmentPlan, connections []aiproxy.EndpointConnection) error {
	return withClaudeRuntimeLock(directory, func() error {
		if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), state); err != nil {
			return err
		}
		if err := writeClaudeEnvironment(directory, state.PID, state.Generation, state.StartedAt, plan, connections, true); err != nil {
			return err
		}
		// disable may have run while the file was written; it removes
		// the files after saving the config, so a second look is enough.
		if claudeHookPhaseAIDisabled() {
			_ = removeClaudeEnvironmentFiles()
			return errClaudeHookPhaseAIDisabled
		}
		return nil
	})
}

func withClaudeRuntimeLock(directory string, mutate func() error) error {
	return withClaudeLeaseMutationLock(context.Background(), filepath.Join(directory, claudeRuntimeLockFile), mutate)
}

func claudeRecycleRetryable(err error) bool {
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

func claudeRecycleRetryDelay(err error, attempt int, remaining time.Duration) time.Duration {
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

func currentClaudeRuntimeFingerprint() (string, error) {
	values, _, err := currentClaudeRuntimeFingerprintValues()
	if err != nil {
		return "", err
	}
	return hashClaudeRuntimeFingerprint(values), nil
}

func currentClaudeRuntimeScopeFingerprint() (string, error) {
	_, values, err := currentClaudeRuntimeFingerprintValues()
	if err != nil {
		return "", err
	}
	return hashClaudeRuntimeFingerprint(values), nil
}

func currentClaudeRuntimeFingerprintValues() ([]string, []string, error) {
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
		host, credential, aiConfig.DefaultWorkflowID, aiConfig.Version, aiConfig.ProxyMode,
		strconv.FormatBool(aiConfig.Enabled), generation,
	}
	return runtimeValues, scopeValues, nil
}

func hashClaudeRuntimeFingerprint(values []string) string {
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
	return probePhaseProxy(ctx, proxyURL, false)
}

func probeClaudeRuntimeState(ctx context.Context, state claudeRuntimeState, expectedFingerprint string) error {
	if err := validateClaudeRuntimeState(state, expectedFingerprint); err != nil {
		return err
	}
	return probePhaseProxy(ctx, state.ProxyURL, true)
}

func loadClaudeRuntimePlan(ctx context.Context, state claudeRuntimeState, expectedFingerprint string) (phaseproxy.ProcessEnvironmentPlan, error) {
	if err := validateClaudeRuntimeState(state, expectedFingerprint); err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	return loadPhaseRuntimePlanFromProxy(ctx, state.ProxyURL, true)
}

func loadPhaseRuntimePlanFromProxy(ctx context.Context, rawProxyURL string, requireLoopback bool) (phaseproxy.ProcessEnvironmentPlan, error) {
	client, err := phaseProxyHTTPClient(rawProxyURL, requireLoopback)
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
	for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		if value := plan.Set[key]; value != "" && value != rawProxyURL {
			return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase Agent proxy aliases disagree")
		}
	}
	for _, forbidden := range []string{
		"PHASE_SERVICE_TOKEN", "PHASE_AGENT_TOKEN", "PHASE_AGENT_SESSION_CREDENTIAL", "PHASE_AI_SESSION_CREDENTIAL",
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

func validateClaudeRuntimeState(state claudeRuntimeState, expectedFingerprint string) error {
	if state.Version != claudeRuntimeStateVersion || state.Generation == "" || state.PID <= 0 || state.ProxyURL == "" {
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

func probePhaseProxy(ctx context.Context, rawProxyURL string, requireLoopback bool) error {
	client, err := phaseProxyHTTPClient(rawProxyURL, requireLoopback)
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

// requestClaudeRuntimeShutdown uses the proxy's process-local capability to
// revoke the backend Agent session and trigger an orderly local daemon stop.
// It is the Windows equivalent of interrupting the detached Unix daemon.
func requestClaudeRuntimeShutdown(ctx context.Context, rawProxyURL string) error {
	client, err := phaseProxyHTTPClient(rawProxyURL, true)
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

func phaseProxyHTTPClient(rawProxyURL string, requireLoopback bool) (*http.Client, error) {
	parsed, err := url.Parse(rawProxyURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User == nil {
		return nil, errors.New("Phase proxy URL is invalid")
	}
	if parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Phase proxy URL is invalid")
	}
	password, present := parsed.User.Password()
	if !phaseproxy.ValidProxyUsername(parsed.User.Username()) || !present || password == "" {
		return nil, errors.New("Phase proxy authentication is unavailable")
	}
	if (requireLoopback || parsed.Scheme == "http") && !isLoopbackProxyHost(parsed.Hostname()) {
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

func isLoopbackProxyHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
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

func randomClaudeGeneration() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return hex.EncodeToString(random), nil
}

func claudeSessionLeasePath(directory, sessionID string) (string, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || len(sessionID) > 512 {
		return "", errors.New("Claude session ID is invalid")
	}
	digest := sha256.Sum256([]byte(sessionID))
	return filepath.Join(directory, claudeSessionLeasePrefix+hex.EncodeToString(digest[:16])+claudeSessionLeaseSuffix), nil
}

func withClaudeLeaseMutationLock(ctx context.Context, leasePath string, mutate func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	lockPath := leasePath + claudeLeaseLockSuffix
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return err
	}
	waitContext, cancel := context.WithTimeout(ctx, claudeLeaseLockWait)
	defer cancel()
	ticker := time.NewTicker(claudeLeaseLockPoll)
	defer ticker.Stop()
	for {
		lockFile, acquired, err := tryLockClaudeLeaseFile(lockPath)
		if err != nil {
			return err
		}
		if acquired {
			mutationErr := mutate()
			releaseErr := unlockClaudeLeaseFile(lockFile)
			if mutationErr != nil {
				return mutationErr
			}
			return releaseErr
		}
		select {
		case <-waitContext.Done():
			return errors.New("Claude session lease is busy")
		case <-ticker.C:
		}
	}
}

func withClaudeLeaseRegistryLock(ctx context.Context, directory string, mutate func() error) error {
	return withClaudeLeaseMutationLock(ctx, filepath.Join(directory, "claude-session-leases.registry"), mutate)
}

func touchClaudeSessionLease(sessionID string) error {
	directory, err := claudeHookRuntimeDir()
	if err != nil {
		return nil
	}
	path, err := claudeSessionLeasePath(directory, sessionID)
	if err != nil {
		return nil
	}
	_ = withClaudeLeaseMutationLock(context.Background(), path, func() error {
		var lease claudeSessionLease
		if err := readOwnerOnlyJSON(path, &lease); err != nil {
			return nil
		}
		state, err := readClaudeRuntimeState(filepath.Join(directory, claudeRuntimeStateFile))
		if err != nil || lease.Generation != state.Generation || lease.Version != claudeRuntimeStateVersion {
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

func removeClaudeSessionLease(sessionID string) error {
	directory, err := claudeHookRuntimeDir()
	if err != nil {
		return nil
	}
	path, err := claudeSessionLeasePath(directory, sessionID)
	if err != nil {
		return nil
	}
	return withClaudeLeaseMutationLock(context.Background(), path, func() error {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	})
}

// errClaudeHookPhaseAIDisabled stops a daemon cycle that would publish an
// environment after phase ai disable.
var errClaudeHookPhaseAIDisabled = errors.New("Phase AI is disabled")

// claudeHookPhaseAIDisabled reports whether phase ai disable has run (or the
// setup was removed). An unreadable or half-written config is not taken as
// disabled, so a concurrent enable cannot stop a healthy daemon.
func claudeHookPhaseAIDisabled() bool {
	if _, err := os.Stat(config.AIConfigPath); errors.Is(err, os.ErrNotExist) {
		return true
	}
	cfg := config.LoadAIConfig()
	return cfg != nil && !cfg.Enabled
}

func monitorClaudeSessionLeases(ctx context.Context, cancel context.CancelFunc, directory, generation string) {
	ticker := time.NewTicker(claudeHookLeasePoll)
	defer ticker.Stop()
	var emptySince time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if claudeHookPhaseAIDisabled() {
				cancel()
				return
			}
			active, err := hasActiveClaudeSessionLease(directory, generation, now)
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
			if now.Sub(emptySince) >= claudeHookIdleGrace {
				cancel()
				return
			}
		}
	}
}

func hasActiveClaudeSessionLease(directory, generation string, now time.Time) (bool, error) {
	sessions, commands, err := activeClaudeLeases(directory, generation, now)
	return sessions || commands, err
}

// activeClaudeLeases reports live session leases and live command leases
// (wrapped commands in flight) for one daemon generation, pruning every lease
// that is invalid, expired, or bound to another generation.
func activeClaudeLeases(directory, generation string, now time.Time) (bool, bool, error) {
	sessions, commands := false, false
	err := withClaudeLeaseRegistryLock(context.Background(), directory, func() error {
		paths, err := filepath.Glob(filepath.Join(directory, claudeSessionLeasePrefix+"*"+claudeSessionLeaseSuffix))
		if err != nil {
			return err
		}
		for _, path := range paths {
			if err := withClaudeLeaseMutationLock(context.Background(), path, func() error {
				var lease claudeSessionLease
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
				if lease.Version != claudeRuntimeStateVersion || lease.UpdatedAt.IsZero() || lease.UpdatedAt.After(checkedAt) ||
					checkedAt.Sub(lease.UpdatedAt) > claudeHookLeaseMaxAge ||
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
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return sessions, commands, err
}

func claudeRuntimeFailurePath(directory, generation string) string {
	return filepath.Join(directory, "claude-runtime-"+generation+".error.json")
}

// claimClaudeRuntimeLock, updateClaudeRuntimeLock and
// releaseClaudeRuntimeLock each run under an OS lock, so stale-owner recovery
// can never hand ownership to two starters.
func claimClaudeRuntimeLock(path, generation string) (bool, error) {
	claimed := false
	err := withClaudeLeaseMutationLock(context.Background(), path, func() error {
		existing, err := readClaudeRuntimeLock(path)
		switch {
		case err == nil:
			if existing.PID > 0 && processIsAlive(existing.PID) {
				return nil
			}
			if existing.PID == 0 && time.Since(existing.CreatedAt) < claudeHookStartTimeout {
				return nil
			}
		case !errors.Is(err, os.ErrNotExist) && !abandonedClaudeRuntimeLock(path, err):
			return err
		}
		claimed = true
		return writeOwnerOnlyJSON(path, claudeRuntimeLock{
			Version: claudeRuntimeStateVersion, Generation: generation, CreatedAt: time.Now().UTC(),
		})
	})
	return claimed && err == nil, err
}

// abandonedClaudeRuntimeLock reports a lock that cannot be parsed and is older
// than any startup: an earlier build was interrupted while writing it.
func abandonedClaudeRuntimeLock(path string, readErr error) bool {
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) &&
		!errors.As(readErr, &syntaxErr) && !errors.As(readErr, &typeErr) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && time.Since(info.ModTime()) > claudeHookStartTimeout
}

func updateClaudeRuntimeLock(path, generation string, update func(*claudeRuntimeLock)) error {
	return withClaudeLeaseMutationLock(context.Background(), path, func() error {
		lock, err := readClaudeRuntimeLock(path)
		if err != nil || lock.Generation != generation {
			return errors.New("Phase AI runtime lock ownership changed")
		}
		update(&lock)
		return writeOwnerOnlyJSON(path, lock)
	})
}

func releaseClaudeRuntimeLock(path, generation string) error {
	return withClaudeLeaseMutationLock(context.Background(), path, func() error {
		lock, err := readClaudeRuntimeLock(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil && !abandonedClaudeRuntimeLock(path, err) {
			return err
		}
		if err == nil && lock.Generation != generation {
			return nil
		}
		return os.Remove(path)
	})
}

func removeClaudeStateIfGeneration(path, generation string) error {
	state, err := readClaudeRuntimeState(path)
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

func readClaudeRuntimeState(path string) (claudeRuntimeState, error) {
	var state claudeRuntimeState
	err := readOwnerOnlyJSON(path, &state)
	if err == nil && state.Version != claudeRuntimeStateVersion {
		return claudeRuntimeState{}, errors.New("Phase AI runtime state version is unsupported")
	}
	return state, err
}

func readClaudeRuntimeLock(path string) (claudeRuntimeLock, error) {
	var lock claudeRuntimeLock
	err := readOwnerOnlyJSON(path, &lock)
	return lock, err
}

func readClaudeRuntimeFailure(path string) (claudeRuntimeFailure, error) {
	var failure claudeRuntimeFailure
	err := readOwnerOnlyJSON(path, &failure)
	if err == nil && !validClaudeLifecycleRecord("startup_failed", failure.Reason) {
		return claudeRuntimeFailure{}, errors.New("Phase AI runtime failure state is invalid")
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

func stopClaudeHookRuntime(ctx context.Context) error {
	directory, err := claudeHookRuntimeDir()
	if err != nil {
		return err
	}
	statePath := filepath.Join(directory, claudeRuntimeStateFile)
	lockPath := filepath.Join(directory, claudeRuntimeLockFile)
	state, err := readClaudeRuntimeState(statePath)
	if errors.Is(err, os.ErrNotExist) {
		lock, lockErr := readClaudeRuntimeLock(lockPath)
		if errors.Is(lockErr, os.ErrNotExist) {
			return nil
		}
		if lockErr != nil && !abandonedClaudeRuntimeLock(lockPath, lockErr) {
			return lockErr
		}
		if lock.PID > 0 && processIsAlive(lock.PID) {
			if time.Since(lock.CreatedAt) > 2*claudeHookStartTimeout && time.Since(lock.RecyclingAt) > 2*claudeHookStartTimeout {
				return errors.New("refusing to stop a live process from a stale Phase AI startup lock")
			}
			process, findErr := os.FindProcess(lock.PID)
			if findErr != nil {
				return findErr
			}
			if killErr := process.Kill(); killErr != nil {
				return killErr
			}
			if err := waitForClaudeProcessExit(ctx, lock.PID, time.Second); err != nil {
				return err
			}
		}
		return releaseClaudeRuntimeLock(lockPath, lock.Generation)
	}
	if err != nil {
		return err
	}
	return stopClaudeRuntimeState(ctx, directory, state)
}

func stopClaudeRuntimeState(ctx context.Context, directory string, state claudeRuntimeState) error {
	statePath := filepath.Join(directory, claudeRuntimeStateFile)
	lockPath := filepath.Join(directory, claudeRuntimeLockFile)
	lock, err := readClaudeRuntimeLock(lockPath)
	if err != nil || lock.Generation != state.Generation || lock.PID != state.PID {
		return errors.New("refusing to stop a Phase AI process without matching ownership state")
	}
	if err := probeClaudeRuntimeState(ctx, state, ""); err != nil {
		if !processIsAlive(state.PID) {
			_ = removeClaudeStateIfGeneration(statePath, state.Generation)
			_ = releaseClaudeRuntimeLock(lockPath, state.Generation)
			_ = removeClaudeLeasesForGeneration(directory, state.Generation)
			return nil
		}
		return errors.New("refusing to signal an owned PID whose authenticated Phase proxy is not healthy")
	}
	process, err := os.FindProcess(state.PID)
	if err != nil {
		return err
	}
	gracefulContext, gracefulCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	stopErr := stopClaudeProcessGracefully(gracefulContext, process, state)
	gracefulCancel()
	if stopErr != nil {
		if killErr := process.Kill(); killErr != nil {
			return fmt.Errorf("stop managed Phase AI runtime: %w", stopErr)
		}
	}
	if err := waitForClaudeProcessExit(ctx, state.PID, 2*time.Second); err != nil {
		if killErr := process.Kill(); killErr != nil {
			return err
		}
		if waitErr := waitForClaudeProcessExit(ctx, state.PID, time.Second); waitErr != nil {
			return waitErr
		}
	}
	_ = removeClaudeStateIfGeneration(statePath, state.Generation)
	_ = releaseClaudeRuntimeLock(lockPath, state.Generation)
	_ = removeClaudeLeasesForGeneration(directory, state.Generation)
	return nil
}

func waitForClaudeProcessExit(ctx context.Context, pid int, timeout time.Duration) error {
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

func removeClaudeLeasesForGeneration(directory, generation string) error {
	return withClaudeLeaseRegistryLock(context.Background(), directory, func() error {
		paths, err := filepath.Glob(filepath.Join(directory, claudeSessionLeasePrefix+"*"+claudeSessionLeaseSuffix))
		if err != nil {
			return err
		}
		for _, path := range paths {
			if err := withClaudeLeaseMutationLock(context.Background(), path, func() error {
				var lease claudeSessionLease
				if err := readOwnerOnlyJSON(path, &lease); err == nil && lease.Generation == generation {
					if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
						return err
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func init() {
	aiClaudeDaemonCmd.Flags().String("generation", "", "")
	aiCmd.AddCommand(aiClaudeHookCmd, aiClaudeDaemonCmd, aiClaudeEventCmd)
}
