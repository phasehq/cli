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
	harnessRuntimeCycleWait = hookRecycleTimeout
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

var aiHarnessExecCmd = &cobra.Command{
	Use:           "__harness-exec",
	Hidden:        true,
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runAIHarnessExec,
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
	if errors.Is(err, errRuntimeAuthenticationRequired) || errors.Is(err, airuntime.ErrAuthenticationRequired) {
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
	directory, err := hookRuntimeDir()
	if err == nil {
		fingerprint, fingerprintErr := hookFingerprint()
		scopeFingerprint, scopeFingerprintErr := hookScopeFingerprint()
		state, stateErr := readHookRuntimeState(filepath.Join(directory, hookRuntimeStateFile))
		if fingerprintErr == nil && scopeFingerprintErr == nil && stateErr == nil &&
			state.RuntimeFingerprint == fingerprint && state.RuntimeScopeFingerprint == scopeFingerprint &&
			probeHookRuntimeState(ctx, state, fingerprint) == nil {
			return nil
		}
	}
	_, err = hookEnsureRuntime(ctx)
	return err
}

func registerHarnessLease(harness, sessionID string, expiresAt time.Time) error {
	directory, err := hookRuntimeDir()
	if err != nil {
		return err
	}
	leaseID := harnessLeaseID(harness, sessionID)
	path, err := sessionLeasePath(directory, leaseID)
	if err != nil {
		return err
	}
	return withLeaseRegistryLock(context.Background(), directory, func() error {
		state, err := readHookRuntimeState(filepath.Join(directory, hookRuntimeStateFile))
		generation := state.Generation
		if errors.Is(err, os.ErrNotExist) {
			// A daemon still starting has no state yet; its lock names the
			// generation whose lease monitor will count this lease.
			lock, lockErr := readHookRuntimeLock(filepath.Join(directory, hookRuntimeLockFile))
			if lockErr != nil || lock.Generation == "" || lock.PID <= 0 || !processIsAlive(lock.PID) {
				return err
			}
			generation, err = lock.Generation, nil
		}
		if err != nil {
			return err
		}
		return writeOwnerOnlyJSON(path, sessionLease{
			Version: hookRuntimeStateVersion, Generation: generation,
			UpdatedAt: time.Now().UTC(), ExpiresAt: expiresAt,
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
// run a quoted executable path; Cursor uses its default terminal profile, and
// OpenCode $SHELL or else PowerShell.
func harnessWrapperCommandLine(goos, harness string, arguments []string) string {
	if goos == "windows" {
		switch {
		case harness == ai.HarnessCodex, harness == ai.HarnessCursor && !cursorWindowsShellIsBashOrCmd(cursorWindowsSettings()):
			return ai.PowerShellCallCommand(arguments)
		case harness == ai.HarnessCursor, harness == ai.HarnessOpenCode && windowsShellIsBashOrCmd(os.Getenv("SHELL")):
			if line, ok := ai.WindowsPlainCommand(arguments); ok {
				return line
			}
			return quoteWindowsCommand(arguments)
		}
		return ai.WindowsShellCommand(arguments)
	}
	quoted := make([]string, len(arguments))
	for index, argument := range arguments {
		quoted[index] = ai.QuotePOSIXShell(argument)
	}
	return strings.Join(quoted, " ")
}

// windowsShellIsBashOrCmd reports a shell path naming a POSIX shell or cmd.
func windowsShellIsBashOrCmd(shell string) bool {
	switch strings.TrimSuffix(strings.ToLower(filepath.Base(strings.ReplaceAll(shell, `\`, "/"))), ".exe") {
	case "bash", "sh", "zsh", "dash", "ksh", "cmd":
		return true
	}
	return false
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
	lease     sessionLease
	lock      hookRuntimeLock
}

func loadHarnessRuntimePlan(ctx context.Context, leaseID string) (phaseproxy.ProcessEnvironmentPlan, error) {
	binding, err := readHarnessRuntimeBinding(leaseID)
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, errors.New("Phase AI session is not authorized")
	}
	statePath := filepath.Join(binding.directory, hookRuntimeStateFile)
	state, err := readHookRuntimeState(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return waitForHarnessRuntimeCycle(ctx, binding, nil, fmt.Errorf("%w: runtime state is cycling", errHookRuntimeRefreshing))
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
	directory, err := hookRuntimeDir()
	if err != nil {
		return binding, err
	}
	leasePath, err := sessionLeasePath(directory, leaseID)
	if err != nil {
		return binding, err
	}
	var lease sessionLease
	if err := readOwnerOnlyJSON(leasePath, &lease); err != nil || !validHarnessRuntimeLease(lease, time.Now().UTC()) {
		return binding, errors.New("Phase AI harness lease is unavailable")
	}
	lock, err := readHookRuntimeLock(filepath.Join(directory, hookRuntimeLockFile))
	if err != nil || lock.Version != hookRuntimeStateVersion || lock.Generation != lease.Generation ||
		lock.PID <= 0 || lock.CreatedAt.IsZero() || !processIsAlive(lock.PID) {
		return binding, errors.New("Phase AI runtime ownership is unavailable")
	}
	return harnessRuntimeBinding{directory: directory, leasePath: leasePath, lease: lease, lock: lock}, nil
}

func validHarnessRuntimeLease(lease sessionLease, now time.Time) bool {
	return lease.Version == hookRuntimeStateVersion && lease.Generation != "" &&
		!lease.UpdatedAt.IsZero() && !lease.UpdatedAt.After(now) &&
		now.Sub(lease.UpdatedAt) <= hookLeaseMaxAge &&
		(lease.ExpiresAt.IsZero() || now.Before(lease.ExpiresAt)) &&
		(lease.Purpose == "" || lease.Purpose == harnessCommandLeasePurpose)
}

func validateHarnessRuntimeBinding(binding harnessRuntimeBinding) error {
	var lease sessionLease
	if err := readOwnerOnlyJSON(binding.leasePath, &lease); err != nil ||
		lease.Generation != binding.lease.Generation || !validHarnessRuntimeLease(lease, time.Now().UTC()) {
		return errors.New("Phase AI harness lease changed during runtime refresh")
	}
	lock, err := readHookRuntimeLock(filepath.Join(binding.directory, hookRuntimeLockFile))
	if err != nil || lock.Version != binding.lock.Version || lock.Generation != binding.lock.Generation ||
		lock.PID != binding.lock.PID || !lock.CreatedAt.Equal(binding.lock.CreatedAt) || !processIsAlive(lock.PID) {
		return errors.New("Phase AI runtime ownership changed during refresh")
	}
	return nil
}

func harnessStateMatchesBinding(state hookRuntimeState, binding harnessRuntimeBinding) bool {
	return state.Version == hookRuntimeStateVersion && state.Generation == binding.lock.Generation &&
		state.PID == binding.lock.PID && state.RuntimeFingerprint != "" && state.ProxyURL != "" &&
		!state.StartedAt.IsZero() && processIsAlive(state.PID)
}

func sameHarnessRuntimeState(left, right hookRuntimeState) bool {
	return left.Version == right.Version && left.Generation == right.Generation &&
		left.RuntimeFingerprint == right.RuntimeFingerprint && left.PID == right.PID &&
		left.StartedAt.Equal(right.StartedAt) && left.ProxyURL == right.ProxyURL
}

func loadAndConfirmHarnessRuntimePlan(ctx context.Context, binding harnessRuntimeBinding, state hookRuntimeState) (phaseproxy.ProcessEnvironmentPlan, error) {
	plan, err := loadHookRuntimePlan(ctx, state, state.RuntimeFingerprint)
	if err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	if err := validateHarnessRuntimeBinding(binding); err != nil {
		return phaseproxy.ProcessEnvironmentPlan{}, err
	}
	current, err := readHookRuntimeState(filepath.Join(binding.directory, hookRuntimeStateFile))
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

func waitForHarnessRuntimeCycle(ctx context.Context, binding harnessRuntimeBinding, previous *hookRuntimeState, initialErr error) (phaseproxy.ProcessEnvironmentPlan, error) {
	waitContext, cancel := context.WithTimeout(ctx, harnessRuntimeCycleWait)
	defer cancel()
	ticker := time.NewTicker(harnessRuntimeCyclePoll)
	defer ticker.Stop()
	statePath := filepath.Join(binding.directory, hookRuntimeStateFile)
	for {
		if err := validateHarnessRuntimeBinding(binding); err != nil {
			return phaseproxy.ProcessEnvironmentPlan{}, initialErr
		}
		state, err := readHookRuntimeState(statePath)
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
			if errors.Is(initialErr, errHookRuntimeRefreshing) || harnessExplicitManifestRefresh(initialErr) {
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

// harnessExecAllowed is the guard the hook ran before wrapping the command.
// The wrapper runs it again, since anything holding a lease can call it.
var harnessExecAllowed = shellCommandRequiresPhase

func runAIHarnessExec(cmd *cobra.Command, _ []string) error {
	harness, _ := cmd.Flags().GetString("harness")
	encodedLease, _ := cmd.Flags().GetString("lease")
	encodedCommand, _ := cmd.Flags().GetString("command")
	if harness != ai.HarnessClaudeCode && harness != ai.HarnessCodex && harness != ai.HarnessCursor && harness != ai.HarnessOpenCode {
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
	if !harnessExecAllowed(string(commandBytes)) {
		return errors.New("Phase AI wrapped command is not a single plain Phase call")
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
	random, err := randomRuntimeGeneration()
	if err != nil {
		return "", nil, err
	}
	sessionID := "command:" + random
	leaseID := harnessLeaseID(harness, sessionID)
	directory, err := hookRuntimeDir()
	if err != nil {
		return "", nil, err
	}
	path, err := sessionLeasePath(directory, leaseID)
	if err != nil {
		return "", nil, err
	}

	var generation string
	var ownerPID int
	var ownerCreatedAt time.Time
	register := func(initial bool) error {
		return withLeaseRegistryLock(context.Background(), directory, func() error {
			state, err := readHookRuntimeState(filepath.Join(directory, hookRuntimeStateFile))
			if err != nil || state.RuntimeFingerprint == "" || state.StartedAt.IsZero() ||
				validateHookRuntimeState(state, state.RuntimeFingerprint) != nil {
				return errActiveHookRuntimeUnavailable
			}
			if requiredScope != "" && state.RuntimeScopeFingerprint != requiredScope {
				return errActiveHookRuntimeUnavailable
			}
			lock, err := readHookRuntimeLock(filepath.Join(directory, hookRuntimeLockFile))
			if err != nil || lock.Version != hookRuntimeStateVersion || lock.Generation != state.Generation ||
				lock.PID != state.PID || lock.CreatedAt.IsZero() || !processIsAlive(lock.PID) {
				return errActiveHookRuntimeUnavailable
			}
			if !initial && (state.Generation != generation || lock.PID != ownerPID || !lock.CreatedAt.Equal(ownerCreatedAt)) {
				return errActiveHookRuntimeUnavailable
			}
			if initial {
				generation, ownerPID, ownerCreatedAt = state.Generation, lock.PID, lock.CreatedAt
			}
			if !initial {
				var current sessionLease
				if err := readOwnerOnlyJSON(path, &current); err != nil ||
					current.Generation != generation || current.Purpose != harnessCommandLeasePurpose {
					return errActiveHookRuntimeUnavailable
				}
			}
			return writeOwnerOnlyJSON(path, sessionLease{
				Version: hookRuntimeStateVersion, Generation: generation,
				UpdatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(harnessCommandLeaseTTL),
				Purpose: harnessCommandLeasePurpose,
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
			_ = withLeaseRegistryLock(context.Background(), directory, func() error {
				var current sessionLease
				if err := readOwnerOnlyJSON(path, &current); err != nil {
					return nil
				}
				if current.Generation == generation && current.Purpose == harnessCommandLeasePurpose {
					_ = os.Remove(path)
				}
				return nil
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

// windowsPowerShellPrelude drops Windows PowerShell's curl and wget aliases of
// Invoke-WebRequest, which ignores HTTP(S)_PROXY.
const windowsPowerShellPrelude = "Remove-Item -Path Alias:curl, Alias:wget -Force -ErrorAction SilentlyContinue; "

// windowsPowerShellEpilogue exits with a failed native command's own status;
// -Command alone reports every failure as 1.
const windowsPowerShellEpilogue = "\nif (-not $?) { if ($LASTEXITCODE) { exit $LASTEXITCODE }; exit 1 }"

func executeHarnessShell(ctx context.Context, command string, environment []string, stdin io.Reader, stdout, stderr io.Writer) error {
	shell := util.GetDefaultShell()
	if len(shell) == 0 {
		return errors.New("default shell is unavailable")
	}
	arguments := []string{"-c", command}
	if runtime.GOOS == "windows" {
		base := strings.ToLower(shell[0])
		if strings.Contains(base, "powershell") || strings.Contains(base, "pwsh") {
			arguments = []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", windowsPowerShellPrelude + command + windowsPowerShellEpilogue}
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

func init() {
	aiHarnessExecCmd.Flags().String("harness", "", "")
	aiHarnessExecCmd.Flags().String("lease", "", "")
	aiHarnessExecCmd.Flags().String("command", "", "")
	aiCmd.AddCommand(aiHarnessExecCmd)
}
