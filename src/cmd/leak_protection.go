package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/pkg/phase"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
)

// errLeakProtectionUnreachable is the whole message an Agent login gets when
// its values cannot be protected. An Agent is given real values by export and
// run only because the proxy removes them from model traffic.
var errLeakProtectionUnreachable = errors.New("Phase could not reach leak protection, so no secret values were handed out. Run phase ai status to see why.")

// errLeakInventoryFull is the Agent's message when the proxy answered but
// holds as many values as it can.
var errLeakInventoryFull = errors.New("Phase's leak protection inventory is full, so no secret values were handed out. Restarting the Phase AI proxy clears it.")

const (
	leakProtectionWarning     = "Phase: leak protection could not be reached, so values from this command are not removed from model traffic. Run phase ai status to see why."
	leakInventoryFullWarning  = "Phase: the leak protection inventory is full, so values from this command are not removed from model traffic. Restarting the Phase AI proxy clears it."
	leakProtectionInactiveMsg = "Phase: leak protection is not active in this shell, so values from this command are not removed from model traffic."
	// The first two for the hook-managed proxy when it is one of several
	// proxies the command found. Another proxy may have taken the values, so
	// the line names this one and speaks of the model traffic it reads only.
	leakHookProxyWarning     = "Phase: the hook-managed Phase AI proxy could not be reached, so values from this command are not removed from the model traffic it reads. Run phase ai status to see why."
	leakHookProxyFullWarning = "Phase: the leak protection inventory of the hook-managed Phase AI proxy is full, so values from this command are not removed from the model traffic it reads. Restarting the Phase AI proxy clears it."
)

// unprotectedWarning says how many of a command's values leak protection
// could not take, and never which: a value too short or plain to tell from
// ordinary text is handed out all the same.
func unprotectedWarning(count int) string {
	if count == 1 {
		return "Phase: 1 value from this command is too short or plain to protect, so it is not removed from model traffic."
	}
	return fmt.Sprintf("Phase: %d values from this command are too short or plain to protect, so they are not removed from model traffic.", count)
}

// leakRuntimeSource names the source that finds the hook-managed proxy from
// the runtime state on disk.
const leakRuntimeSource = "runtime"

// leakProxyWarning is what a failed registration says of a proxy that is not
// the session's own: unreachable and full when it is the only proxy the
// command found, and the two that name it when it is one of several.
type leakProxyWarning struct {
	unreachable, full           string
	namedUnreachable, namedFull string
}

// leakProxyWarnings holds those lines by the source that found the proxy. A
// source that is not here speaks as the hook-managed proxy does on its own.
var leakProxyWarnings = map[string]leakProxyWarning{
	leakRuntimeSource: {leakProtectionWarning, leakInventoryFullWarning, leakHookProxyWarning, leakHookProxyFullWarning},
}

// The session's own environment is leakguard's first source. The proxy the
// harness hooks keep running is the second: a command in a shell that does
// not load the Phase environment (Codex's and Cursor's shells, another
// terminal) still hands out values a harness on this machine can read. So
// can a command inside a session, which is why every source is asked and
// every proxy found is registered with. A later source, such as the phase up
// engine, is one more AddSource and one more entry in leakProxyWarnings.
func init() {
	leakguard.AddSource(leakguard.Source{Name: leakRuntimeSource, Find: hookRuntimeProxy, Restarting: hookRuntimeRestarting})
}

// leakRuntimeStat is the file check a command pays when no proxy runs, once
// for the runtime state and once for the runtime lock; tests count it.
var leakRuntimeStat = os.Lstat

// hookRuntimeProxy finds the hook-managed proxy the way phase ai status does:
// from the runtime state, when the process that wrote it is alive. With no
// state file it costs one stat, and it never touches the network.
func hookRuntimeProxy() (string, bool) {
	directory, err := hookRuntimeDir()
	if err != nil {
		return "", false
	}
	path := filepath.Join(directory, hookRuntimeStateFile)
	if _, err := leakRuntimeStat(path); err != nil {
		return "", false
	}
	state, err := readHookRuntimeState(path)
	if err != nil || validateHookRuntimeState(state, "") != nil {
		return "", false
	}
	return state.ProxyURL, true
}

// hookRuntimeRestarting reports a hook daemon that runs and has no proxy to
// register with at this moment. Each time it recycles its session the daemon
// closes its listener, some seconds later withdraws its state, and publishes
// it again once the Console has answered; while it starts there is a lock and
// no state yet. A value handed out in such a gap would never reach the
// inventory the daemon comes back with, so the gap is not taken for no proxy:
// the registration waits for it (leakguard.Proxy.Register).
//
// The runtime lock tells. Its process is alive, and either it is starting or
// recycling (what inspectHookRuntime calls starting), or it still owns the
// state it published: the seconds between its listener closing and its state
// going. With no lock file, as on any machine with no daemon, this costs one
// more stat and nothing is waited for. Liveness is all there is to go by, so
// a lock and state left by a daemon that was killed, whose process id another
// program holds by now, read as a daemon between two sessions.
func hookRuntimeRestarting() bool {
	directory, err := hookRuntimeDir()
	if err != nil {
		return false
	}
	path := filepath.Join(directory, hookRuntimeLockFile)
	if _, err := leakRuntimeStat(path); err != nil {
		return false
	}
	lock, err := readHookRuntimeLock(path)
	if err != nil {
		return false
	}
	if hookRuntimeStarting(lock) {
		return true
	}
	state, err := readHookRuntimeState(filepath.Join(directory, hookRuntimeStateFile))
	return err == nil && lock.PID > 0 && state.PID == lock.PID && state.Generation == lock.Generation && processIsAlive(lock.PID)
}

// leakLocate finds the proxies to register with, and leakRegister registers
// with one of them; tests replace them.
var (
	leakLocate   = leakguard.Locate
	leakRegister = func(ctx context.Context, proxy leakguard.Proxy, values []leakguard.Value) (leakguard.Result, error) {
		return proxy.Register(ctx, values)
	}
)

// leakWarnings is where warnings go; tests replace it. Never stdout, which
// may be what the command's output is piped into.
var leakWarnings io.Writer = os.Stderr

// oncePerSource runs what it is given at most once in a process for each
// source.
type oncePerSource struct {
	mu   sync.Mutex
	done map[string]bool
}

func (o *oncePerSource) Do(source string, run func()) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done[source] {
		return
	}
	if o.done == nil {
		o.done = map[string]bool{}
	}
	o.done[source] = true
	run()
}

// inactiveNotice is printed at most once per process, and so is the warning
// about each proxy that is not the session's own.
var (
	inactiveNotice sync.Once
	proxyWarning   oncePerSource
)

// protectValues registers values with leak protection before the command
// hands them to anything outside the CLI.
func protectValues(ctx context.Context, agent bool, values []leakguard.Value) error {
	if len(values) == 0 {
		return nil
	}
	return protectValuesWith(ctx, leakLocate(), agent, values)
}

// noProxyRunning is what a command does when there is no proxy to register
// with: an Agent login is told once that nothing is protected, and nobody
// else is told anything. An Agent login is not refused, since Agent tokens
// are used from shells that do not load the Phase environment.
func noProxyRunning(agent bool) {
	if agent {
		inactiveNotice.Do(func() { fmt.Fprintln(leakWarnings, leakProtectionInactiveMsg) })
	}
}

// inSession reports proxies found by a command that runs inside a session:
// the session's own proxy is then the first of them.
func inSession(proxies []leakguard.Proxy) bool {
	return len(proxies) > 0 && proxies[0].InSession()
}

// protectValuesWith registers values with every proxy that was found, one
// after another, and says what a failure means:
//   - the session's own proxy comes first and decides for the command: a
//     failure refuses it for an Agent login, before any other proxy is
//     spoken to, and warns otherwise. What the command hands out is in front
//     of the model;
//   - every other proxy is registered with as well, inside a session or not:
//     it reads the model traffic of tools the session's proxy never sees. A
//     failure there warns once and never refuses, whoever is logged in: the
//     command may have nothing to do with an AI tool. When it is one of
//     several proxies the warning names it;
//   - such a proxy that nothing listens at is no proxy: the state that named
//     it is stale, or its process id went to another program. Warning then
//     would warn on every command, in every shell. Nothing listens where the
//     connection is refused or is not made within the registration's short
//     dial timeout, which is how it shows where the system is slow to
//     refuse, as Windows can be (leakguard.ErrNotListening);
//   - unless its daemon is starting or recycling its session: the
//     registration has then waited for it (hookRuntimeRestarting), and a
//     daemon that did not come back in time is a proxy that could not be
//     reached, not one that is not running;
//   - with no proxy at all, or none that runs, see noProxyRunning.
//
// Values a proxy took the registration of and could not protect are counted
// in a warning and handed out all the same. Every proxy is sent the same
// values, so the warning is given once, with the most any of them counted.
//
// What the registrations may take in all is leakguard's to bound: the first
// has a registration's usual time and each one after it what is left of that
// (leakguard.Proxy.Register).
func protectValuesWith(ctx context.Context, proxies []leakguard.Proxy, agent bool, values []leakguard.Value) error {
	if len(values) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// running says some proxy runs: it took the values, or was there and
	// did not. unprotected is the most values any of them could not protect.
	running, unprotected := false, 0
	for _, proxy := range proxies {
		result, err := leakRegister(ctx, proxy, values)
		full := errors.Is(err, leakguard.ErrInventoryFull)
		switch {
		case err == nil:
			running = true
			unprotected = max(unprotected, result.Unprotected)
		case proxy.InSession() && agent && full:
			return errLeakInventoryFull
		case proxy.InSession() && agent:
			return errLeakProtectionUnreachable
		case proxy.InSession():
			running = true
			if full {
				fmt.Fprintln(leakWarnings, leakInventoryFullWarning)
			} else {
				fmt.Fprintln(leakWarnings, leakProtectionWarning)
			}
		case errors.Is(err, leakguard.ErrNotListening):
			// Nothing listens where its state points: no proxy runs there.
		default:
			running = true
			warning := failedProxyWarning(proxy.Source, len(proxies) > 1, full)
			proxyWarning.Do(proxy.Source, func() { fmt.Fprintln(leakWarnings, warning) })
		}
	}
	if unprotected > 0 {
		fmt.Fprintln(leakWarnings, unprotectedWarning(unprotected))
	}
	if !running {
		noProxyRunning(agent)
	}
	return nil
}

// failedProxyWarning is the line for a failed registration with the proxy a
// source other than the session's found. several says the command found
// more than one proxy, and full that this one's inventory is.
func failedProxyWarning(source string, several, full bool) string {
	lines, known := leakProxyWarnings[source]
	if !known {
		lines = leakProxyWarnings[leakRuntimeSource]
		several = false
	}
	switch {
	case several && full:
		return lines.namedFull
	case several:
		return lines.namedUnreachable
	case full:
		return lines.full
	}
	return lines.unreachable
}

// protectSecrets registers the secrets a command is about to hand out. A
// secret's placeholder id is its Phase id when the backend knows it, otherwise
// its key name, and the registration says which it is.
func protectSecrets(ctx context.Context, backend phase.SecretsBackend, secrets []sdk.SecretResult) error {
	typed, agent := backend.(*phase.AgentBackend)
	proxies := leakLocate()
	if len(proxies) == 0 && !agent {
		return nil
	}
	values := make([]leakguard.Value, 0, len(secrets))
	for _, secret := range secrets {
		value := leakguard.Value{Type: secret.Type, ID: secret.Key, KeyName: true, Value: secret.Value}
		if secret.IsDynamic {
			value.Type = "dynamic"
		}
		if agent {
			if id := typed.SecretID(secret); id != "" {
				value.ID, value.KeyName = id, false
			}
		}
		if !leakguard.Protectable(value.Type) {
			continue
		}
		values = append(values, value)
	}
	// Only a session treats an Agent login differently, and outside one only
	// the backend says whether this is an Agent login, so nothing else is read
	// for a command that registers nothing.
	if inSession(proxies) && !agent {
		agent = phase.ActiveLoginIsAgent()
	}
	return protectValuesWith(ctx, proxies, agent, values)
}

// protectLeaseCredentials registers the credentials of the leases in a
// dynamic secrets response, each under its lease id.
func protectLeaseCredentials(ctx context.Context, payload []byte) error {
	var root any
	if json.Unmarshal(payload, &root) != nil {
		return nil
	}
	var values []leakguard.Value
	collectLeaseCredentials(root, &values, 0)
	if len(values) == 0 {
		return nil
	}
	return protectValues(ctx, phase.ActiveLoginIsAgent(), values)
}

func collectLeaseCredentials(node any, values *[]leakguard.Value, depth int) {
	if depth > 8 {
		return
	}
	switch value := node.(type) {
	case []any:
		for _, item := range value {
			collectLeaseCredentials(item, values, depth+1)
		}
	case map[string]any:
		if lease, ok := value["lease"].(map[string]any); ok {
			id, _ := lease["id"].(string)
			credentials, _ := lease["credentials"].([]any)
			for _, raw := range credentials {
				credential, _ := raw.(map[string]any)
				secret, _ := credential["value"].(string)
				if secret != "" {
					// A lease's id is the Console's own.
					*values = append(*values, leakguard.Value{Type: "dynamic", ID: id, Value: secret})
				}
			}
		}
		for key, item := range value {
			if key != "lease" {
				collectLeaseCredentials(item, values, depth+1)
			}
		}
	}
}
