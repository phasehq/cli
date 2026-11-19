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
)

// leakRuntimeSource names the source that finds the hook-managed proxy from
// the runtime state on disk.
const leakRuntimeSource = "runtime"

// The session's own environment is leakguard's first source. The proxy the
// harness hooks keep running is the second: a command in a shell that does
// not load the Phase environment (Codex's and Cursor's shells, another
// terminal) still hands out values a harness on this machine can read. A
// later source, such as the phase up engine, is one more AddSource.
func init() {
	leakguard.AddSource(leakguard.Source{Name: leakRuntimeSource, Find: hookRuntimeProxy})
}

// leakRuntimeStat is the one file check a command pays when no proxy runs;
// tests count it.
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

// leakLocate finds the proxy to register with, and leakRegister registers
// with it; tests replace them.
var (
	leakLocate   = leakguard.Locate
	leakRegister = func(ctx context.Context, proxy leakguard.Proxy, values []leakguard.Value) (leakguard.Result, error) {
		return proxy.Register(ctx, values)
	}
)

// leakWarnings is where warnings go; tests replace it. Never stdout, which
// may be what the command's output is piped into.
var leakWarnings io.Writer = os.Stderr

// inactiveNotice and runtimeWarning are each printed at most once per process.
var inactiveNotice, runtimeWarning sync.Once

// protectValues registers values with leak protection before the command
// hands them to anything outside the CLI.
func protectValues(ctx context.Context, agent bool, values []leakguard.Value) error {
	if len(values) == 0 {
		return nil
	}
	proxy, found := leakLocate()
	return protectValuesWith(ctx, proxy, found, agent, values)
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

// protectValuesWith registers values with the proxy that was found, and says
// what a failure means:
//   - inside a session, a failure refuses the command for an Agent login and
//     warns otherwise: what the command hands out is in front of the model;
//   - a proxy found any other way is registered with as well, and a failure
//     there warns once and never refuses, whoever is logged in: the command
//     may have nothing to do with an AI tool;
//   - a proxy found any other way that nothing listens at is no proxy: the
//     state that named it is stale, or its process id went to another
//     program. Warning then would warn on every command, in every shell;
//   - with no proxy at all, see noProxyRunning.
func protectValuesWith(ctx context.Context, proxy leakguard.Proxy, found, agent bool, values []leakguard.Value) error {
	if len(values) == 0 {
		return nil
	}
	if !found {
		noProxyRunning(agent)
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	_, err := leakRegister(ctx, proxy, values)
	if err == nil {
		return nil
	}
	if !proxy.InSession() && errors.Is(err, leakguard.ErrNotListening) {
		noProxyRunning(agent)
		return nil
	}
	full := errors.Is(err, leakguard.ErrInventoryFull)
	warning := leakProtectionWarning
	if full {
		warning = leakInventoryFullWarning
	}
	switch {
	case !proxy.InSession():
		runtimeWarning.Do(func() { fmt.Fprintln(leakWarnings, warning) })
	case agent && full:
		return errLeakInventoryFull
	case agent:
		return errLeakProtectionUnreachable
	default:
		fmt.Fprintln(leakWarnings, warning)
	}
	return nil
}

// protectSecrets registers the secrets a command is about to hand out. A
// secret's placeholder id is its Phase id when the backend knows it, otherwise
// its key name, and the registration says which it is.
func protectSecrets(ctx context.Context, backend phase.SecretsBackend, secrets []sdk.SecretResult) error {
	typed, agent := backend.(*phase.AgentBackend)
	proxy, found := leakLocate()
	if !found && !agent {
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
	if found && proxy.InSession() && !agent {
		agent = phase.ActiveLoginIsAgent()
	}
	return protectValuesWith(ctx, proxy, found, agent, values)
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
