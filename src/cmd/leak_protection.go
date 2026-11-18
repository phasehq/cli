package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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

// leakRegister is the registration call; tests replace it.
var leakRegister = leakguard.Register

// leakWarnings is where warnings go; tests replace it. Never stdout, which
// may be what the command's output is piped into.
var leakWarnings io.Writer = os.Stderr

// inactiveNotice is printed at most once per process.
var inactiveNotice sync.Once

// protectValues registers values with the session's leak protection before
// the command hands them to anything outside the CLI. Inside a session, a
// failure refuses the command for an Agent login and warns otherwise. Outside
// one, an Agent login is told once that nothing is protected; it is not
// refused, since Agent tokens are used from shells that do not load the Phase
// environment.
func protectValues(ctx context.Context, agent bool, values []leakguard.Value) error {
	if len(values) == 0 {
		return nil
	}
	if !leakguard.Active() {
		if agent {
			inactiveNotice.Do(func() { fmt.Fprintln(leakWarnings, leakProtectionInactiveMsg) })
		}
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := leakRegister(ctx, values); err != nil {
		full := errors.Is(err, leakguard.ErrInventoryFull)
		switch {
		case agent && full:
			return errLeakInventoryFull
		case agent:
			return errLeakProtectionUnreachable
		case full:
			fmt.Fprintln(leakWarnings, leakInventoryFullWarning)
		default:
			fmt.Fprintln(leakWarnings, leakProtectionWarning)
		}
	}
	return nil
}

// protectSecrets registers the secrets a command is about to hand out. A
// secret's placeholder id is its Phase id when the backend knows it, otherwise
// its key name.
func protectSecrets(ctx context.Context, backend phase.SecretsBackend, secrets []sdk.SecretResult) error {
	_, agent := backend.(*phase.AgentBackend)
	active := leakguard.Active()
	if !active && !agent {
		return nil
	}
	values := make([]leakguard.Value, 0, len(secrets))
	for _, secret := range secrets {
		value := leakguard.Value{Type: secret.Type, ID: secret.Key, Value: secret.Value}
		if secret.IsDynamic {
			value.Type = "dynamic"
		}
		if typed, ok := backend.(*phase.AgentBackend); ok {
			if id := typed.SecretID(secret); id != "" {
				value.ID = id
			}
		}
		if !leakguard.Protectable(value.Type) {
			continue
		}
		values = append(values, value)
	}
	// Outside a session only the backend says whether this is an Agent login,
	// so nothing else is read for a command that registers nothing.
	if active && !agent {
		agent = phase.ActiveLoginIsAgent()
	}
	return protectValues(ctx, agent, values)
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
