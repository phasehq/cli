package phase

import (
	"errors"
	"os"
	"strings"

	"github.com/phasehq/cli/pkg/config"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
	"github.com/phasehq/golang-sdk/v2/phase/misc"
)

// SecretsBackend is what the secrets commands, run, apps list and init need
// from the active login. *sdk.Phase implements it for personal and service
// tokens, unchanged; *AgentBackend implements it for an Agent token through
// the Console's secrets API.
type SecretsBackend interface {
	Get(opts sdk.GetOptions) ([]sdk.SecretResult, error)
	Create(opts sdk.CreateOptions) error
	Update(opts sdk.UpdateOptions) error
	Delete(opts sdk.DeleteOptions) ([]string, error)
}

// Sentences for what an Agent login cannot do. Each is the whole message.
var (
	ErrAgentOverride       = errors.New("Personal overrides are not available to an Agent login.")
	ErrAgentShell          = errors.New("phase shell is not available to an Agent login. Use phase run <command> instead.")
	ErrAgentDynamicSecrets = errors.New("Dynamic secrets are not available to Agents yet.")
	ErrAgentOffline        = errors.New("Offline mode is not available to an Agent login: every call is checked by the Phase Console. Unset PHASE_OFFLINE and run the command again.")
)

// ActiveLoginIsAgent reports whether the login a command would use is an
// Agent token. It reads no credential: PHASE_SERVICE_TOKEN wins as it does in
// keyring.GetCredentials, otherwise the default user's recorded principal.
func ActiveLoginIsAgent() bool {
	if token := strings.TrimSpace(os.Getenv("PHASE_SERVICE_TOKEN")); token != "" {
		return strings.HasPrefix(token, "pss_agent:")
	}
	user, err := config.GetDefaultUser()
	return err == nil && user != nil && user.IsAgentPrincipal()
}

// NewBackend returns the backend for the active login.
func NewBackend() (SecretsBackend, error) {
	if ActiveLoginIsAgent() {
		return newAgentBackend()
	}
	p, err := NewPhase(true, "", "")
	if err != nil {
		return nil, err
	}
	return p, nil
}

// UserData lists the apps and environments the login can use, in the shape
// apps list and init render.
func UserData(backend SecretsBackend) (*misc.AppKeyResponse, error) {
	switch b := backend.(type) {
	case *AgentBackend:
		return b.UserData()
	case *sdk.Phase:
		return Init(b)
	default:
		return nil, errors.New("unsupported Phase login")
	}
}
