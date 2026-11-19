package phase

import (
	"context"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/offline"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
)

// loginUsed is the login this command's backend was built from: the backend
// and the saved account its token was read for, "" for one from the environment.
var loginUsed struct {
	sync.Mutex
	backend  SecretsBackend
	account  string
	asked    bool
	identity phaseproxy.InventoryIdentity
}

func rememberLogin(backend SecretsBackend, account string) {
	loginUsed.Lock()
	defer loginUsed.Unlock()
	loginUsed.backend, loginUsed.account, loginUsed.asked = backend, account, false
}

// identityTimeout bounds asking the Console who a token from the
// environment is, before a command registers what it hands out.
const identityTimeout = 3 * time.Second

// LoginIdentity is who this command is: its backend's login, from its saved
// record or, for a token from the environment, the Console. Empty if unknown.
func LoginIdentity(ctx context.Context) phaseproxy.InventoryIdentity {
	loginUsed.Lock()
	defer loginUsed.Unlock()
	if !loginUsed.asked {
		loginUsed.identity, loginUsed.asked = loginIdentity(ctx, loginUsed.backend, loginUsed.account), true
	}
	return loginUsed.identity
}

func loginIdentity(ctx context.Context, backend SecretsBackend, account string) phaseproxy.InventoryIdentity {
	var host, kind string
	switch b := backend.(type) {
	case *AgentBackend:
		host, kind = b.client.Host(), agentapi.IdentityAgent
	case *sdk.Phase:
		host, kind = b.Host, agentapi.TokenType(b.TokenType).IdentityKind()
	default:
		return phaseproxy.InventoryIdentity{}
	}
	if account != "" {
		return savedIdentity(host, kind, account)
	}
	if offline.IsOffline() {
		return phaseproxy.InventoryIdentity{}
	}
	// The Console is asked off this goroutine: the SDK's call takes no context.
	answered := make(chan phaseproxy.InventoryIdentity, 1)
	go func() { answered <- consoleIdentity(ctx, backend, host, kind) }()
	select {
	case identity := <-answered:
		return identity
	case <-ctx.Done():
	case <-time.After(identityTimeout):
	}
	return phaseproxy.InventoryIdentity{}
}

// savedIdentity is the identity of a saved login, as its own record holds it.
func savedIdentity(host, kind, account string) phaseproxy.InventoryIdentity {
	saved, err := config.LoadConfig()
	if err != nil {
		return phaseproxy.InventoryIdentity{}
	}
	for _, user := range saved.PhaseUsers {
		if user.ID != account {
			continue
		}
		return SavedLoginIdentity(host, kind, user)
	}
	return phaseproxy.InventoryIdentity{}
}

// SavedLoginIdentity is the identity a saved login has at host when its
// token is of kind. A record that is not that kind's names nobody.
func SavedLoginIdentity(host, kind string, user config.UserConfig) phaseproxy.InventoryIdentity {
	id := user.ID
	if user.IsAgentPrincipal() {
		id = user.PrincipalID
	}
	if user.OrganizationID == nil || user.IsAgentPrincipal() != (kind == agentapi.IdentityAgent) {
		return phaseproxy.InventoryIdentity{}
	}
	return phaseproxy.NewInventoryIdentity(host, *user.OrganizationID, kind, id)
}

// consoleIdentity asks the Console who the backend's token is.
func consoleIdentity(ctx context.Context, backend SecretsBackend, host, kind string) phaseproxy.InventoryIdentity {
	switch b := backend.(type) {
	case *AgentBackend:
		asked, cancel := context.WithTimeout(ctx, identityTimeout)
		defer cancel()
		who, err := b.client.Identity(asked)
		if err != nil {
			return phaseproxy.InventoryIdentity{}
		}
		return phaseproxy.NewInventoryIdentity(host, who.Organization.ID, kind, who.Agent.ID)
	case *sdk.Phase:
		data, err := Init(b)
		if err != nil || data.Organisation == nil {
			return phaseproxy.InventoryIdentity{}
		}
		id := data.UserID
		if kind == agentapi.IdentityServiceAccount {
			id = data.AccountID
		}
		return phaseproxy.NewInventoryIdentity(host, data.Organisation.ID, kind, id)
	}
	return phaseproxy.InventoryIdentity{}
}
