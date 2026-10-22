package aiproxy

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// A selection is carried by one authenticated client, never stored as a
// workflow-wide default. Concurrent commands can therefore select identities
// at the same upstream host without affecting each other.
func (s *runtimeState) connectionByID(id string) *binding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.availabilityLocked(time.Now()) != nil {
		return nil
	}
	for _, b := range s.bindings {
		if b.connection.ConnectionID == id {
			return b
		}
	}
	return nil
}

func (s *runtimeState) selectProtocolBinding(protocol, username, decoy, grantID string) (protocolBindingSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.availabilityLocked(time.Now()); err != nil {
		return protocolBindingSnapshot{}, err
	}
	var selected *binding
	for _, b := range s.bindings {
		if b.connection.Protocol != protocol {
			continue
		}
		if grantID != "" && b.connection.GrantID != grantID {
			continue
		}
		matched := protocolCredentialsMatch(b.connection, username, decoy)
		if !matched {
			// A client bootstrapped from an earlier backend session still
			// presents that session's decoy; see decoyHistory.
			for _, previous := range s.decoys.previous(b.connection) {
				if protocolCredentialsMatch(previous, username, decoy) {
					matched = true
					break
				}
			}
		}
		if !matched {
			continue
		}
		if selected != nil {
			return protocolBindingSnapshot{}, errors.New("ambiguous protocol credentials")
		}
		selected = b
	}
	if selected == nil {
		return protocolBindingSnapshot{}, errors.New("invalid protocol credentials")
	}
	return newProtocolBindingSnapshot(selected, s.generation), nil
}

// protocolCredentialsMatch reports whether a protocol client presented the
// Agent-visible username and decoy password of one credential generation.
func protocolCredentialsMatch(connection agentapi.Connection, username, decoy string) bool {
	field := tcpRoleField(connection.Injection.ValueFrom.Fields, "username")
	identifier, ok := agentapi.LookupMaterial(connection.Identifiers, field)
	if !ok || identifier != username {
		return false
	}
	expected := connection.DecoyMaterial["password"]
	return expected != "" && len(expected) == len(decoy) && subtle.ConstantTimeCompare([]byte(expected), []byte(decoy)) == 1
}

type connectionEnvironmentResponse struct {
	SchemaVersion      int                               `json:"schemaVersion"`
	ConnectionID       string                            `json:"connectionId"`
	ConfigGeneration   int                               `json:"configGeneration"`
	ProcessEnvironment phaseproxy.ProcessEnvironmentPlan `json:"processEnvironment"`
}

type connectionEnvironmentCompiler struct {
	session  *airuntime.ProxySession
	proxyURL string
	base     []string
	adapters map[string]string
}

func (c *connectionEnvironmentCompiler) compile(state *runtimeState, id string) (connectionEnvironmentResponse, error) {
	state.mu.RLock()
	if err := state.availabilityLocked(time.Now()); err != nil {
		state.mu.RUnlock()
		return connectionEnvironmentResponse{}, err
	}
	var chosen *agentapi.Connection
	for _, b := range state.bindings {
		if b.connection.ConnectionID == id {
			copy := b.connection
			copy.SecretMaterial = b.connection.SecretMaterial.Copy()
			chosen = &copy
			break
		}
	}
	configEnv := cloneStringMap(state.configEnv)
	generation := state.generation
	state.mu.RUnlock()
	if chosen == nil {
		return connectionEnvironmentResponse{}, errors.New("selected Connection is unavailable")
	}
	defer chosen.SecretMaterial.Destroy()
	// Authorization remains enforced at each credential injection/authentication;
	// supplying a decoy plan does not authorize the upstream operation.
	proxyURL, err := url.Parse(c.proxyURL)
	if err != nil {
		return connectionEnvironmentResponse{}, errors.New("invalid proxy endpoint")
	}
	capability, _ := proxyURL.User.Password()
	proxyURL.User = url.UserPassword("phase."+id, capability)
	config := *c.session.Config
	config.ConfigEnv = configEnv
	config.Connections = []agentapi.Connection{*chosen}
	session := *c.session
	session.Config = &config
	adapters := make(map[string]string)
	prefix := ""
	switch chosen.Protocol {
	case "postgres":
		prefix = "PG"
	}
	for key, value := range c.adapters {
		if prefix != "" && strings.HasPrefix(key, prefix) {
			adapters[key] = value
		}
	}
	if chosen.Protocol == "postgres" {
		adapters["PGPASSWORD"] = chosen.DecoyMaterial["password"]
	}
	plan, err := session.CompileProcessEnvironment(proxyURL.String(), c.base, adapters)
	if err != nil {
		return connectionEnvironmentResponse{}, err
	}
	return connectionEnvironmentResponse{SchemaVersion: agentapi.SchemaVersion, ConnectionID: id, ConfigGeneration: generation, ProcessEnvironment: plan}, nil
}

func (h *controlHandler) connectionEnvironment(w http.ResponseWriter, req *http.Request, id string) {
	if !controlIdentifier.MatchString(id) || h.environments == nil {
		writeControlError(w, http.StatusNotFound, "connection_unavailable", "The Connection environment is unavailable.", false)
		return
	}
	response, err := h.environments.compile(h.state, id)
	if err != nil {
		if errors.Is(err, agentapi.ErrUnsafeAgentVisibleEnvironment) {
			writeControlError(w, http.StatusBadGateway, "unsafe_connection_environment", "The Connection environment contained proxy-only material.", false)
			return
		}
		writeControlError(w, http.StatusConflict, "connection_environment_unavailable", "The selected Connection environment cannot be compiled.", true)
		return
	}
	payload, marshalErr := json.Marshal(response)
	if marshalErr != nil || manifestPayloadContains(payload, append(h.state.manifestPayloadForbiddenSecrets(), h.state.currentBackendCredential().Reveal())) {
		writeControlError(w, http.StatusBadGateway, "unsafe_connection_environment", "The Connection environment contained proxy-only material.", false)
		return
	}
	h.writeRelay(w, response, nil)
}
