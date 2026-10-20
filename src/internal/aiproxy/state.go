package aiproxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

var errRefreshedConfigRejected = errors.New("Agent refreshed config was rejected")

type binding struct {
	connection agentapi.Connection
}

type connectionAuthorizationDecision struct {
	allowed bool
	code    string
	reason  string
	message string
	status  int
}

type runtimeState struct {
	mu        sync.RWMutex
	refreshMu sync.Mutex

	sessionUID        string
	backendCredential agentapi.SensitiveString
	runtimeCapability agentapi.SensitiveString
	expiresAt         time.Time
	generation        int
	configEnv         map[string]string
	bindings          []*binding
	healthy           bool
	revoked           bool
	changed           chan struct{}
	// decoys is shared with the owning Engine so credential generations issued
	// by earlier backend sessions of the same process stay translatable.
	decoys *decoyHistory

	client *agentapi.Client
	fatal  chan error
	once   sync.Once
}

var errDiscoverProcessEnvironmentMismatch = errors.New("Agent discover response does not match the active process environment")

func newRuntimeStateWithCapability(session *airuntime.ProxySession, runtimeCapability agentapi.SensitiveString) (*runtimeState, error) {
	if session == nil || session.Config == nil || session.Client == nil || session.CA == nil {
		return nil, errors.New("Agent proxy session is incomplete")
	}
	if runtimeCapability.Reveal() == "" {
		return nil, errors.New("Agent runtime capability is unavailable")
	}
	if runtimeCapability.Reveal() == session.Config.SessionCredential.Reveal() {
		return nil, errors.New("Agent runtime capability must be distinct from the backend session credential")
	}
	if err := agentapi.ValidateAgentVisibleEnvironment(session.Config.ConfigEnv, session.Config.Connections); err != nil {
		return nil, err
	}
	bindings, err := parseBindings(session.Config.Connections)
	if err != nil {
		return nil, err
	}
	return &runtimeState{
		sessionUID:        session.Config.SessionUID,
		backendCredential: session.Config.SessionCredential,
		runtimeCapability: runtimeCapability,
		expiresAt:         session.Config.ExpiresAt,
		generation:        session.Config.ConfigGeneration,
		configEnv:         cloneStringMap(session.Config.ConfigEnv),
		bindings:          bindings,
		healthy:           true,
		changed:           make(chan struct{}),
		client:            session.Client,
		fatal:             make(chan error, 1),
	}, nil
}

func parseBindings(connections []agentapi.Connection) ([]*binding, error) {
	bindings := make([]*binding, 0, len(connections))
	seen := make(map[string]bool)
	for index := range connections {
		connection := connections[index]
		if connection.GrantID == "" || connection.ConnectionID == "" || connection.CredentialID == "" ||
			connection.CredentialProvider == "" || connection.CredentialName == "" {
			return nil, errors.New("Agent binding has incomplete grant or credential identity")
		}
		if connection.ConnectionID != "" {
			if seen[connection.ConnectionID] {
				return nil, errors.New("duplicate Connection ID")
			}
			seen[connection.ConnectionID] = true
		}
		for _, environmentBinding := range connection.EnvironmentBindings {
			if err := environmentBinding.Validate(); err != nil {
				return nil, fmt.Errorf("Agent binding %s: %w", connection.ConnectionID, err)
			}
		}
		for _, role := range []string{"username", "password", "accessKeyId", "secretAccessKey", "sessionToken"} {
			if _, status := agentapi.ResolveMaterial(connection.Injection.ValueFrom.Fields, role); status == agentapi.MaterialAmbiguous {
				return nil, fmt.Errorf("Agent binding %s has an ambiguous credential role mapping", connection.ConnectionID)
			}
		}
		switch connection.Protocol {
		case "http":
			switch connection.Injection.Action {
			case "set_header", "replace_header", "remove_header", "set_param", "set_path", "replace_path_regex", "aws_sigv4":
			default:
				return nil, fmt.Errorf("Agent HTTP binding %s uses unsupported injection action %q", connection.ConnectionID, connection.Injection.Action)
			}
		case "postgres":
			if connection.Injection.Action != "pg_handshake" {
				return nil, fmt.Errorf("Agent PostgreSQL binding %s has an invalid finalizer", connection.ConnectionID)
			}
			if connection.DecoyMaterial["password"] == "" {
				return nil, fmt.Errorf("Agent PostgreSQL binding %s has no decoy password", connection.ConnectionID)
			}
		default:
			return nil, fmt.Errorf("Agent binding %s uses unsupported protocol %q", connection.ConnectionID, connection.Protocol)
		}
		if len(connection.Hosts) == 0 {
			return nil, fmt.Errorf("Agent HTTP binding %s has no host rules", connection.ConnectionID)
		}
		for _, rule := range connection.Hosts {
			if rule.Match != "exact" && rule.Match != "suffix" {
				return nil, fmt.Errorf("Agent HTTP binding %s has an invalid host rule", connection.ConnectionID)
			}
		}
		if err := validateConnectionAuthorization(connection.Authorization); err != nil {
			return nil, fmt.Errorf("Agent binding %s: %w", connection.ConnectionID, err)
		}
		bindings = append(bindings, &binding{connection: connection})
	}
	return bindings, nil
}

func validateConnectionAuthorization(authorization agentapi.ConnectionAuthorization) error {
	if authorization.Version != 1 || authorization.Mode != "connection" ||
		authorization.AccessMode != "allow" || authorization.State != "allowed" {
		return errors.New("connection authorization is not a supported allow attestation")
	}
	return nil
}

func (b *binding) authorizationDecision(now time.Time) connectionAuthorizationDecision {
	if b == nil {
		return connectionAuthorizationDecision{code: "agent_connection_denied", reason: "missing_binding", message: "The Agent connection is unavailable.", status: http.StatusForbidden}
	}
	if b.connection.CredentialExpiresAt != nil && !now.Before(*b.connection.CredentialExpiresAt) {
		return connectionAuthorizationDecision{code: "agent_credential_expired", reason: "credential_expired", message: "The Connection credential has expired.", status: http.StatusForbidden}
	}
	authorization := b.connection.Authorization
	if validateConnectionAuthorization(authorization) == nil {
		return connectionAuthorizationDecision{allowed: true, reason: "connection_allowed"}
	}
	return connectionAuthorizationDecision{
		code: "agent_connection_denied", reason: "connection_denied",
		message: "This Agent is not authorized to use the connection.", status: http.StatusForbidden,
	}
}

func (s *runtimeState) fail(err error) {
	if err == nil {
		err = errors.New("Agent proxy stopped")
	}
	s.once.Do(func() {
		s.mu.Lock()
		s.healthy = false
		s.notifyLocked()
		s.mu.Unlock()
		s.fatal <- err
	})
}

func (s *runtimeState) currentBackendCredential() agentapi.SensitiveString {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backendCredential
}

func (s *runtimeState) expiration() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.expiresAt
}

func (s *runtimeState) authenticateRuntimeCapability(value string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.availabilityLocked(time.Now()) != nil {
		return false
	}
	expected := s.runtimeCapability.Reveal()
	return expected != "" && len(value) == len(expected) && subtle.ConstantTimeCompare([]byte(value), []byte(expected)) == 1
}

func (s *runtimeState) setBackendCredential(credential agentapi.SensitiveString) {
	s.mu.Lock()
	s.backendCredential = credential
	s.notifyLocked()
	s.mu.Unlock()
}

func (s *runtimeState) availability() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.availabilityLocked(time.Now())
}

func (s *runtimeState) availabilityLocked(now time.Time) error {
	if s.revoked {
		return errors.New("Agent session has been revoked")
	}
	if !s.healthy {
		return errors.New("Agent session configuration is not currently validated")
	}
	if !now.Before(s.expiresAt) {
		return errors.New("Agent session has expired")
	}
	return nil
}

func (s *runtimeState) findBinding(host string, port int, requestPath string, selection ...string) (*binding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var matched *binding
	for _, candidate := range s.bindings {
		if len(selection) > 0 && selection[0] != "" && candidate.connection.ConnectionID != selection[0] {
			continue
		}
		if candidate.connection.Protocol != "http" {
			continue
		}
		for _, rule := range candidate.connection.Hosts {
			if phaseproxy.MatchHostRule(rule, host, port, requestPath) {
				if matched != nil && matched.connection.GrantID != candidate.connection.GrantID {
					return nil, errors.New("multiple Agent bindings match this request")
				}
				matched = candidate
				break
			}
		}
	}
	return matched, nil
}

func (s *runtimeState) hasBoundHost(host string, port int, selection ...string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grant := ""
	for _, candidate := range s.bindings {
		if len(selection) > 0 && selection[0] != "" && candidate.connection.ConnectionID != selection[0] {
			continue
		}
		if candidate.connection.Protocol != "http" {
			continue
		}
		for _, rule := range candidate.connection.Hosts {
			if phaseproxy.MatchHostOnly(rule, host, port) {
				if grant != "" && grant != candidate.connection.GrantID {
					return false, errors.New("multiple Agent bindings match this host")
				}
				grant = candidate.connection.GrantID
				break
			}
		}
	}
	return grant != "", nil
}

func (s *runtimeState) protocolBindings(protocol string) []*binding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*binding, 0)
	for _, candidate := range s.bindings {
		if candidate.connection.Protocol == protocol {
			connection := candidate.connection
			connection.SecretMaterial = agentapi.SecretMaterial{}
			result = append(result, &binding{connection: connection})
		}
	}
	return result
}

type protocolBindingSnapshot struct {
	binding    *binding
	generation int
	releaseOne *sync.Once
}

func newProtocolBindingSnapshot(candidate *binding, generation int) protocolBindingSnapshot {
	connection := candidate.connection
	connection.SecretMaterial = candidate.connection.SecretMaterial.Copy()
	return protocolBindingSnapshot{
		binding: &binding{connection: connection}, generation: generation, releaseOne: &sync.Once{},
	}
}

func (snapshot protocolBindingSnapshot) release() {
	if snapshot.binding == nil || snapshot.releaseOne == nil {
		return
	}
	snapshot.releaseOne.Do(func() {
		snapshot.binding.connection.SecretMaterial.Destroy()
	})
}

func (s *runtimeState) protocolBinding(grantID, protocol string) (protocolBindingSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.availabilityLocked(time.Now()); err != nil {
		return protocolBindingSnapshot{}, err
	}
	for _, candidate := range s.bindings {
		if candidate.connection.GrantID != grantID {
			continue
		}
		if candidate.connection.Protocol != protocol {
			return protocolBindingSnapshot{}, errors.New("Agent protocol binding changed")
		}
		return newProtocolBindingSnapshot(candidate, s.generation), nil
	}
	return protocolBindingSnapshot{}, errors.New("Agent protocol binding is unavailable")
}

func (s *runtimeState) snapshotForBinding(binding *binding, protocol string) (protocolBindingSnapshot, error) {
	if binding == nil {
		return protocolBindingSnapshot{}, errors.New("Agent binding is unavailable")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.availabilityLocked(time.Now()); err != nil {
		return protocolBindingSnapshot{}, err
	}
	for _, candidate := range s.bindings {
		if candidate != binding {
			continue
		}
		if candidate.connection.Protocol != protocol {
			return protocolBindingSnapshot{}, errors.New("Agent binding is unavailable")
		}
		return newProtocolBindingSnapshot(candidate, s.generation), nil
	}
	return protocolBindingSnapshot{}, errors.New("Agent binding changed")
}

func (s *runtimeState) validateProtocolBinding(snapshot protocolBindingSnapshot) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.availabilityLocked(time.Now()); err != nil {
		return err
	}
	if snapshot.binding == nil || snapshot.generation != s.generation {
		return errors.New("Agent protocol binding changed")
	}
	for _, candidate := range s.bindings {
		if candidate.connection.GrantID == snapshot.binding.connection.GrantID &&
			candidate.connection.ConnectionID == snapshot.binding.connection.ConnectionID &&
			candidate.connection.CredentialID == snapshot.binding.connection.CredentialID {
			if !candidate.authorizationDecision(time.Now()).allowed {
				return errors.New("Agent connection authorization is unavailable")
			}
			return nil
		}
	}
	return errors.New("Agent protocol binding is unavailable")
}

func (s *runtimeState) changeSignal() <-chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.changed
}

func (s *runtimeState) notifyLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *runtimeState) replaceConfig(config *agentapi.SessionConfig) error {
	if config == nil || config.SessionUID != s.sessionUID {
		return errors.New("Agent session refresh returned the wrong session")
	}
	bindings, err := parseBindings(config.Connections)
	if err != nil {
		return err
	}
	if err := agentapi.ValidateAgentVisibleEnvironment(config.ConfigEnv, config.Connections); err != nil {
		for _, fresh := range bindings {
			fresh.connection.SecretMaterial.Destroy()
		}
		return err
	}
	s.mu.Lock()
	if config.ConfigGeneration < s.generation {
		s.mu.Unlock()
		for _, fresh := range bindings {
			fresh.connection.SecretMaterial.Destroy()
		}
		return errors.New("Agent session refresh returned a stale generation")
	}
	if requiresEnvironmentReprovision(s.bindings, bindings, s.configEnv, config.ConfigEnv) {
		s.mu.Unlock()
		for _, fresh := range bindings {
			fresh.connection.SecretMaterial.Destroy()
		}
		return fmt.Errorf("%w: Agent-visible decoys, identifiers, adapters, or environment changed", airuntime.ErrSessionReprovisionRequired)
	}
	oldBindings := s.bindings
	s.bindings = bindings
	s.expiresAt = config.ExpiresAt
	s.generation = config.ConfigGeneration
	s.configEnv = cloneStringMap(config.ConfigEnv)
	s.healthy = true
	s.notifyLocked()
	s.mu.Unlock()
	s.decoys.remember(config.Connections)
	for _, old := range oldBindings {
		old.connection.SecretMaterial.Destroy()
	}
	return nil
}

// refreshConfig serializes every backend config fetch and application. This
// prevents the monitor, manual compatibility route, and request waiter from
// racing generations or applying older configuration after newer state.
func (s *runtimeState) refreshConfig(ctx context.Context) (*agentapi.SessionConfig, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	config, err := s.client.RefreshSession(ctx, s.sessionUID, s.currentBackendCredential())
	if err != nil {
		return nil, err
	}
	if err := s.replaceConfig(config); err != nil {
		return config, fmt.Errorf("%w: %w", errRefreshedConfigRejected, err)
	}
	return config, nil
}

func (s *runtimeState) statusConnections(now time.Time) []remoteapi.StatusConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	connections := make([]remoteapi.StatusConnection, 0, len(s.bindings))
	for _, candidate := range s.bindings {
		decision := candidate.authorizationDecision(now)
		state := "unavailable"
		if decision.allowed {
			state = "ready"
		} else if decision.code == "agent_credential_expired" {
			state = "expired"
		}
		connections = append(connections, remoteapi.StatusConnection{
			ConnectionID:       candidate.connection.ConnectionID,
			Name:               candidate.connection.ConnectionName,
			CredentialID:       candidate.connection.CredentialID,
			CredentialName:     candidate.connection.CredentialName,
			CredentialProvider: candidate.connection.CredentialProvider,
			CredentialRevision: candidate.connection.CredentialRevision,
			ServiceType:        candidate.connection.ServiceType,
			Protocol:           candidate.connection.Protocol,
			State:              state,
			ExpiresAt:          candidate.connection.CredentialExpiresAt,
		})
	}
	return connections
}

func requiresEnvironmentReprovision(oldBindings, newBindings []*binding, oldConfigEnv, newConfigEnv map[string]string) bool {
	if !equalStringMap(oldConfigEnv, newConfigEnv) || len(oldBindings) != len(newBindings) {
		return true
	}
	oldByGrant := make(map[string]*binding, len(oldBindings))
	for _, candidate := range oldBindings {
		oldByGrant[candidate.connection.GrantID] = candidate
	}
	for _, fresh := range newBindings {
		old := oldByGrant[fresh.connection.GrantID]
		if old == nil {
			return true
		}
		left, right := old.connection, fresh.connection
		if left.ConnectionID != right.ConnectionID || left.CredentialID != right.CredentialID ||
			left.Protocol != right.Protocol || left.ServiceType != right.ServiceType || left.CredentialProvider != right.CredentialProvider || !reflect.DeepEqual(left.ConfigEnv, right.ConfigEnv) ||
			!reflect.DeepEqual(left.Hosts, right.Hosts) || !reflect.DeepEqual(left.ConnectionConfig, right.ConnectionConfig) ||
			!reflect.DeepEqual(left.Injection, right.Injection) ||
			!equalStringMap(left.Identifiers, right.Identifiers) || !equalStringMap(left.DecoyMaterial, right.DecoyMaterial) ||
			!equalStringMap(left.AgentEnv.Clone(), right.AgentEnv.Clone()) ||
			!reflect.DeepEqual(left.EnvironmentBindings, right.EnvironmentBindings) {
			return true
		}
	}
	return false
}

func cloneStringMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func (s *runtimeState) setUnhealthy() {
	s.mu.Lock()
	s.healthy = false
	s.notifyLocked()
	s.mu.Unlock()
}

func (s *runtimeState) markRevoked() {
	s.mu.Lock()
	s.revoked = true
	s.healthy = false
	s.notifyLocked()
	s.mu.Unlock()
}

func (s *runtimeState) hasBindingTarget(grantID, connectionID, credentialID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, candidate := range s.bindings {
		if candidate.connection.GrantID == grantID &&
			candidate.connection.ConnectionID == connectionID &&
			candidate.connection.CredentialID == credentialID {
			return true
		}
	}
	return false
}

func (s *runtimeState) eventSecrets() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := []string{s.backendCredential.Reveal(), s.runtimeCapability.Reveal()}
	for _, binding := range s.bindings {
		for _, value := range binding.connection.DecoyMaterial {
			if value != "" {
				values = append(values, value)
			}
		}
		for _, value := range binding.connection.SecretMaterial.Clone() {
			if value != "" {
				values = append(values, value)
			}
		}
	}
	return values
}

func (s *runtimeState) manifestForbiddenSecrets() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := []string{s.runtimeCapability.Reveal()}
	return append(values, s.liveNonIdentifierSecretsLocked()...)
}

func (s *runtimeState) manifestPayloadForbiddenSecrets() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.liveNonIdentifierSecretsLocked()
}

func (s *runtimeState) liveNonIdentifierSecretsLocked() []string {
	connections := make([]agentapi.Connection, 0, len(s.bindings))
	for _, binding := range s.bindings {
		connections = append(connections, binding.connection)
	}
	return agentapi.ProxyOnlyCredentialValues(connections)
}

func (s *runtimeState) applyTrustedDiscoverAuthorization(discover *agentapi.DiscoverResponse) error {
	if discover == nil {
		return errors.New("Agent discover response is missing")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if discover.ConfigGeneration != s.generation || !equalStringMap(discover.ConfigEnv, s.configEnv) || len(discover.Connections) != len(s.bindings) {
		return errDiscoverProcessEnvironmentMismatch
	}
	byGrant := make(map[string]*binding, len(s.bindings))
	for _, candidate := range s.bindings {
		byGrant[candidate.connection.GrantID] = candidate
	}
	for index := range discover.Connections {
		connection := &discover.Connections[index]
		trusted := byGrant[connection.GrantID]
		if trusted == nil || !discoverConnectionMatchesRuntime(*connection, trusted.connection) {
			return fmt.Errorf("%w: connection data changed", errDiscoverProcessEnvironmentMismatch)
		}
		connection.Authorization = trusted.connection.Authorization
	}
	return nil
}

func discoverConnectionMatchesRuntime(discover agentapi.DiscoverConnection, runtime agentapi.Connection) bool {
	return discover.ConnectionID == runtime.ConnectionID &&
		discover.ConnectionName == runtime.ConnectionName &&
		discover.ServiceType == runtime.ServiceType && discover.Protocol == runtime.Protocol &&
		reflect.DeepEqual(discover.Hosts, runtime.Hosts) &&
		reflect.DeepEqual(discover.ConnectionConfig, runtime.ConnectionConfig) && reflect.DeepEqual(discover.ConfigEnv, runtime.ConfigEnv) && discover.CredentialID == runtime.CredentialID && discover.CredentialName == runtime.CredentialName && discover.CredentialProvider == runtime.CredentialProvider && discover.CredentialRevision == runtime.CredentialRevision && discover.MaterialGeneration == runtime.MaterialGeneration && reflect.DeepEqual(discover.CredentialExpiresAt, runtime.CredentialExpiresAt) &&
		reflect.DeepEqual(discover.Injection, runtime.Injection) && discover.OnRefresh == runtime.OnRefresh &&
		equalStringMap(discover.Identifiers, runtime.Identifiers) &&
		equalStringMap(discover.DecoyMaterial, runtime.DecoyMaterial) &&
		equalStringMap(discover.AgentEnv, runtime.AgentEnv.Clone()) &&
		reflect.DeepEqual(discover.EnvironmentBindings, runtime.EnvironmentBindings)
}

func (s *runtimeState) destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, binding := range s.bindings {
		binding.connection.SecretMaterial.Destroy()
	}
	s.bindings = nil
	s.backendCredential = ""
	s.runtimeCapability = ""
}

func requestAuthority(req *http.Request) (string, int, error) {
	if req == nil || req.URL == nil || req.URL.User != nil {
		return "", 0, errors.New("invalid proxy request")
	}
	defaultPort := 80
	if strings.EqualFold(req.URL.Scheme, "https") {
		defaultPort = 443
	}
	authority := req.URL.Host
	if authority == "" {
		authority = req.Host
	}
	return phaseproxy.ParseAuthority(authority, defaultPort)
}
