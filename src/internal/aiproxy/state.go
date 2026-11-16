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
	// refreshRequests asks the monitor for one extra config refresh. It is fed
	// only when an upstream refuses a custom Connection's credential.
	refreshRequests      chan struct{}
	rejectionMu          sync.Mutex
	lastRejectionRefresh time.Time
	// environmentHolds is supplied by the engine. It reports whether the
	// process environment compiled for a refreshed configuration is already
	// satisfied by the one this session started with; see replaceConfig.
	environmentHolds func(*agentapi.SessionConfig) bool
	// retiredEnvironment holds what custom Connections removed from the
	// running session had exported. Those variables stay behind in processes
	// that already started; they name decoys nothing accepts any more.
	retiredEnvironment map[string]string
	// expired are this Workflow's grants whose time limit passed recently, as
	// the Console last listed them. They carry nothing the Agent's processes
	// were given, so they change in place.
	expired []agentapi.ExpiredConnection
	// presets and hints are session-local memory: the Console's preset list,
	// and recent dead ends with what to ask for to get past them.
	presets *presetCache
	hints   *hintLog

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
		refreshRequests:   make(chan struct{}, 1),
		expired:           append([]agentapi.ExpiredConnection(nil), session.Config.ExpiredConnections...),
		presets:           newPresetCache(session.Client),
		hints:             &hintLog{},
		client:            session.Client,
		fatal:             make(chan error, 1),
	}, nil
}

// upstreamRejectionRefreshInterval bounds the extra config refreshes a session
// may trigger. Runtime API calls count against the plan rate limit.
const upstreamRejectionRefreshInterval = 30 * time.Second

// requestRefreshAfterRejection is called when an upstream answers 401 or 403
// to a request carrying a custom Connection's credential: the value may have
// been replaced in the Console since the last refresh. It asks the monitor
// for one refresh, at most once per interval, and never waits for it.
func (s *runtimeState) requestRefreshAfterRejection(now time.Time) bool {
	s.rejectionMu.Lock()
	defer s.rejectionMu.Unlock()
	if !s.lastRejectionRefresh.IsZero() && now.Sub(s.lastRejectionRefresh) < upstreamRejectionRefreshInterval {
		return false
	}
	select {
	case s.refreshRequests <- struct{}{}:
		s.lastRejectionRefresh = now
		return true
	default:
		return false
	}
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
		for _, injection := range connection.EffectiveInjections() {
			for _, role := range []string{"username", "password", "accessKeyId", "secretAccessKey", "sessionToken"} {
				if _, status := agentapi.ResolveMaterial(injection.ValueFrom.Fields, role); status == agentapi.MaterialAmbiguous {
					return nil, fmt.Errorf("Agent binding %s has an ambiguous credential role mapping", connection.ConnectionID)
				}
			}
			switch injection.WhenAbsent {
			case "", agentapi.WhenAbsentBlock, agentapi.WhenAbsentAttach:
			default:
				return nil, fmt.Errorf("Agent binding %s uses unsupported whenAbsent %q", connection.ConnectionID, injection.WhenAbsent)
			}
		}
		listed := len(connection.Injections) > 0
		switch connection.Protocol {
		case "http":
			// The single injection may repeat the first list entry for an older
			// reader, but must never name a different finalizer. Request signing
			// is a finalizer of its own and cannot be one entry of a list.
			if listed && connection.Injection.Action != "" && connection.Injection.Action != connection.Injections[0].Action {
				return nil, fmt.Errorf("Agent HTTP binding %s has conflicting injections", connection.ConnectionID)
			}
			for _, injection := range connection.EffectiveInjections() {
				switch injection.Action {
				case "set_header", "replace_header", "remove_header", "set_param", "set_path", "replace_path_regex", "basic_auth":
					continue
				case "aws_sigv4":
					if !listed {
						continue
					}
				}
				return nil, fmt.Errorf("Agent HTTP binding %s uses unsupported injection action %q", connection.ConnectionID, injection.Action)
			}
		case "postgres":
			if listed || connection.Injection.Action != "pg_handshake" {
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
	// Time-limited access ends by the clock, whether or not a refresh has
	// removed the Connection yet.
	if b.connection.GrantExpired(now) {
		return connectionAuthorizationDecision{
			code: codeAccessExpired, reason: agentapi.AccessExpired, status: http.StatusForbidden,
			message: "This Workflow's access to the Connection has expired. To ask a member to renew it, send the JSON in details.request unchanged to POST " + requestsURL + ".",
		}
	}
	// A policy this client cannot read is never enforced in part.
	if failure := b.connection.AccessPolicyFailure(); failure != "" {
		return connectionAuthorizationDecision{
			code: codeAccessPolicyUnsupported, reason: failure, status: http.StatusForbidden,
			message: "This Phase CLI cannot enforce the access policy on the Connection. Update the Phase CLI.",
		}
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
	change := classifyConfigChange(s.bindings, bindings, s.configEnv, config.ConfigEnv)
	// Routing can still reach the Agent's environment: a host may fall under
	// an inherited NO_PROXY entry, and a removal may free a variable name for
	// another Connection. The engine compiles the environment to find out.
	if !change.reprovision && change.reshaped && s.environmentHolds != nil && !s.environmentHolds(config) {
		change.reprovision = true
	}
	if change.reprovision {
		s.mu.Unlock()
		for _, fresh := range bindings {
			fresh.connection.SecretMaterial.Destroy()
		}
		return fmt.Errorf("%w: Agent-visible decoys, identifiers, adapters, or environment changed", airuntime.ErrSessionReprovisionRequired)
	}
	for _, removed := range change.removed {
		if s.retiredEnvironment == nil {
			s.retiredEnvironment = make(map[string]string)
		}
		for name, value := range removed.connection.ConfigEnv {
			s.retiredEnvironment[name] = value
		}
		for name, value := range removed.connection.AgentEnv.Clone() {
			s.retiredEnvironment[name] = value
		}
	}
	oldBindings := s.bindings
	s.bindings = bindings
	s.expired = append([]agentapi.ExpiredConnection(nil), config.ExpiredConnections...)
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
		connections = append(connections, remoteapi.StatusConnection{
			ConnectionID:       candidate.connection.ConnectionID,
			Name:               candidate.connection.ConnectionName,
			CredentialID:       candidate.connection.CredentialID,
			CredentialName:     candidate.connection.CredentialName,
			CredentialProvider: candidate.connection.CredentialProvider,
			CredentialRevision: candidate.connection.CredentialRevision,
			ServiceType:        candidate.connection.ServiceType,
			Protocol:           candidate.connection.Protocol,
			State:              candidate.printableState(now),
			StateReason:        candidate.stateReason(now),
			ExpiresAt:          candidate.connection.CredentialExpiresAt,
			GrantExpiresAt:     candidate.connection.GrantExpiresAt,
		})
	}
	return connections
}

// printableState is the state of a Connection in this proxy: ready, expired
// (the credential expiry or the grant's time limit passed) or unavailable (not
// authorized, a policy this client cannot enforce, or a sealed value that
// could not be opened).
func (b *binding) printableState(now time.Time) string {
	decision := b.authorizationDecision(now)
	switch {
	case decision.code == "agent_credential_expired" || decision.code == codeAccessExpired:
		return "expired"
	case !decision.allowed || b.connection.MaterialUnavailable():
		return "unavailable"
	default:
		return "ready"
	}
}

// stateReason says why a Connection is not ready, when the proxy can name it.
func (b *binding) stateReason(now time.Time) string {
	switch {
	case b.connection.GrantExpired(now):
		return agentapi.AccessExpired
	case b.connection.AccessPolicyFailure() != "":
		return b.connection.AccessPolicyFailure()
	default:
		return b.connection.MaterialFailure()
	}
}

func requiresEnvironmentReprovision(oldBindings, newBindings []*binding, oldConfigEnv, newConfigEnv map[string]string) bool {
	return classifyConfigChange(oldBindings, newBindings, oldConfigEnv, newConfigEnv).reprovision
}

// configChange says how a refreshed configuration relates to the running one.
type configChange struct {
	// reprovision: the session must be recycled, because what the Agent
	// process was given changed or a packaged service changed shape.
	reprovision bool
	// reshaped: custom HTTP Connections changed their routing or injections,
	// were removed, or were added without exporting anything, with the
	// Agent-visible environment left as it was.
	reshaped bool
	removed  []*binding
}

// classifyConfigChange keeps the rule that a running process can never be
// handed a different environment: any change to identifiers, decoys, exported
// variables, or a new grant, needs a fresh session. Packaged services also
// recycle when their hosts, configuration or injection change. A custom HTTP
// Connection is built to be reshaped by approved requests, so its hosts,
// definition, injections and plain-HTTP setting may change, and its grant may
// go away, while the session keeps running. One that exports nothing may also
// be added: the Agent's processes are given nothing new, the proxy only starts
// serving it.
//
// A grant's access policy, its temporary allows, a definition's operation
// classes, the grant's time limit and the list of expired Connections are
// deliberately not compared: none of them is visible to the Agent's
// processes, the proxy alone enforces them, so they always apply in place.
func classifyConfigChange(oldBindings, newBindings []*binding, oldConfigEnv, newConfigEnv map[string]string) configChange {
	if !equalStringMap(oldConfigEnv, newConfigEnv) {
		return configChange{reprovision: true}
	}
	oldByGrant := make(map[string]*binding, len(oldBindings))
	for _, candidate := range oldBindings {
		oldByGrant[candidate.connection.GrantID] = candidate
	}
	var change configChange
	kept := make(map[string]struct{}, len(newBindings))
	for _, fresh := range newBindings {
		old := oldByGrant[fresh.connection.GrantID]
		if old == nil {
			if !exportsNothing(fresh.connection) {
				return configChange{reprovision: true}
			}
			change.reshaped = true
			continue
		}
		kept[fresh.connection.GrantID] = struct{}{}
		left, right := old.connection, fresh.connection
		if left.ConnectionID != right.ConnectionID || left.CredentialID != right.CredentialID ||
			left.Protocol != right.Protocol || left.ServiceType != right.ServiceType || left.CredentialProvider != right.CredentialProvider || !reflect.DeepEqual(left.ConfigEnv, right.ConfigEnv) ||
			!equalStringMap(left.Identifiers, right.Identifiers) || !equalStringMap(left.DecoyMaterial, right.DecoyMaterial) ||
			!equalStringMap(left.AgentEnv.Clone(), right.AgentEnv.Clone()) ||
			!reflect.DeepEqual(left.EnvironmentBindings, right.EnvironmentBindings) {
			return configChange{reprovision: true}
		}
		if !reflect.DeepEqual(left.Hosts, right.Hosts) || !reflect.DeepEqual(left.ConnectionConfig, right.ConnectionConfig) ||
			!reflect.DeepEqual(left.Injection, right.Injection) || !equalInjections(left.Injections, right.Injections) ||
			left.AllowPlainHTTP != right.AllowPlainHTTP {
			if right.ServiceType != agentapi.CustomHTTPServiceType {
				return configChange{reprovision: true}
			}
			change.reshaped = true
		}
	}
	for _, old := range oldBindings {
		if _, present := kept[old.connection.GrantID]; present {
			continue
		}
		if old.connection.ServiceType != agentapi.CustomHTTPServiceType {
			return configChange{reprovision: true}
		}
		change.reshaped = true
		change.removed = append(change.removed, old)
	}
	return change
}

// exportsNothing reports whether a custom HTTP Connection contributes no
// variable to the Agent's process environment.
func exportsNothing(connection agentapi.Connection) bool {
	return connection.ServiceType == agentapi.CustomHTTPServiceType && connection.Protocol == "http" &&
		len(connection.ConfigEnv) == 0 && len(connection.AgentEnv.Clone()) == 0 && len(connection.EnvironmentBindings) == 0
}

// equalInjections treats an absent list and an empty one alike, since both
// mean the Connection uses its single injection.
func equalInjections(left, right []agentapi.Injection) bool {
	return (len(left) == 0 && len(right) == 0) || reflect.DeepEqual(left, right)
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

// setEnvironmentCheck is called once by the engine, before it serves traffic.
func (s *runtimeState) setEnvironmentCheck(holds func(*agentapi.SessionConfig) bool) {
	s.mu.Lock()
	s.environmentHolds = holds
	s.mu.Unlock()
}

// retiredEnvironmentValue returns what a removed custom Connection exported
// under name, if anything.
func (s *runtimeState) retiredEnvironmentValue(name string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, retired := s.retiredEnvironment[name]
	return value, retired
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

// eventSecrets is everything that must not appear in text the Agent supplied
// or may read back: the session credentials, every decoy and every live
// Connection value.
func (s *runtimeState) eventSecrets() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append(s.issuedSecretsLocked(), s.liveNonIdentifierSecretsLocked()...)
}

// issuedSecrets is what the Console and the proxy issued for this session:
// the session credentials and every decoy. They are long random values, so
// finding one inside a proxy-written field is never a coincidence.
func (s *runtimeState) issuedSecrets() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.issuedSecretsLocked()
}

func (s *runtimeState) issuedSecretsLocked() []string {
	values := []string{s.backendCredential.Reveal(), s.runtimeCapability.Reveal()}
	for _, binding := range s.bindings {
		for _, value := range binding.connection.DecoyMaterial {
			if value != "" {
				values = append(values, value)
			}
		}
	}
	return values
}

// readTripwireSecrets is what a control read is refused for when its payload
// contains it anywhere: everything issued, and the live values of packaged
// Connections. A custom Connection's value is chosen by a member and can
// coincide with ordinary words of a payload, so it is not compared with a
// whole payload: customLiveValues lists those values by Connection, to be
// compared with that Connection's own description and with text the Agent
// supplied.
func (s *runtimeState) readTripwireSecrets() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	packaged := make([]agentapi.Connection, 0, len(s.bindings))
	for _, binding := range s.bindings {
		if binding.connection.ServiceType != agentapi.CustomHTTPServiceType {
			packaged = append(packaged, binding.connection)
		}
	}
	return append(s.issuedSecretsLocked(), agentapi.ProxyOnlyCredentialValues(packaged)...)
}

func (s *runtimeState) customLiveValues() map[string][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	values := make(map[string][]string)
	for _, binding := range s.bindings {
		if binding.connection.ServiceType != agentapi.CustomHTTPServiceType {
			continue
		}
		if live := agentapi.ProxyOnlyCredentialValues([]agentapi.Connection{binding.connection}); len(live) > 0 {
			values[binding.connection.ConnectionID] = live
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

// discoverConnectionMatchesRuntime checks the Agent-visible shape of a
// Connection. The credential expiry is left out: assumed-role credentials get
// a fresh expiry on every refresh without the environment changing. The
// policy, operation classes and grant expiry are left out too: they are not
// part of the environment, a temporary allow or a renewal changes them between
// two reads, and the proxy enforces its own copy, never the discover one.
func discoverConnectionMatchesRuntime(discover agentapi.DiscoverConnection, runtime agentapi.Connection) bool {
	return discover.ConnectionID == runtime.ConnectionID &&
		discover.ConnectionName == runtime.ConnectionName &&
		discover.ServiceType == runtime.ServiceType && discover.Protocol == runtime.Protocol &&
		reflect.DeepEqual(discover.Hosts, runtime.Hosts) &&
		reflect.DeepEqual(discover.ConnectionConfig, runtime.ConnectionConfig) && reflect.DeepEqual(discover.ConfigEnv, runtime.ConfigEnv) && discover.CredentialID == runtime.CredentialID && discover.CredentialName == runtime.CredentialName && discover.CredentialProvider == runtime.CredentialProvider && discover.CredentialRevision == runtime.CredentialRevision && discover.MaterialGeneration == runtime.MaterialGeneration &&
		reflect.DeepEqual(discover.Injection, runtime.Injection) && equalInjections(discover.Injections, runtime.Injections) &&
		discover.AllowPlainHTTP == runtime.AllowPlainHTTP && discover.OnRefresh == runtime.OnRefresh &&
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
