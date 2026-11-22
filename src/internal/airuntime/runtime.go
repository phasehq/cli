package airuntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/proxy"
	"github.com/phasehq/cli/pkg/version"
)

var ErrProxyEngineNotReady = errors.New("the Phase AI proxy engine is not available in this build; session and credential APIs are ready, but no traffic will be proxied")

var (
	ErrSessionExpired             = errors.New("the Phase AI session reached hard expiry")
	ErrSessionReprovisionRequired = errors.New("the Phase AI session must be re-provisioned")
	ErrAuthenticationRequired     = errors.New("Phase login is invalid or no longer active; authenticate with a current token using phase auth --mode token")
)

type Engine interface {
	Ready() error
	Capabilities() EngineCapabilities
	Serve(context.Context, *ProxySession) error
	Run(context.Context, *ProxySession, []string) error
}

type EngineCapabilities struct {
	Protocols        []string
	InjectionActions []string
	// Features are the optional runtime capabilities the engine implements.
	Features []string
}

type UnavailableEngine struct{}

func (UnavailableEngine) Ready() error                               { return ErrProxyEngineNotReady }
func (UnavailableEngine) Capabilities() EngineCapabilities           { return EngineCapabilities{} }
func (UnavailableEngine) Serve(context.Context, *ProxySession) error { return ErrProxyEngineNotReady }
func (UnavailableEngine) Run(context.Context, *ProxySession, []string) error {
	return ErrProxyEngineNotReady
}

type Runtime struct {
	Client       *agentapi.Client
	WorkflowID   string
	HarnessLabel string
	CAStore      proxy.CAStore

	// nameless says the first session opened named nobody: see identify.
	identified sync.Once
	nameless   bool
}

type ProxySession struct {
	Config  *agentapi.OpenSessionResponse
	Client  *agentapi.Client
	CA      *proxy.CA
	CAPaths proxy.CAPaths
	// Inventory is where the proxy keeps its leak protection inventory
	// across restarts: beside the CA. Nil keeps it in memory.
	Inventory *proxy.InventoryStore
	// Identity is whose session this is, as the Console's answer that opened
	// it said: the tenant and the login, never a token. Zero when it did not.
	Identity proxy.InventoryIdentity
	// HarnessLabel names the one AI tool this session's proxy serves, as
	// phase ai run and phase ai exec resolve it. It is empty for a proxy that
	// serves whatever harness reaches it, such as the hook-managed daemon.
	HarnessLabel string
	// ReadHosts are the hosts the proxy reads for leak protection, as the
	// engine names them. Like a Connection's own hosts they must reach the
	// proxy, so an inherited NO_PROXY entry that covers one is dropped.
	ReadHosts []string
}

func New(workflowOverride string) (*Runtime, error) {
	aiConfig := config.LoadAIConfig()
	if aiConfig == nil || !aiConfig.Enabled {
		return nil, errors.New("Phase AI mode is disabled; a user must run phase ai enable")
	}
	// One look at the login for the whole start: the host and the token are
	// one account's, and who that is comes from the session the Console opens.
	login, err := activeLogin()
	if err != nil {
		return nil, ErrAuthenticationRequired
	}
	client, err := clientForSavedLogin(login.Host, login.Token)
	if err != nil {
		return nil, err
	}
	if client.TokenType() == agentapi.TokenService {
		return nil, errors.New("Phase Service tokens cannot use phase ai; use a User or Agent token")
	}
	workflowID := workflowOverride
	if client.TokenType() == agentapi.TokenAgent {
		workflowID = ""
	} else if workflowID == "" {
		workflowID = aiConfig.DefaultWorkflowID
	}
	return &Runtime{Client: client, WorkflowID: workflowID}, nil
}

// activeLogin reads the login the runtime starts with; tests replace it.
var activeLogin = keyring.ActiveLogin

// sessionIdentity is whose session the Console says it opened: the session's
// organisation and principal, at the client's host. Zero when it names neither.
func sessionIdentity(client *agentapi.Client, session *agentapi.OpenSessionResponse) proxy.InventoryIdentity {
	if client == nil || session == nil || session.Organisation == nil || session.Principal == nil {
		return proxy.InventoryIdentity{}
	}
	// A principal of another kind than the token's is not this client's login.
	if session.Principal.Type != client.TokenType().IdentityKind() {
		return proxy.InventoryIdentity{}
	}
	return proxy.NewInventoryIdentity(client.Host(), session.Organisation.ID, session.Principal.Type, session.Principal.ID)
}

// identify is sessionIdentity for this runtime's proxy, which serves one
// identity for its life: once a first session named nobody, every later one does.
func (r *Runtime) identify(session *agentapi.OpenSessionResponse) proxy.InventoryIdentity {
	identity := sessionIdentity(r.Client, session)
	r.identified.Do(func() { r.nameless = !identity.Known() })
	if r.nameless {
		return proxy.InventoryIdentity{}
	}
	return identity
}

// NewForUp builds the runtime for `phase up`. It's a network feature, so it doesn't
// depend on the `phase ai enable` setup, and it takes the same logins `phase ai run`
// does: an Agent token, or a user login with a Workflow.
func NewForUp(workflowOverride string) (*Runtime, error) {
	// One look at the login, as New takes it: the host and the token are one
	// account's, and who that is comes from the session the Console opens.
	login, err := activeLogin()
	if err != nil {
		return nil, ErrAuthenticationRequired
	}
	client, err := clientForSavedLogin(login.Host, login.Token)
	if err != nil {
		return nil, err
	}
	if client.TokenType() == agentapi.TokenService {
		return nil, errors.New("Phase Service tokens cannot use phase up; use a User or Agent token")
	}
	workflowID := workflowOverride
	if client.TokenType() == agentapi.TokenAgent {
		workflowID = ""
	} else if workflowID == "" {
		if aiConfig := config.LoadAIConfig(); aiConfig != nil {
			workflowID = aiConfig.DefaultWorkflowID
		}
	}
	return &Runtime{Client: client, WorkflowID: workflowID, HarnessLabel: "phase up"}, nil
}

func clientForSavedLogin(host, token string) (*agentapi.Client, error) {
	if _, _, err := agentapi.ParseDurableToken(token); err != nil {
		return nil, ErrAuthenticationRequired
	}
	client, err := agentapi.NewClient(host, token, nil)
	if err != nil {
		return nil, ErrAuthenticationRequired
	}
	return client, nil
}

func (r *Runtime) open(ctx context.Context, capabilities EngineCapabilities) (*agentapi.OpenSessionResponse, error) {
	if r.Client == nil {
		return nil, errors.New("Phase AI runtime client is unavailable")
	}
	if r.Client.TokenType() == agentapi.TokenService {
		return nil, errors.New("Phase Service tokens cannot use phase ai; use a User or Agent token")
	}
	if r.Client.TokenType() != agentapi.TokenAgent && r.WorkflowID == "" {
		return nil, errors.New("an Agent Workflow is required; pass --workflow or set one with phase ai enable --workflow")
	}
	idempotencyKey, err := randomID("proxy-start-")
	if err != nil {
		return nil, err
	}
	harnessLabel := r.HarnessLabel
	if harnessLabel == "" {
		harnessLabel = ai.DetectAIAgent()
	}
	session, err := r.Client.OpenSession(ctx, agentapi.OpenSessionRequest{
		SchemaVersion:  agentapi.SchemaVersion,
		WorkflowID:     r.WorkflowID,
		IdempotencyKey: idempotencyKey,
		HarnessLabel:   harnessLabel,
		Client: agentapi.ClientCapabilities{
			Name:                    "phase-cli",
			Version:                 version.Version,
			SupportedSchemaVersions: []int{agentapi.SchemaVersion},
			Protocols:               append([]string(nil), capabilities.Protocols...),
			InjectionActions:        append([]string(nil), capabilities.InjectionActions...),
			Features:                advertisedFeatures(capabilities.Features, r.Client),
		},
	})
	if err != nil {
		var apiErr *agentapi.Error
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized {
			return nil, ErrAuthenticationRequired
		}
		return nil, err
	}
	return session, nil
}

// advertisedFeatures is what the client tells the Console it can do for this
// session. Opening sealed material needs the Agent key, which can be rebuilt
// only from an Agent token, so a User or Service Account login never lists it
// and keeps receiving values the Console resolved.
func advertisedFeatures(engineFeatures []string, client *agentapi.Client) []string {
	features := make([]string, 0, len(engineFeatures))
	for _, feature := range engineFeatures {
		if feature == agentapi.FeatureSealedMaterial && !client.CanOpenSealedMaterial() {
			continue
		}
		features = append(features, feature)
	}
	return features
}

// ServeManaged runs one backend session without translating lifecycle errors
// into foreground-harness restart guidance. Hook-owned daemons use this entry
// point to drain one proxy engine completely before opening a
// successor session in the same supervising process. Run and Exec retain
// their terminal semantics because their child environments are immutable
// after launch.
func (r *Runtime) ServeManaged(ctx context.Context, engine Engine) error {
	return r.withSession(ctx, engine, nil)
}

func (r *Runtime) Run(ctx context.Context, engine Engine, command []string) error {
	if len(command) == 0 {
		return errors.New("an Agent harness command is required")
	}
	if r.HarnessLabel == "" {
		r.HarnessLabel = ai.DetectAIAgentCommand(command)
	}
	err := r.withSession(ctx, engine, command)
	if errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrSessionReprovisionRequired) {
		return fmt.Errorf("%w; the managed child was terminated because its backend session and decoy environment cannot be replaced atomically; run phase ai run again", err)
	}
	return err
}

// Exec runs one command through a transient Phase AI session. Unlike Run, it
// does not classify or prepare the command as an Agent harness; attribution is
// inherited only from the invoking harness environment.
func (r *Runtime) Exec(ctx context.Context, engine Engine, command []string) error {
	if len(command) == 0 {
		return errors.New("a command is required")
	}
	if r.HarnessLabel == "" {
		r.HarnessLabel = ai.DetectAIAgent()
	}
	err := r.withSession(ctx, engine, command)
	if errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrSessionReprovisionRequired) {
		return fmt.Errorf("%w; the one-off command was terminated because its backend session and decoy environment cannot be replaced atomically; run phase ai exec again", err)
	}
	return err
}

func (r *Runtime) withSession(ctx context.Context, engine Engine, command []string) error {
	if engine == nil {
		engine = UnavailableEngine{}
	}
	// Readiness is deliberately checked before opening a session. An unavailable
	// engine must not resolve live credentials it cannot safely proxy.
	if err := engine.Ready(); err != nil {
		return err
	}
	session, err := r.open(ctx, engine.Capabilities())
	if err != nil {
		return err
	}
	defer func() {
		for i := range session.Connections {
			session.Connections[i].SecretMaterial.Destroy()
		}
	}()
	defer func() {
		revokeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = r.Client.RevokeSession(revokeContext, session.SessionUID, session.SessionCredential) // best effort
	}()
	if err := agentapi.ValidateAgentVisibleEnvironment(session.ConfigEnv, session.Connections); err != nil {
		return fmt.Errorf("reject unsafe Agent session environment: %w", err)
	}

	caStore := r.CAStore
	ca, paths, err := caStore.Ensure()
	if err != nil {
		return err
	}
	// The inventory is the session's tenant's: the proxy opens no other.
	identity := r.identify(session)
	proxySession := &ProxySession{Config: session, Client: r.Client, CA: ca, CAPaths: paths,
		Inventory: &proxy.InventoryStore{Directory: caStore.Directory, Keyring: caStore.Keyring, Tenant: identity.Tenant}, Identity: identity}
	if command == nil {
		return engine.Serve(ctx, proxySession)
	}
	// Only a proxy started for one command knows whose traffic it carries.
	proxySession.HarnessLabel = r.HarnessLabel
	return engine.Run(ctx, proxySession, command)
}

// CompileProcessEnvironment is the single session-to-process compiler used by
// phase ai run, phase ai exec and the hook daemons. It resolves only Phase-owned changes;
// ApplyProcessEnvironment is the separate child-launch boundary which retains
// unrelated inherited variables.
func (s *ProxySession) CompileProcessEnvironment(proxyURL string, base []string, adapterEnv map[string]string) (proxy.ProcessEnvironmentPlan, error) {
	inputs, err := s.environmentInputs()
	if err != nil {
		return proxy.ProcessEnvironmentPlan{}, err
	}
	return proxy.CompileProcessEnvironment(proxy.EnvironmentOptions{
		Base:                  base,
		ProxyURL:              proxyURL,
		CABundlePath:          s.CAPaths.Bundle,
		CABundleComplete:      s.CAPaths.BundleComplete,
		ConfigEnv:             inputs.configEnv,
		AgentEnv:              inputs.agentEnv,
		AdapterEnv:            adapterEnv,
		CredentialEnvironment: inputs.credentialEnvironment,
		ScopedTrustKeys:       inputs.scopedTrustKeys,
		EnvironmentBindings:   inputs.environmentBindings,
		ProxyRequiredHosts:    inputs.proxyRequiredHosts,
	})
}

// ProviderProcessEnvironment is the value/unset portion sourced from the
// Console. The proxy keeps it to verify that a later discover response still
// describes the exact environment compiled at process launch.
func (s *ProxySession) ProviderProcessEnvironment() (proxy.ProcessEnvironmentPlan, error) {
	inputs, err := s.environmentInputs()
	if err != nil {
		return proxy.ProcessEnvironmentPlan{}, err
	}
	return proxy.PlanResolvedProcessEnvironment(
		inputs.configEnv,
		inputs.agentEnv,
		inputs.environmentBindings,
		inputs.credentialEnvironment,
	)
}

type processEnvironmentInputs struct {
	configEnv map[string]string
	agentEnv  map[string]string
	// credentialEnvironment is the union of every Connection's
	// credentialEnvironment, including a Connection that is not the default
	// identity of its service: its provider's variables are still the session's.
	credentialEnvironment []string
	scopedTrustKeys       []string
	environmentBindings   []proxy.EnvironmentBinding
	proxyRequiredHosts    []string
}

func (s *ProxySession) environmentInputs() (processEnvironmentInputs, error) {
	if s == nil || s.Config == nil {
		return processEnvironmentInputs{}, errors.New("Agent proxy session is incomplete")
	}
	if err := agentapi.ValidateAgentVisibleEnvironment(s.Config.ConfigEnv, s.Config.Connections); err != nil {
		return processEnvironmentInputs{}, err
	}
	agentEnv := make(map[string]string)
	configEnv := make(map[string]string)
	for key, value := range s.Config.ConfigEnv {
		configEnv[key] = value
	}
	identityCount := make(map[string]int)
	for _, connection := range s.Config.Connections {
		identityCount[defaultIdentity(connection)]++
	}
	contested := contestedCustomEnvironmentNames(s.Config.Connections)
	credentialEnvironment := make([]string, 0)
	scopedTrustKeys := make([]string, 0)
	environmentBindings := make([]proxy.EnvironmentBinding, 0)
	exportedBindings := make([]exportedBinding, 0)
	proxyRequiredHosts := append(make([]string, 0), s.ReadHosts...)
	for _, connection := range s.Config.Connections {
		if err := agentapi.ValidateCredentialEnvironment(connection.CredentialEnvironment); err != nil {
			return processEnvironmentInputs{}, fmt.Errorf("Agent connection %s: %w", connection.ConnectionID, err)
		}
		credentialEnvironment = append(credentialEnvironment, connection.CredentialEnvironment...)
		scopedTrustKeys = append(scopedTrustKeys, proxy.ScopedTrustEnvironmentKeys(connection.PrimaryInjectionAction())...)
		for _, host := range connection.Hosts {
			proxyRequiredHosts = append(proxyRequiredHosts, host.Value)
		}
		if connection.ConfigEnv == nil {
			return processEnvironmentInputs{}, fmt.Errorf("Agent connection %s has no v1 configEnv", connection.ConnectionID)
		}
		if connection.EnvironmentBindings == nil {
			return processEnvironmentInputs{}, fmt.Errorf("Agent connection %s has no v1 environmentBindings", connection.ConnectionID)
		}
		if err := agentapi.ValidateResolvedEnvironmentBindings(
			connection.EnvironmentBindings,
			connection.Identifiers,
			connection.DecoyMaterial,
			connection.ConnectionConfig,
			connection.AgentEnv.Clone(),
			connection.ConfigEnv,
		); err != nil {
			return processEnvironmentInputs{}, fmt.Errorf("Agent connection %s: %w", connection.ConnectionID, err)
		}
		if identityCount[defaultIdentity(connection)] > 1 {
			continue // Explicit selection is required; never pick a default identity.
		}
		for key, value := range connection.ConfigEnv {
			if contested.claims(connection, key) {
				continue
			}
			configEnv[key] = value
		}
		for key, value := range connection.AgentEnv.Clone() {
			if contested.claims(connection, key) {
				continue
			}
			for existingKey, existingValue := range agentEnv {
				if strings.EqualFold(existingKey, key) {
					if existingValue != value {
						return processEnvironmentInputs{}, fmt.Errorf("Agent connections provide conflicting values for %s", key)
					}
					key = existingKey
					break
				}
			}
			agentEnv[key] = value
		}
		agentValues := connection.AgentEnv.Clone()
		for _, binding := range connection.EnvironmentBindings {
			if contested.claims(connection, binding.Name) {
				continue
			}
			exported := exportedBinding{
				binding: proxy.EnvironmentBinding{
					Name: binding.Name, Action: string(binding.Action), Source: string(binding.Source), SourceField: binding.SourceField,
				},
				value: connection.ConfigEnv[binding.Name],
			}
			if value, set := agentValues[binding.Name]; set {
				exported.value = value
			}
			// Two Connections may export one name the same way with the same
			// value. Anything else under one name is kept, and the plan
			// refuses it as a duplicate.
			if slices.Contains(exportedBindings, exported) {
				continue
			}
			exportedBindings = append(exportedBindings, exported)
			environmentBindings = append(environmentBindings, exported.binding)
		}
	}
	return processEnvironmentInputs{
		configEnv: configEnv, agentEnv: agentEnv, credentialEnvironment: credentialEnvironment, scopedTrustKeys: scopedTrustKeys,
		environmentBindings: environmentBindings, proxyRequiredHosts: proxyRequiredHosts,
	}, nil
}

// exportedBinding is one Connection's binding with the value it resolves to.
type exportedBinding struct {
	binding proxy.EnvironmentBinding
	value   string
}

// defaultIdentity groups the Connections that compete to be the default
// identity of one service. Packaged services compete per service type. Every
// custom HTTP Connection is a service of its own, so two of them only compete
// over an environment name they both use.
func defaultIdentity(connection agentapi.Connection) string {
	if connection.ServiceType == agentapi.CustomHTTPServiceType {
		return connection.ServiceType + ":" + connection.ConnectionID
	}
	return connection.ServiceType
}

// contestedEnvironmentNames holds the environment names, upper-cased, that
// more than one custom HTTP Connection would set to different values.
type contestedEnvironmentNames map[string]struct{}

func (c contestedEnvironmentNames) claims(connection agentapi.Connection, name string) bool {
	if connection.ServiceType != agentapi.CustomHTTPServiceType {
		return false
	}
	_, contested := c[strings.ToUpper(name)]
	return contested
}

// contestedCustomEnvironmentNames finds names that custom HTTP Connections
// disagree on. Such a name is left out of the default environment, like the
// default identity of a service with several Connections; the per-Connection
// environment still carries it.
func contestedCustomEnvironmentNames(connections []agentapi.Connection) contestedEnvironmentNames {
	values := make(map[string]string)
	contested := make(contestedEnvironmentNames)
	note := func(name, value string) {
		name = strings.ToUpper(name)
		if known, seen := values[name]; seen && known != value {
			contested[name] = struct{}{}
		}
		values[name] = value
	}
	for _, connection := range connections {
		if connection.ServiceType != agentapi.CustomHTTPServiceType {
			continue
		}
		for name, value := range connection.ConfigEnv {
			note(name, value)
		}
		for name, value := range connection.AgentEnv.Clone() {
			note(name, value)
		}
	}
	return contested
}

func randomID(prefix string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate Agent idempotency key: %w", err)
	}
	return prefix + hex.EncodeToString(random), nil
}
