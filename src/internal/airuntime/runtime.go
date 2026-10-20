package airuntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

type agentTokenRequiredEngine interface {
	RequiresAgentToken() bool
}

type EngineCapabilities struct {
	Protocols        []string
	InjectionActions []string
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
}

type ProxySession struct {
	Config  *agentapi.OpenSessionResponse
	Client  *agentapi.Client
	CA      *proxy.CA
	CAPaths proxy.CAPaths
}

func New(workflowOverride string) (*Runtime, error) {
	aiConfig := config.LoadAIConfig()
	if aiConfig == nil || !aiConfig.Enabled {
		return nil, errors.New("Phase AI mode is disabled; a user must run phase ai enable")
	}
	if aiConfig.ProxyMode != config.AIProxyModeLocal {
		return nil, fmt.Errorf("unsupported AI proxy mode %q", aiConfig.ProxyMode)
	}
	host, err := config.GetDefaultUserHost()
	if err != nil {
		return nil, ErrAuthenticationRequired
	}
	token, err := keyring.GetCredentials()
	if err != nil {
		return nil, ErrAuthenticationRequired
	}
	client, err := clientForSavedLogin(host, token)
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

// NewForRelay builds the runtime for `phase relay start`. A relay is a server:
// it does not depend on the per-user `phase ai enable` setup, and it must be
// logged in with an Agent token so the Workflow comes from the token itself.
func NewForRelay() (*Runtime, error) {
	host, err := config.GetDefaultUserHost()
	if err != nil {
		return nil, ErrAuthenticationRequired
	}
	token, err := keyring.GetCredentials()
	if err != nil {
		return nil, ErrAuthenticationRequired
	}
	client, err := clientForSavedLogin(host, token)
	if err != nil {
		return nil, err
	}
	if client.TokenType() != agentapi.TokenAgent {
		return nil, errors.New("phase relay start requires an Agent token login; run phase auth --mode token with an Agent token")
	}
	return &Runtime{Client: client}, nil
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

// ServeManaged runs one backend session without translating lifecycle errors
// into foreground-harness restart guidance. Hook-owned daemons and the relay
// use this entry point to drain one proxy engine completely before opening a
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
	if required, ok := engine.(agentTokenRequiredEngine); ok && required.RequiresAgentToken() &&
		(r.Client == nil || r.Client.TokenType() != agentapi.TokenAgent) {
		return errors.New("remote Phase AI mode requires Agent-token login")
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
	proxySession := &ProxySession{Config: session, Client: r.Client, CA: ca, CAPaths: paths}
	if command == nil {
		return engine.Serve(ctx, proxySession)
	}
	return engine.Run(ctx, proxySession, command)
}

// CompileProcessEnvironment is the single session-to-process compiler used by
// phase ai run, phase ai exec, the hook daemons and phase relay start. It resolves only Phase-owned changes;
// ApplyProcessEnvironment is the separate child-launch boundary which retains
// unrelated inherited variables.
func (s *ProxySession) CompileProcessEnvironment(proxyURL string, base []string, adapterEnv map[string]string) (proxy.ProcessEnvironmentPlan, error) {
	inputs, err := s.environmentInputs()
	if err != nil {
		return proxy.ProcessEnvironmentPlan{}, err
	}
	return proxy.CompileProcessEnvironment(proxy.EnvironmentOptions{
		Base:                base,
		ProxyURL:            proxyURL,
		CertificatePath:     s.CAPaths.Certificate,
		CABundlePath:        s.CAPaths.Bundle,
		CABundleComplete:    s.CAPaths.BundleComplete,
		ConfigEnv:           inputs.configEnv,
		AgentEnv:            inputs.agentEnv,
		AdapterEnv:          adapterEnv,
		CredentialFamilies:  inputs.credentialFamilies,
		EnvironmentBindings: inputs.environmentBindings,
		ProxyRequiredHosts:  inputs.proxyRequiredHosts,
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
	)
}

type processEnvironmentInputs struct {
	configEnv           map[string]string
	agentEnv            map[string]string
	credentialFamilies  []string
	environmentBindings []proxy.EnvironmentBinding
	proxyRequiredHosts  []string
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
	serviceCount := make(map[string]int)
	for _, connection := range s.Config.Connections {
		serviceCount[connection.ServiceType]++
	}
	credentialFamilies := make([]string, 0)
	environmentBindings := make([]proxy.EnvironmentBinding, 0)
	proxyRequiredHosts := make([]string, 0)
	for _, connection := range s.Config.Connections {
		families := proxy.CredentialFamiliesForConnection(connection.ServiceType, connection.Injection.Action)
		credentialFamilies = append(credentialFamilies, families...)
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
		if serviceCount[connection.ServiceType] > 1 {
			continue // Explicit selection is required; never pick a default identity.
		}
		for key, value := range connection.ConfigEnv {
			configEnv[key] = value
		}
		for key, value := range connection.AgentEnv.Clone() {
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
		for _, binding := range connection.EnvironmentBindings {
			environmentBindings = append(environmentBindings, proxy.EnvironmentBinding{
				Name: binding.Name, Action: string(binding.Action), Source: string(binding.Source), SourceField: binding.SourceField,
			})
		}
	}
	return processEnvironmentInputs{
		configEnv: configEnv, agentEnv: agentEnv, credentialFamilies: credentialFamilies,
		environmentBindings: environmentBindings, proxyRequiredHosts: proxyRequiredHosts,
	}, nil
}

func randomID(prefix string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate Agent idempotency key: %w", err)
	}
	return prefix + hex.EncodeToString(random), nil
}
