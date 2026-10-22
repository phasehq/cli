// Package agentsdk provides the typed client and wire types for the Phase AI
// Agents runtime API. It is intentionally independent from phase.New: Agent,
// User, and Service Account bearer credentials can all use this package.
package agentsdk

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
)

const (
	// CurrentSchemaVersion is the latest Agent runtime contract understood by
	// this SDK release.
	CurrentSchemaVersion = 1
	redactedValue        = "[REDACTED]"
)

// SensitiveString is reveal-once or live credential material. Formatting it
// through fmt always redacts the value; JSON encoding remains available for
// the API transport.
type SensitiveString string

// Reveal returns the underlying value for the narrow point where a caller must
// install or transmit it.
func (s SensitiveString) Reveal() string { return string(s) }

func (s SensitiveString) String() string   { return redactedValue }
func (s SensitiveString) GoString() string { return redactedValue }
func (s SensitiveString) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redactedValue)
}

// SecretMaterial contains live proxy-only credential fields. Its fmt output is
// always redacted, including with %#v and when nested in another struct.
type SecretMaterial map[string]string

func (s SecretMaterial) String() string   { return redactedValue }
func (s SecretMaterial) GoString() string { return redactedValue }
func (s SecretMaterial) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redactedValue)
}

// AgentEnvironment contains agent-visible identifiers and decoys, including
// native-protocol adapter passwords. Decoys are not live upstream secrets, but
// they are still capabilities within the active proxy runtime and must not be
// emitted through ordinary formatting.
type AgentEnvironment map[string]string

func (s AgentEnvironment) String() string   { return redactedValue }
func (s AgentEnvironment) GoString() string { return redactedValue }
func (s AgentEnvironment) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redactedValue)
}

// EnvironmentBindingAction describes how a resolved runtime binding changes a
// harness environment. The Console emits provider bindings; proxy and CA
// bindings remain local to the CLI that owns those paths and capabilities.
type EnvironmentBindingAction string

const (
	EnvironmentBindingSet   EnvironmentBindingAction = "set"
	EnvironmentBindingUnset EnvironmentBindingAction = "unset"
)

// EnvironmentBindingSource describes the declarative source of an environment
// binding without exposing credential material. It is intentionally a string
// type so a newer server's source can be decoded before a caller explicitly
// validates it.
type EnvironmentBindingSource string

const (
	EnvironmentSourceProxy            EnvironmentBindingSource = "proxy"
	EnvironmentSourceCA               EnvironmentBindingSource = "ca"
	EnvironmentSourceIdentifier       EnvironmentBindingSource = "identifier"
	EnvironmentSourceDecoy            EnvironmentBindingSource = "decoy"
	EnvironmentSourceConnectionConfig EnvironmentBindingSource = "connection_config"
	EnvironmentSourceRuntime          EnvironmentBindingSource = "runtime"
)

// EnvironmentBinding is value-free environment metadata for one
// RuntimeConnection or DiscoverConnection. Ownership is implicit from the
// containing connection. Resolved identifiers and decoys remain in AgentEnv;
// bindings describe only their provenance and application behavior.
type EnvironmentBinding struct {
	Name          string                   `json:"name"`
	Action        EnvironmentBindingAction `json:"action"`
	Source        EnvironmentBindingSource `json:"source"`
	SourceField   string                   `json:"sourceField,omitempty"`
	Sensitive     bool                     `json:"sensitive"`
	SystemManaged bool                     `json:"systemManaged"`
}

// Validate checks the currently supported binding vocabulary. Unknown actions
// and sources remain decodable for forward compatibility but fail explicit
// validation so an environment compiler can fail closed.
func (b EnvironmentBinding) Validate() error {
	if !validBindingEnvironmentName(b.Name) {
		return fmt.Errorf("agents: environment binding name is invalid")
	}
	switch b.Action {
	case EnvironmentBindingSet, EnvironmentBindingUnset:
	default:
		return fmt.Errorf("agents: unsupported environment binding action")
	}

	switch b.Source {
	case EnvironmentSourceProxy,
		EnvironmentSourceCA,
		EnvironmentSourceIdentifier,
		EnvironmentSourceDecoy,
		EnvironmentSourceConnectionConfig,
		EnvironmentSourceRuntime:
	default:
		return fmt.Errorf("agents: unsupported environment binding source")
	}
	if b.SourceField != "" && !validSourceField(b.SourceField) {
		return fmt.Errorf("agents: environment binding source field is invalid")
	}
	switch b.Action {
	case EnvironmentBindingSet:
		switch b.Source {
		case EnvironmentSourceIdentifier, EnvironmentSourceDecoy, EnvironmentSourceConnectionConfig:
			if b.SourceField == "" {
				return fmt.Errorf("agents: provider set environment binding requires a source field")
			}
		case EnvironmentSourceProxy, EnvironmentSourceCA:
			// Proxy and CA values are resolved locally by the CLI and do not
			// necessarily map to a backend field.
		default:
			return fmt.Errorf("agents: set environment binding has an unsupported source")
		}
	case EnvironmentBindingUnset:
		if b.Source != EnvironmentSourceRuntime {
			return fmt.Errorf("agents: unset environment binding must use the runtime source")
		}
		if b.SourceField == "" {
			return fmt.Errorf("agents: unset environment binding requires an activating source field")
		}
	}
	return nil
}

// ValidateEnvironmentBindings validates a connection's binding collection and
// rejects duplicate ownership of an environment name. It never resolves or
// includes environment values in validation errors.
func ValidateEnvironmentBindings(bindings []EnvironmentBinding) error {
	seen := make(map[string]struct{}, len(bindings))
	for index, binding := range bindings {
		if err := binding.Validate(); err != nil {
			return fmt.Errorf("agents: environment binding %d: %w", index, err)
		}
		canonical := strings.ToUpper(binding.Name)
		if _, exists := seen[canonical]; exists {
			return fmt.Errorf("agents: environment binding %d duplicates an environment name", index)
		}
		seen[canonical] = struct{}{}
	}
	return nil
}

// ValidateResolvedEnvironmentBindings verifies value-free provider provenance
// against the resolved planes carried by one runtime or discovery connection.
// Errors identify binding metadata only and never include resolved values.
func ValidateResolvedEnvironmentBindings(
	bindings []EnvironmentBinding,
	identifiers map[string]string,
	decoyMaterial map[string]string,
	connectionConfig map[string]interface{},
	agentEnv map[string]string,
	configEnv map[string]string,
) error {
	if bindings == nil {
		return fmt.Errorf("agents: environmentBindings is required by schema version %d", CurrentSchemaVersion)
	}
	if err := ValidateEnvironmentBindings(bindings); err != nil {
		return err
	}
	declaredAgentEnv := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		switch binding.Source {
		case EnvironmentSourceIdentifier:
			value, found, ambiguous := semanticMapValue(identifiers, binding.SourceField)
			environmentValue, present := agentEnv[binding.Name]
			if !found || ambiguous || !present || environmentValue != value {
				return fmt.Errorf("agents: environment binding %s does not resolve from its identifier", binding.Name)
			}
			declaredAgentEnv[binding.Name] = struct{}{}
		case EnvironmentSourceDecoy:
			value, found, ambiguous := semanticMapValue(decoyMaterial, binding.SourceField)
			environmentValue, present := agentEnv[binding.Name]
			if !found || ambiguous || !present || environmentValue != value {
				return fmt.Errorf("agents: environment binding %s does not resolve from its decoy", binding.Name)
			}
			declaredAgentEnv[binding.Name] = struct{}{}
		case EnvironmentSourceConnectionConfig:
			value, found, ambiguous := semanticConnectionConfigString(connectionConfig, binding.SourceField)
			if !found || ambiguous || configEnv[binding.Name] != value {
				return fmt.Errorf("agents: environment binding %s does not resolve from connection configuration", binding.Name)
			}
		case EnvironmentSourceRuntime:
			_, found, ambiguous := semanticMapValue(decoyMaterial, binding.SourceField)
			if !found || ambiguous {
				return fmt.Errorf("agents: environment binding %s has no unambiguous decoy activation field", binding.Name)
			}
		case EnvironmentSourceProxy, EnvironmentSourceCA:
			return fmt.Errorf("agents: environment binding %s uses a CLI-local source in a provider response", binding.Name)
		default:
			return fmt.Errorf("agents: environment binding %s has unsupported provenance", binding.Name)
		}
	}
	for name := range agentEnv {
		if _, declared := declaredAgentEnv[name]; !declared {
			return fmt.Errorf("agents: Agent environment contains an entry without an environment binding")
		}
	}
	return nil
}

func semanticConnectionConfigString(values map[string]interface{}, canonical string) (string, bool, bool) {
	alias := lowerCamelSemanticName(canonical)
	raw, exact := values[canonical]
	if alias == canonical {
		value, valid := raw.(string)
		return value, exact && valid, false
	}
	aliasRaw, aliased := values[alias]
	if exact && aliased {
		return "", false, true
	}
	if aliased {
		raw, exact = aliasRaw, true
	}
	value, valid := raw.(string)
	return value, exact && valid, false
}

func validBindingEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for index, character := range name {
		if (character >= 'A' && character <= 'Z') || character == '_' ||
			(index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func validSourceField(field string) bool {
	for index, character := range field {
		if (character >= 'a' && character <= 'z') ||
			(index > 0 && (character == '_' || character >= '0' && character <= '9')) {
			continue
		}
		return false
	}
	return field != ""
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for index, character := range name {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || character == '_' ||
			(index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

// ProcessEnvironmentPlan is the authenticated proxy-manifest representation
// consumed by a harness launcher. Set contains configuration and runtime decoy
// values and is therefore redacted from fmt output; Unset names inherited
// credentials that would otherwise compete with an injected provider family.
// EnvironmentBindings on each connection supplies the provider provenance.
type ProcessEnvironmentPlan struct {
	Set   AgentEnvironment `json:"set"`
	Unset []string         `json:"unset"`
}

func (p ProcessEnvironmentPlan) String() string {
	return fmt.Sprintf("ProcessEnvironmentPlan{Set:%s Unset:%q}", redactedValue, p.Unset)
}
func (p ProcessEnvironmentPlan) GoString() string { return p.String() }
func (p ProcessEnvironmentPlan) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, p.String())
}

// Validate rejects case-insensitive collisions and malformed names without
// compiling or mutating an operating-system environment. Environment
// compilation remains the CLI's responsibility because it owns proxy and CA
// paths.
func (p ProcessEnvironmentPlan) Validate() error {
	type setEntry struct {
		name  string
		value string
	}
	seenSet := make(map[string]setEntry, len(p.Set))
	for name, value := range p.Set {
		if !validEnvironmentName(name) {
			return fmt.Errorf("agents: process environment contains an invalid set name")
		}
		canonical := strings.ToUpper(name)
		if previous, exists := seenSet[canonical]; exists {
			// The CLI intentionally publishes upper- and lower-case aliases for
			// these three conventional proxy variables. No provider credential
			// or arbitrary user variable receives the same exception.
			if !allowedProcessEnvironmentAlias(canonical) || previous.value != value {
				return fmt.Errorf("agents: process environment contains a case-insensitive set collision between %s and %s", previous.name, name)
			}
			continue
		}
		seenSet[canonical] = setEntry{name: name, value: value}
	}
	seenUnset := make(map[string]string, len(p.Unset))
	for _, name := range p.Unset {
		if !validEnvironmentName(name) {
			return fmt.Errorf("agents: process environment contains an invalid unset name")
		}
		canonical := strings.ToUpper(name)
		if previous, exists := seenSet[canonical]; exists {
			return fmt.Errorf("agents: process environment contains a set/unset collision between %s and %s", previous.name, name)
		}
		if previous, exists := seenUnset[canonical]; exists {
			return fmt.Errorf("agents: process environment contains a case-insensitive unset collision between %s and %s", previous, name)
		}
		seenUnset[canonical] = name
	}
	return nil
}

func allowedProcessEnvironmentAlias(canonical string) bool {
	switch canonical {
	case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY":
		return true
	default:
		return false
	}
}

// DecoyMaterial contains agent-visible credentials that are valid only at the
// active Phase proxy boundary. They are not live upstream secrets, but logging
// them would still disclose usable runtime capabilities.
type DecoyMaterial map[string]string

func (s DecoyMaterial) String() string   { return redactedValue }
func (s DecoyMaterial) GoString() string { return redactedValue }
func (s DecoyMaterial) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redactedValue)
}

// AuthenticationType is the principal name used in Phase's bearer scheme.
type AuthenticationType string

const (
	AuthenticationAgent          AuthenticationType = "Agent"
	AuthenticationUser           AuthenticationType = "User"
	AuthenticationServiceAccount AuthenticationType = "ServiceAccount"
)

// Authentication carries the durable Phase credential used by the proxy.
// Token is the lookup token value, not a preformatted Authorization header.
type Authentication struct {
	Type  AuthenticationType
	Token SensitiveString
}

func AgentAuthentication(token string) Authentication {
	return Authentication{Type: AuthenticationAgent, Token: SensitiveString(token)}
}

func UserAuthentication(token string) Authentication {
	return Authentication{Type: AuthenticationUser, Token: SensitiveString(token)}
}

func ServiceAccountAuthentication(token string) Authentication {
	return Authentication{Type: AuthenticationServiceAccount, Token: SensitiveString(token)}
}

// AuthenticationFromPhaseToken extracts the bearer lookup value from a full
// Agent, Personal Access, or Service Account token without involving phase.New
// or the secrets client. Agent tokens are opaque v1 bearer secrets. Personal
// Access Tokens use v1 and Service Account tokens use v2.
func AuthenticationFromPhaseToken(token string) (Authentication, error) {
	parts := strings.Split(token, ":")
	if len(parts) < 2 {
		return Authentication{}, fmt.Errorf("agents: invalid Phase token")
	}
	switch parts[0] {
	case "pss_agent":
		if parts[1] != "v1" {
			return Authentication{}, fmt.Errorf("agents: invalid Agent token version")
		}
		if len(parts) != 3 || !isHex64(parts[2]) {
			return Authentication{}, fmt.Errorf("agents: invalid Phase token")
		}
		return AgentAuthentication(parts[2]), nil
	case "pss_user":
		if parts[1] != "v1" {
			return Authentication{}, fmt.Errorf("agents: invalid Personal Access Token version")
		}
		if !validKeyShareToken(parts) {
			return Authentication{}, fmt.Errorf("agents: invalid Phase token")
		}
		return UserAuthentication(parts[2]), nil
	case "pss_service":
		if parts[1] != "v2" {
			return Authentication{}, fmt.Errorf("agents: invalid Service Account token version")
		}
		if !validKeyShareToken(parts) {
			return Authentication{}, fmt.Errorf("agents: invalid Phase token")
		}
		return ServiceAccountAuthentication(parts[2]), nil
	default:
		return Authentication{}, fmt.Errorf("agents: unsupported Phase token type")
	}
}

func validKeyShareToken(parts []string) bool {
	if len(parts) != 6 {
		return false
	}
	for _, part := range parts[2:] {
		if !isHex64(part) {
			return false
		}
	}
	return true
}

func isHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func (a Authentication) String() string {
	return fmt.Sprintf("Authentication{Type:%s Token:%s}", a.Type, redactedValue)
}
func (a Authentication) GoString() string { return a.String() }
func (a Authentication) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, a.String())
}

type StringMap map[string]string

type ClientCapabilities struct {
	Name                    string            `json:"name"`
	Version                 string            `json:"version"`
	SupportedSchemaVersions []int             `json:"supportedSchemaVersions"`
	Protocols               []Protocol        `json:"protocols"`
	InjectionActions        []InjectionAction `json:"injectionActions"`
}

type OpenSessionRequest struct {
	SchemaVersion  int                `json:"schemaVersion"`
	WorkflowID     string             `json:"workflowId,omitempty"`
	IdempotencyKey string             `json:"idempotencyKey,omitempty"`
	Client         ClientCapabilities `json:"client"`
	HarnessLabel   string             `json:"harnessLabel,omitempty"`
}

type OpenSessionResponse struct {
	SchemaVersion     int                 `json:"schemaVersion"`
	SessionUID        string              `json:"sessionUid"`
	SessionCredential SensitiveString     `json:"sessionCredential"`
	ExpiresAt         time.Time           `json:"expiresAt"`
	MaxExpiresAt      *time.Time          `json:"maxExpiresAt,omitempty"`
	ConfigGeneration  uint64              `json:"configGeneration"`
	ConfigEnv         StringMap           `json:"configEnv"`
	Connections       []RuntimeConnection `json:"connections"`
}

// SessionAuth identifies a live session and carries its short-lived #1 value.
// It is used in addition to, never instead of, the Client's durable Phase
// Authorization credential.
type SessionAuth struct {
	SessionUID string
	Credential SensitiveString
}

func (r OpenSessionResponse) SessionAuth() SessionAuth {
	return SessionAuth{SessionUID: r.SessionUID, Credential: r.SessionCredential}
}

func (s SessionAuth) String() string {
	return fmt.Sprintf("SessionAuth{SessionUID:%q Credential:%s}", s.SessionUID, redactedValue)
}
func (s SessionAuth) GoString() string { return s.String() }
func (s SessionAuth) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, s.String())
}

// RefreshConfigResponse deliberately has no SessionCredential field. Rotation
// is the only operation allowed to return a replacement session credential.
type RefreshConfigResponse struct {
	SchemaVersion    int                 `json:"schemaVersion"`
	SessionUID       string              `json:"sessionUid"`
	ExpiresAt        time.Time           `json:"expiresAt"`
	MaxExpiresAt     *time.Time          `json:"maxExpiresAt,omitempty"`
	ConfigGeneration uint64              `json:"configGeneration"`
	ConfigEnv        StringMap           `json:"configEnv"`
	Connections      []RuntimeConnection `json:"connections"`
}

type RuntimeConnection struct {
	GrantID             string     `json:"grantId"`
	ConnectionID        string     `json:"connectionId"`
	ConnectionName      string     `json:"connectionName,omitempty"`
	CredentialID        string     `json:"credentialId"`
	CredentialName      string     `json:"credentialName,omitempty"`
	CredentialProvider  string     `json:"credentialProvider"`
	CredentialRevision  string     `json:"credentialRevision,omitempty"`
	MaterialGeneration  string     `json:"materialGeneration,omitempty"`
	CredentialExpiresAt *time.Time `json:"credentialExpiresAt,omitempty"`
	ServiceType         string     `json:"serviceType"`
	Protocol            Protocol   `json:"protocol"`
	Hosts               []HostRule `json:"hosts"`
	// ConnectionConfig is compiled effective provider configuration. It is not
	// an independently editable credential store.
	ConnectionConfig    map[string]interface{}  `json:"connectionConfig,omitempty"`
	ConfigEnv           StringMap               `json:"configEnv,omitzero"`
	Injection           Injection               `json:"injection"`
	OnRefresh           RefreshBehavior         `json:"onRefresh,omitempty"`
	Identifiers         StringMap               `json:"identifiers"`
	DecoyMaterial       DecoyMaterial           `json:"decoyMaterial"`
	AgentEnv            AgentEnvironment        `json:"agentEnv"`
	EnvironmentBindings []EnvironmentBinding    `json:"environmentBindings,omitempty"`
	SecretMaterial      SecretMaterial          `json:"secretMaterial"`
	Authorization       ConnectionAuthorization `json:"authorization"`
}

// ValidateEnvironmentBindings verifies this runtime connection's binding
// metadata and resolved provenance against its v1 per-Connection ConfigEnv.
func (c RuntimeConnection) ValidateEnvironmentBindings() error {
	if c.ConfigEnv == nil {
		return fmt.Errorf("agents: configEnv is required by schema version %d", CurrentSchemaVersion)
	}
	return ValidateResolvedEnvironmentBindings(
		c.EnvironmentBindings,
		c.Identifiers,
		c.DecoyMaterial,
		c.ConnectionConfig,
		c.AgentEnv,
		c.ConfigEnv,
	)
}

// AllowsUse checks both the Connection's authorization and the validity of its
// currently resolved credential. A missing expiry represents a credential
// without a declared expiration.
func (c RuntimeConnection) AllowsUse(now time.Time) bool {
	return c.Authorization.AllowsUse() &&
		(c.CredentialExpiresAt == nil || c.CredentialExpiresAt.After(now))
}

type RefreshBehavior string

const (
	RefreshNone        RefreshBehavior = "none"
	RefreshSyntheticOK RefreshBehavior = "synthetic_ok"
)

type HostRule struct {
	Match string `json:"match"`
	Value string `json:"value"`
	Port  int    `json:"port,omitempty"`
	Path  string `json:"path,omitempty"`
}

type Protocol string

const (
	ProtocolHTTP     Protocol = "http"
	ProtocolPostgres Protocol = "postgres"
)

// InjectionAction is a string rather than a closed enum so a newer server's
// action can still be decoded and reported. Call Validate or IsKnown before
// executing an action; proxy callers should fail closed when it is unknown.
type InjectionAction string

const (
	InjectionSetHeader        InjectionAction = "set_header"
	InjectionReplaceHeader    InjectionAction = "replace_header"
	InjectionRemoveHeader     InjectionAction = "remove_header"
	InjectionSetParam         InjectionAction = "set_param"
	InjectionSetPath          InjectionAction = "set_path"
	InjectionReplacePathRegex InjectionAction = "replace_path_regex"
	InjectionAWSSigV4         InjectionAction = "aws_sigv4"
	InjectionPGHandshake      InjectionAction = "pg_handshake"
)

func (a InjectionAction) IsKnown() bool {
	switch a {
	case InjectionSetHeader,
		InjectionReplaceHeader,
		InjectionRemoveHeader,
		InjectionSetParam,
		InjectionSetPath,
		InjectionReplacePathRegex,
		InjectionAWSSigV4,
		InjectionPGHandshake:
		return true
	default:
		return false
	}
}

func (a InjectionAction) Validate() error {
	if !a.IsKnown() {
		return &UnsupportedInjectionActionError{Action: a}
	}
	return nil
}

type UnsupportedInjectionActionError struct {
	Action InjectionAction
}

func (e *UnsupportedInjectionActionError) Error() string {
	return "agents: unsupported injection action"
}
func (e *UnsupportedInjectionActionError) String() string   { return e.Error() }
func (e *UnsupportedInjectionActionError) GoString() string { return e.Error() }
func (e *UnsupportedInjectionActionError) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.Error())
}

type Injection struct {
	Action      InjectionAction      `json:"action"`
	Name        string               `json:"name,omitempty"`
	ValueFormat string               `json:"valueFormat,omitempty"`
	ValueFrom   *CredentialValueFrom `json:"valueFrom,omitempty"`
	Pattern     string               `json:"pattern,omitempty"`
	Replacement string               `json:"replacement,omitempty"`
	ServiceFrom string               `json:"serviceFrom,omitempty"`
	RegionFrom  string               `json:"regionFrom,omitempty"`
}

func (i Injection) Validate() error { return i.Action.Validate() }

type CredentialValueFrom struct {
	Source string            `json:"source"`
	Field  string            `json:"field,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
}

// AuthorizationMode identifies the authorization mechanism enforced by the
// proxy for a connection. Connection mode deliberately does not infer or
// maintain provider-operation permissions: the upstream credential remains the
// least-privilege boundary.
type AuthorizationMode string

const AuthorizationConnection AuthorizationMode = "connection"

type ConnectionAccessMode string

const (
	ConnectionAccessAllow ConnectionAccessMode = "allow"
)

type ConnectionAuthorizationState string

const (
	ConnectionAuthorizationAllowed ConnectionAuthorizationState = "allowed"
)

type ConnectionAuthorization struct {
	Version    int                          `json:"version"`
	Mode       AuthorizationMode            `json:"mode"`
	AccessMode ConnectionAccessMode         `json:"accessMode"`
	State      ConnectionAuthorizationState `json:"state"`
}

// AllowsUse reports whether the backend supplied the v1 policy-free allow
// attestation. Unknown versions, modes, access modes, and states fail closed.
func (a ConnectionAuthorization) AllowsUse() bool {
	return a.Version == CurrentSchemaVersion &&
		a.Mode == AuthorizationConnection &&
		a.AccessMode == ConnectionAccessAllow &&
		a.State == ConnectionAuthorizationAllowed
}

// DiscoverResponse is agent-facing and deliberately uses distinct types from
// runtime configuration. It cannot carry SessionCredential or SecretMaterial.
type DiscoverResponse struct {
	SchemaVersion    int                  `json:"schemaVersion"`
	SessionUID       string               `json:"sessionUid"`
	ConfigGeneration uint64               `json:"configGeneration"`
	ConfigEnv        StringMap            `json:"configEnv"`
	Connections      []DiscoverConnection `json:"connections"`
}

type DiscoverConnection struct {
	GrantID             string                  `json:"grantId"`
	ConnectionID        string                  `json:"connectionId"`
	ConnectionName      string                  `json:"connectionName,omitempty"`
	CredentialID        string                  `json:"credentialId"`
	CredentialName      string                  `json:"credentialName,omitempty"`
	CredentialProvider  string                  `json:"credentialProvider"`
	CredentialRevision  string                  `json:"credentialRevision,omitempty"`
	MaterialGeneration  string                  `json:"materialGeneration,omitempty"`
	CredentialExpiresAt *time.Time              `json:"credentialExpiresAt,omitempty"`
	ServiceType         string                  `json:"serviceType"`
	Protocol            Protocol                `json:"protocol"`
	Hosts               []HostRule              `json:"hosts"`
	ConnectionConfig    map[string]interface{}  `json:"connectionConfig,omitempty"`
	ConfigEnv           StringMap               `json:"configEnv,omitzero"`
	Injection           *Injection              `json:"injection,omitempty"`
	OnRefresh           RefreshBehavior         `json:"onRefresh,omitempty"`
	Identifiers         StringMap               `json:"identifiers"`
	DecoyMaterial       DecoyMaterial           `json:"decoyMaterial"`
	AgentEnv            AgentEnvironment        `json:"agentEnv"`
	EnvironmentBindings []EnvironmentBinding    `json:"environmentBindings,omitempty"`
	Authorization       ConnectionAuthorization `json:"authorization"`
}

// ValidateEnvironmentBindings verifies this agent-facing connection's binding
// metadata and resolved provenance against its v1 per-Connection ConfigEnv.
func (c DiscoverConnection) ValidateEnvironmentBindings() error {
	if c.ConfigEnv == nil {
		return fmt.Errorf("agents: configEnv is required by schema version %d", CurrentSchemaVersion)
	}
	return ValidateResolvedEnvironmentBindings(
		c.EnvironmentBindings,
		c.Identifiers,
		c.DecoyMaterial,
		c.ConnectionConfig,
		c.AgentEnv,
		c.ConfigEnv,
	)
}

type ContextResponse struct {
	SchemaVersion int    `json:"schemaVersion,omitempty"`
	SessionUID    string `json:"sessionUid,omitempty"`
	ServiceType   string `json:"serviceType,omitempty"`
	Markdown      string `json:"markdown"`
}

// ClientMatcherKind identifies a safe, exact client-discovery hint. Matchers
// are advisory metadata for choosing whether Phase can help with an operation;
// they never authorize or transparently reroute a process.
type ClientMatcherKind string

const (
	// ClientMatcherSchemaVersion versions the exact-match vocabulary
	// independently from the surrounding Agent runtime API.
	ClientMatcherSchemaVersion = 1

	ClientMatcherExecutable ClientMatcherKind = "executable"
	ClientMatcherURIScheme  ClientMatcherKind = "uri_scheme"
	maxClientMatcherLength                    = 64
)

// ClientMatcher contains exact, lower-case values supplied by the versioned
// service registry. Regex and shell fragments are intentionally unsupported.
type ClientMatcher struct {
	Kind   ClientMatcherKind `json:"kind"`
	Values []string          `json:"values"`
}

// Validate rejects executable paths, regex, shell fragments, and non-canonical
// URI schemes. Matching remains a deliberately small exact-value contract.
func (m ClientMatcher) Validate() error {
	if len(m.Values) == 0 {
		return fmt.Errorf("agents: client matcher values are required")
	}
	seen := make(map[string]struct{}, len(m.Values))
	for _, value := range m.Values {
		if value == "" || value != strings.ToLower(value) {
			return fmt.Errorf("agents: client matcher values must be canonical lower-case tokens")
		}
		valid := false
		switch m.Kind {
		case ClientMatcherExecutable:
			valid = validExecutableMatcher(value)
		case ClientMatcherURIScheme:
			valid = validURISchemeMatcher(value)
		default:
			return fmt.Errorf("agents: unsupported client matcher kind")
		}
		if !valid {
			return fmt.Errorf("agents: invalid client matcher value")
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("agents: duplicate client matcher value")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validExecutableMatcher(value string) bool {
	if len(value) == 0 || len(value) > maxClientMatcherLength || strings.HasSuffix(value, ".exe") {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && strings.ContainsRune("._+-", character)) {
			continue
		}
		return false
	}
	return true
}

func validURISchemeMatcher(value string) bool {
	if len(value) == 0 || len(value) > maxClientMatcherLength {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(index > 0 && character >= '0' && character <= '9') ||
			(index > 0 && strings.ContainsRune("+.-", character)) {
			continue
		}
		return false
	}
	return true
}

// CapabilityService describes a service Phase could manage and the active
// Workflow Connections, if any, that currently provide it.
type CapabilityService struct {
	ServiceType         string          `json:"serviceType"`
	DisplayName         string          `json:"displayName"`
	CredentialProviders []string        `json:"credentialProviders"`
	ClientMatchers      []ClientMatcher `json:"clientMatchers"`
	ConnectionIDs       []string        `json:"connectionIds"`
}

// CapabilitiesResponse is safe discovery metadata. It contains neither
// credential material nor process-environment values.
type CapabilitiesResponse struct {
	SchemaVersion        int                 `json:"schemaVersion"`
	MatcherSchemaVersion int                 `json:"matcherSchemaVersion"`
	Kind                 string              `json:"kind"`
	SessionUID           string              `json:"sessionUid"`
	Services             []CapabilityService `json:"services"`
}

// Validate checks the v1 credential-free discovery contract before a caller
// uses it for routing guidance. Unknown schema versions and matcher kinds fail
// closed without preventing ordinary ambient tool use.
func (r CapabilitiesResponse) Validate() error {
	if r.SchemaVersion != CurrentSchemaVersion || r.MatcherSchemaVersion != ClientMatcherSchemaVersion ||
		r.Kind != "phase.ai.capabilities" || strings.TrimSpace(r.SessionUID) == "" {
		return fmt.Errorf("agents: capabilities response identity is invalid")
	}
	seenServices := make(map[string]struct{}, len(r.Services))
	for _, service := range r.Services {
		if !validRequestServiceType(service.ServiceType) || service.ServiceType != strings.ToLower(service.ServiceType) ||
			service.DisplayName == "" || service.DisplayName != strings.TrimSpace(service.DisplayName) ||
			strings.IndexFunc(service.DisplayName, func(character rune) bool { return character < 32 }) >= 0 {
			return fmt.Errorf("agents: capability service metadata is invalid")
		}
		if _, duplicate := seenServices[service.ServiceType]; duplicate {
			return fmt.Errorf("agents: duplicate capability service")
		}
		seenServices[service.ServiceType] = struct{}{}
		if len(service.CredentialProviders) == 0 || len(service.ClientMatchers) == 0 {
			return fmt.Errorf("agents: capability service discovery metadata is required")
		}
		seenProviders := make(map[string]struct{}, len(service.CredentialProviders))
		for _, provider := range service.CredentialProviders {
			if !validRequestServiceType(provider) || provider != strings.ToLower(provider) {
				return fmt.Errorf("agents: capability credential provider is invalid")
			}
			if _, duplicate := seenProviders[provider]; duplicate {
				return fmt.Errorf("agents: duplicate capability credential provider")
			}
			seenProviders[provider] = struct{}{}
		}
		seenMatcherKinds := make(map[ClientMatcherKind]struct{}, len(service.ClientMatchers))
		for _, matcher := range service.ClientMatchers {
			if _, duplicate := seenMatcherKinds[matcher.Kind]; duplicate {
				return fmt.Errorf("agents: duplicate capability client matcher kind")
			}
			if err := matcher.Validate(); err != nil {
				return err
			}
			seenMatcherKinds[matcher.Kind] = struct{}{}
		}
		seenConnectionIDs := make(map[string]struct{}, len(service.ConnectionIDs))
		for _, connectionID := range service.ConnectionIDs {
			if connectionID == "" || strings.IndexFunc(connectionID, func(character rune) bool {
				return unicode.IsSpace(character) || unicode.IsControl(character)
			}) >= 0 {
				return fmt.Errorf("agents: capability connection ID is invalid")
			}
			if _, duplicate := seenConnectionIDs[connectionID]; duplicate {
				return fmt.Errorf("agents: duplicate capability connection ID")
			}
			seenConnectionIDs[connectionID] = struct{}{}
		}
	}
	return nil
}

type RotateSessionResponse struct {
	SchemaVersion     int             `json:"schemaVersion,omitempty"`
	SessionUID        string          `json:"sessionUid"`
	SessionCredential SensitiveString `json:"sessionCredential"`
	ExpiresAt         *time.Time      `json:"expiresAt,omitempty"`
	ConfigGeneration  uint64          `json:"configGeneration,omitempty"`
}

func (r RotateSessionResponse) SessionAuth() SessionAuth {
	return SessionAuth{SessionUID: r.SessionUID, Credential: r.SessionCredential}
}

type RequestKind string

const (
	RequestSetup            RequestKind = "setup"
	RequestCredentialUpdate RequestKind = "credential_update"
)

type RequestStatus string

const (
	RequestPending   RequestStatus = "pending"
	RequestApproved  RequestStatus = "approved"
	RequestDenied    RequestStatus = "denied"
	RequestExpired   RequestStatus = "expired"
	RequestCancelled RequestStatus = "cancelled"
)

// RequestRuntimeAction tells the runtime owner how to consume a terminal
// request result without embedding CLI- or harness-specific behavior in the
// shared API contract.
type RequestRuntimeAction string

const (
	RequestRuntimeActionRetry           RequestRuntimeAction = "retry"
	RequestRuntimeActionRestartRequired RequestRuntimeAction = "restart_required"
)

type CreateRequestInput struct {
	SchemaVersion      int         `json:"schemaVersion,omitempty"`
	ConnectionID       string      `json:"connectionId,omitempty"`
	CredentialID       string      `json:"credentialId,omitempty"`
	Kind               RequestKind `json:"kind"`
	CredentialProvider string      `json:"credentialProvider"`
	CredentialName     string      `json:"credentialName"`
	ServiceType        string      `json:"serviceType,omitempty"`
	Markdown           string      `json:"markdown"`
	DedupKey           string      `json:"dedupKey,omitempty"`
	RelatedRequestID   string      `json:"relatedRequestId,omitempty"`
}

// RequestProgress carries safe, resumable setup selections. It deliberately
// cannot carry secret values, source producer credentials, or bearer tokens.
type RequestProgress struct {
	Revision           string `json:"revision,omitempty"`
	Stage              string `json:"stage,omitempty"`
	CredentialID       string `json:"credentialId,omitempty"`
	CredentialName     string `json:"credentialName,omitempty"`
	CredentialProvider string `json:"credentialProvider,omitempty"`
	CredentialRevision string `json:"credentialRevision,omitempty"`
	ConnectionID       string `json:"connectionId,omitempty"`
	GrantID            string `json:"grantId,omitempty"`
}

// RequestResolution records the resources and revisions that were approved.
// Runtime owners must refresh trusted configuration before using the result.
type RequestResolution struct {
	Revision           string `json:"revision,omitempty"`
	CredentialID       string `json:"credentialId,omitempty"`
	CredentialRevision string `json:"credentialRevision,omitempty"`
	ConnectionID       string `json:"connectionId,omitempty"`
	GrantID            string `json:"grantId,omitempty"`
}

type ListRequestsResponse struct {
	SchemaVersion int            `json:"schemaVersion"`
	Requests      []AgentRequest `json:"requests"`
}

type AgentRequest struct {
	SchemaVersion      int                  `json:"schemaVersion,omitempty"`
	ID                 string               `json:"id"`
	Revision           string               `json:"revision,omitempty"`
	WorkflowID         string               `json:"workflowId,omitempty"`
	GrantID            string               `json:"grantId,omitempty"`
	ConnectionID       string               `json:"connectionId,omitempty"`
	CredentialID       string               `json:"credentialId,omitempty"`
	Kind               RequestKind          `json:"kind,omitempty"`
	CredentialProvider string               `json:"credentialProvider,omitempty"`
	CredentialName     string               `json:"credentialName,omitempty"`
	ServiceType        string               `json:"serviceType,omitempty"`
	Markdown           string               `json:"markdown,omitempty"`
	Status             RequestStatus        `json:"status"`
	Cooldown           bool                 `json:"cooldown,omitempty"`
	ApprovalURL        string               `json:"approvalUrl,omitempty"`
	RuntimeAction      RequestRuntimeAction `json:"runtimeAction,omitempty"`
	ResolutionNote     string               `json:"resolutionNote,omitempty"`
	Progress           *RequestProgress     `json:"progress,omitempty"`
	Resolution         *RequestResolution   `json:"resolution,omitempty"`
	RelatedRequestID   string               `json:"relatedRequestId,omitempty"`
	CreatedAt          *time.Time           `json:"createdAt,omitempty"`
	UpdatedAt          *time.Time           `json:"updatedAt,omitempty"`
	ResolvedAt         *time.Time           `json:"resolvedAt,omitempty"`
	RequestExpiresAt   *time.Time           `json:"requestExpiresAt,omitempty"`
}

type EventBatch struct {
	SchemaVersion int          `json:"schemaVersion"`
	BatchID       string       `json:"batchId"`
	Events        []AgentEvent `json:"events"`
}

type AgentEvent struct {
	EventID          string                 `json:"eventId"`
	CreatedAt        time.Time              `json:"createdAt"`
	GrantID          string                 `json:"grantId,omitempty"`
	EventType        string                 `json:"eventType"`
	Protocol         Protocol               `json:"protocol"`
	Method           string                 `json:"method,omitempty"`
	Host             string                 `json:"host"`
	Port             *int                   `json:"port,omitempty"`
	Path             string                 `json:"path,omitempty"`
	Provider         string                 `json:"provider,omitempty"`
	StatusCode       *int                   `json:"statusCode,omitempty"`
	ProxyDecision    string                 `json:"proxyDecision"`
	Outcome          string                 `json:"outcome,omitempty"`
	LatencyMS        *int                   `json:"latencyMs,omitempty"`
	CredentialAction InjectionAction        `json:"credentialAction,omitempty"`
	BytesIn          int64                  `json:"bytesIn,omitempty"`
	BytesOut         int64                  `json:"bytesOut,omitempty"`
	Reason           string                 `json:"reason,omitempty"`
	Detail           map[string]interface{} `json:"detail"`
}

type ShipEventsResponse struct {
	SchemaVersion int    `json:"schemaVersion,omitempty"`
	BatchID       string `json:"batchId,omitempty"`
	SessionUID    string `json:"sessionUid,omitempty"`
	Accepted      int    `json:"accepted,omitempty"`
	Duplicates    int    `json:"duplicates,omitempty"`
}

type MintAgentTokenRequest struct {
	SchemaVersion int        `json:"schemaVersion,omitempty"`
	WorkflowID    string     `json:"workflowId"`
	Name          string     `json:"name"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
}

type MintAgentTokenResponse struct {
	SchemaVersion int             `json:"schemaVersion,omitempty"`
	ID            string          `json:"id"`
	AgentID       string          `json:"agentId,omitempty"`
	WorkflowID    string          `json:"workflowId"`
	Name          string          `json:"name,omitempty"`
	ExpiresAt     *time.Time      `json:"expiresAt,omitempty"`
	FullToken     SensitiveString `json:"fullToken"`
	BearerToken   SensitiveString `json:"bearerToken"`
}

func (r MintAgentTokenResponse) Authentication() (Authentication, error) {
	return AuthenticationFromPhaseToken(r.FullToken.Reveal())
}
