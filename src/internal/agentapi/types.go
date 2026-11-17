package agentapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	sdkagents "github.com/phasehq/cli/internal/agentsdk"
	"io"
	"strings"
	"time"
)

type SensitiveString string

func (s SensitiveString) Reveal() string               { return string(s) }
func (s SensitiveString) String() string               { return "[REDACTED]" }
func (s SensitiveString) GoString() string             { return "[REDACTED]" }
func (s SensitiveString) MarshalJSON() ([]byte, error) { return json.Marshal("[REDACTED]") }

type SecretMaterial struct {
	values map[string]string
}

type MaterialLookupStatus uint8

const (
	MaterialMissing MaterialLookupStatus = iota
	MaterialFound
	MaterialAmbiguous
)

func (s *SecretMaterial) UnmarshalJSON(data []byte) error {
	values := make(map[string]string)
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	s.values = values
	return nil
}

func (s SecretMaterial) Get(name string) (string, bool) {
	return LookupMaterial(s.values, name)
}

func (s SecretMaterial) Resolve(name string) (string, MaterialLookupStatus) {
	return ResolveMaterial(s.values, name)
}

// LookupMaterial resolves the snake_case and lowerCamel spellings used on the
// two sides of the v1 Console contract. It deliberately refuses collisions:
// two keys that normalize to the same field are ambiguous even if one is an
// exact spelling, so renderer changes cannot silently select credential data.
func LookupMaterial(values map[string]string, name string) (string, bool) {
	value, status := ResolveMaterial(values, name)
	return value, status == MaterialFound
}

func ResolveMaterial(values map[string]string, name string) (string, MaterialLookupStatus) {
	wanted, semantic := semanticMaterialName(name)
	if !semantic {
		value, ok := values[name]
		if !ok {
			return "", MaterialMissing
		}
		return value, MaterialFound
	}
	matched, matches := "", 0
	for key, value := range values {
		candidate, ok := semanticMaterialName(key)
		if !ok || candidate != wanted {
			continue
		}
		matched = value
		matches++
		if matches > 1 {
			return "", MaterialAmbiguous
		}
	}
	if matches == 0 {
		return "", MaterialMissing
	}
	return matched, MaterialFound
}

func semanticMaterialName(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	var normalized strings.Builder
	normalized.Grow(len(value))
	for _, character := range value {
		switch {
		case character == '_':
			continue
		case character >= 'A' && character <= 'Z':
			normalized.WriteRune(character + ('a' - 'A'))
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
			normalized.WriteRune(character)
		default:
			return "", false
		}
	}
	return normalized.String(), normalized.Len() > 0
}

func (s SecretMaterial) Clone() map[string]string {
	clone := make(map[string]string, len(s.values))
	for key, value := range s.values {
		clone[key] = value
	}
	return clone
}

// Copy returns an independently destroyable copy for one in-flight proxy
// operation. It prevents config rotation from either mutating an active
// request or retaining superseded live material in runtime state.
func (s SecretMaterial) Copy() SecretMaterial {
	return SecretMaterial{values: s.Clone()}
}

func (s *SecretMaterial) Destroy() {
	for key := range s.values {
		delete(s.values, key)
	}
}

func (s SecretMaterial) String() string               { return "[REDACTED]" }
func (s SecretMaterial) GoString() string             { return "[REDACTED]" }
func (s SecretMaterial) MarshalJSON() ([]byte, error) { return json.Marshal("[REDACTED]") }

// AgentEnvironment is redacting because it contains binding-specific decoys
// such as AWS_SECRET_ACCESS_KEY or PGPASSWORD. It never carries
// the backend session credential. Callers must explicitly Clone or Get values
// for the child environment boundary.
type AgentEnvironment struct {
	values map[string]string
}

// ErrUnsafeAgentVisibleEnvironment marks a fixed, redacted failure at the
// boundary between proxy-only credential material and the Agent process.
var ErrUnsafeAgentVisibleEnvironment = errors.New("Agent-visible environment contains proxy-only credential material")

func (e *AgentEnvironment) UnmarshalJSON(data []byte) error {
	values := make(map[string]string)
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	e.values = values
	return nil
}

func (e AgentEnvironment) Get(name string) (string, bool) {
	value, ok := e.values[name]
	return value, ok
}

func (e AgentEnvironment) Clone() map[string]string {
	clone := make(map[string]string, len(e.values))
	for key, value := range e.values {
		clone[key] = value
	}
	return clone
}

func (e AgentEnvironment) String() string               { return "[REDACTED]" }
func (e AgentEnvironment) GoString() string             { return "[REDACTED]" }
func (e AgentEnvironment) MarshalJSON() ([]byte, error) { return json.Marshal("[REDACTED]") }

// ProxyOnlyCredentialValues returns live material that must not cross into the
// Agent process. Only the credential field explicitly assigned the username
// role may equal its corresponding Agent-visible identifier. A secret-bearing
// field is still proxy-only when it happens to equal some other identifier.
func ProxyOnlyCredentialValues(connections []Connection) []string {
	seen := make(map[string]struct{})
	values := make([]string, 0)
	for _, connection := range connections {
		for field, value := range connection.SecretMaterial.Clone() {
			if value == "" {
				continue
			}
			identifier, identifierStatus := ResolveMaterial(connection.Identifiers, field)
			if identifierStatus == MaterialFound && identifier == value && !proxyOnlyCredentialField(connection, field) {
				continue
			}
			if _, duplicate := seen[value]; duplicate {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	return values
}

func proxyOnlyCredentialField(connection Connection, field string) bool {
	if _, status := ResolveMaterial(connection.DecoyMaterial, field); status != MaterialMissing {
		return true
	}
	for _, injection := range connection.EffectiveInjections() {
		if sameMaterialField(injection.ValueFrom.Field, field) {
			return true
		}
		for _, role := range []string{"accessKeyId", "secretAccessKey", "sessionToken", "password"} {
			mapped, status := ResolveMaterial(injection.ValueFrom.Fields, role)
			if status == MaterialAmbiguous {
				return true
			}
			if status == MaterialFound && sameMaterialField(mapped, field) {
				return true
			}
		}
	}
	return false
}

func sameMaterialField(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	leftSemantic, leftOK := semanticMaterialName(left)
	rightSemantic, rightOK := semanticMaterialName(right)
	if leftOK && rightOK {
		return leftSemantic == rightSemantic
	}
	return left == right
}

// ValidateAgentVisibleEnvironment rejects any process-visible environment
// value containing proxy-only live credential material. Errors never include
// the offending environment value or credential.
func ValidateAgentVisibleEnvironment(configEnv map[string]string, connections []Connection) error {
	if agentVisibleValueContains(configEnv, connections, ProxyOnlyCredentialValues(connections)) {
		return ErrUnsafeAgentVisibleEnvironment
	}
	return nil
}

// agentVisibleValueContains reports whether any value the Agent process can
// see, in the session or in any of its Connections, contains a forbidden one.
func agentVisibleValueContains(configEnv map[string]string, connections []Connection, forbidden []string) bool {
	containsForbidden := func(environment map[string]string) bool {
		for _, value := range environment {
			for _, secret := range forbidden {
				if strings.Contains(value, secret) {
					return true
				}
			}
		}
		return false
	}
	if containsForbidden(configEnv) {
		return true
	}
	for _, connection := range connections {
		if containsForbidden(connection.ConfigEnv) || containsForbidden(connection.AgentEnv.Clone()) ||
			containsForbidden(connection.Identifiers) || containsForbidden(connection.DecoyMaterial) {
			return true
		}
	}
	return false
}

// minimumCustomValueBytes is the shortest value a custom HTTP Connection may
// hold. The Console refuses a shorter one when it is entered; this is the
// backstop. A value this short can be found by trying, and it turns up by
// chance inside the text every redaction check compares it with.
const minimumCustomValueBytes = 8

// withholdExposedCustomMaterial keeps one member-entered value from taking a
// whole session down. A packaged service whose live value shows up in an
// Agent-visible value still fails the session in ValidateAgentVisibleEnvironment.
// A custom HTTP Connection in that position only loses its own material: it
// becomes unavailable and every other Connection keeps working. The same
// holds for a custom value that is too short to be a secret, and for one that
// the Connection's own description (its name, definition or policy, all of
// which the Agent can read) already contains.
func withholdExposedCustomMaterial(config *SessionConfig) {
	for index := range config.Connections {
		connection := &config.Connections[index]
		if connection.ServiceType != CustomHTTPServiceType {
			continue
		}
		live := ProxyOnlyCredentialValues([]Connection{*connection})
		if len(live) == 0 {
			continue
		}
		if !shorterThan(live, minimumCustomValueBytes) && !agentVisibleValueContains(config.ConfigEnv, config.Connections, live) &&
			!descriptionContains(*connection, live) {
			continue
		}
		connection.SecretMaterial.Destroy()
		connection.SecretMaterial = SecretMaterial{}
		connection.materialFailure = MaterialFailureExposed
	}
}

func shorterThan(values []string, minimum int) bool {
	for _, value := range values {
		if len(value) < minimum {
			return true
		}
	}
	return false
}

// descriptionContains reports whether what an Agent can read about the
// Connection contains one of the values, as text or as JSON would escape it.
func descriptionContains(connection Connection, values []string) bool {
	described, err := json.Marshal([]any{
		connection.ConnectionName, connection.CredentialName, connection.Hosts,
		connection.ConnectionConfig, connection.Policy, connection.OperationClasses,
	})
	if err != nil {
		return true
	}
	for _, value := range values {
		if bytes.Contains(described, []byte(value)) {
			return true
		}
		if escaped, err := json.Marshal(value); err == nil && bytes.Contains(described, escaped[1:len(escaped)-1]) {
			return true
		}
	}
	return false
}

type EnvironmentBindingAction string

const (
	EnvironmentBindingSet   EnvironmentBindingAction = "set"
	EnvironmentBindingUnset EnvironmentBindingAction = "unset"
)

type EnvironmentBindingSource string

const (
	EnvironmentSourceIdentifier       EnvironmentBindingSource = "identifier"
	EnvironmentSourceDecoy            EnvironmentBindingSource = "decoy"
	EnvironmentSourceConnectionConfig EnvironmentBindingSource = "connection_config"
	EnvironmentSourceRuntime          EnvironmentBindingSource = "runtime"
	EnvironmentSourceProxy            EnvironmentBindingSource = "proxy"
	EnvironmentSourceCA               EnvironmentBindingSource = "ca"
)

// EnvironmentBinding is value-free provenance for one resolved provider
// environment change. Current Console responses carry values in agentEnv or
// configEnv; keeping metadata separate lets the CLI apply explicit cleanup and
// lets the Console expose names and ownership without exposing decoys.
type EnvironmentBinding struct {
	Name          string                   `json:"name"`
	Action        EnvironmentBindingAction `json:"action"`
	Source        EnvironmentBindingSource `json:"source"`
	SourceField   string                   `json:"sourceField,omitempty"`
	Sensitive     bool                     `json:"sensitive"`
	SystemManaged bool                     `json:"systemManaged"`
}

func (b *EnvironmentBinding) UnmarshalJSON(payload []byte) error {
	type wire EnvironmentBinding
	var decoded wire
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("environment binding contains trailing JSON")
	}
	*b = EnvironmentBinding(decoded)
	return nil
}

func (b EnvironmentBinding) Validate() error {
	if !validEnvironmentName(b.Name) || b.Name != strings.ToUpper(b.Name) {
		return errors.New("environment binding name is invalid")
	}
	switch b.Action {
	case EnvironmentBindingSet:
		if b.Source == EnvironmentSourceRuntime {
			return errors.New("set environment binding cannot use runtime source")
		}
	case EnvironmentBindingUnset:
		if b.Source != EnvironmentSourceRuntime {
			return errors.New("unset environment binding must use runtime source")
		}
		if strings.TrimSpace(b.SourceField) == "" {
			return errors.New("unset environment binding activation source field is required")
		}
	default:
		return errors.New("environment binding action is unsupported")
	}
	switch b.Source {
	case EnvironmentSourceIdentifier, EnvironmentSourceDecoy, EnvironmentSourceConnectionConfig:
		if strings.TrimSpace(b.SourceField) == "" {
			return errors.New("environment binding source field is required")
		}
	case EnvironmentSourceRuntime, EnvironmentSourceProxy, EnvironmentSourceCA:
	default:
		return errors.New("environment binding source is unsupported")
	}
	return nil
}

// ValidateResolvedEnvironmentBindings verifies value-free provenance against
// the resolved planes in one connection. Errors identify metadata, never the
// corresponding identifier, decoy, or configuration value.
func ValidateResolvedEnvironmentBindings(
	bindings []EnvironmentBinding,
	identifiers map[string]string,
	decoyMaterial map[string]string,
	connectionConfig map[string]any,
	agentEnv map[string]string,
	configEnv map[string]string,
) error {
	if bindings == nil {
		return fmt.Errorf("environmentBindings is required by schema version %d", SchemaVersion)
	}
	for _, binding := range bindings {
		if err := binding.Validate(); err != nil {
			return err
		}
		switch binding.Source {
		case EnvironmentSourceIdentifier:
			value, status := ResolveMaterial(identifiers, binding.SourceField)
			if status != MaterialFound || agentEnv[binding.Name] != value {
				return fmt.Errorf("environment binding %s does not resolve from its identifier", binding.Name)
			}
		case EnvironmentSourceDecoy:
			value, status := ResolveMaterial(decoyMaterial, binding.SourceField)
			if status != MaterialFound || agentEnv[binding.Name] != value {
				return fmt.Errorf("environment binding %s does not resolve from its decoy", binding.Name)
			}
		case EnvironmentSourceConnectionConfig:
			value, found := resolveConnectionConfigString(connectionConfig, binding.SourceField)
			if !found || configEnv[binding.Name] != value {
				return fmt.Errorf("environment binding %s does not resolve from connection configuration", binding.Name)
			}
		case EnvironmentSourceRuntime:
			if _, status := ResolveMaterial(decoyMaterial, binding.SourceField); status != MaterialFound {
				return fmt.Errorf("environment binding %s has no decoy activation field", binding.Name)
			}
		case EnvironmentSourceProxy, EnvironmentSourceCA:
			return fmt.Errorf("environment binding %s uses a CLI-local source in a provider response", binding.Name)
		default:
			return fmt.Errorf("environment binding %s has unsupported provenance", binding.Name)
		}
	}
	return nil
}

func resolveConnectionConfigString(values map[string]any, name string) (string, bool) {
	wanted, semantic := semanticMaterialName(name)
	if !semantic {
		value, ok := values[name].(string)
		return value, ok
	}
	matched, matches := "", 0
	for key, raw := range values {
		candidate, ok := semanticMaterialName(key)
		if !ok || candidate != wanted {
			continue
		}
		value, ok := raw.(string)
		if !ok {
			return "", false
		}
		matched = value
		matches++
		if matches > 1 {
			return "", false
		}
	}
	return matched, matches == 1
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

// Client features advertised when a session is opened. The Console refuses a
// session whose granted Connections need one the client did not list.
const (
	FeatureInjectionList  = string(sdkagents.FeatureInjectionList)
	FeatureWhenAbsent     = string(sdkagents.FeatureWhenAbsent)
	FeatureSealedMaterial = string(sdkagents.FeatureSealedMaterial)
	FeatureAccessPolicy   = string(sdkagents.FeatureAccessPolicy)
	FeatureProviderRules  = string(sdkagents.FeatureProviderRules)
)

type ClientCapabilities struct {
	Name                    string   `json:"name"`
	Version                 string   `json:"version"`
	SupportedSchemaVersions []int    `json:"supportedSchemaVersions"`
	Protocols               []string `json:"protocols"`
	InjectionActions        []string `json:"injectionActions"`
	Features                []string `json:"features"`
}

// IdentityResource is non-secret display metadata for an Agent-scoped
// principal. The durable token remains opaque and is never derived from these
// identifiers.
type IdentityResource struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AgentIdentity is returned by the Agent-token-only identity endpoint. It lets
// the CLI label a locally stored Agent login without opening a runtime session
// or resolving any credential material.
type AgentIdentity struct {
	SchemaVersion int              `json:"schemaVersion"`
	PrincipalType string           `json:"principalType"`
	Agent         IdentityResource `json:"agent"`
	Workflow      IdentityResource `json:"workflow"`
	Organization  IdentityResource `json:"organization"`
}

type OpenSessionRequest struct {
	SchemaVersion  int                `json:"schemaVersion"`
	WorkflowID     string             `json:"workflowId,omitempty"`
	IdempotencyKey string             `json:"idempotencyKey"`
	Client         ClientCapabilities `json:"client"`
	HarnessLabel   string             `json:"harnessLabel,omitempty"`
}

type HostRule struct {
	Match string `json:"match"`
	Value string `json:"value"`
	Port  int    `json:"port"`
	Path  string `json:"path,omitempty"`
}

type ValueFrom struct {
	Source string            `json:"source"`
	Field  string            `json:"field,omitempty"`
	Fields map[string]string `json:"fields"`
}

// Values of Injection.WhenAbsent: what the proxy does when a request carries
// nothing at the injection point. An empty value means block, which is how
// every packaged service behaves.
const (
	WhenAbsentAttach = "attach"
	WhenAbsentBlock  = "block"
)

type Injection struct {
	Action      string `json:"action"`
	Name        string `json:"name,omitempty"`
	ValueFormat string `json:"valueFormat,omitempty"`
	// ValueFormats are further forms a request may present the decoy in for
	// set_header, replace_header and set_param (at most 4, each with exactly
	// one {value}). A swap keeps the form it was presented in; attaching uses
	// ValueFormat.
	ValueFormats    []string  `json:"valueFormats,omitempty"`
	ValueFrom       ValueFrom `json:"valueFrom"`
	ServiceFrom     string    `json:"serviceFrom,omitempty"`
	RegionFrom      string    `json:"regionFrom,omitempty"`
	PathPattern     string    `json:"pathPattern,omitempty"`
	PathReplacement string    `json:"pathReplacement,omitempty"`
	Pattern         string    `json:"pattern,omitempty"`
	Replacement     string    `json:"replacement,omitempty"`
	WhenAbsent      string    `json:"whenAbsent,omitempty"`
}

// ConnectionAuthorization is the backend's versioned, policy-free allow
// attestation. Provider permissions remain the operation-level boundary.
type ConnectionAuthorization struct {
	Version    int    `json:"version"`
	Mode       string `json:"mode"`
	AccessMode string `json:"accessMode"`
	State      string `json:"state"`
}

// Connection is one granted Connection of a session. A packaged service has a
// single Injection; a custom HTTP Connection carries Injections instead (see
// EffectiveInjections). SecretMaterial holds the live value for both lanes: the
// Console sends it resolved, or the client fills it in memory once it has
// opened SealedMaterial. Unless AllowPlainHTTP is set, a custom HTTP
// Connection's value is never put on a plain-HTTP request.
type Connection struct {
	GrantID             string                  `json:"grantId"`
	ConnectionID        string                  `json:"connectionId"`
	ConnectionName      string                  `json:"connectionName,omitempty"`
	CredentialID        string                  `json:"credentialId"`
	CredentialName      string                  `json:"credentialName,omitempty"`
	CredentialProvider  string                  `json:"credentialProvider"`
	CredentialRevision  string                  `json:"credentialRevision,omitempty"`
	ServiceType         string                  `json:"serviceType"`
	Protocol            string                  `json:"protocol"`
	Hosts               []HostRule              `json:"hosts"`
	MaterialGeneration  string                  `json:"materialGeneration,omitempty"`
	CredentialExpiresAt *time.Time              `json:"credentialExpiresAt,omitempty"`
	ConnectionConfig    map[string]any          `json:"connectionConfig,omitempty"`
	ConfigEnv           map[string]string       `json:"configEnv,omitempty"`
	Injection           Injection               `json:"injection"`
	Injections          []Injection             `json:"injections,omitempty"`
	OnRefresh           string                  `json:"onRefresh,omitempty"`
	Identifiers         map[string]string       `json:"identifiers"`
	DecoyMaterial       map[string]string       `json:"decoyMaterial"`
	AgentEnv            AgentEnvironment        `json:"agentEnv"`
	EnvironmentBindings []EnvironmentBinding    `json:"environmentBindings,omitempty"`
	SecretMaterial      SecretMaterial          `json:"secretMaterial"`
	SealedMaterial      *SealedMaterial         `json:"sealedMaterial,omitempty"`
	AllowPlainHTTP      bool                    `json:"allowPlainHttp,omitempty"`
	Authorization       ConnectionAuthorization `json:"authorization"`
	// Policy, OperationClasses and GrantExpiresAt limit how this grant may be
	// used. The proxy enforces them before it swaps in or attaches the
	// credential. None of them reaches the Agent's environment, so a change to
	// any of them applies to a running session.
	Policy           *AccessPolicy    `json:"policy,omitempty"`
	OperationClasses OperationClasses `json:"operationClasses,omitzero"`
	GrantExpiresAt   *time.Time       `json:"grantExpiresAt,omitempty"`
	// CredentialEnvironment, SecretGuard and ActionClasses are the provider's
	// rules from the Console's manifest (see provider_rules.go). The guard and
	// the classes are applied in place on refresh, like the policy; the
	// credential environment names are exported to the Agent's processes.
	CredentialEnvironment []string       `json:"credentialEnvironment,omitempty"`
	SecretGuard           *SecretGuard   `json:"secretGuard,omitempty"`
	ActionClasses         *ActionClasses `json:"actionClasses,omitempty"`

	// materialFailure is set when the client withheld this Connection's value.
	materialFailure string
}

// CustomHTTPServiceType is the service type of a member-defined HTTP
// Connection. Packaged services keep their own service types.
const CustomHTTPServiceType = sdkagents.CustomHTTPServiceType

// PhaseAppServiceType is the service type of an app Connection.
const PhaseAppServiceType = sdkagents.PhaseAppServiceType

type AppConnection = sdkagents.AppConnection
type AppAccessResponse = sdkagents.AppAccessResponse
type AppRef = sdkagents.AppRef
type AppEnvironment = sdkagents.AppEnvironment
type AppAccess = sdkagents.AppAccess

// EffectiveInjections returns what the proxy applies to a request: the list
// when the payload carries one, otherwise the single packaged-service
// injection.
func (c Connection) EffectiveInjections() []Injection {
	if len(c.Injections) > 0 {
		return c.Injections
	}
	return []Injection{c.Injection}
}

// PrimaryInjectionAction names the Connection's first injection for events
// and for the trust variables of the clients its protocol handling covers.
func (c Connection) PrimaryInjectionAction() string {
	return c.EffectiveInjections()[0].Action
}

// AgentKey carries the server's wrapped share of the Agent's key exchange
// private key. It is useless without the matching Agent token.
type AgentKey struct {
	WrappedKeyShare SensitiveString `json:"wrappedKeyShare"`
}

type SessionConfig struct {
	SchemaVersion    int               `json:"schemaVersion"`
	SessionUID       string            `json:"sessionUid"`
	ExpiresAt        time.Time         `json:"expiresAt"`
	MaxExpiresAt     time.Time         `json:"maxExpiresAt"`
	ConfigGeneration int               `json:"configGeneration"`
	ConfigEnv        map[string]string `json:"configEnv"`
	Connections      []Connection      `json:"connections"`
	AgentKey         *AgentKey         `json:"agentKey,omitempty"`
	// ExpiredConnections are this Workflow's grants whose time limit passed
	// recently; the proxy lists them so the Agent knows what to ask to renew.
	ExpiredConnections []ExpiredConnection `json:"expiredConnections,omitempty"`
	// AppConnections are the app Connections the Workflow can use. The proxy
	// only lists them: secrets calls go to the Console with the Agent token.
	AppConnections []AppConnection `json:"appConnections,omitempty"`
}

type OpenSessionResponse struct {
	SessionConfig
	SessionCredential SensitiveString `json:"sessionCredential"`
}

func (r OpenSessionResponse) String() string {
	return fmt.Sprintf("AgentSession{uid:%s generation:%d credential:[REDACTED]}", r.SessionUID, r.ConfigGeneration)
}
func (r OpenSessionResponse) GoString() string { return r.String() }

type DiscoverConnection struct {
	GrantID             string                  `json:"grantId"`
	ConnectionID        string                  `json:"connectionId"`
	ConnectionName      string                  `json:"connectionName,omitempty"`
	CredentialID        string                  `json:"credentialId"`
	CredentialName      string                  `json:"credentialName,omitempty"`
	CredentialProvider  string                  `json:"credentialProvider"`
	CredentialRevision  string                  `json:"credentialRevision,omitempty"`
	ServiceType         string                  `json:"serviceType"`
	Protocol            string                  `json:"protocol"`
	Hosts               []HostRule              `json:"hosts"`
	MaterialGeneration  string                  `json:"materialGeneration,omitempty"`
	CredentialExpiresAt *time.Time              `json:"credentialExpiresAt,omitempty"`
	ConnectionConfig    map[string]any          `json:"connectionConfig,omitempty"`
	ConfigEnv           map[string]string       `json:"configEnv,omitempty"`
	Injection           Injection               `json:"injection,omitzero"`
	Injections          []Injection             `json:"injections,omitempty"`
	OnRefresh           string                  `json:"onRefresh,omitempty"`
	Identifiers         map[string]string       `json:"identifiers"`
	DecoyMaterial       map[string]string       `json:"decoyMaterial"`
	AgentEnv            map[string]string       `json:"agentEnv"`
	EnvironmentBindings []EnvironmentBinding    `json:"environmentBindings,omitempty"`
	AllowPlainHTTP      bool                    `json:"allowPlainHttp,omitempty"`
	Authorization       ConnectionAuthorization `json:"authorization"`
	// Policy, OperationClasses and GrantExpiresAt are relayed as the Console
	// sent them. The proxy enforces the copies in its own configuration and
	// never compares these against it: none of them is part of the Agent's
	// environment.
	Policy           json.RawMessage `json:"policy,omitempty"`
	OperationClasses json.RawMessage `json:"operationClasses,omitempty"`
	GrantExpiresAt   *time.Time      `json:"grantExpiresAt,omitempty"`
}

type DiscoverResponse struct {
	SchemaVersion      int                  `json:"schemaVersion"`
	SessionUID         string               `json:"sessionUid"`
	ConfigGeneration   int                  `json:"configGeneration"`
	ConfigEnv          map[string]string    `json:"configEnv"`
	Connections        []DiscoverConnection `json:"connections"`
	ExpiredConnections []ExpiredConnection  `json:"expiredConnections,omitempty"`
	AppConnections     []AppConnection      `json:"appConnections,omitempty"`
}

type ContextResponse struct {
	SchemaVersion int    `json:"schemaVersion"`
	SessionUID    string `json:"sessionUid"`
	ServiceType   string `json:"serviceType,omitempty"`
	Markdown      string `json:"markdown"`
}

type ClientMatcher = sdkagents.ClientMatcher
type ClientMatcherKind = sdkagents.ClientMatcherKind
type CapabilityService = sdkagents.CapabilityService
type CapabilitiesResponse = sdkagents.CapabilitiesResponse

type RefreshResponse struct {
	SchemaVersion    int    `json:"schemaVersion"`
	SessionUID       string `json:"sessionUid"`
	ConfigGeneration int    `json:"configGeneration"`
	Refreshed        bool   `json:"refreshed"`
}

type RotateResponse struct {
	SchemaVersion     int             `json:"schemaVersion"`
	SessionUID        string          `json:"sessionUid"`
	SessionCredential SensitiveString `json:"sessionCredential"`
	ExpiresAt         time.Time       `json:"expiresAt"`
	ConfigGeneration  int             `json:"configGeneration"`
}

type RevokeResponse struct {
	SchemaVersion int       `json:"schemaVersion"`
	SessionUID    string    `json:"sessionUid"`
	RevokedAt     time.Time `json:"revokedAt"`
}

// CreateRequestRequest asks a member for something. Action is the requested
// change, forwarded as opaque, versioned JSON; it never holds a secret value.
// Beside an action the packaged-service members are optional. DurationSeconds
// asks for time-limited access; absent, the organisation's default applies.
type CreateRequestRequest struct {
	SchemaVersion      int             `json:"schemaVersion,omitempty"`
	Kind               string          `json:"kind"`
	Title              string          `json:"title,omitempty"`
	ConnectionID       string          `json:"connectionId,omitempty"`
	CredentialID       string          `json:"credentialId,omitempty"`
	CredentialProvider string          `json:"credentialProvider,omitempty"`
	CredentialName     string          `json:"credentialName,omitempty"`
	ServiceType        string          `json:"serviceType,omitempty"`
	Markdown           string          `json:"markdown"`
	Action             json.RawMessage `json:"action,omitempty"`
	DurationSeconds    *int            `json:"durationSeconds,omitempty"`
	DedupKey           string          `json:"dedupKey,omitempty"`
	RelatedRequestID   string          `json:"relatedRequestId,omitempty"`
}

type RequestRuntimeAction string

const (
	RequestRuntimeActionRetry           RequestRuntimeAction = "retry"
	RequestRuntimeActionRestartRequired RequestRuntimeAction = "restart_required"
)

type RequestProgress = sdkagents.RequestProgress
type RequestResolution = sdkagents.RequestResolution
type ListRequestsResponse struct {
	SchemaVersion int               `json:"schemaVersion"`
	Requests      []RequestResponse `json:"requests"`
}

type RequestResponse struct {
	Revision           string               `json:"revision,omitempty"`
	WorkflowID         string               `json:"workflowId,omitempty"`
	Progress           *RequestProgress     `json:"progress,omitempty"`
	Resolution         *RequestResolution   `json:"resolution,omitempty"`
	RelatedRequestID   string               `json:"relatedRequestId,omitempty"`
	SchemaVersion      int                  `json:"schemaVersion,omitempty"`
	ID                 string               `json:"id"`
	PollURL            string               `json:"pollUrl,omitempty"`
	ApprovalURL        string               `json:"approvalUrl,omitempty"`
	Status             string               `json:"status"`
	Kind               string               `json:"kind,omitempty"`
	Title              string               `json:"title,omitempty"`
	Action             json.RawMessage      `json:"action,omitempty"`
	CredentialProvider string               `json:"credentialProvider,omitempty"`
	CredentialName     string               `json:"credentialName,omitempty"`
	ServiceType        string               `json:"serviceType,omitempty"`
	CredentialID       string               `json:"credentialId,omitempty"`
	ConnectionID       string               `json:"connectionId,omitempty"`
	GrantID            string               `json:"grantId,omitempty"`
	RuntimeAction      RequestRuntimeAction `json:"runtimeAction,omitempty"`
	Markdown           string               `json:"markdown,omitempty"`
	Cooldown           bool                 `json:"cooldown,omitempty"`
	ResolutionNote     string               `json:"resolutionNote,omitempty"`
	ResolvedAt         *time.Time           `json:"resolvedAt,omitempty"`
	RequestExpiresAt   *time.Time           `json:"requestExpiresAt,omitempty"`
}

type Event struct {
	EventID          string         `json:"eventId"`
	CreatedAt        time.Time      `json:"createdAt"`
	GrantID          string         `json:"grantId,omitempty"`
	EventType        string         `json:"eventType"`
	Protocol         string         `json:"protocol,omitempty"`
	Method           string         `json:"method,omitempty"`
	Host             string         `json:"host,omitempty"`
	Port             int            `json:"port,omitempty"`
	Path             string         `json:"path,omitempty"`
	Provider         string         `json:"provider,omitempty"`
	StatusCode       int            `json:"statusCode,omitempty"`
	ProxyDecision    string         `json:"proxyDecision,omitempty"`
	Outcome          string         `json:"outcome"`
	LatencyMS        int64          `json:"latencyMs,omitempty"`
	CredentialAction string         `json:"credentialAction,omitempty"`
	BytesIn          int64          `json:"bytesIn,omitempty"`
	BytesOut         int64          `json:"bytesOut,omitempty"`
	Reason           string         `json:"reason,omitempty"`
	Detail           map[string]any `json:"detail"`
}

type EventBatchRequest struct {
	SchemaVersion int     `json:"schemaVersion"`
	BatchID       string  `json:"batchId"`
	Events        []Event `json:"events"`
}

type EventBatchResponse struct {
	SchemaVersion int    `json:"schemaVersion"`
	BatchID       string `json:"batchId"`
	SessionUID    string `json:"sessionUid"`
	Accepted      int    `json:"accepted"`
	Duplicates    int    `json:"duplicates"`
}
