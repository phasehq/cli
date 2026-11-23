package agentapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	sdkagents "github.com/phasehq/cli/internal/agentsdk"
)

// Effects of an access policy and the classes it sorts calls into. The class
// credential_minting belongs to the secret guard: it is always blocked and can
// never appear in a stored rule or a temporary allow.
const (
	PolicyAllow = string(sdkagents.PolicyAllow)
	PolicyAsk   = string(sdkagents.PolicyAsk)
	PolicyBlock = string(sdkagents.PolicyBlock)

	ClassRead              = string(sdkagents.ClassRead)
	ClassCreate            = string(sdkagents.ClassCreate)
	ClassUpdate            = string(sdkagents.ClassUpdate)
	ClassDelete            = string(sdkagents.ClassDelete)
	ClassCredentialMinting = string(sdkagents.ClassCredentialMinting)

	// The policy version this client enforces. A policy with a higher one
	// holds something this client cannot enforce, so it is refused.
	accessPolicyVersion = 1
	maxPolicyPathLength = 1024
	maxPolicyMethods    = 9

	// AccessPolicyUnsupported is the reason a Connection is unavailable when
	// its policy is not something this client can enforce. Nothing is
	// forwarded for it until the client understands it.
	AccessPolicyUnsupported = "access_policy_unsupported"
	// AccessExpired is the reason a Connection whose time limit passed is
	// unavailable.
	AccessExpired = "access_expired"
)

// PolicyMatch selects calls by HTTP method, by path glob (the syntax host
// rules use), or by both.
type PolicyMatch struct {
	Methods []string `json:"methods,omitempty"`
	Path    string   `json:"path,omitempty"`
}

// PolicyRule has exactly one of Class or Match.
type PolicyRule struct {
	Class  string       `json:"class,omitempty"`
	Match  *PolicyMatch `json:"match,omitempty"`
	Effect string       `json:"effect"`
}

// TemporaryAllow is an approved exception to an ask. It is honoured only
// until ExpiresAt, never changes a block and never touches the secret guard.
type TemporaryAllow struct {
	ID        string       `json:"id"`
	Class     string       `json:"class,omitempty"`
	Match     *PolicyMatch `json:"match,omitempty"`
	ExpiresAt time.Time    `json:"expiresAt"`
}

// AccessPolicy is a Connection's access policy, with this Workflow's
// temporary allows, as the proxy enforces it. A higher version, or a class, effect or rule kind this client
// does not know, makes the policy unsupported rather than silently weaker,
// and the Connection is then unavailable (see Unsupported). Other members it
// does not know are ignored.
type AccessPolicy struct {
	Default         string
	Rules           []PolicyRule
	TemporaryAllows []TemporaryAllow

	// raw is the policy as the Console sent it, shown to the Agent unchanged.
	raw         json.RawMessage
	unsupported bool
}

func (p *AccessPolicy) UnmarshalJSON(data []byte) error {
	*p = AccessPolicy{raw: append(json.RawMessage(nil), data...)}
	var wire struct {
		Version         *int              `json:"version"`
		Default         string            `json:"default"`
		Rules           []json.RawMessage `json:"rules"`
		TemporaryAllows []json.RawMessage `json:"temporaryAllows"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		p.unsupported = true
		return nil
	}
	if wire.Version == nil && wire.Default == "" && len(wire.Rules) == 0 {
		// An empty policy: allow by default, no rules.
		p.Default = PolicyAllow
	} else if wire.Version == nil || *wire.Version != accessPolicyVersion {
		p.unsupported = true
		return nil
	}
	switch wire.Default {
	case "":
		p.Default = PolicyAllow
	case PolicyAllow, PolicyAsk, PolicyBlock:
		p.Default = wire.Default
	default:
		p.unsupported = true
		return nil
	}
	for _, rawRule := range wire.Rules {
		var rule PolicyRule
		if strictDecode(rawRule, &rule) != nil || validatePolicyRule(rule) != nil {
			p.unsupported = true
			p.Rules = nil
			return nil
		}
		p.Rules = append(p.Rules, rule)
	}
	// A temporary allow can only turn an ask into an allow, so one this client
	// cannot read is left out: the call it covered keeps asking.
	for _, rawAllow := range wire.TemporaryAllows {
		var allow TemporaryAllow
		if strictDecode(rawAllow, &allow) != nil || allow.ExpiresAt.IsZero() ||
			validatePolicyTarget(allow.Class, allow.Match) != nil {
			continue
		}
		p.TemporaryAllows = append(p.TemporaryAllows, allow)
	}
	return nil
}

// MarshalJSON returns the policy as the Console sent it.
func (p AccessPolicy) MarshalJSON() ([]byte, error) {
	if len(p.raw) > 0 {
		return p.raw, nil
	}
	return json.Marshal(struct {
		Version         int              `json:"version"`
		Default         string           `json:"default"`
		Rules           []PolicyRule     `json:"rules"`
		TemporaryAllows []TemporaryAllow `json:"temporaryAllows,omitempty"`
	}{accessPolicyVersion, p.Default, append([]PolicyRule{}, p.Rules...), p.TemporaryAllows})
}

// Unsupported reports whether the policy could not be read in full. Such a
// policy is never enforced in part.
func (p *AccessPolicy) Unsupported() bool { return p != nil && p.unsupported }

// Restricts reports whether the policy can stop a call: it has an ask or a
// block rule, or does not allow by default. A policy that only allows needs
// no evaluation, and the Connection behaves as one without a policy.
func (p *AccessPolicy) Restricts() bool {
	if p == nil || p.unsupported {
		return false
	}
	if p.Default != "" && p.Default != PolicyAllow {
		return true
	}
	for _, rule := range p.Rules {
		if rule.Effect != PolicyAllow {
			return true
		}
	}
	return false
}

// ExpiredConnection names a grant of this Workflow whose time limit passed
// recently. It carries nothing but identity, so the proxy can tell the Agent
// what to ask to renew.
type ExpiredConnection struct {
	ConnectionID   string    `json:"connectionId"`
	ConnectionName string    `json:"connectionName,omitempty"`
	ServiceType    string    `json:"serviceType"`
	ExpiredAt      time.Time `json:"expiredAt"`
}

// AccessPolicyFailure names why the Connection's policy or provider rules
// cannot be enforced, or is empty when they can.
func (c Connection) AccessPolicyFailure() string {
	if c.Policy.Unsupported() {
		return AccessPolicyUnsupported
	}
	if failure := c.providerRulesFailure(); failure != "" {
		return failure
	}
	// A policy that stops calls can be evaluated for HTTP only. One on any
	// other protocol is not something this client can enforce.
	if c.Protocol != "http" && c.Policy.Restricts() {
		return AccessPolicyUnsupported
	}
	return ""
}

// GrantExpired reports whether the grant's time limit has passed. It is
// checked against the clock on every use, not only when the configuration is
// refreshed.
func (c Connection) GrantExpired(now time.Time) bool {
	return c.GrantExpiresAt != nil && !now.Before(*c.GrantExpiresAt)
}

func strictDecode(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing JSON")
	}
	return nil
}

func validatePolicyRule(rule PolicyRule) error {
	switch rule.Effect {
	case PolicyAllow, PolicyAsk, PolicyBlock:
	default:
		return fmt.Errorf("unsupported policy effect")
	}
	return validatePolicyTarget(rule.Class, rule.Match)
}

// validatePolicyTarget accepts exactly one of a user class or a match.
func validatePolicyTarget(class string, match *PolicyMatch) error {
	if (class != "") == (match != nil) {
		return fmt.Errorf("expected exactly one of class or match")
	}
	if class != "" {
		if !userOperationClass(class) {
			return fmt.Errorf("unsupported operation class")
		}
		return nil
	}
	return validatePolicyMatch(match)
}

func validatePolicyMatch(match *PolicyMatch) error {
	if match == nil || (len(match.Methods) == 0 && match.Path == "") {
		return fmt.Errorf("expected methods, a path, or both")
	}
	if len(match.Methods) > maxPolicyMethods {
		return fmt.Errorf("too many methods")
	}
	for _, method := range match.Methods {
		if method == "" || method != strings.ToUpper(method) || strings.ContainsAny(method, " \t\r\n") {
			return fmt.Errorf("methods must be upper-case HTTP methods")
		}
	}
	if match.Path != "" && (len(match.Path) > maxPolicyPathLength || !strings.HasPrefix(match.Path, "/")) {
		return fmt.Errorf("unsupported path")
	}
	return nil
}

func userOperationClass(class string) bool {
	switch class {
	case ClassRead, ClassCreate, ClassUpdate, ClassDelete:
		return true
	}
	return false
}

// Preset is a provider preset as the Console lists it: enough to recognise a
// host and to ask for a Connection by preset ID. It never carries a secret.
type Preset struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Description   string          `json:"description,omitempty"`
	Category      string          `json:"category,omitempty"`
	DocsURL       string          `json:"docsUrl,omitempty"`
	HostsEditable bool            `json:"hostsEditable,omitempty"`
	Hosts         json.RawMessage `json:"hosts,omitempty"`
}

// HostRules reads the preset's hosts, which the Console lists either as host
// rules or as plain host names. An entry in neither shape is skipped.
func (p Preset) HostRules() []HostRule {
	var entries []json.RawMessage
	if json.Unmarshal(p.Hosts, &entries) != nil {
		return nil
	}
	rules := make([]HostRule, 0, len(entries))
	for _, entry := range entries {
		var name string
		if json.Unmarshal(entry, &name) == nil {
			if name != "" {
				rules = append(rules, HostRule{Match: "exact", Value: name})
			}
			continue
		}
		var rule HostRule
		if json.Unmarshal(entry, &rule) == nil && rule.Value != "" {
			if rule.Match == "" {
				rule.Match = "exact"
			}
			rules = append(rules, rule)
		}
	}
	return rules
}

// RegistryResponse is the part of the Agent registry this client reads.
type RegistryResponse struct {
	SchemaVersion int      `json:"schemaVersion"`
	Presets       []Preset `json:"presets"`
	// Services is the packaged services, an object keyed by service type. It
	// is read leniently (see ServiceList) so that an entry in a shape this
	// client does not know never costs it the presets.
	Services json.RawMessage `json:"services,omitempty"`
}

// RegistryService is a packaged service as the registry lists it: enough to
// recognise its hosts and to ask for it with a setup request.
type RegistryService struct {
	ServiceType         string     `json:"serviceType"`
	DisplayName         string     `json:"displayName"`
	CredentialProviders []string   `json:"credentialProviders"`
	Hosts               []HostRule `json:"hosts"`
}

// ServiceList reads the packaged services, ordered by service type. An entry
// that is not an object, or is filed under another service type than it
// names, is skipped.
func (r RegistryResponse) ServiceList() []RegistryService {
	var entries map[string]json.RawMessage
	if json.Unmarshal(r.Services, &entries) != nil {
		return nil
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	services := make([]RegistryService, 0, len(keys))
	for _, key := range keys {
		var service RegistryService
		if json.Unmarshal(entries[key], &service) != nil || service.ServiceType != key {
			continue
		}
		services = append(services, service)
	}
	return services
}
