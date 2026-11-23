package agentapi

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Provider rules: data about a packaged service that the Console's manifest
// owns and sends with each Connection, so a new provider needs no new CLI.
// The mechanics that apply them (naming an AWS action, path normalisation,
// the comparison rules) stay in pkg/proxy.
//
// Like a policy, the guard is decoded strictly: rules this client cannot read
// in full are never enforced in part, and the Connection is unavailable
// instead (see AccessPolicyFailure).

const (
	// ProviderRulesMissing is the reason an AWS Connection is unavailable when
	// the Console sent it without its secret guard, so its calls could not be
	// guarded.
	ProviderRulesMissing = "provider_rules_missing"

	maxCredentialEnvironmentNames  = 64
	maxCredentialEnvironmentLength = 128
)

// SecretGuard is the provider's credential-minting guard: the calls that would
// hand back a new credential. See pkg/proxy/minting.go.
type SecretGuard struct {
	// Operations: AWS signing service -> operation names, for providers whose
	// calls the client can name.
	Operations map[string][]string `json:"operations,omitempty"`
	Paths      []SecretGuardPath   `json:"paths,omitempty"`

	raw         json.RawMessage
	unsupported bool
}

// SecretGuardPath matches a call by method, path pattern (path.Match) and,
// optionally, a query parameter the request carries.
type SecretGuardPath struct {
	Method  string `json:"method,omitempty"`
	Pattern string `json:"pattern"`
	Query   string `json:"query,omitempty"`
	// Operation names the call in the refusal and the audit event.
	Operation string `json:"operation"`
	// Services limits an AWS rule to requests signed for one of these
	// services, so an S3 object key that happens to share the path is not
	// blocked. An unknown service still matches, failing closed.
	Services []string `json:"services,omitempty"`
	// HostLabel further limits a rule to hosts that carry this DNS label, for
	// a service whose signing name is shared with unrelated APIs.
	HostLabel string `json:"hostLabel,omitempty"`
}

func (g *SecretGuard) UnmarshalJSON(data []byte) error {
	*g = SecretGuard{raw: append(json.RawMessage(nil), data...)}
	var wire struct {
		Operations map[string][]string `json:"operations"`
		Paths      []SecretGuardPath   `json:"paths"`
	}
	if strictDecode(data, &wire) != nil || validateSecretGuard(wire.Operations, wire.Paths) != nil {
		g.unsupported = true
		return nil
	}
	g.Operations, g.Paths = wire.Operations, wire.Paths
	return nil
}

func (g SecretGuard) MarshalJSON() ([]byte, error) {
	if len(g.raw) > 0 {
		return g.raw, nil
	}
	type plain SecretGuard
	return json.Marshal(plain(g))
}

// Unsupported reports whether the guard could not be read in full.
func (g *SecretGuard) Unsupported() bool { return g != nil && g.unsupported }

func validateSecretGuard(operations map[string][]string, paths []SecretGuardPath) error {
	// A guard with nothing in it would read as "nothing to block".
	if len(operations) == 0 && len(paths) == 0 {
		return fmt.Errorf("secret guard has no rules")
	}
	for service, names := range operations {
		if service == "" || len(names) == 0 {
			return fmt.Errorf("secret guard operations need a service and names")
		}
		for _, name := range names {
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("secret guard operation is empty")
			}
		}
	}
	for _, rule := range paths {
		if !strings.HasPrefix(rule.Pattern, "/") || rule.Operation == "" || rule.Method != strings.ToUpper(rule.Method) || hasEmpty(rule.Services) {
			return fmt.Errorf("secret guard path rule is incomplete")
		}
	}
	return nil
}

// hasEmpty reports whether a list has an empty or blank entry, which no guard
// rule may name.
func hasEmpty(list []string) bool {
	for _, entry := range list {
		if strings.TrimSpace(entry) == "" {
			return true
		}
	}
	return false
}

// AWSRulesIncomplete reports whether an AWS Connection's guard, though read in
// full, names no guarded operations. Only the shape is checked; the Console
// owns and tests the content.
func (c Connection) AWSRulesIncomplete() bool {
	return c.AWSRulesRequired() && c.SecretGuard != nil && len(c.SecretGuard.Operations) == 0
}

// AWSRulesRequired reports whether the Connection's calls are AWS calls: the
// aws service, or one signed with SigV4. Its secret guard must come with it;
// without it the Connection is not used.
func (c Connection) AWSRulesRequired() bool {
	if strings.EqualFold(strings.TrimSpace(c.ServiceType), "aws") {
		return true
	}
	for _, injection := range c.EffectiveInjections() {
		if injection.Action == "aws_sigv4" {
			return true
		}
	}
	return false
}

// providerRulesFailure names why the Connection's provider rules cannot be
// enforced, or is empty when they can.
func (c Connection) providerRulesFailure() string {
	// The guard applies to every call, so a guard this client cannot read
	// always makes the Connection unusable.
	if c.SecretGuard.Unsupported() {
		return AccessPolicyUnsupported
	}
	if c.AWSRulesRequired() && c.SecretGuard == nil {
		return ProviderRulesMissing
	}
	if c.AWSRulesIncomplete() {
		return AccessPolicyUnsupported
	}
	return ""
}

// ValidateCredentialEnvironment checks the names of the variables a
// provider's own tools read credentials from. They are exported to the
// Agent's processes as one comma-separated list, so each must be a plain
// upper-case environment name.
func ValidateCredentialEnvironment(names []string) error {
	if len(names) > maxCredentialEnvironmentNames {
		return fmt.Errorf("credentialEnvironment lists more than %d names", maxCredentialEnvironmentNames)
	}
	for _, name := range names {
		if name == "" || len(name) > maxCredentialEnvironmentLength || name != strings.ToUpper(name) || !validEnvironmentName(name) {
			return fmt.Errorf("credentialEnvironment contains an invalid name")
		}
	}
	return nil
}
