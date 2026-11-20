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
// Like a policy, the guard and the call classes are decoded strictly: rules
// this client cannot read in full are never enforced in part, and the
// Connection is unavailable instead (see AccessPolicyFailure).

const (
	// ActionClassesSchemeAWS is the only call class scheme this client knows.
	ActionClassesSchemeAWS  = "aws_actions"
	actionClassesVersionAWS = 1

	// ProviderRulesMissing is the reason an AWS Connection is unavailable when
	// the Console sent it without its secret guard or call classes. Its calls
	// could otherwise neither be guarded nor classified.
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

// ActionClasses is how a provider's calls are sorted into operation classes
// by the action they name. Only the aws_actions scheme exists; its fields are
// read by pkg/proxy/aws_classes.go, which documents what each one means.
type ActionClasses struct {
	Scheme                string                     `json:"scheme"`
	Version               int                        `json:"version"`
	ReadVerbs             []string                   `json:"readVerbs"`
	CreateVerbs           []string                   `json:"createVerbs"`
	DeleteVerbs           []string                   `json:"deleteVerbs"`
	AdminServices         []string                   `json:"adminServices"`
	AdminSuffixes         []string                   `json:"adminSuffixes"`
	Exact                 map[string]string          `json:"exact"`
	S3Subresources        map[string]string          `json:"s3Subresources"`
	RESTOperations        []ActionClassRESTOperation `json:"restOperations"`
	QueryProtocolServices []string                   `json:"queryProtocolServices"`
	DualProtocolServices  []string                   `json:"dualProtocolServices"`
	JSONTargetServices    []string                   `json:"jsonTargetServices"`
	MixedServices         []string                   `json:"mixedServices"`

	// exactFolded is Exact keyed without regard to letter case.
	exactFolded map[string]string
	raw         json.RawMessage
	unsupported bool
}

// ActionClassRESTOperation is one REST call of a service, by method and path
// pattern (path.Match syntax), and the action it performs.
type ActionClassRESTOperation struct {
	Service string `json:"service"`
	Method  string `json:"method"`
	Pattern string `json:"pattern"`
	Action  string `json:"action"`
}

func (a *ActionClasses) UnmarshalJSON(data []byte) error {
	*a = ActionClasses{raw: append(json.RawMessage(nil), data...)}
	type plain ActionClasses
	var wire plain
	if strictDecode(data, &wire) != nil || validateActionClasses((*ActionClasses)(&wire)) != nil {
		a.unsupported = true
		return nil
	}
	wire.raw = a.raw
	*a = ActionClasses(wire)
	a.exactFolded = make(map[string]string, len(a.Exact))
	for operation, class := range a.Exact {
		a.exactFolded[strings.ToLower(operation)] = class
	}
	return nil
}

func (a ActionClasses) MarshalJSON() ([]byte, error) {
	if len(a.raw) > 0 {
		return a.raw, nil
	}
	type plain ActionClasses
	return json.Marshal(plain(a))
}

// Unsupported reports whether the classes are in a scheme or version this
// client does not know, or could not be read in full.
func (a *ActionClasses) Unsupported() bool { return a != nil && a.unsupported }

// ExactClass returns the class Exact gives "service:action", compared without
// regard to letter case.
func (a *ActionClasses) ExactClass(service, action string) (string, bool) {
	key := strings.ToLower(service + ":" + action)
	if a.exactFolded != nil {
		class, ok := a.exactFolded[key]
		return class, ok
	}
	for operation, class := range a.Exact {
		if strings.ToLower(operation) == key {
			return class, true
		}
	}
	return "", false
}

func validateActionClasses(classes *ActionClasses) error {
	if classes.Scheme != ActionClassesSchemeAWS || classes.Version != actionClassesVersionAWS {
		return fmt.Errorf("unsupported action class scheme")
	}
	for _, table := range []map[string]string{classes.Exact, classes.S3Subresources} {
		for _, class := range table {
			if !userOperationClass(class) {
				return fmt.Errorf("unsupported operation class")
			}
		}
	}
	for _, list := range [][]string{
		classes.ReadVerbs, classes.CreateVerbs, classes.DeleteVerbs, classes.AdminServices, classes.AdminSuffixes,
		classes.QueryProtocolServices, classes.DualProtocolServices, classes.JSONTargetServices, classes.MixedServices,
	} {
		if hasEmpty(list) {
			return fmt.Errorf("action class list has an empty entry")
		}
	}
	for _, operation := range classes.RESTOperations {
		if operation.Service == "" || operation.Method == "" || !strings.HasPrefix(operation.Pattern, "/") || operation.Action == "" {
			return fmt.Errorf("incomplete REST operation")
		}
	}
	return nil
}

// hasEmpty reports whether a list has an empty entry, which would match
// everything where entries are compared as prefixes or suffixes.
func hasEmpty(list []string) bool {
	for _, entry := range list {
		if strings.TrimSpace(entry) == "" {
			return true
		}
	}
	return false
}

// AWSRulesIncomplete reports whether an AWS Connection's rules, though read in
// full, lack what its guard and classifier need to work: guarded operations,
// the verbs that sort calls, and which services speak which protocol (without
// those, a form body sent under another content type is never read). Only the
// shape is checked; the Console owns and tests the content.
func (c Connection) AWSRulesIncomplete() bool {
	if !c.AWSRulesRequired() || c.SecretGuard == nil || c.ActionClasses == nil {
		return false
	}
	classes := c.ActionClasses
	return len(c.SecretGuard.Operations) == 0 || len(classes.ReadVerbs) == 0 || len(classes.CreateVerbs) == 0 ||
		len(classes.DeleteVerbs) == 0 || len(classes.QueryProtocolServices) == 0 || len(classes.JSONTargetServices) == 0
}

// AWSRulesRequired reports whether the Connection's calls are AWS calls: the
// aws service, or one signed with SigV4. Its secret guard and call classes
// must come with it; without them the Connection is not used.
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
	aws := c.AWSRulesRequired()
	// The guard applies to every call, so a guard this client cannot read
	// always makes the Connection unusable. The classes matter where calls
	// are classified (a restricting policy) and, for AWS, to the guard too.
	if c.SecretGuard.Unsupported() || (c.ActionClasses.Unsupported() && (aws || c.Policy.Restricts())) {
		return AccessPolicyUnsupported
	}
	if aws && (c.SecretGuard == nil || c.ActionClasses == nil) {
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
