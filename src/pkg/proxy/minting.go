package proxy

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/phasehq/cli/internal/agentapi"
)

// Credential-minting block.
//
// A Phase-managed Connection lends the Agent exactly one credential for one
// service. Some calls on that service hand back a brand-new, real credential
// (an STS session, an IAM access key, a registry login token). Letting those
// through would give the Agent material that Phase neither issued nor can
// revoke, so the proxy refuses them before anything is re-signed or injected.
//
// Rules are data, keyed by the Connection's serviceType. To cover another
// service, add an entry to credentialMintingRules:
//   - Operations (AWS): SigV4 scope service -> operation names. Every operation
//     selector the request carries is checked: X-Amz-Target, the Action query
//     parameter and the Action field of a form-encoded body, which the proxy
//     buffers and restores. AWS services differ in which selector they honour,
//     so a request is refused when any of them names a blocked operation.
//   - Paths (any HTTP API): method plus path pattern, matched with path.Match.
//
// A Connection whose connectionConfig carries allowCredentialMinting: true is
// exempt. Console does not set that today; it is the hook for a per-Connection
// toggle later. Postgres (ALTER ROLE ... PASSWORD) is not covered here; it
// needs statement inspection in the protocol adapter.

const (
	allowCredentialMintingConfigKey = "allowCredentialMinting"
	// Query-protocol AWS bodies (sts, iam, redshift) are small; SAML assertions
	// are the largest legitimate payload and stay well under this bound.
	maximumMintingInspectionBytes = int64(256 << 10)
)

type MintingPathRule struct {
	Method    string
	Pattern   string
	Operation string
	// Service limits an AWS rule to requests for that service, so an S3 object
	// key that happens to share the path is not blocked. An unknown service
	// still matches, failing closed.
	Service string
}

type MintingRules struct {
	Operations map[string][]string
	Paths      []MintingPathRule
}

var credentialMintingRules = map[string]MintingRules{
	"aws": {
		Operations: map[string][]string{
			"sts":              {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity", "AssumeRoot", "GetFederationToken", "GetSessionToken"},
			"iam":              {"CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "CreateServiceSpecificCredential", "ResetServiceSpecificCredential", "UploadSSHPublicKey", "UploadSigningCertificate"},
			"ecr":              {"GetAuthorizationToken"},
			"ecr-public":       {"GetAuthorizationToken"},
			"redshift":         {"GetClusterCredentials", "GetClusterCredentialsWithIAM"},
			"cognito-identity": {"GetCredentialsForIdentity", "GetOpenIdToken", "GetOpenIdTokenForDeveloperIdentity"},
		},
		Paths: []MintingPathRule{
			{Method: http.MethodPost, Pattern: "/v1/authorization-token", Operation: "codeartifact:GetAuthorizationToken", Service: "codeartifact"},
		},
	},
	"github": {
		Paths: []MintingPathRule{
			{Method: http.MethodPost, Pattern: "/app/installations/*/access_tokens", Operation: "GitHub App installation access token"},
		},
	},
}

// CredentialMintingBlock names the refused operation, for the error returned
// to the client and the audit event. It never contains request material.
type CredentialMintingBlock struct {
	Operation string
}

func (b *CredentialMintingBlock) Message() string {
	return "Phase blocked " + b.Operation + ": this call would mint a new credential that Phase did not issue and cannot revoke. " +
		"A Phase-managed Connection only permits calls that use the Connection's own credential. " +
		"If the task needs this operation, ask the human for a Connection or role that already has the required access."
}

// ErrMintingInspectionUnavailable is returned when a request on a guarded
// service cannot be classified (for example, a form body above the bound).
// Callers must fail closed.
var ErrMintingInspectionUnavailable = errors.New("request could not be inspected for credential minting")

// CredentialMintingBlocked reports whether req would mint a new credential on
// the Connection's service. It may buffer a bounded form-encoded body to read
// the AWS Action parameter, and always leaves req forwardable.
func CredentialMintingBlocked(req *http.Request, connection agentapi.Connection) (*CredentialMintingBlock, error) {
	if req == nil || req.URL == nil {
		return nil, nil
	}
	if allowed, _ := connection.ConnectionConfig[allowCredentialMintingConfigKey].(bool); allowed {
		return nil, nil
	}
	rules, ok := credentialMintingRules[strings.ToLower(strings.TrimSpace(connection.ServiceType))]
	if !ok {
		return nil, nil
	}
	for _, rule := range rules.Paths {
		if rule.Method != "" && !strings.EqualFold(rule.Method, req.Method) {
			continue
		}
		if rule.Service != "" {
			if service := awsScopeService(req); service != "" && service != rule.Service {
				continue
			}
		}
		if matched, _ := path.Match(rule.Pattern, req.URL.Path); matched {
			return &CredentialMintingBlock{Operation: rule.Operation}, nil
		}
	}
	if len(rules.Operations) == 0 {
		return nil, nil
	}
	service := awsScopeService(req)
	blocked, guarded := rules.Operations[service]
	if !guarded {
		return nil, nil
	}
	operations, err := awsOperations(req)
	if err != nil {
		return nil, err
	}
	for _, operation := range operations {
		for _, candidate := range blocked {
			if strings.EqualFold(candidate, operation) {
				return &CredentialMintingBlock{Operation: service + ":" + candidate}, nil
			}
		}
	}
	return nil, nil
}

// awsScopeService prefers the SigV4 credential scope the client signed with and
// falls back to the endpoint hostname.
func awsScopeService(req *http.Request) string {
	if authorization, present, err := singleHeader(req.Header, "Authorization"); err == nil && present {
		if scope, parseErr := parseSigV4Authorization(authorization); parseErr == nil {
			return scope.service
		}
	}
	host := req.URL.Hostname()
	if host == "" {
		host = req.Host
	}
	service, _, _ := deriveAWSHostScope(host)
	return service
}

// awsOperations resolves every operation selector the request carries: the
// JSON X-Amz-Target header, the Action query parameter and the Action field of
// a form-encoded body. The selectors are not reconciled against the service's
// protocol; a request that names a blocked operation through any of them is
// refused, so a decoy selector cannot hide the one the service will act on.
func awsOperations(req *http.Request) ([]string, error) {
	var operations []string
	if target, present, err := singleHeader(req.Header, "X-Amz-Target"); present {
		if err != nil {
			// A repeated or malformed target cannot be classified; refuse rather
			// than let the service pick one the proxy never saw.
			return nil, ErrMintingInspectionUnavailable
		}
		target = strings.TrimSpace(target)
		if index := strings.LastIndex(target, "."); index >= 0 {
			target = strings.TrimSpace(target[index+1:])
		}
		operations = appendOperation(operations, target)
	}
	for _, action := range req.URL.Query()["Action"] {
		operations = appendOperation(operations, action)
	}
	if req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0 {
		return operations, nil
	}
	// JSON-protocol bodies name their operation in X-Amz-Target, checked
	// above. Every other body on a guarded service is read as a form: the
	// query protocol takes its Action from the body, and a missing or odd
	// Content-Type must not hide it.
	mediaType, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if mediaType == "application/json" || strings.HasPrefix(mediaType, "application/x-amz-json-") {
		return operations, nil
	}
	if req.ContentLength < 0 || req.ContentLength > maximumMintingInspectionBytes {
		return nil, ErrMintingInspectionUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, maximumMintingInspectionBytes+1))
	_ = req.Body.Close()
	if err != nil || int64(len(data)) > maximumMintingInspectionBytes {
		return nil, ErrMintingInspectionUnavailable
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	// A malformed body still yields the pairs that parsed; those are checked too.
	form, _ := url.ParseQuery(string(data))
	for _, action := range form["Action"] {
		operations = appendOperation(operations, action)
	}
	return operations, nil
}

func appendOperation(operations []string, operation string) []string {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return operations
	}
	return append(operations, operation)
}
