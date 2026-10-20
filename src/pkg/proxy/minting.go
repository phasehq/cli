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
//   - Operations (AWS): SigV4 scope service -> operation names. The operation
//     is resolved from X-Amz-Target, the Action query parameter, or the Action
//     field of a form-encoded body, which the proxy buffers and restores.
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
			"redshift":         {"GetClusterCredentials", "GetClusterCredentialsWithIAM"},
			"cognito-identity": {"GetCredentialsForIdentity", "GetOpenIdToken", "GetOpenIdTokenForDeveloperIdentity"},
		},
		Paths: []MintingPathRule{
			{Method: http.MethodPost, Pattern: "/v1/authorization/token", Operation: "codeartifact:GetAuthorizationToken"},
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
	operation, err := awsOperation(req)
	if err != nil {
		return nil, err
	}
	for _, candidate := range blocked {
		if strings.EqualFold(candidate, operation) {
			return &CredentialMintingBlock{Operation: service + ":" + candidate}, nil
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

// awsOperation resolves the operation name for JSON (X-Amz-Target), query
// (Action parameter), and form-encoded query-protocol requests.
func awsOperation(req *http.Request) (string, error) {
	if target, present, err := singleHeader(req.Header, "X-Amz-Target"); err == nil && present {
		if index := strings.LastIndex(target, "."); index >= 0 {
			return strings.TrimSpace(target[index+1:]), nil
		}
		return strings.TrimSpace(target), nil
	}
	if action := req.URL.Query().Get("Action"); action != "" {
		return action, nil
	}
	mediaType, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if mediaType != "application/x-www-form-urlencoded" || req.Body == nil || req.Body == http.NoBody {
		return "", nil
	}
	if req.ContentLength < 0 || req.ContentLength > maximumMintingInspectionBytes {
		return "", ErrMintingInspectionUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, maximumMintingInspectionBytes+1))
	_ = req.Body.Close()
	if err != nil || int64(len(data)) > maximumMintingInspectionBytes {
		return "", ErrMintingInspectionUnavailable
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	form, err := url.ParseQuery(string(data))
	if err != nil {
		return "", nil
	}
	return form.Get("Action"), nil
}
