package proxy

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/phasehq/cli/internal/agentapi"
)

// Secret guard: the credential-minting block.
//
// A Phase-managed Connection lends the Agent exactly one credential for one
// service. Some calls on that service hand back a brand-new, real credential
// (an STS session, an IAM access key, a registry login token). Letting those
// through would give the Agent material that Phase neither issued nor can
// revoke, so the proxy refuses them before anything is re-signed or injected.
//
// The guard is a managed policy: it is always on, no Connection setting turns
// it off, and no access policy rule or temporary allow overrides it. Calls it
// stops belong to the class credential_minting. Response scrubbing in
// scrub.go is its backstop for AWS Connections.
//
// Rules are data, keyed by the Connection's serviceType. To cover another
// service, add an entry to credentialMintingRules:
//   - Operations (AWS): SigV4 scope service -> operation names. Every operation
//     selector the request carries is checked: X-Amz-Target, the Action query
//     parameter, a Smithy RPC v2 path and the Action field of a form-encoded
//     body, which the proxy buffers and restores. AWS services differ in which
//     selector they honour, so a request is refused when any of them names a
//     blocked operation. A query-protocol service acts on a form body whatever
//     Content-Type the request claims, so there the body is always read, and a
//     body that names no operation at all cannot be inspected.
//   - Paths (any HTTP API): method plus path pattern, matched with path.Match,
//     and optionally a query parameter the request must carry. The path is
//     compared as loosePathMatch reads it, so a respelling does not get past.
//
// Postgres (ALTER ROLE ... PASSWORD) is not covered here; it needs statement
// inspection in the protocol adapter.

const (
	// SecretGuardRule names the guard wherever a stopped call reports the rule
	// that stopped it.
	SecretGuardRule = "secret_guard"
	// Query-protocol AWS bodies (sts, iam, redshift) are small; SAML assertions
	// are the largest legitimate payload and stay well under this bound.
	maximumMintingInspectionBytes = int64(256 << 10)
)

type MintingPathRule struct {
	Method    string
	Pattern   string
	Query     string
	Operation string
	// Services limits an AWS rule to requests signed for one of these
	// services, so an S3 object key that happens to share the path is not
	// blocked. An unknown service still matches, failing closed.
	Services []string
	// HostLabel further limits a rule to hosts that carry this DNS label,
	// for a service whose signing name is shared with unrelated APIs.
	HostLabel string
}

type MintingRules struct {
	Operations map[string][]string
	Paths      []MintingPathRule
}

var credentialMintingRules = map[string]MintingRules{
	"aws": {
		Operations: map[string][]string{
			"sts":                 {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity", "AssumeRoot", "GetFederationToken", "GetSessionToken", "GetWebIdentityToken"},
			"iam":                 {"CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "CreateServiceSpecificCredential", "ResetServiceSpecificCredential", "UploadSSHPublicKey", "UploadSigningCertificate"},
			"ecr":                 {"GetAuthorizationToken"},
			"ecr-public":          {"GetAuthorizationToken"},
			"redshift":            {"GetClusterCredentials", "GetClusterCredentialsWithIAM"},
			"redshift-serverless": {"GetCredentials"},
			"cognito-identity":    {"GetCredentialsForIdentity", "GetOpenIdToken", "GetOpenIdTokenForDeveloperIdentity"},
			"ec2":                 {"CreateKeyPair"},
			"elasticmapreduce":    {"GetClusterSessionCredentials"},
			"lightsail":           {"GetInstanceAccessDetails", "CreateKeyPair", "DownloadDefaultKeyPair", "CreateBucketAccessKey"},
		},
		Paths: []MintingPathRule{
			{Method: http.MethodPost, Pattern: "/v1/authorization-token", Operation: "codeartifact:GetAuthorizationToken", Services: []string{"codeartifact"}},
			{Method: http.MethodGet, Pattern: "/*", Query: "session", Operation: "s3express:CreateSession", Services: []string{"s3express"}},
			// The IoT control plane is signed as iot or, by older clients, as
			// execute-api, which API Gateway also uses: hence the host label.
			{Method: http.MethodPost, Pattern: "/keys-and-certificate", Operation: "iot:CreateKeysAndCertificate", Services: []string{"iot", "execute-api"}, HostLabel: "iot"},
			{Method: http.MethodPost, Pattern: "/apikeys", Operation: "apigateway:CreateApiKey", Services: []string{"apigateway"}},
			{Method: http.MethodPost, Pattern: "/clitoken/*", Operation: "airflow:CreateCliToken", Services: []string{"airflow"}},
			{Method: http.MethodPost, Pattern: "/webtoken/*", Operation: "airflow:CreateWebLoginToken", Services: []string{"airflow"}},
			{Method: http.MethodPost, Pattern: "/workspaces/*/apikeys", Operation: "grafana:CreateWorkspaceApiKey", Services: []string{"grafana"}},
			{Method: http.MethodPost, Pattern: "/virtualclusters/*/endpoints/*/credentials", Operation: "emr-containers:GetManagedEndpointSessionCredentials", Services: []string{"emr-containers"}},
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
		"This block is always on and cannot be requested around. " +
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
	rules, ok := credentialMintingRules[strings.ToLower(strings.TrimSpace(connection.ServiceType))]
	if !ok {
		return nil, nil
	}
	for _, rule := range rules.Paths {
		if rule.Method != "" && !strings.EqualFold(rule.Method, req.Method) {
			continue
		}
		if len(rule.Services) > 0 {
			if service := awsScopeService(req); service != "" && !containsString(rule.Services, service) {
				continue
			}
		}
		if rule.HostLabel != "" && !hostHasLabel(req, rule.HostLabel) {
			continue
		}
		if rule.Query != "" && !req.URL.Query().Has(rule.Query) {
			continue
		}
		if loosePathMatch(rule.Pattern, req.URL.Path) {
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
	operations, err := awsOperations(req, service, true)
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

// hostHasLabel reports whether the request's host carries the DNS label, with
// or without the -fips suffix AWS endpoints use.
func hostHasLabel(req *http.Request, label string) bool {
	host := req.URL.Hostname()
	if host == "" {
		host = req.Host
	}
	for _, candidate := range strings.Split(strings.ToLower(host), ".") {
		if strings.TrimSuffix(candidate, "-fips") == label {
			return true
		}
	}
	return false
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
// JSON X-Amz-Target header, the Action query parameter, a Smithy RPC v2 path
// and the Action field of a form-encoded body. The selectors are not
// reconciled against the service's protocol; a request that names a blocked
// operation through any of them is refused, so a decoy selector cannot hide
// the one the service will act on. guarded says the caller is the secret
// guard on a service it has rules for, which reads a body of any type that is
// not JSON.
func awsOperations(req *http.Request, service string, guarded bool) ([]string, error) {
	operations, err := awsHeaderAndQueryOperations(req)
	if err != nil {
		return nil, err
	}
	if awsBodyReadAsForm(req, service, guarded) {
		fromBody, err := awsFormBodyOperations(req)
		if err != nil {
			return nil, err
		}
		operations = append(operations, fromBody...)
	}
	// A call to a query-protocol service always names its action. A body with
	// no selector beside it hides the action from the proxy (an encoding it
	// does not read, for one), so the call cannot be judged.
	if len(operations) == 0 && awsRequestHasBody(req) && awsQueryProtocolCall(req, service) {
		return nil, ErrMintingInspectionUnavailable
	}
	return operations, nil
}

// awsHeaderAndQueryOperations reads the selectors that need no body.
func awsHeaderAndQueryOperations(req *http.Request) ([]string, error) {
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
	if operation, named := smithyRPCOperation(req.URL.Path); named {
		operations = appendOperation(operations, operation)
	}
	return operations, nil
}

// smithyRPCOperation reads the operation of a Smithy RPC v2 request, which
// names it in the path: /service/<Service>/operation/<Name>, under any prefix.
func smithyRPCOperation(requestPath string) (string, bool) {
	segments := strings.Split(strings.Trim(requestPath, "/"), "/")
	count := len(segments)
	if count < 4 || segments[count-4] != "service" || segments[count-3] == "" ||
		segments[count-2] != "operation" || segments[count-1] == "" {
		return "", false
	}
	return segments[count-1], true
}

// awsFormBodyOperations reads the Action field of a body the query protocol
// would act on. It buffers a bounded body and leaves req forwardable.
func awsFormBodyOperations(req *http.Request) ([]string, error) {
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
	var operations []string
	for _, action := range form["Action"] {
		operations = appendOperation(operations, action)
	}
	return operations, nil
}

func awsRequestHasBody(req *http.Request) bool {
	return req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0
}

// awsBodyReadAsForm reports whether the body has to be read to know the
// action.
//
// A query-protocol service takes its Action from a form body whatever
// Content-Type the request claims, so its body is always read. The exception
// is a service that also speaks a JSON or CBOR protocol and is sent that
// protocol's own content type: the body is then not a form, and the action is
// in X-Amz-Target or the path.
//
// On any other service the body is read only when it says it is a form, so an
// S3 upload is never buffered. The secret guard, and a request whose service
// the proxy cannot name, read every body that is not JSON: a missing or odd
// Content-Type must not hide an Action.
func awsBodyReadAsForm(req *http.Request, service string, guarded bool) bool {
	if !awsRequestHasBody(req) {
		return false
	}
	mediaType, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	protocolBody := strings.HasPrefix(mediaType, "application/x-amz-json-") || mediaType == "application/cbor"
	if awsQueryProtocolCall(req, service) {
		return !(protocolBody && containsString(awsClasses.DualProtocolServices, service))
	}
	if guarded || service == "" {
		return !protocolBody && mediaType != "application/json"
	}
	return mediaType == "application/x-www-form-urlencoded"
}

func appendOperation(operations []string, operation string) []string {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return operations
	}
	return append(operations, operation)
}
