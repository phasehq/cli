package proxy

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/phasehq/cli/internal/agentapi"
)

// awsCall is a request as an AWS client under Phase sends it: signed with the
// decoy key for the given service.
func awsCall(t *testing.T, method, target, service, contentType, body string, headers map[string]string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body == "" {
		request.Body, request.ContentLength = http.NoBody, 0
	}
	request.Host = request.URL.Host
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	signRequest(t, request, aws.Credentials{AccessKeyID: testExpectedAccessKeyID, SecretAccessKey: testDecoySecret}, service, "us-east-1", sha256Hex(body))
	return request
}

func awsPolicyConnection(t *testing.T, policy string) agentapi.Connection {
	t.Helper()
	connection := withProviderRules(t, agentapi.Connection{ServiceType: "aws", Protocol: "http", Injection: agentapi.Injection{Action: "aws_sigv4"}})
	if policy != "" {
		connection.Policy = testPolicy(t, policy)
	}
	return connection
}

func callClasses(t *testing.T, request *http.Request, connection agentapi.Connection) []string {
	t.Helper()
	calls, err := ClassifyCall(request, connection)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	classes := make([]string, 0, len(calls))
	for _, call := range calls {
		classes = append(classes, call.Class)
	}
	return classes
}

func decide(t *testing.T, request *http.Request, connection agentapi.Connection) PolicyDecision {
	t.Helper()
	calls, err := ClassifyCall(request, connection)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	return EvaluateAccessPolicy(connection.Policy, calls, request, policyTestNow)
}

func httpPolicyConnection(t *testing.T, policy string) agentapi.Connection {
	t.Helper()
	connection := agentapi.Connection{ServiceType: agentapi.CustomHTTPServiceType, Protocol: "http"}
	if policy != "" {
		connection.Policy = testPolicy(t, policy)
	}
	return connection
}

// Rails (Rack), Laravel and Symfony read the method of a POST from a form
// body's _method field.
func TestFormBodyMethodOverrideAddsTheNamedMethodsClass(t *testing.T) {
	connection := httpPolicyConnection(t, `{"version":1,"default":"allow","rules":[{"class":"delete","effect":"block"}]}`)
	form := func(method, contentType, body string) *http.Request {
		created, err := http.NewRequest(method, "https://api.example.test/v1/items/1", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if contentType != "" {
			created.Header.Set("Content-Type", contentType)
		}
		return created
	}
	for _, contentType := range []string{"application/x-www-form-urlencoded", "Application/X-WWW-Form-Urlencoded; charset=utf-8", ""} {
		request := form("POST", contentType, "name=x&_method=delete")
		decision := decide(t, request, connection)
		if decision.Effect != agentapi.PolicyBlock || decision.Method != "DELETE" {
			t.Errorf("%q form: effect=%s method=%s", contentType, decision.Effect, decision.Method)
		}
		if forwarded, _ := io.ReadAll(request.Body); string(forwarded) != "name=x&_method=delete" {
			t.Errorf("%q form: body forwarded as %q", contentType, forwarded)
		}
	}
	// Only a form body sent with POST is read, and only for _method.
	for name, request := range map[string]*http.Request{
		"JSON body":    form("POST", "application/json", `{"_method":"DELETE"}`),
		"PUT form":     form("PUT", "application/x-www-form-urlencoded", "_method=DELETE"),
		"plain form":   form("POST", "application/x-www-form-urlencoded", "name=x"),
		"POST renamed": form("POST", "application/x-www-form-urlencoded", "_method=post"),
	} {
		if classes := callClasses(t, request, connection); len(classes) != 1 {
			t.Errorf("%s: classes = %v", name, classes)
		}
	}
	// A form body that cannot be read in full is not judged by its method.
	large := form("POST", "application/x-www-form-urlencoded", "_method=DELETE&pad="+strings.Repeat("x", int(maximumMintingInspectionBytes)))
	if _, err := ClassifyCall(large, connection); !errors.Is(err, ErrCallUninspectable) {
		t.Errorf("an oversized form body: err=%v", err)
	}
	unknownLength := form("POST", "application/x-www-form-urlencoded", "_method=DELETE&pad="+strings.Repeat("x", int(maximumMintingInspectionBytes)))
	unknownLength.ContentLength = -1
	if _, err := ClassifyCall(unknownLength, connection); !errors.Is(err, ErrCallUninspectable) {
		t.Errorf("an oversized form body of unknown length: err=%v", err)
	}
	if _, err := ClassifyCall(form("POST", "application/x-www-form-urlencoded", "a=%zz&_method=DELETE"), connection); !errors.Is(err, ErrCallUninspectable) {
		t.Errorf("an unreadable form naming _method: err=%v", err)
	}
}

// multipartForm is a multipart/form-data body with a file part of fileBytes
// before or after a _method part, and its Content-Type.
func multipartForm(t *testing.T, fileBytes int, methodFirst bool) (string, []byte) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	method := func() {
		if err := writer.WriteField("_method", "DELETE"); err != nil {
			t.Fatal(err)
		}
	}
	if methodFirst {
		method()
	}
	file, err := writer.CreateFormFile("upload", "report.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(bytes.Repeat([]byte("r"), fileBytes)); err != nil {
		t.Fatal(err)
	}
	if !methodFirst {
		method()
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return writer.FormDataContentType(), body.Bytes()
}

// A _method part is read from the first 256 KiB of a multipart body only. A
// larger upload is never refused for it, and the body goes on unchanged.
func TestMultipartMethodOverrideIsReadWithinTheBound(t *testing.T) {
	connection := httpPolicyConnection(t, `{"version":1,"default":"allow","rules":[{"class":"delete","effect":"block"}]}`)
	bound := int(maximumMintingInspectionBytes)
	// The file size that starts the _method value three bytes before the bound.
	_, probe := multipartForm(t, bound, false)
	straddling := bound - (bytes.LastIndex(probe, []byte("DELETE")) - bound) - 3
	for name, test := range map[string]struct {
		fileBytes     int
		methodFirst   bool
		unknownLength bool
		classes       []string
	}{
		"a small form":                        {fileBytes: 1024, classes: []string{"create", "delete"}},
		"_method before a large upload":       {fileBytes: bound * 2, methodFirst: true, classes: []string{"create", "delete"}},
		"_method after the bound":             {fileBytes: bound + 1, classes: []string{"create"}},
		"_method after the bound, any length": {fileBytes: bound * 3, unknownLength: true, classes: []string{"create"}},
		"_method cut off by the bound":        {fileBytes: straddling, classes: []string{"create"}},
	} {
		contentType, body := multipartForm(t, test.fileBytes, test.methodFirst)
		if name == "_method cut off by the bound" {
			if at := bytes.LastIndex(body, []byte("DELETE")); at >= bound || at+len("DELETE") <= bound {
				t.Fatalf("the _method value spans %d..%d, not the bound %d", at, at+6, bound)
			}
		}
		request, err := http.NewRequest(http.MethodPost, "https://api.example.test/v1/items", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", contentType)
		if test.unknownLength {
			request.ContentLength = -1
		}
		if classes := callClasses(t, request, connection); !reflect.DeepEqual(classes, test.classes) {
			t.Errorf("%s: classes = %v, want %v", name, classes, test.classes)
		}
		want := agentapi.PolicyAllow
		if len(test.classes) > 1 {
			want = agentapi.PolicyBlock
		}
		if decision := decide(t, request, connection); decision.Effect != want {
			t.Errorf("%s: effect = %s, want %s", name, decision.Effect, want)
		}
		if forwarded, err := io.ReadAll(request.Body); err != nil || !bytes.Equal(forwarded, body) {
			t.Errorf("%s: the body was not forwarded unchanged (%d of %d bytes, err=%v)", name, len(forwarded), len(body), err)
		}
	}
}

func TestMethodOverrideAddsTheNamedMethodsClass(t *testing.T) {
	policy := `{"version":1,"default":"allow","rules":[{"class":"delete","effect":"block"},{"match":{"methods":["PUT"],"path":"/v1/settings"},"effect":"ask"}]}`
	connection := httpPolicyConnection(t, policy)
	request := func(method, target string, headers map[string]string) *http.Request {
		created := policyRequest(t, method, target)
		for name, value := range headers {
			created.Header.Set(name, value)
		}
		return created
	}
	const item = "https://api.example.test/v1/items/1"
	if decision := decide(t, request("POST", item, nil), connection); decision.Effect != agentapi.PolicyAllow {
		t.Fatalf("a plain POST = %s", decision.Effect)
	}
	for _, header := range []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"} {
		overridden := request("POST", item, map[string]string{header: "delete"})
		if classes := callClasses(t, overridden, connection); !reflect.DeepEqual(classes, []string{"create", "delete"}) {
			t.Errorf("%s: classes = %v", header, classes)
		}
		decision := decide(t, overridden, connection)
		if decision.Effect != agentapi.PolicyBlock || decision.Class != "delete" || decision.Method != "DELETE" {
			t.Errorf("%s: effect=%s class=%s method=%s", header, decision.Effect, decision.Class, decision.Method)
		}
	}
	if decision := decide(t, request("POST", item+"?_method=DELETE", nil), connection); decision.Effect != agentapi.PolicyBlock {
		t.Errorf("_method parameter: effect=%s", decision.Effect)
	}
	// A query the proxy cannot fully parse may still carry the parameter.
	if classes := callClasses(t, request("POST", item+"?a=%zz&_method=DELETE;x", nil), connection); !reflect.DeepEqual(classes, []string{"create", "update"}) {
		t.Errorf("unreadable query naming _method: classes = %v", classes)
	}
	// A name that is no HTTP method counts as an update.
	if classes := callClasses(t, request("POST", item, map[string]string{"X-HTTP-Method-Override": "PURGE"}), connection); !reflect.DeepEqual(classes, []string{"create", "update"}) {
		t.Errorf("unknown method name: classes = %v", classes)
	}
	// The request's own method named again adds nothing.
	if classes := callClasses(t, request("POST", item, map[string]string{"X-HTTP-Method-Override": "POST"}), connection); !reflect.DeepEqual(classes, []string{"create"}) {
		t.Errorf("own method named again: classes = %v", classes)
	}
	// A rule by method is matched against the method the call would run as.
	settings := request("POST", "https://api.example.test/v1/settings", map[string]string{"X-HTTP-Method-Override": "PUT"})
	if decision := decide(t, settings, connection); decision.Effect != agentapi.PolicyAsk || decision.Method != "PUT" || decision.Rule == nil {
		t.Errorf("a method rule on the overridden method: effect=%s method=%s", decision.Effect, decision.Method)
	}
	// Every HTTP Connection, AWS included: the call is also the class of the
	// method the override names.
	aws := awsPolicyConnection(t, `{"version":1,"rules":[{"class":"delete","effect":"block"}]}`)
	object := awsCall(t, "POST", "https://bucket.s3.us-east-1.amazonaws.com/key?uploads", "s3", "", "", map[string]string{"X-HTTP-Method-Override": "DELETE"})
	if classes := callClasses(t, object, aws); !reflect.DeepEqual(classes, []string{"create", "delete"}) {
		t.Errorf("AWS call with a method override: classes = %v", classes)
	}
	if decision := decide(t, object, aws); decision.Effect != agentapi.PolicyBlock || decision.Class != "delete" || decision.Method != "DELETE" {
		t.Errorf("AWS call with a method override: effect=%s class=%s method=%s", decision.Effect, decision.Class, decision.Method)
	}
	query := awsCall(t, "POST", "https://ec2.us-east-1.amazonaws.com/?_method=DELETE", "ec2", "application/x-www-form-urlencoded", "Action=DescribeInstances", nil)
	if classes := callClasses(t, query, aws); !reflect.DeepEqual(classes, []string{"create", "delete"}) {
		t.Errorf("AWS call with a _method parameter: classes = %v", classes)
	}
}

// A temporary allow for the overridden method lifts the ask on that candidate
// and on nothing else.
func TestTemporaryAllowCoversTheOverriddenMethod(t *testing.T) {
	future := policyTestNow.AddDate(0, 0, 1).Format("2006-01-02T15:04:05Z07:00")
	connection := httpPolicyConnection(t, `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"allow-1","match":{"methods":["DELETE"],"path":"/v1/items/1"},"expiresAt":"`+future+`"}]}`)
	covered := policyRequest(t, "POST", "https://api.example.test/v1/items/1")
	covered.Header.Set("X-HTTP-Method-Override", "DELETE")
	if decision := decide(t, covered, connection); decision.Effect != agentapi.PolicyAllow {
		t.Fatalf("the allowed call = %s", decision.Effect)
	}
	other := policyRequest(t, "POST", "https://api.example.test/v1/items/2")
	other.Header.Set("X-HTTP-Method-Override", "DELETE")
	if decision := decide(t, other, connection); decision.Effect != agentapi.PolicyAsk {
		t.Fatalf("another path = %s", decision.Effect)
	}
}

// Rules that stop a call match a respelled path; rules and temporary allows
// that let one through match only the path as sent.
func TestStoppingRulesMatchARespelledPathAndAllowingOnesDoNot(t *testing.T) {
	respellings := []string{"/v1/admin", "/v1/admin/", "/V1/Admin", "/v1/admin;jsessionid=1", "/v1/ADMIN;x/", "/v1/admin/;x", "/v1;x/admin"}
	for _, effect := range []string{"block", "ask"} {
		connection := httpPolicyConnection(t, `{"version":1,"default":"allow","rules":[{"match":{"path":"/v1/admin"},"effect":"`+effect+`"}]}`)
		for _, spelled := range respellings {
			if decision := decide(t, policyRequest(t, "GET", "https://api.example.test"+spelled), connection); decision.Effect != effect {
				t.Errorf("%s rule, %s: effect=%s", effect, spelled, decision.Effect)
			}
		}
		for _, other := range []string{"/v1/administrator", "/v1/admin/users", "/v1/adm"} {
			if decision := decide(t, policyRequest(t, "GET", "https://api.example.test"+other), connection); decision.Effect != agentapi.PolicyAllow {
				t.Errorf("%s rule, another path %s: effect=%s", effect, other, decision.Effect)
			}
		}
	}
	// A rule written with a trailing slash covers the path without one.
	slashed := httpPolicyConnection(t, `{"version":1,"rules":[{"match":{"path":"/v1/admin/"},"effect":"block"}]}`)
	if decision := decide(t, policyRequest(t, "GET", "https://api.example.test/v1/admin"), slashed); decision.Effect != agentapi.PolicyBlock {
		t.Errorf("a rule with a trailing slash: effect=%s", decision.Effect)
	}

	allowing := httpPolicyConnection(t, `{"version":1,"default":"block","rules":[{"match":{"path":"/v1/public"},"effect":"allow"}]}`)
	if decision := decide(t, policyRequest(t, "GET", "https://api.example.test/v1/public"), allowing); decision.Effect != agentapi.PolicyAllow {
		t.Fatalf("an allow rule on the path as written: effect=%s", decision.Effect)
	}
	for _, spelled := range []string{"/v1/public/", "/V1/PUBLIC", "/v1/public;x"} {
		if decision := decide(t, policyRequest(t, "GET", "https://api.example.test"+spelled), allowing); decision.Effect != agentapi.PolicyBlock {
			t.Errorf("allow rule, %s: effect=%s", spelled, decision.Effect)
		}
	}

	future := policyTestNow.AddDate(0, 0, 1).Format("2006-01-02T15:04:05Z07:00")
	temporary := httpPolicyConnection(t, `{"version":1,"default":"ask","rules":[],"temporaryAllows":[{"id":"allow-1","match":{"methods":["GET"],"path":"/v1/reports"},"expiresAt":"`+future+`"}]}`)
	if decision := decide(t, policyRequest(t, "GET", "https://api.example.test/v1/reports"), temporary); decision.Effect != agentapi.PolicyAllow {
		t.Fatalf("a temporary allow on the path as written: effect=%s", decision.Effect)
	}
	for _, spelled := range []string{"/v1/reports/", "/v1/Reports", "/v1/reports;x"} {
		if decision := decide(t, policyRequest(t, "GET", "https://api.example.test"+spelled), temporary); decision.Effect != agentapi.PolicyAsk {
			t.Errorf("temporary allow, %s: effect=%s", spelled, decision.Effect)
		}
	}
}

func TestSecretGuardPathRulesMatchARespelledPath(t *testing.T) {
	github := withProviderRules(t, agentapi.Connection{ServiceType: "github", Protocol: "http"})
	for _, spelled := range []string{
		"/app/installations/42/access_tokens", "/app/installations/42/access_tokens/", "/APP/Installations/42/Access_Tokens",
		"/app/installations/42/access_tokens;x", "//app/installations/42/access_tokens", "/app/./installations/42/access_tokens",
	} {
		request := policyRequest(t, "POST", "https://api.github.com"+spelled)
		if blocked, err := CredentialMintingBlocked(request, github); err != nil || blocked == nil {
			t.Errorf("%s: blocked=%v err=%v", spelled, blocked, err)
		}
	}
	for _, other := range []string{"/app/installations/42", "/app/installations/42/access_tokens/more", "/repos/acme/app/installations"} {
		if blocked, _ := CredentialMintingBlocked(policyRequest(t, "POST", "https://api.github.com"+other), github); blocked != nil {
			t.Errorf("%s was taken for the installation token call", other)
		}
	}
	aws := mintingAWSConnection(nil)
	for _, spelled := range []string{"/v1/authorization-token/", "/V1/Authorization-Token", "/v1/authorization-token;x"} {
		request := awsCall(t, "POST", "https://codeartifact.us-east-1.amazonaws.com"+spelled+"?domain=d", "codeartifact", "", "", nil)
		if blocked, err := CredentialMintingBlocked(request, aws); err != nil || blocked == nil || blocked.Operation != "codeartifact:GetAuthorizationToken" {
			t.Errorf("%s: blocked=%v err=%v", spelled, blocked, err)
		}
	}
}

func TestUpgradeRequestIsAlsoAnUpdate(t *testing.T) {
	upgrade := func(target string) *http.Request {
		request := policyRequest(t, "GET", target)
		request.Header.Set("Connection", "keep-alive, Upgrade")
		request.Header.Set("Upgrade", "websocket")
		return request
	}
	policy := `{"version":1,"default":"allow","rules":[{"class":"update","effect":"ask"}]}`
	connection := httpPolicyConnection(t, policy)
	if classes := callClasses(t, upgrade("https://api.example.test/socket"), connection); !reflect.DeepEqual(classes, []string{"read", "update"}) {
		t.Fatalf("upgrade classes = %v", classes)
	}
	if decision := decide(t, upgrade("https://api.example.test/socket"), connection); decision.Effect != agentapi.PolicyAsk || decision.Class != "update" {
		t.Fatalf("upgrade: effect=%s class=%s", decision.Effect, decision.Class)
	}
	// An ordinary GET, and one that only names Upgrade without asking for it.
	if classes := callClasses(t, policyRequest(t, "GET", "https://api.example.test/socket"), connection); !reflect.DeepEqual(classes, []string{"read"}) {
		t.Fatalf("plain GET classes = %v", classes)
	}
	named := policyRequest(t, "GET", "https://api.example.test/socket")
	named.Header.Set("Upgrade", "websocket")
	if classes := callClasses(t, named, connection); !reflect.DeepEqual(classes, []string{"read"}) {
		t.Fatalf("Upgrade without Connection: classes = %v", classes)
	}
	aws := awsPolicyConnection(t, policy)
	stream := awsCall(t, "GET", "https://ssmmessages.us-east-1.amazonaws.com/v1/data-channel/session-1", "ssmmessages", "", "", map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"})
	if decision := decide(t, stream, aws); decision.Effect != agentapi.PolicyAsk {
		t.Fatalf("AWS upgrade: effect=%s", decision.Effect)
	}
}

// Smithy RPC v2 names the operation in the path, and the secret guard reads
// it there.
func TestSmithyRPCPathNamesTheAction(t *testing.T) {
	for requestPath, want := range map[string]string{
		"/service/Example/operation/GetThing":         "GetThing",
		"/prefix/service/Example/operation/GetThing/": "GetThing",
		"/service/Example/operation":                  "",
		"/service//operation/GetThing":                "",
		"/services/Example/operation/GetThing":        "",
		"/bucket/key":                                 "",
	} {
		if operation, _ := smithyRPCOperation(requestPath); operation != want {
			t.Errorf("%s: operation = %q, want %q", requestPath, operation, want)
		}
	}
	cbor := map[string]string{"Smithy-Protocol": "rpc-v2-cbor"}
	assume := awsCall(t, "POST", "https://sts.us-east-1.amazonaws.com/service/AWSSecurityTokenServiceV20110615/operation/AssumeRole", "sts", "application/cbor", "\xbf\xff", cbor)
	if blocked, err := CredentialMintingBlocked(assume, mintingAWSConnection(nil)); err != nil || blocked == nil || blocked.Operation != "sts:AssumeRole" {
		t.Fatalf("a minting call named in the path: blocked=%v err=%v", blocked, err)
	}
}

// A query-protocol service acts on a form body whatever the request calls it,
// so the secret guard reads it under any Content-Type.
func TestQueryProtocolBodyIsReadWhateverItsContentType(t *testing.T) {
	guard := mintingAWSConnection(nil)
	const assume = "Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A123%3Arole%2Fx&RoleSessionName=s&Version=2011-06-15"
	for _, contentType := range []string{"application/x-www-form-urlencoded", "application/json", "application/x-amz-json-1.0", "application/cbor", "text/plain", ""} {
		request := awsCall(t, "POST", "https://sts.us-east-1.amazonaws.com/", "sts", contentType, assume, nil)
		if blocked, err := CredentialMintingBlocked(request, guard); err != nil || blocked == nil || blocked.Operation != "sts:AssumeRole" {
			t.Errorf("secret guard, content type %q: blocked=%v err=%v", contentType, blocked, err)
		}
		assertRequestBody(t, request, assume)
	}
	// A body that names no action hides it: the call cannot be judged.
	for name, request := range map[string]*http.Request{
		"a body in another encoding":  awsCall(t, "POST", "https://sts.us-east-1.amazonaws.com/", "sts", "application/x-www-form-urlencoded", "\x1f\x8b\x08\x00opaque", map[string]string{"Content-Encoding": "gzip"}),
		"pairs the form parser drops": awsCall(t, "POST", "https://iam.amazonaws.com/", "iam", "application/x-www-form-urlencoded", "Version=2010-05-08;Action=CreateAccessKey", nil),
	} {
		if blocked, err := CredentialMintingBlocked(request, guard); blocked != nil || !errors.Is(err, ErrMintingInspectionUnavailable) {
			t.Errorf("secret guard on %s: blocked=%v err=%v", name, blocked, err)
		}
	}
}

func TestSecretGuardBlocksFurtherCredentialMintingCalls(t *testing.T) {
	connection := mintingAWSConnection(nil)
	post := func(target, service string) *http.Request {
		return awsCall(t, "POST", target, service, "application/json", "{}", nil)
	}
	for _, test := range []struct {
		request   *http.Request
		operation string
	}{
		{post("https://iot.us-east-1.amazonaws.com/keys-and-certificate?setAsActive=true", "iot"), "iot:CreateKeysAndCertificate"},
		{post("https://iot.us-east-1.amazonaws.com/keys-and-certificate", "execute-api"), "iot:CreateKeysAndCertificate"},
		{post("https://iot-fips.us-east-1.amazonaws.com/keys-and-certificate/", "iot"), "iot:CreateKeysAndCertificate"},
		{post("https://apigateway.us-east-1.amazonaws.com/apikeys", "apigateway"), "apigateway:CreateApiKey"},
		{post("https://env.airflow.us-east-1.amazonaws.com/clitoken/production", "airflow"), "airflow:CreateCliToken"},
		{post("https://env.airflow.us-east-1.amazonaws.com/webtoken/production", "airflow"), "airflow:CreateWebLoginToken"},
		{post("https://grafana.us-east-1.amazonaws.com/workspaces/g-0123456789/apikeys", "grafana"), "grafana:CreateWorkspaceApiKey"},
		{post("https://emr-containers.us-east-1.amazonaws.com/virtualclusters/vc-1/endpoints/ep-1/credentials", "emr-containers"), "emr-containers:GetManagedEndpointSessionCredentials"},
	} {
		blocked, err := CredentialMintingBlocked(test.request, connection)
		if err != nil || blocked == nil || blocked.Operation != test.operation {
			t.Errorf("%s: blocked=%v err=%v", test.operation, blocked, err)
		}
	}
	get := func(target, service string) *http.Request { return awsCall(t, "GET", target, service, "", "", nil) }
	for name, request := range map[string]*http.Request{
		"listing API keys":                       get("https://apigateway.us-east-1.amazonaws.com/apikeys", "apigateway"),
		"an API Gateway resource of another API": post("https://apigateway.us-east-1.amazonaws.com/restapis/a1/resources", "apigateway"),
		"an invoke of an API with the IoT path":  post("https://a1b2c3.execute-api.us-east-1.amazonaws.com/keys-and-certificate", "execute-api"),
		"an S3 object under the IoT path":        post("https://bucket.s3.us-east-1.amazonaws.com/keys-and-certificate", "s3"),
		"listing IoT certificates":               get("https://iot.us-east-1.amazonaws.com/certificates", "iot"),
		"an Airflow environment read":            get("https://airflow.us-east-1.amazonaws.com/environments/production", "airflow"),
		"listing Grafana workspaces":             get("https://grafana.us-east-1.amazonaws.com/workspaces", "grafana"),
		"deleting a Grafana API key":             awsCall(t, "DELETE", "https://grafana.us-east-1.amazonaws.com/workspaces/g-0123456789/apikeys/ci", "grafana", "", "", nil),
		"describing a managed endpoint":          get("https://emr-containers.us-east-1.amazonaws.com/virtualclusters/vc-1/endpoints/ep-1", "emr-containers"),
		"an S3 object under the Grafana path":    post("https://bucket.s3.us-east-1.amazonaws.com/workspaces/g-0123456789/apikeys", "s3"),
	} {
		if blocked, err := CredentialMintingBlocked(request, connection); err != nil || blocked != nil {
			t.Errorf("%s: blocked=%v err=%v", name, blocked, err)
		}
	}
}

func TestLoosePathComparisons(t *testing.T) {
	for _, test := range []struct {
		pattern, path string
		want          bool
	}{
		{"/v1/admin", "/v1/admin", true},
		{"/v1/admin", "/v1/admin/", true},
		{"/v1/admin", "/V1/ADMIN", true},
		{"/v1/admin", "/v1/admin;a=b", true},
		{"/v1/admin", "/v1/admin;a=b/", true},
		{"/v1/admin", "/v1/admin/;a=b", true},
		{"/v1/admin/", "/v1/admin", true},
		{"/v1/admin/*", "/V1/Admin/Users/", true},
		{"/v1/[a-c]dmin", "/v1/Bdmin", true},
		{"/", "/", true},
		{"/v1/admin", "/v1/admin//", false},
		{"/v1/admin", "/v1/admin/users", false},
		{"/v1/admin", "/v1;x/admin", true},
		{"/v1/admin/secret", "/v1/admin;x/secret", true},
		{"/v1/admin/secret", "/v1;a/ADMIN;b/secret;c/", true},
		{"/v1/admin", "/v1/admins", false},
		{"/v1/admin", "/", false},
	} {
		if got := looseGlobMatch(test.pattern, test.path); got != test.want {
			t.Errorf("looseGlobMatch(%q, %q) = %t, want %t", test.pattern, test.path, got, test.want)
		}
	}
	for path, want := range map[string]string{
		"/": "/", "/a": "/a", "/a/": "/a", "/a;x": "/a", "/a;x/": "/a", "/a/;x": "/a", "/;x": "/", "/a;x/b": "/a/b", "/a;x/b;y/": "/a/b", "/a//": "/a/",
	} {
		if got := loosePath(path); got != want {
			t.Errorf("loosePath(%q) = %q, want %q", path, got, want)
		}
	}
	for _, test := range []struct {
		pattern, path string
		want          bool
	}{
		{"/app/installations/*/access_tokens", "/app/installations/1/access_tokens", true},
		{"/app/installations/*/access_tokens", "//APP/installations/./1/access_tokens/;x", true},
		{"/app/installations/*/access_tokens", "/app/installations/1/2/access_tokens", false},
		{"/*", "/", true},
		{"/*", "/bucket/", true},
		{"/*", "/bucket/key", false},
	} {
		if got := loosePathMatch(test.pattern, test.path); got != test.want {
			t.Errorf("loosePathMatch(%q, %q) = %t, want %t", test.pattern, test.path, got, test.want)
		}
	}
}

// An AWS action, a Slack-style RPC and a GraphQL query all travel as a POST,
// so each is a create, whatever it does: a read-only policy refuses them, and
// the body that says what they do is left as it was.
func TestPOSTCallsAreCreatesWhateverTheyDo(t *testing.T) {
	const readOnly = `{"version":1,"default":"block","rules":[{"class":"read","effect":"allow"}]}`
	post := func(target, contentType, body string) *http.Request {
		request, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", contentType)
		return request
	}
	github := withProviderRules(t, agentapi.Connection{ServiceType: "github", Protocol: "http"})
	github.Policy = testPolicy(t, readOnly)
	tests := map[string]struct {
		connection agentapi.Connection
		request    *http.Request
		body       string
	}{
		"an AWS DescribeInstances": {awsPolicyConnection(t, readOnly),
			awsCall(t, "POST", "https://ec2.us-east-1.amazonaws.com/", "ec2", "application/x-www-form-urlencoded", "Action=DescribeInstances&Version=2016-11-15", nil),
			"Action=DescribeInstances&Version=2016-11-15"},
		"an AWS DynamoDB GetItem": {awsPolicyConnection(t, readOnly),
			awsCall(t, "POST", "https://dynamodb.us-east-1.amazonaws.com/", "dynamodb", "application/x-amz-json-1.0", `{"TableName":"orders"}`, map[string]string{"X-Amz-Target": "DynamoDB_20120810.GetItem"}),
			`{"TableName":"orders"}`},
		"a Slack-style RPC": {httpPolicyConnection(t, readOnly),
			post("https://slack.com/api/conversations.list", "application/x-www-form-urlencoded", "limit=10"), "limit=10"},
		"a GitHub GraphQL query": {github,
			post("https://api.github.com/graphql", "application/json", `{"query":"{ viewer { login } }"}`), `{"query":"{ viewer { login } }"}`},
	}
	for name, test := range tests {
		if classes := callClasses(t, test.request, test.connection); !reflect.DeepEqual(classes, []string{"create"}) {
			t.Errorf("%s: classes = %v, want create", name, classes)
		}
		if decision := decide(t, test.request, test.connection); decision.Effect != agentapi.PolicyBlock || decision.Class != "create" || decision.Rule != nil {
			t.Errorf("%s: effect=%s class=%s rule=%v, want the default to block a create", name, decision.Effect, decision.Class, decision.Rule)
		}
		assertRequestBody(t, test.request, test.body)
	}
	// A read stays a read on the same Connections.
	if decision := decide(t, awsCall(t, "GET", "https://bucket.s3.us-east-1.amazonaws.com/key", "s3", "", "", nil), awsPolicyConnection(t, readOnly)); decision.Effect != agentapi.PolicyAllow {
		t.Errorf("an AWS GET: effect=%s", decision.Effect)
	}
	if decision := decide(t, policyRequest(t, "GET", "https://api.github.com/user"), github); decision.Effect != agentapi.PolicyAllow {
		t.Errorf("a GitHub GET: effect=%s", decision.Effect)
	}
}
