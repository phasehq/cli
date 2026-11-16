package proxy

import (
	"encoding/json"
	"errors"
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
	connection := agentapi.Connection{ServiceType: "aws", Protocol: "http", Injection: agentapi.Injection{Action: "aws_sigv4"}}
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

func httpPolicyConnection(t *testing.T, policy, operationClasses string) agentapi.Connection {
	t.Helper()
	connection := agentapi.Connection{ServiceType: agentapi.CustomHTTPServiceType, Protocol: "http"}
	if policy != "" {
		connection.Policy = testPolicy(t, policy)
	}
	if operationClasses != "" {
		if err := json.Unmarshal([]byte(operationClasses), &connection.OperationClasses); err != nil || connection.OperationClasses.Unsupported() {
			t.Fatalf("operation classes: %v", err)
		}
	}
	return connection
}

// A REST service ignores X-Amz-Target and an Action parameter, so a selector
// that names a read must not replace what the method and sub-resource say.
func TestAWSDecoySelectorDoesNotHideARESTCall(t *testing.T) {
	connection := awsPolicyConnection(t, `{"version":1,"default":"block","rules":[{"class":"read","effect":"allow"}]}`)
	const bucket = "https://bucket.s3.us-east-1.amazonaws.com"
	tests := []struct {
		name, method, target, body string
		headers                    map[string]string
		class                      string
	}{
		{"delete an object, target decoy", "DELETE", bucket + "/reports/2026.csv", "", map[string]string{"X-Amz-Target": "x.GetObject"}, "delete"},
		{"delete an object, action decoy", "DELETE", bucket + "/reports/2026.csv?Action=GetObject", "", nil, "delete"},
		{"set a bucket policy, target decoy", "PUT", bucket + "/?policy", `{"Version":"2012-10-17"}`, map[string]string{"X-Amz-Target": "x.GetBucketPolicy"}, "admin"},
		{"set a bucket policy, action decoy", "PUT", bucket + "/?policy&Action=GetBucketPolicy", `{"Version":"2012-10-17"}`, nil, "admin"},
		{"delete objects in bulk, target decoy", "POST", bucket + "/?delete", "<Delete/>", map[string]string{"X-Amz-Target": "x.ListObjects"}, "delete"},
		{"delete objects in bulk, action decoy", "POST", bucket + "/?delete&Action=ListObjects", "<Delete/>", nil, "delete"},
		{"delete a function, target decoy", "DELETE", "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/f", "", map[string]string{"X-Amz-Target": "x.GetFunction"}, "delete"},
	}
	for _, test := range tests {
		service := "s3"
		if strings.Contains(test.target, "lambda") {
			service = "lambda"
		}
		contentType := ""
		if test.body != "" {
			contentType = "application/xml"
		}
		request := awsCall(t, test.method, test.target, service, contentType, test.body, test.headers)
		classes := callClasses(t, request, connection)
		if !reflect.DeepEqual(classes, []string{"read", test.class}) {
			t.Errorf("%s: classes = %v, want read and %s", test.name, classes, test.class)
		}
		if decision := decide(t, request, connection); decision.Effect != agentapi.PolicyBlock || decision.Class != test.class {
			t.Errorf("%s: effect=%s class=%s, want the %s call blocked", test.name, decision.Effect, decision.Class, test.class)
		}
	}
}

// Where the service acts on its selectors they still decide alone, so a read
// on a JSON-target or query-protocol service is not also taken for a POST.
func TestAWSSelectorsDecideAloneOnlyWhereTheServiceActsOnThem(t *testing.T) {
	connection := awsPolicyConnection(t, "")
	tests := []struct {
		name    string
		request *http.Request
		classes []string
	}{
		{"JSON-target read", awsCall(t, "POST", "https://dynamodb.us-east-1.amazonaws.com/", "dynamodb", "application/x-amz-json-1.0", `{}`, map[string]string{"X-Amz-Target": "DynamoDB_20120810.GetItem"}), []string{"read"}},
		{"query-protocol read", awsCall(t, "POST", "https://ec2.us-east-1.amazonaws.com/", "ec2", "application/x-www-form-urlencoded", "Action=DescribeInstances", nil), []string{"read"}},
		{"query protocol on a queue path", awsCall(t, "POST", "https://sqs.us-east-1.amazonaws.com/123456789012/jobs", "sqs", "application/x-www-form-urlencoded", "Action=GetQueueAttributes", nil), []string{"read"}},
		{"a service the table does not know", awsCall(t, "POST", "https://example.us-east-1.amazonaws.com/", "example", "application/x-amz-json-1.1", `{}`, map[string]string{"X-Amz-Target": "Example.GetThing"}), []string{"read", "create"}},
		// SES signs its REST API (v2) and its query API (v1) alike.
		{"the action API of a mixed service", awsCall(t, "POST", "https://email.us-east-1.amazonaws.com/", "ses", "application/x-www-form-urlencoded", "Action=ListIdentities", nil), []string{"read"}},
		{"the REST API of a mixed service", awsCall(t, "DELETE", "https://email.us-east-1.amazonaws.com/v2/email/identities/example.com?Action=ListIdentities", "ses", "", "", nil), []string{"read", "delete"}},
		{"a REST body on a mixed service is not required to name an action", awsCall(t, "POST", "https://email.us-east-1.amazonaws.com/v2/email/outbound-emails", "ses", "application/json", `{"Content":{}}`, nil), []string{"create"}},
	}
	for _, test := range tests {
		if classes := callClasses(t, test.request, connection); !reflect.DeepEqual(classes, test.classes) {
			t.Errorf("%s: classes = %v, want %v", test.name, classes, test.classes)
		}
	}
}

func TestMethodOverrideAddsTheNamedMethodsClass(t *testing.T) {
	policy := `{"version":1,"default":"allow","rules":[{"class":"delete","effect":"block"},{"match":{"methods":["PUT"],"path":"/v1/settings"},"effect":"ask"}]}`
	connection := httpPolicyConnection(t, policy, "")
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
	// An override is also classified by the Connection's operationClasses.
	withOverrides := httpPolicyConnection(t, `{"version":1,"rules":[{"class":"admin","effect":"block"}]}`,
		`[{"match":{"methods":["PUT"],"path":"/v1/members/*"},"class":"admin"}]`)
	members := request("POST", "https://api.example.test/v1/members/7", map[string]string{"X-HTTP-Method-Override": "PUT"})
	if decision := decide(t, members, withOverrides); decision.Effect != agentapi.PolicyBlock || decision.Class != "admin" {
		t.Errorf("an override classified by operationClasses: effect=%s class=%s", decision.Effect, decision.Class)
	}
	// Every HTTP Connection, AWS included.
	aws := awsPolicyConnection(t, `{"version":1,"rules":[{"class":"delete","effect":"block"}]}`)
	object := awsCall(t, "POST", "https://bucket.s3.us-east-1.amazonaws.com/key?uploads", "s3", "", "", map[string]string{"X-HTTP-Method-Override": "DELETE"})
	if decision := decide(t, object, aws); decision.Effect != agentapi.PolicyBlock {
		t.Errorf("AWS call with a method override: effect=%s", decision.Effect)
	}
}

// A temporary allow for the overridden method lifts the ask on that candidate
// and on nothing else.
func TestTemporaryAllowCoversTheOverriddenMethod(t *testing.T) {
	future := policyTestNow.AddDate(0, 0, 1).Format("2006-01-02T15:04:05Z07:00")
	connection := httpPolicyConnection(t, `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"allow-1","match":{"methods":["DELETE"],"path":"/v1/items/1"},"expiresAt":"`+future+`"}]}`, "")
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
	respellings := []string{"/v1/admin", "/v1/admin/", "/V1/Admin", "/v1/admin;jsessionid=1", "/v1/ADMIN;x/", "/v1/admin/;x"}
	for _, effect := range []string{"block", "ask"} {
		connection := httpPolicyConnection(t, `{"version":1,"default":"allow","rules":[{"match":{"path":"/v1/admin"},"effect":"`+effect+`"}]}`, "")
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
	slashed := httpPolicyConnection(t, `{"version":1,"rules":[{"match":{"path":"/v1/admin/"},"effect":"block"}]}`, "")
	if decision := decide(t, policyRequest(t, "GET", "https://api.example.test/v1/admin"), slashed); decision.Effect != agentapi.PolicyBlock {
		t.Errorf("a rule with a trailing slash: effect=%s", decision.Effect)
	}

	allowing := httpPolicyConnection(t, `{"version":1,"default":"block","rules":[{"match":{"path":"/v1/public"},"effect":"allow"}]}`, "")
	if decision := decide(t, policyRequest(t, "GET", "https://api.example.test/v1/public"), allowing); decision.Effect != agentapi.PolicyAllow {
		t.Fatalf("an allow rule on the path as written: effect=%s", decision.Effect)
	}
	for _, spelled := range []string{"/v1/public/", "/V1/PUBLIC", "/v1/public;x"} {
		if decision := decide(t, policyRequest(t, "GET", "https://api.example.test"+spelled), allowing); decision.Effect != agentapi.PolicyBlock {
			t.Errorf("allow rule, %s: effect=%s", spelled, decision.Effect)
		}
	}

	future := policyTestNow.AddDate(0, 0, 1).Format("2006-01-02T15:04:05Z07:00")
	temporary := httpPolicyConnection(t, `{"version":1,"default":"ask","rules":[],"temporaryAllows":[{"id":"allow-1","match":{"methods":["GET"],"path":"/v1/reports"},"expiresAt":"`+future+`"}]}`, "")
	if decision := decide(t, policyRequest(t, "GET", "https://api.example.test/v1/reports"), temporary); decision.Effect != agentapi.PolicyAllow {
		t.Fatalf("a temporary allow on the path as written: effect=%s", decision.Effect)
	}
	for _, spelled := range []string{"/v1/reports/", "/v1/Reports", "/v1/reports;x"} {
		if decision := decide(t, policyRequest(t, "GET", "https://api.example.test"+spelled), temporary); decision.Effect != agentapi.PolicyAsk {
			t.Errorf("temporary allow, %s: effect=%s", spelled, decision.Effect)
		}
	}
}

// A class override that covers the path only when it is respelled may or may
// not apply, so its class is one candidate and the method's another.
func TestClassOverridesAlsoCoverARespelledPath(t *testing.T) {
	overrides := `[{"match":{"methods":["POST"],"path":"/api/graphql"},"class":"update"},{"match":{"methods":["POST"],"path":"/v1/search"},"class":"read"}]`
	connection := httpPolicyConnection(t, `{"version":1,"rules":[{"class":"update","effect":"ask"},{"class":"create","effect":"block"}]}`, overrides)
	if classes := callClasses(t, policyRequest(t, "POST", "https://gitlab.example.test/api/graphql"), connection); !reflect.DeepEqual(classes, []string{"update"}) {
		t.Fatalf("the path as written: classes = %v", classes)
	}
	for _, spelled := range []string{"/api/graphql/", "/API/GraphQL", "/api/graphql;x"} {
		request := policyRequest(t, "POST", "https://gitlab.example.test"+spelled)
		if classes := callClasses(t, request, connection); !reflect.DeepEqual(classes, []string{"update", "create"}) {
			t.Errorf("%s: classes = %v", spelled, classes)
		}
	}
	// An override that makes a call lighter does not do so for a respelling:
	// the method's class is still there and the stricter outcome decides.
	if decision := decide(t, policyRequest(t, "POST", "https://api.example.test/v1/search"), connection); decision.Effect != agentapi.PolicyAllow {
		t.Fatalf("a POST classified as a read: effect=%s", decision.Effect)
	}
	if decision := decide(t, policyRequest(t, "POST", "https://api.example.test/v1/search/"), connection); decision.Effect != agentapi.PolicyBlock {
		t.Fatalf("the same POST respelled: effect=%s", decision.Effect)
	}
}

func TestSecretGuardPathRulesMatchARespelledPath(t *testing.T) {
	github := agentapi.Connection{ServiceType: "github", Protocol: "http"}
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
	connection := httpPolicyConnection(t, policy, "")
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
	// An override may say what the stream is.
	explicit := httpPolicyConnection(t, policy, `[{"match":{"methods":["GET"],"path":"/events"},"class":"read"}]`)
	if classes := callClasses(t, upgrade("https://api.example.test/events"), explicit); !reflect.DeepEqual(classes, []string{"read"}) {
		t.Fatalf("an upgrade an override classifies: classes = %v", classes)
	}
	if classes := callClasses(t, upgrade("https://api.example.test/other"), explicit); !reflect.DeepEqual(classes, []string{"read", "update"}) {
		t.Fatalf("an upgrade no override covers: classes = %v", classes)
	}
	aws := awsPolicyConnection(t, policy)
	stream := awsCall(t, "GET", "https://ssmmessages.us-east-1.amazonaws.com/v1/data-channel/session-1", "ssmmessages", "", "", map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"})
	if decision := decide(t, stream, aws); decision.Effect != agentapi.PolicyAsk {
		t.Fatalf("AWS upgrade: effect=%s", decision.Effect)
	}
}

// Smithy RPC v2 names the operation in the path.
func TestSmithyRPCPathNamesTheAction(t *testing.T) {
	connection := awsPolicyConnection(t, `{"version":1,"rules":[{"operation":"monitoring:DeleteAlarms","effect":"block"},{"class":"create","effect":"ask"}]}`)
	cbor := map[string]string{"Smithy-Protocol": "rpc-v2-cbor"}
	deleteAlarms := awsCall(t, "POST", "https://monitoring.us-east-1.amazonaws.com/service/GraniteServiceVersion20100801/operation/DeleteAlarms", "monitoring", "application/cbor", "\xbf\xff", cbor)
	calls, err := ClassifyCall(deleteAlarms, connection)
	if err != nil || !reflect.DeepEqual(calls, []ClassifiedCall{{Class: "delete", Operation: "monitoring:DeleteAlarms"}}) {
		t.Fatalf("calls = %+v err=%v", calls, err)
	}
	if decision := decide(t, deleteAlarms, connection); decision.Effect != agentapi.PolicyBlock || decision.Operation != "monitoring:DeleteAlarms" {
		t.Fatalf("effect=%s operation=%s", decision.Effect, decision.Operation)
	}
	// A read stays a read: the POST that carries it is not a create.
	list := awsCall(t, "POST", "https://monitoring.us-east-1.amazonaws.com/service/GraniteServiceVersion20100801/operation/ListMetrics", "monitoring", "application/cbor", "\xbf\xff", cbor)
	if decision := decide(t, list, connection); decision.Effect != agentapi.PolicyAllow || decision.Class != "read" {
		t.Fatalf("a read over RPC v2: effect=%s class=%s", decision.Effect, decision.Class)
	}
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
	// The secret guard reads the same selector.
	assume := awsCall(t, "POST", "https://sts.us-east-1.amazonaws.com/service/AWSSecurityTokenServiceV20110615/operation/AssumeRole", "sts", "application/cbor", "\xbf\xff", cbor)
	if blocked, err := CredentialMintingBlocked(assume, mintingAWSConnection(nil)); err != nil || blocked == nil || blocked.Operation != "sts:AssumeRole" {
		t.Fatalf("a minting call named in the path: blocked=%v err=%v", blocked, err)
	}
}

func TestS3FamilySubresourcesGrantsAndSharingAreAdmin(t *testing.T) {
	connection := awsPolicyConnection(t, "")
	for _, service := range []string{"s3", "s3express", "s3-outposts", "s3-object-lambda"} {
		host := "https://bucket." + service + ".us-east-1.amazonaws.com"
		if classes := callClasses(t, awsCall(t, "PUT", host+"/?policy", service, "application/json", "{}", nil), connection); !reflect.DeepEqual(classes, []string{"admin"}) {
			t.Errorf("%s PUT ?policy = %v", service, classes)
		}
		if classes := callClasses(t, awsCall(t, "POST", host+"/?delete", service, "application/xml", "<Delete/>", nil), connection); !reflect.DeepEqual(classes, []string{"delete"}) {
			t.Errorf("%s POST ?delete = %v", service, classes)
		}
		if classes := callClasses(t, awsCall(t, "GET", host+"/?policy", service, "", "", nil), connection); !reflect.DeepEqual(classes, []string{"read"}) {
			t.Errorf("%s GET ?policy = %v", service, classes)
		}
	}
	const bucket = "https://bucket.s3.us-east-1.amazonaws.com"
	for name, request := range map[string]*http.Request{
		"a canned ACL on an upload":      awsCall(t, "PUT", bucket+"/key", "s3", "text/plain", "x", map[string]string{"x-amz-acl": "public-read"}),
		"an explicit grant on an upload": awsCall(t, "PUT", bucket+"/key", "s3", "text/plain", "x", map[string]string{"x-amz-grant-read": `uri="http://acs.amazonaws.com/groups/global/AllUsers"`}),
		"a canned ACL on a new bucket":   awsCall(t, "PUT", bucket+"/", "s3", "", "", map[string]string{"X-Amz-Acl": "public-read-write"}),
		"a canned ACL on a copy":         awsCall(t, "POST", bucket+"/key?uploads", "s3", "", "", map[string]string{"x-amz-acl": "public-read"}),
	} {
		if classes := callClasses(t, request, connection); !reflect.DeepEqual(classes, []string{"admin"}) {
			t.Errorf("%s = %v", name, classes)
		}
	}
	// A read that names an ACL header is still a read, and an upload without
	// one is still an update.
	if classes := callClasses(t, awsCall(t, "GET", bucket+"/key", "s3", "", "", map[string]string{"x-amz-acl": "public-read"}), connection); !reflect.DeepEqual(classes, []string{"read"}) {
		t.Errorf("a GET with an ACL header = %v", classes)
	}
	if classes := callClasses(t, awsCall(t, "PUT", bucket+"/key", "s3", "text/plain", "x", nil), connection); !reflect.DeepEqual(classes, []string{"update"}) {
		t.Errorf("a plain upload = %v", classes)
	}

	for _, operation := range []string{
		"ec2:ModifySnapshotAttribute", "ec2:ModifyImageAttribute", "rds:ModifyDBSnapshotAttribute", "rds:ModifyDBClusterSnapshotAttribute",
		"sns:SetTopicAttributes", "sns:AddPermission", "sqs:SetQueueAttributes", "sqs:AddPermission",
		"lambda:AddPermission", "lambda:CreateFunctionUrlConfig", "lambda:UpdateFunctionUrlConfig",
	} {
		service, action, _ := strings.Cut(operation, ":")
		if class := classifyAWSAction(service, action); class != agentapi.ClassAdmin {
			t.Errorf("%s = %s, want admin", operation, class)
		}
	}
	// Lambda is a REST service: its entries are recognised by method and path.
	const lambda = "https://lambda.us-east-1.amazonaws.com"
	for _, test := range []struct{ method, path, operation string }{
		{"POST", "/2015-03-31/functions/report/policy", "lambda:AddPermission"},
		{"POST", "/2021-10-31/functions/report/url", "lambda:CreateFunctionUrlConfig"},
		{"PUT", "/2021-10-31/functions/arn:aws:lambda:us-east-1:123456789012:function:report/url", "lambda:UpdateFunctionUrlConfig"},
		{"PUT", "/2021-10-31/Functions/report/URL/", "lambda:UpdateFunctionUrlConfig"},
	} {
		calls, err := ClassifyCall(awsCall(t, test.method, lambda+test.path, "lambda", "application/json", "{}", nil), connection)
		if err != nil || !reflect.DeepEqual(calls, []ClassifiedCall{{Class: "admin", Operation: test.operation}}) {
			t.Errorf("%s %s = %+v err=%v", test.method, test.path, calls, err)
		}
	}
	for _, test := range []struct{ method, path, class string }{
		{"GET", "/2021-10-31/functions/report/url", "read"},
		{"GET", "/2015-03-31/functions/report/policy", "read"},
		{"POST", "/2015-03-31/functions/report/invocations", "create"},
		{"PUT", "/2015-03-31/functions/report/code", "update"},
	} {
		if classes := callClasses(t, awsCall(t, test.method, lambda+test.path, "lambda", "", "", nil), connection); !reflect.DeepEqual(classes, []string{test.class}) {
			t.Errorf("%s %s = %v, want %s", test.method, test.path, classes, test.class)
		}
	}
	for _, operation := range awsClasses.RESTOperations {
		if _, exact := awsClasses.Exact[operation.Service+":"+operation.Action]; !exact {
			t.Errorf("REST operation %s:%s has no exact class", operation.Service, operation.Action)
		}
	}
}

func TestS3SelectIsAReadOnlyOnItsOwn(t *testing.T) {
	connection := awsPolicyConnection(t, "")
	const key = "https://bucket.s3.us-east-1.amazonaws.com/key"
	for query, class := range map[string]string{
		"select&select-type=2":             "read",
		"select-type=2&select":             "read",
		"select=&select-type=anything":     "read",
		"select":                           "create",
		"select&select-type=2&restore":     "create",
		"select&select-type=2&uploads":     "create",
		"select&select-type=2&uploadId=u1": "create",
		"select&select-type=2&delete":      "delete",
		"select&select-type=2&acl":         "admin",
		// A query the proxy cannot read in full is never taken for a read.
		"select&select-type=2&x=%zz": "create",
	} {
		request := awsCall(t, "POST", key, "s3", "application/xml", "<x/>", nil)
		request.URL.RawQuery = query
		if classes := callClasses(t, request, connection); !reflect.DeepEqual(classes, []string{class}) {
			t.Errorf("POST ?%s = %v, want %s", query, classes, class)
		}
	}
	other := awsCall(t, "PUT", key, "s3", "application/xml", "<x/>", nil)
	other.URL.RawQuery = "select&select-type=2"
	if classes := callClasses(t, other, connection); !reflect.DeepEqual(classes, []string{"update"}) {
		t.Errorf("PUT ?select = %v", classes)
	}
}

// A query-protocol service acts on a form body whatever the request calls it.
func TestQueryProtocolBodyIsReadWhateverItsContentType(t *testing.T) {
	connection := awsPolicyConnection(t, "")
	const terminate = "Action=TerminateInstances&InstanceId.1=i-1&Version=2016-11-15"
	for _, contentType := range []string{"application/x-www-form-urlencoded", "application/json", "application/x-amz-json-1.1", "application/cbor", "text/plain", ""} {
		request := awsCall(t, "POST", "https://ec2.us-east-1.amazonaws.com/", "ec2", contentType, terminate, nil)
		calls, err := ClassifyCall(request, connection)
		if err != nil || !reflect.DeepEqual(calls, []ClassifiedCall{{Class: "delete", Operation: "ec2:TerminateInstances"}}) {
			t.Errorf("content type %q: calls=%+v err=%v", contentType, calls, err)
		}
		assertRequestBody(t, request, terminate)
	}
	guard := mintingAWSConnection(nil)
	const assume = "Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A123%3Arole%2Fx&RoleSessionName=s&Version=2011-06-15"
	for _, contentType := range []string{"application/json", "application/x-amz-json-1.0", "application/cbor"} {
		request := awsCall(t, "POST", "https://sts.us-east-1.amazonaws.com/", "sts", contentType, assume, nil)
		if blocked, err := CredentialMintingBlocked(request, guard); err != nil || blocked == nil || blocked.Operation != "sts:AssumeRole" {
			t.Errorf("secret guard, content type %q: blocked=%v err=%v", contentType, blocked, err)
		}
		assertRequestBody(t, request, assume)
	}

	// A body that names no action hides it: the call cannot be judged.
	for name, request := range map[string]*http.Request{
		"a body in another encoding":  awsCall(t, "POST", "https://ec2.us-east-1.amazonaws.com/", "ec2", "application/x-www-form-urlencoded", "\x1f\x8b\x08\x00opaque", map[string]string{"Content-Encoding": "gzip"}),
		"a JSON body with no target":  awsCall(t, "POST", "https://sqs.us-east-1.amazonaws.com/", "sqs", "application/x-amz-json-1.0", `{"QueueName":"jobs"}`, nil),
		"pairs the form parser drops": awsCall(t, "POST", "https://ec2.us-east-1.amazonaws.com/", "ec2", "application/x-www-form-urlencoded", "Version=2016-11-15;Action=TerminateInstances", nil),
	} {
		if _, err := ClassifyCall(request, connection); !errors.Is(err, ErrCallUninspectable) {
			t.Errorf("%s: err=%v, want the call to be uninspectable", name, err)
		}
	}
	hidden := awsCall(t, "POST", "https://sts.us-east-1.amazonaws.com/", "sts", "application/x-www-form-urlencoded", "\x1f\x8b\x08\x00opaque", map[string]string{"Content-Encoding": "gzip"})
	if blocked, err := CredentialMintingBlocked(hidden, guard); blocked != nil || !errors.Is(err, ErrMintingInspectionUnavailable) {
		t.Errorf("secret guard on a body that names no action: blocked=%v err=%v", blocked, err)
	}
	// With no body the query string or nothing at all names the call.
	if classes := callClasses(t, awsCall(t, "POST", "https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances", "ec2", "", "", nil), connection); !reflect.DeepEqual(classes, []string{"read"}) {
		t.Errorf("an action in the query string = %v", classes)
	}
	if classes := callClasses(t, awsCall(t, "GET", "https://ec2.us-east-1.amazonaws.com/", "ec2", "", "", nil), connection); !reflect.DeepEqual(classes, []string{"read"}) {
		t.Errorf("a bare GET = %v", classes)
	}

	// A service that also speaks a JSON protocol is sent JSON under that
	// protocol's content type: the body is not a form and is not buffered.
	large := strings.Repeat("m", int(maximumMintingInspectionBytes)+1)
	send := awsCall(t, "POST", "https://sqs.us-east-1.amazonaws.com/", "sqs", "application/x-amz-json-1.0", `{"MessageBody":"`+large+`&Action=DeleteQueue&"}`, map[string]string{"X-Amz-Target": "AmazonSQS.SendMessage"})
	if calls, err := ClassifyCall(send, connection); err != nil || !reflect.DeepEqual(calls, []ClassifiedCall{{Class: "update", Operation: "sqs:SendMessage"}}) {
		t.Errorf("a JSON-protocol call on a dual-protocol service: calls=%+v err=%v", calls, err)
	}
	// Plain application/json is not that protocol's content type.
	mislabelled := awsCall(t, "POST", "https://sqs.us-east-1.amazonaws.com/", "sqs", "application/json", "Action=DeleteQueue&QueueUrl=q", map[string]string{"X-Amz-Target": "AmazonSQS.ListQueues"})
	if classes := callClasses(t, mislabelled, connection); !reflect.DeepEqual(classes, []string{"read", "delete"}) {
		t.Errorf("a form body on a dual-protocol service = %v", classes)
	}
}

func TestAWSActionNamesAreClassifiedInAnyLetterCase(t *testing.T) {
	for operation, want := range map[string]string{
		"ec2:terminateInstances":          "delete",
		"ec2:TERMINATEINSTANCES":          "delete",
		"ec2:runInstances":                "create",
		"s3:putbucketpolicy":              "admin",
		"kms:creategrant":                 "admin",
		"ec2:modifysnapshotattribute":     "admin",
		"autoscaling:PUTSCALINGPOLICY":    "update",
		"ec2:describeInstances":           "update", // an oddly cased name is never a read
		"ec2:DESCRIBEINSTANCES":           "update",
		"dynamodb:getItem":                "update",
		"example:Deleted":                 "update", // a verb spelled as AWS spells it is still a whole word
		"example:Runner":                  "update",
		"example:somethingNeverSeenBefor": "update",
	} {
		service, action, _ := strings.Cut(operation, ":")
		if got := classifyAWSAction(service, action); got != want {
			t.Errorf("%s = %s, want %s", operation, got, want)
		}
	}
	connection := awsPolicyConnection(t, `{"version":1,"rules":[{"class":"delete","effect":"block"}]}`)
	lowered := awsCall(t, "POST", "https://ec2.us-east-1.amazonaws.com/", "ec2", "application/x-www-form-urlencoded", "Action=terminateInstances&InstanceId.1=i-1", nil)
	if decision := decide(t, lowered, connection); decision.Effect != agentapi.PolicyBlock {
		t.Errorf("an action in another letter case: effect=%s", decision.Effect)
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
		{"/v1/admin", "/v1;x/admin", false},
		{"/v1/admin", "/v1/admins", false},
		{"/v1/admin", "/", false},
	} {
		if got := looseGlobMatch(test.pattern, test.path); got != test.want {
			t.Errorf("looseGlobMatch(%q, %q) = %t, want %t", test.pattern, test.path, got, test.want)
		}
	}
	for path, want := range map[string]string{
		"/": "/", "/a": "/a", "/a/": "/a", "/a;x": "/a", "/a;x/": "/a", "/a/;x": "/a", "/;x": "/", "/a;x/b": "/a;x/b", "/a//": "/a/",
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
