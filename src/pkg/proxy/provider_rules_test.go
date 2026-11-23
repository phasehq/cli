package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/agentapi/providerrulestest"
)

// withProviderRules gives a test Connection the rules its service's manifest
// sends, decoded as a session payload carries them.
func withProviderRules(_ testing.TB, connection agentapi.Connection) agentapi.Connection {
	return providerrulestest.Apply(connection)
}

func testSecretGuard(t testing.TB, serviceType string) *agentapi.SecretGuard {
	return withProviderRules(t, agentapi.Connection{ServiceType: serviceType}).SecretGuard
}

func decodedConnection(t *testing.T, document string) agentapi.Connection {
	t.Helper()
	var connection agentapi.Connection
	if err := json.Unmarshal([]byte(document), &connection); err != nil {
		t.Fatal(err)
	}
	return connection
}

// An AWS Connection that arrives without its secret guard is never served as
// if it had no guard: it is unavailable, and the guard refuses its calls if it
// is ever asked. The guard is all the provider rules it needs.
func TestAWSConnectionWithoutItsSecretGuardFailsClosed(t *testing.T) {
	ordinary := func() *http.Request {
		return awsCall(t, "GET", "https://bucket.s3.us-east-1.amazonaws.com/key", "s3", "", "", nil)
	}
	complete := withProviderRules(t, agentapi.Connection{ServiceType: "aws", Protocol: "http", Injection: agentapi.Injection{Action: "aws_sigv4"}})
	if failure := complete.AccessPolicyFailure(); failure != "" {
		t.Fatalf("an AWS Connection with its guard is unavailable: %s", failure)
	}
	for _, minting := range []struct{ host, service, body, operation string }{
		{"sts.us-east-1.amazonaws.com", "sts", "Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A123%3Arole%2Fx&RoleSessionName=s", "sts:AssumeRole"},
		{"iam.amazonaws.com", "iam", "Action=CreateAccessKey&UserName=bob", "iam:CreateAccessKey"},
	} {
		request := awsCall(t, "POST", "https://"+minting.host+"/", minting.service, "application/x-www-form-urlencoded", minting.body, nil)
		if blocked, err := CredentialMintingBlocked(request, complete); err != nil || blocked == nil || blocked.Operation != minting.operation {
			t.Errorf("%s with the guard alone: blocked=%v err=%v", minting.operation, blocked, err)
		}
	}

	bare := complete
	bare.SecretGuard = nil
	signedOnly := bare
	signedOnly.ServiceType = "unlisted-service"
	for name, connection := range map[string]agentapi.Connection{"no guard": bare, "SigV4 on another service": signedOnly} {
		if failure := connection.AccessPolicyFailure(); failure != agentapi.ProviderRulesMissing {
			t.Errorf("%s: failure = %q", name, failure)
		}
		if blocked, err := CredentialMintingBlocked(ordinary(), connection); blocked != nil || !errors.Is(err, ErrMintingInspectionUnavailable) {
			t.Errorf("%s: guard = %v err=%v", name, blocked, err)
		}
	}
}

// A guard this client cannot read in full makes the Connection unusable with
// the "update the Phase CLI" refusal. Keys it does not know elsewhere on a
// Connection, such as the call classes Consoles used to send, are ignored.
func TestProviderRulesThisClientCannotReadAreNeverEnforcedInPart(t *testing.T) {
	aws := string(providerrulestest.Raw("aws"))
	unknownGuardMember := strings.Replace(aws, `"hostLabel": "iot"`, `"hostLabel": "iot", "hostSuffix": "amazonaws.com"`, 1)
	if unknownGuardMember == aws {
		t.Fatal("the rules were not changed")
	}
	connection := decodedConnection(t, `{"serviceType":"aws","protocol":"http","injection":{"action":"aws_sigv4"}}`)
	if err := json.Unmarshal([]byte(unknownGuardMember), &connection); err != nil {
		t.Fatalf("a session would fail to decode: %v", err)
	}
	if failure := connection.AccessPolicyFailure(); failure != agentapi.AccessPolicyUnsupported {
		t.Errorf("unknown guard member: failure = %q", failure)
	}
	request := awsCall(t, "POST", "https://sts.us-east-1.amazonaws.com/", "sts", "application/x-www-form-urlencoded", "Action=AssumeRole", nil)
	if blocked, err := CredentialMintingBlocked(request, connection); blocked == nil && err == nil {
		t.Error("unknown guard member: the guard let a minting call through")
	}
	guard := decodedConnection(t, `{"serviceType":"github","protocol":"http","secretGuard":{"paths":[{"method":"POST","pattern":"/x","operation":"x","bodyField":"token"}]}}`)
	if failure := guard.AccessPolicyFailure(); failure != agentapi.AccessPolicyUnsupported {
		t.Errorf("unread guard: failure = %q", failure)
	}
	if blocked, err := CredentialMintingBlocked(policyRequest(t, "GET", "https://api.github.com/user"), guard); blocked != nil || !errors.Is(err, ErrMintingInspectionUnavailable) {
		t.Errorf("unread guard: blocked=%v err=%v", blocked, err)
	}

	restricting := `"policy":{"version":1,"default":"allow","rules":[{"class":"delete","effect":"block"}]}`
	elsewhere := `"actionClasses":{"scheme":"graphql_operations","version":9},"operationClasses":[{"match":{"methods":["POST"]},"class":"read"}],"riskScore":{"nested":[1,2]}`
	for _, document := range []string{
		`{"serviceType":"github","protocol":"http",` + elsewhere + `,` + restricting + `}`,
		`{"serviceType":"aws","protocol":"http","injection":{"action":"aws_sigv4"},` + elsewhere + `,` + restricting + `}`,
	} {
		connection := decodedConnection(t, document)
		connection = withProviderRules(t, connection)
		if failure := connection.AccessPolicyFailure(); failure != "" {
			t.Errorf("unknown keys beside the rules made the Connection unavailable: %q", failure)
		}
		calls, err := ClassifyCall(policyRequest(t, "POST", "https://api.example.test/graphql"), connection)
		if err != nil || len(calls) != 1 || calls[0].Class != agentapi.ClassCreate {
			t.Errorf("%s: a POST = %+v err=%v, want a create by its method", connection.ServiceType, calls, err)
		}
	}
}

// A guard that is read in full but cannot work makes the Connection unusable
// too, judged by its shape alone: an empty guard, an AWS guard without
// operations, or a list with an empty entry.
func TestProviderRulesThatCannotWorkFailClosed(t *testing.T) {
	mutated := func(change func(rules map[string]any)) string {
		var rules map[string]any
		if err := json.Unmarshal(providerrulestest.Raw("aws"), &rules); err != nil {
			t.Fatal(err)
		}
		change(rules)
		encoded, err := json.Marshal(rules)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	guard := func(rules map[string]any) map[string]any { return rules["secretGuard"].(map[string]any) }
	cases := map[string]string{
		"empty guard":              mutated(func(r map[string]any) { r["secretGuard"] = map[string]any{} }),
		"guard without operations": mutated(func(r map[string]any) { delete(guard(r), "operations") }),
	}
	requests := map[string]func() *http.Request{
		"form AssumeRole": func() *http.Request {
			return awsCall(t, "POST", "https://sts.us-east-1.amazonaws.com/", "sts", "application/x-www-form-urlencoded", "Action=AssumeRole", nil)
		},
		"form AssumeRole as JSON": func() *http.Request {
			return awsCall(t, "POST", "https://sts.us-east-1.amazonaws.com/", "sts", "application/x-amz-json-1.1", "Action=AssumeRole&Version=2011-06-15", nil)
		},
	}
	for name, rules := range cases {
		connection := decodedConnection(t, `{"serviceType":"aws","protocol":"http","injection":{"action":"aws_sigv4"}}`)
		if err := json.Unmarshal([]byte(rules), &connection); err != nil {
			t.Fatalf("%s: a session would fail to decode: %v", name, err)
		}
		if failure := connection.AccessPolicyFailure(); failure != agentapi.AccessPolicyUnsupported {
			t.Errorf("%s: failure = %q", name, failure)
		}
		for requestName, request := range requests {
			if blocked, err := CredentialMintingBlocked(request(), connection); blocked == nil && err == nil {
				t.Errorf("%s: the guard let %s through", name, requestName)
			}
		}
	}
	// The complete guard stops both as well: STS takes a form body whatever
	// Content-Type the request claims.
	complete := withProviderRules(t, agentapi.Connection{ServiceType: "aws", Protocol: "http", Injection: agentapi.Injection{Action: "aws_sigv4"}})
	for requestName, request := range requests {
		if blocked, err := CredentialMintingBlocked(request(), complete); err != nil || blocked == nil || blocked.Operation != "sts:AssumeRole" {
			t.Errorf("complete guard, %s: blocked=%v err=%v", requestName, blocked, err)
		}
	}
	empty := decodedConnection(t, `{"serviceType":"github","protocol":"http","secretGuard":{}}`)
	if failure := empty.AccessPolicyFailure(); failure != agentapi.AccessPolicyUnsupported {
		t.Errorf("empty guard on another service: failure = %q", failure)
	}
	if blocked, err := CredentialMintingBlocked(policyRequest(t, "POST", "https://api.github.com/x"), empty); blocked != nil || !errors.Is(err, ErrMintingInspectionUnavailable) {
		t.Errorf("empty guard on another service: blocked=%v err=%v", blocked, err)
	}
	emptyService := decodedConnection(t, `{"serviceType":"github","protocol":"http","secretGuard":{"paths":[{"method":"POST","pattern":"/x","operation":"x","services":[""]}]}}`)
	if failure := emptyService.AccessPolicyFailure(); failure != agentapi.AccessPolicyUnsupported {
		t.Errorf("empty service in a guard path: failure = %q", failure)
	}
}

// The credential variables come from the session's Connections: configEnv
// may not supply them, phase run reserves them through PHASE_AI_RESERVED_ENV,
// and that variable is itself Phase's.
func TestCredentialEnvironmentComesFromTheSessionsConnections(t *testing.T) {
	options := EnvironmentOptions{
		ProxyURL: "http://phase:capability@127.0.0.1:9543", CABundlePath: "/bundle.pem",
		CredentialEnvironment: append(providerrulestest.CredentialEnvironment("github", "postgres"), "GH_TOKEN", "custom_token_var"),
	}
	plan, err := CompileProcessEnvironment(options)
	if err != nil {
		t.Fatal(err)
	}
	reserved := plan.Set[ReservedEnvironmentKey]
	// The providers' names, and every name the session itself sets or unsets.
	if reserved != "CUSTOM_TOKEN_VAR,DATABASE_URL,GH_ENTERPRISE_TOKEN,GH_TOKEN,GITHUB_ENTERPRISE_TOKEN,GITHUB_TOKEN,HTTPS_PROXY,HTTP_PROXY,NODE_EXTRA_CA_CERTS,NO_PROXY,"+
		"PGPASSFILE,PGPASSWORD,PGSERVICE,PGSERVICEFILE,PHASE_AGENT_TOKEN,PHASE_AI_CA_BUNDLE,PHASE_AI_ENABLED,PHASE_AI_RESERVED_ENV,PHASE_SERVICE_TOKEN,POSTGRESQL_URL,POSTGRES_URL" {
		t.Fatalf("%s = %q", ReservedEnvironmentKey, reserved)
	}
	names := SplitReservedEnvironment(reserved)
	for _, name := range []string{"GITHUB_TOKEN", "gh_token", "PGPASSWORD", "PHASE_AI_RESERVED_ENV", "HTTPS_PROXY", "PHASE_SERVICE_TOKEN", "PHASE_AGENT_TOKEN"} {
		if !ReservedRunEnvironmentKey(name, names) {
			t.Errorf("%s is not reserved", name)
		}
	}
	if ReservedRunEnvironmentKey("AWS_SECRET_ACCESS_KEY", names) || ReservedRunEnvironmentKey("APP_SETTING", names) {
		t.Error("a name no Connection in the session uses is reserved")
	}

	for _, name := range []string{"GITHUB_TOKEN", "pgpassword"} {
		withConfig := options
		withConfig.ConfigEnv = map[string]string{name: "x"}
		if _, err := CompileProcessEnvironment(withConfig); err == nil || !strings.Contains(err.Error(), "credential environment key") {
			t.Errorf("configEnv supplied %s: %v", name, err)
		}
	}
	withConfig := options
	withConfig.ConfigEnv = map[string]string{ReservedEnvironmentKey: "NOTHING"}
	if _, err := CompileProcessEnvironment(withConfig); err == nil || !strings.Contains(err.Error(), "protected") {
		t.Errorf("configEnv replaced %s: %v", ReservedEnvironmentKey, err)
	}

	// An outer session's list never survives into a session without one.
	options.CredentialEnvironment = nil
	plan, err = CompileProcessEnvironment(options)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := ApplyProcessEnvironment([]string{ReservedEnvironmentKey + "=GITHUB_TOKEN"}, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !containsEnvironmentKey(environment, ReservedEnvironmentKey+"="+plan.Set[ReservedEnvironmentKey]) ||
		strings.Contains(plan.Set[ReservedEnvironmentKey], "GITHUB_TOKEN") {
		t.Fatalf("inherited reserved list survived: %v", environment)
	}
}
