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

func testAWSClasses(t testing.TB) *agentapi.ActionClasses {
	return withProviderRules(t, agentapi.Connection{ServiceType: "aws"}).ActionClasses
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

// An AWS Connection that arrives without its secret guard or call classes is
// never served as if it had no guard: it is unavailable, and the guard and
// the classifier refuse its calls if they are ever asked.
func TestAWSConnectionWithoutItsProviderRulesFailsClosed(t *testing.T) {
	ordinary := func() *http.Request {
		return awsCall(t, "GET", "https://bucket.s3.us-east-1.amazonaws.com/key", "s3", "", "", nil)
	}
	assume := func() *http.Request {
		return awsCall(t, "POST", "https://sts.us-east-1.amazonaws.com/", "sts", "application/x-www-form-urlencoded", "Action=AssumeRole", nil)
	}
	complete := withProviderRules(t, agentapi.Connection{ServiceType: "aws", Protocol: "http", Injection: agentapi.Injection{Action: "aws_sigv4"}})
	if failure := complete.AccessPolicyFailure(); failure != "" {
		t.Fatalf("an AWS Connection with its rules is unavailable: %s", failure)
	}

	bare := complete
	bare.SecretGuard, bare.ActionClasses = nil, nil
	guardOnly := complete
	guardOnly.ActionClasses = nil
	classesOnly := complete
	classesOnly.SecretGuard = nil
	signedOnly := classesOnly
	signedOnly.ServiceType = "unlisted-service"
	for name, connection := range map[string]agentapi.Connection{"no rules": bare, "no classes": guardOnly, "no guard": classesOnly, "SigV4 on another service": signedOnly} {
		if failure := connection.AccessPolicyFailure(); failure != agentapi.ProviderRulesMissing {
			t.Errorf("%s: failure = %q", name, failure)
		}
	}
	for name, connection := range map[string]agentapi.Connection{"no rules": bare, "no guard": classesOnly} {
		if blocked, err := CredentialMintingBlocked(ordinary(), connection); blocked != nil || !errors.Is(err, ErrMintingInspectionUnavailable) {
			t.Errorf("%s: guard = %v err=%v", name, blocked, err)
		}
	}
	if blocked, err := CredentialMintingBlocked(assume(), guardOnly); blocked != nil || !errors.Is(err, ErrMintingInspectionUnavailable) {
		t.Errorf("guard without classes on a guarded service: %v err=%v", blocked, err)
	}
	for name, connection := range map[string]agentapi.Connection{"no rules": bare, "no classes": guardOnly} {
		if calls, err := ClassifyCall(ordinary(), connection); !errors.Is(err, ErrCallUninspectable) {
			t.Errorf("%s: classified as %+v", name, calls)
		}
	}
}

// Rules this client cannot read in full make the Connection unusable with the
// "update the Phase CLI" refusal. Call classes matter only where calls are
// classified, except on AWS, whose guard reads them too.
func TestProviderRulesThisClientCannotReadAreNeverEnforcedInPart(t *testing.T) {
	aws := string(providerrulestest.Raw("aws"))
	newerScheme := strings.Replace(aws, `"version": 1`, `"version": 2`, 1)
	otherScheme := strings.Replace(aws, `"scheme": "aws_actions"`, `"scheme": "graphql_operations"`, 1)
	unknownClass := strings.Replace(aws, `"kms:ScheduleKeyDeletion": "delete"`, `"kms:ScheduleKeyDeletion": "destroy"`, 1)
	unknownGuardMember := strings.Replace(aws, `"hostLabel": "iot"`, `"hostLabel": "iot", "hostSuffix": "amazonaws.com"`, 1)
	for name, rules := range map[string]string{"newer version": newerScheme, "other scheme": otherScheme, "unknown class": unknownClass, "unknown guard member": unknownGuardMember} {
		if rules == aws {
			t.Fatalf("%s: the rules were not changed", name)
		}
		connection := decodedConnection(t, `{"serviceType":"aws","protocol":"http","injection":{"action":"aws_sigv4"}}`)
		if err := json.Unmarshal([]byte(rules), &connection); err != nil {
			t.Fatalf("%s: a session would fail to decode: %v", name, err)
		}
		if failure := connection.AccessPolicyFailure(); failure != agentapi.AccessPolicyUnsupported {
			t.Errorf("%s: failure = %q", name, failure)
		}
		request := awsCall(t, "POST", "https://sts.us-east-1.amazonaws.com/", "sts", "application/x-www-form-urlencoded", "Action=AssumeRole", nil)
		if blocked, err := CredentialMintingBlocked(request, connection); blocked == nil && err == nil {
			t.Errorf("%s: the guard let a minting call through", name)
		}
	}

	restricting := `"policy":{"version":1,"default":"allow","rules":[{"class":"delete","effect":"block"}]}`
	classes := `"actionClasses":{"scheme":"graphql_operations","version":1}`
	github := decodedConnection(t, `{"serviceType":"github","protocol":"http",`+classes+`}`)
	if failure := github.AccessPolicyFailure(); failure != "" {
		t.Errorf("unread classes unused without a restricting policy made the Connection unavailable: %q", failure)
	}
	github = decodedConnection(t, `{"serviceType":"github","protocol":"http",`+classes+`,`+restricting+`}`)
	if failure := github.AccessPolicyFailure(); failure != agentapi.AccessPolicyUnsupported {
		t.Errorf("unread classes under a restricting policy: failure = %q", failure)
	}
	guard := decodedConnection(t, `{"serviceType":"github","protocol":"http","secretGuard":{"paths":[{"method":"POST","pattern":"/x","operation":"x","bodyField":"token"}]}}`)
	if failure := guard.AccessPolicyFailure(); failure != agentapi.AccessPolicyUnsupported {
		t.Errorf("unread guard: failure = %q", failure)
	}
	if blocked, err := CredentialMintingBlocked(policyRequest(t, "GET", "https://api.github.com/user"), guard); blocked != nil || !errors.Is(err, ErrMintingInspectionUnavailable) {
		t.Errorf("unread guard: blocked=%v err=%v", blocked, err)
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
	if reserved != "CUSTOM_TOKEN_VAR,DATABASE_URL,GH_ENTERPRISE_TOKEN,GH_TOKEN,GITHUB_ENTERPRISE_TOKEN,GITHUB_TOKEN,PGPASSFILE,PGPASSWORD,PGSERVICE,PGSERVICEFILE,POSTGRESQL_URL,POSTGRES_URL" {
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
	if !containsEnvironmentKey(environment, ReservedEnvironmentKey+"=") {
		t.Fatalf("inherited reserved list survived: %v", environment)
	}
}
