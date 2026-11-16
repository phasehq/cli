package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
)

// An operation rule or allow matches an AWS call whose classified action is
// that action, whatever its case, and nothing else.
func TestOperationRulesAndAllowsMatchTheNamedAWSAction(t *testing.T) {
	future := policyTestNow.Add(time.Hour).Format(time.RFC3339)
	request := policyRequest(t, http.MethodPost, "https://ec2.eu-central-1.amazonaws.com/")
	terminate := []ClassifiedCall{{Class: agentapi.ClassDelete, Operation: "ec2:TerminateInstances"}}
	tests := []struct {
		name      string
		policy    string
		calls     []ClassifiedCall
		effect    string
		ruleIndex int
		allowedBy string
	}{
		{name: "block by action", policy: `{"version":1,"rules":[{"operation":"ec2:TerminateInstances","effect":"block"}]}`, calls: terminate, effect: "block", ruleIndex: 0},
		{name: "compared without regard to case", policy: `{"version":1,"rules":[{"operation":"ec2:terminateinstances","effect":"block"}]}`, calls: terminate, effect: "block", ruleIndex: 0},
		{name: "another action does not match", policy: `{"version":1,"rules":[{"operation":"ec2:StopInstances","effect":"block"}]}`, calls: terminate, effect: "allow", ruleIndex: -1},
		{name: "another service does not match", policy: `{"version":1,"rules":[{"operation":"rds:TerminateInstances","effect":"block"}]}`, calls: terminate, effect: "allow", ruleIndex: -1},
		{name: "a call with no named action never matches", policy: `{"version":1,"rules":[{"operation":"ec2:TerminateInstances","effect":"block"}]}`, calls: []ClassifiedCall{{Class: agentapi.ClassDelete}}, effect: "allow", ruleIndex: -1},
		{name: "ask by action beside a class rule", policy: `{"version":1,"rules":[{"class":"delete","effect":"allow"},{"operation":"ec2:TerminateInstances","effect":"ask"}]}`, calls: terminate, effect: "ask", ruleIndex: 1},
		{name: "block beats an operation allow", policy: `{"version":1,"rules":[{"operation":"ec2:TerminateInstances","effect":"allow"},{"class":"delete","effect":"block"}]}`, calls: terminate, effect: "block", ruleIndex: 1},
		{name: "operation allow under default block", policy: `{"version":1,"default":"block","rules":[{"operation":"ec2:DescribeInstances","effect":"allow"}]}`, calls: []ClassifiedCall{{Class: agentapi.ClassRead, Operation: "ec2:DescribeInstances"}}, effect: "allow", ruleIndex: 0},
		{name: "temporary allow by action turns an ask into an allow", policy: `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"a1","operation":"ec2:TerminateInstances","expiresAt":"` + future + `"}]}`, calls: terminate, effect: "allow", ruleIndex: 0, allowedBy: "a1"},
		{name: "temporary allow by action is case-insensitive", policy: `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"a1","operation":"ec2:TERMINATEINSTANCES","expiresAt":"` + future + `"}]}`, calls: terminate, effect: "allow", ruleIndex: 0, allowedBy: "a1"},
		{name: "temporary allow for another action does not apply", policy: `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"a1","operation":"ec2:DeleteVolume","expiresAt":"` + future + `"}]}`, calls: terminate, effect: "ask", ruleIndex: 0},
		{name: "temporary allow never changes a block", policy: `{"version":1,"rules":[{"operation":"ec2:TerminateInstances","effect":"block"}],"temporaryAllows":[{"id":"a1","operation":"ec2:TerminateInstances","expiresAt":"` + future + `"}]}`, calls: terminate, effect: "block", ruleIndex: 0},
		{name: "an action allow does not cover a named other action in the same request", policy: `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[{"id":"a1","operation":"ec2:DescribeInstances","expiresAt":"` + future + `"}]}`, calls: []ClassifiedCall{{Class: agentapi.ClassRead, Operation: "ec2:DescribeInstances"}, {Class: agentapi.ClassDelete, Operation: "ec2:TerminateInstances"}}, effect: "ask", ruleIndex: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := EvaluateAccessPolicy(testPolicy(t, test.policy), test.calls, request, policyTestNow)
			if decision.Effect != test.effect || decision.RuleIndex != test.ruleIndex || decision.TemporaryAllowID != test.allowedBy {
				t.Fatalf("decision = %+v, want %s by rule %d (allow %q)", decision, test.effect, test.ruleIndex, test.allowedBy)
			}
		})
	}
}

// An operation never matches a call on another service: those calls carry no
// action, whatever their class.
func TestOperationNeverMatchesANonAWSCall(t *testing.T) {
	policy := testPolicy(t, `{"version":1,"rules":[{"operation":"ec2:TerminateInstances","effect":"block"}]}`)
	connection := agentapi.Connection{ServiceType: "github", Protocol: "http", Policy: policy}
	calls, err := ClassifyCall(policyRequest(t, http.MethodDelete, "https://api.github.com/repos/acme/x"), connection)
	if err != nil || len(calls) != 1 || calls[0].Operation != "" {
		t.Fatalf("calls = %+v err=%v", calls, err)
	}
	if decision := EvaluateAccessPolicy(policy, calls, policyRequest(t, http.MethodDelete, "https://api.github.com/repos/acme/x"), policyTestNow); decision.Effect != agentapi.PolicyAllow {
		t.Fatalf("decision = %+v", decision)
	}
}

// operationClasses apply to every HTTP Connection that carries them, packaged
// or custom, ahead of the method; AWS ignores them.
func TestOperationClassesApplyToAnyHTTPConnectionButNotAWS(t *testing.T) {
	var classes agentapi.OperationClasses
	if err := json.Unmarshal([]byte(`[{"match":{"methods":["POST"],"path":"/graphql"},"class":"update"}]`), &classes); err != nil || classes.Unsupported() {
		t.Fatalf("classes = %+v err=%v", classes, err)
	}
	for _, serviceType := range []string{"github", "gitlab", "railway", "cloudflare", "http", "unlisted-service"} {
		connection := agentapi.Connection{ServiceType: serviceType, Protocol: "http", OperationClasses: classes}
		overridden, err := ClassifyCall(policyRequest(t, http.MethodPost, "https://api.example.test/graphql"), connection)
		if err != nil || len(overridden) != 1 || overridden[0].Class != agentapi.ClassUpdate {
			t.Errorf("%s: GraphQL POST = %+v err=%v, want update", serviceType, overridden, err)
		}
		byMethod, err := ClassifyCall(policyRequest(t, http.MethodPost, "https://api.example.test/repos"), connection)
		if err != nil || len(byMethod) != 1 || byMethod[0].Class != agentapi.ClassCreate {
			t.Errorf("%s: other POST = %+v err=%v, want create by method", serviceType, byMethod, err)
		}
	}
	aws := agentapi.Connection{ServiceType: "aws", Protocol: "http", OperationClasses: classes, Injection: agentapi.Injection{Action: "aws_sigv4"}}
	calls, err := ClassifyCall(policyRequest(t, http.MethodPost, "https://api.example.test/graphql"), aws)
	if err != nil || len(calls) != 1 || calls[0].Class != agentapi.ClassCreate {
		t.Fatalf("an AWS Connection used operationClasses: %+v err=%v", calls, err)
	}
}

// packagedConnection is a packaged HTTP service as the Console compiles it
// for the services that attach when absent: one header injection, an
// integration credential in the resolved material, a decoy.
func packagedConnection(t *testing.T, serviceType, headerName, valueFormat, operationClasses, policy string) agentapi.Connection {
	t.Helper()
	document := map[string]any{
		"serviceType": serviceType, "protocol": "http", "credentialProvider": serviceType,
		"injection": map[string]any{
			"action": "set_header", "name": headerName, "valueFormat": valueFormat, "whenAbsent": "attach",
			"valueFrom": map[string]any{"source": "credential", "field": "token"},
		},
		"identifiers":    map[string]string{},
		"decoyMaterial":  map[string]string{"token": "ghp_decoy0123456789abcdef"},
		"agentEnv":       map[string]string{"GITHUB_TOKEN": "ghp_decoy0123456789abcdef"},
		"secretMaterial": map[string]string{"token": "ghp_live-proxy-only-value"},
	}
	if operationClasses != "" {
		document["operationClasses"] = json.RawMessage(operationClasses)
	}
	if policy != "" {
		document["policy"] = json.RawMessage(policy)
	}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var connection agentapi.Connection
	if err := json.Unmarshal(payload, &connection); err != nil {
		t.Fatal(err)
	}
	return connection
}

// A packaged service with a single injection that attaches when absent needs
// no service-specific code: swap, attach, block, HTTPS only, policy, guard.
func TestPackagedHTTPServiceWorksEndToEndInTheProxy(t *testing.T) {
	const decoy, live = "ghp_decoy0123456789abcdef", "ghp_live-proxy-only-value"
	services := map[string]struct{ header, format, wantValue string }{
		"github": {"Authorization", "Bearer {value}", "Bearer " + live},
		"gitlab": {"PRIVATE-TOKEN", "{value}", live},
	}
	for serviceType, service := range services {
		t.Run(serviceType, func(t *testing.T) {
			connection := packagedConnection(t, serviceType, service.header, service.format, "", "")
			header := func(value string) http.Header {
				if value == "" {
					return http.Header{}
				}
				headers := http.Header{}
				headers.Set(service.header, strings.ReplaceAll(service.format, "{value}", value))
				return headers
			}
			newRequest := func(target string, headers http.Header) *http.Request {
				request := policyRequest(t, http.MethodGet, target)
				request.Header = headers
				return request
			}

			// The decoy is swapped.
			swapped := newRequest("https://api.example.test/user", header(decoy))
			if _, err := ApplyHTTPInjection(context.Background(), swapped, connection); err != nil || swapped.Header.Get(service.header) != service.wantValue {
				t.Fatalf("swap: err=%v header=%q", err, swapped.Header.Get(service.header))
			}
			// A request with no credential gets the live one attached.
			attached := newRequest("https://api.example.test/user", header(""))
			if _, err := ApplyHTTPInjection(context.Background(), attached, connection); err != nil || attached.Header.Get(service.header) != service.wantValue {
				t.Fatalf("attach: err=%v header=%q", err, attached.Header.Get(service.header))
			}
			// Another value is a swap miss and is left alone.
			other := newRequest("https://api.example.test/user", header("someone-elses-token"))
			if _, err := ApplyHTTPInjection(context.Background(), other, connection); injectionCode(err) != InjectionSwapMiss ||
				strings.Contains(other.Header.Get(service.header), live) {
				t.Fatalf("another value: err=%v header=%q", err, other.Header.Get(service.header))
			}
			// Never over plain HTTP, swap or attach, unless allowPlainHttp.
			for name, headers := range map[string]http.Header{"swap": header(decoy), "attach": header("")} {
				plain := newRequest("http://api.example.test/user", headers)
				before := plain.Header.Get(service.header)
				if _, err := ApplyHTTPInjection(context.Background(), plain, connection); injectionCode(err) != InjectionPlainHTTP || plain.Header.Get(service.header) != before {
					t.Fatalf("plain HTTP %s: err=%v header=%q", name, err, plain.Header.Get(service.header))
				}
			}
			connection.AllowPlainHTTP = true
			allowed := newRequest("http://api.example.test/user", header(""))
			if _, err := ApplyHTTPInjection(context.Background(), allowed, connection); err != nil || allowed.Header.Get(service.header) != service.wantValue {
				t.Fatalf("allowPlainHttp: err=%v", err)
			}
		})
	}
}

// Policy for a packaged service: its operationClasses first, then the method,
// and the secret guard ahead of both.
func TestPackagedHTTPServicePolicyUsesOperationClassesThenMethodAndTheGuard(t *testing.T) {
	policy := `{"version":1,"default":"allow","rules":[{"class":"update","effect":"ask"},{"class":"delete","effect":"block"}],"temporaryAllows":[]}`
	classes := `[{"match":{"methods":["POST"],"path":"/graphql"},"class":"update"}]`
	connection := packagedConnection(t, "github", "Authorization", "Bearer {value}", classes, policy)
	if !PolicyApplies(connection) || connection.AccessPolicyFailure() != "" {
		t.Fatalf("policy applies=%t failure=%q", PolicyApplies(connection), connection.AccessPolicyFailure())
	}
	decide := func(method, target string) PolicyDecision {
		request := policyRequest(t, method, target)
		calls, err := ClassifyCall(request, connection)
		if err != nil {
			t.Fatal(err)
		}
		return EvaluateAccessPolicy(connection.Policy, calls, request, policyTestNow)
	}
	if d := decide(http.MethodPost, "https://api.github.com/graphql"); d.Effect != agentapi.PolicyAsk || d.Class != agentapi.ClassUpdate {
		t.Fatalf("GraphQL POST = %+v, want an ask as update", d)
	}
	if d := decide(http.MethodGet, "https://api.github.com/user"); d.Effect != agentapi.PolicyAllow || d.Class != agentapi.ClassRead {
		t.Fatalf("GET = %+v", d)
	}
	if d := decide(http.MethodDelete, "https://api.github.com/repos/acme/x"); d.Effect != agentapi.PolicyBlock || d.Class != agentapi.ClassDelete {
		t.Fatalf("DELETE = %+v", d)
	}

	// The secret guard still stops the call and is decided before the policy.
	mint := policyRequest(t, http.MethodPost, "https://api.github.com/app/installations/42/access_tokens")
	blocked, err := CredentialMintingBlocked(mint, connection)
	if err != nil || blocked == nil {
		t.Fatalf("guard = %+v err=%v", blocked, err)
	}
}
