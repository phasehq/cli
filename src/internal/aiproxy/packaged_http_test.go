package aiproxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
)

const (
	packagedDecoy = "ghp_phasedecoy0123456789abcdefghijkl"
	packagedLive  = "ghp_liveproxyonlyvalue0123456789abcd"
)

// packagedHTTPPayload is a packaged HTTP service that attaches when absent,
// as the Console compiles it: one header injection, an integration credential
// in the resolved material, a decoy and environment bindings. It is not a
// custom Connection and has no definition.
func packagedHTTPPayload(policy map[string]any, classes []any) map[string]any {
	connection := customConnectionPayload(packagedDecoy, packagedLive)
	connection["grantId"], connection["connectionId"], connection["connectionName"] = "grant-github", "connection-github", "GitHub"
	connection["credentialId"], connection["credentialName"], connection["credentialProvider"], connection["serviceType"] = "credential-github", "GitHub token", "github", "github"
	connection["hosts"] = []any{map[string]any{"match": "exact", "value": "api.github.com", "port": 443}}
	delete(connection, "connectionConfig")
	delete(connection, "injections")
	connection["injection"] = bearerAttachInjection()
	connection["identifiers"] = map[string]string{}
	connection["agentEnv"] = map[string]string{"GITHUB_TOKEN": packagedDecoy, "GH_TOKEN": packagedDecoy}
	connection["environmentBindings"] = []any{
		map[string]any{"name": "GITHUB_TOKEN", "action": "set", "source": "decoy", "sourceField": "token", "sensitive": true, "systemManaged": false},
		map[string]any{"name": "GH_TOKEN", "action": "set", "source": "decoy", "sourceField": "token", "sensitive": true, "systemManaged": false},
	}
	if policy != nil {
		connection["policy"] = policy
	}
	if classes != nil {
		connection["operationClasses"] = classes
	}
	return connection
}

var githubGraphQLUpdate = []any{map[string]any{"match": map[string]any{"methods": []string{"POST"}, "path": "/graphql"}, "class": "update"}}

func githubRequest(t *testing.T, method, path, authorization string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, "https://api.github.com"+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	return request
}

// A packaged service needs no service-specific code in the proxy: the decoy
// is swapped, an absent value is attached, anything else is refused, and the
// access policy and the secret guard apply.
func TestPackagedHTTPServiceThroughTheProxy(t *testing.T) {
	policy := policyDocument("allow", []any{classRule("update", "ask"), classRule("delete", "block")})
	_, proxy, upstream := policyProxy(t, packagedHTTPPayload(policy, githubGraphQLUpdate))

	// Swap and attach, with the live value and never the decoy upstream.
	for name, authorization := range map[string]string{"swap": "Bearer " + packagedDecoy, "attach": ""} {
		before := upstream.calls.Load()
		if result := processThrough(proxy, githubRequest(t, http.MethodGet, "/user", authorization)); result.failure != nil ||
			upstream.calls.Load() != before+1 || upstream.last.Load().Header.Get("Authorization") != "Bearer "+packagedLive {
			t.Fatalf("%s: %+v", name, result.failure)
		}
	}
	// Another value is refused and nothing is sent.
	before := upstream.calls.Load()
	if result := processThrough(proxy, githubRequest(t, http.MethodGet, "/user", "Bearer someone-elses-token")); result.failure == nil || upstream.calls.Load() != before {
		t.Fatal("a foreign credential was forwarded")
	}
	// Never in the clear.
	plain, _ := http.NewRequest(http.MethodGet, "http://api.github.com:443/user", nil)
	if result := processThrough(proxy, plain); result.failure == nil || upstream.calls.Load() != before {
		t.Fatalf("a plain HTTP request carried the credential: %+v", result.failure)
	}

	// The single GraphQL endpoint is an update by operationClasses, not a
	// create by its method.
	asked := processThrough(proxy, githubRequest(t, http.MethodPost, "/graphql", "Bearer "+packagedDecoy))
	if asked.failure == nil || asked.failure.code != "agent_access_policy_ask" || asked.failure.details["class"] != "update" || upstream.calls.Load() != before {
		t.Fatalf("GraphQL POST = %+v", asked.failure)
	}
	if rule, _ := asked.event.Detail["rule"].(agentapi.PolicyRule); rule.Class != "update" || asked.event.ProxyDecision != "ask" {
		t.Fatalf("event = %+v", asked.event)
	}
	// Another POST is a create by method and the policy allows it.
	if result := processThrough(proxy, githubRequest(t, http.MethodPost, "/repos/acme/x/issues", "Bearer "+packagedDecoy)); result.failure != nil {
		t.Fatalf("a create was refused: %+v", result.failure)
	}
	// A delete is blocked.
	blocked := processThrough(proxy, githubRequest(t, http.MethodDelete, "/repos/acme/x", "Bearer "+packagedDecoy))
	if blocked.failure == nil || blocked.failure.code != "agent_access_policy_blocked" || blocked.failure.details["class"] != "delete" {
		t.Fatalf("DELETE = %+v", blocked.failure)
	}
	// The secret guard stops a minting call whatever the policy says.
	mint := processThrough(proxy, githubRequest(t, http.MethodPost, "/app/installations/42/access_tokens", "Bearer "+packagedDecoy))
	if mint.failure == nil || mint.failure.details["rule"] != "secret_guard" {
		t.Fatalf("a minting call = %+v", mint.failure)
	}
	// An event never carries either value.
	for _, result := range []processedResponse{asked, blocked, mint} {
		encoded, _ := json.Marshal(result.event)
		if strings.Contains(string(encoded), packagedLive) || strings.Contains(string(encoded), packagedDecoy) {
			t.Fatalf("an event carries a credential: %s", encoded)
		}
	}
}

// A packaged service's operationClasses change applies to the running
// session, and discover relays them without reading them as drift.
func TestPackagedHTTPServiceOperationClassesApplyInPlace(t *testing.T) {
	first := packagedHTTPPayload(policyDocument("allow", []any{classRule("update", "ask")}), nil)
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-packaged", 1, first), "runtime-packaged")
	defer state.destroy()
	state.decoys = newDecoyHistory()
	environmentChecks := 0
	state.setEnvironmentCheck(func(*agentapi.SessionConfig) bool { environmentChecks++; return false })

	next := packagedHTTPPayload(policyDocument("allow", []any{classRule("update", "ask")}), githubGraphQLUpdate)
	fresh := decodeTestSession(t, customSessionPayload("", 2, next))
	if change := classifyConfigChange(state.bindings, mustParseBindings(t, fresh.Connections), state.configEnv, fresh.ConfigEnv); change.reprovision || change.reshaped || len(change.removed) != 0 {
		t.Fatalf("the change was classified as %+v", change)
	}
	if err := state.replaceConfig(&fresh.SessionConfig); err != nil || state.availability() != nil || environmentChecks != 0 {
		t.Fatalf("not applied in place: err=%v availability=%v checks=%d", err, state.availability(), environmentChecks)
	}
	if entries := state.bindings[0].connection.OperationClasses.Entries; len(entries) != 1 || entries[0].Class != "update" {
		t.Fatalf("operation classes = %+v", entries)
	}
	proxy := &httpProxy{state: state, transport: &recordingUpstream{}, control: &controlHandler{state: state}}
	if result := processThrough(proxy, githubRequest(t, http.MethodPost, "/graphql", "Bearer "+packagedDecoy)); result.failure == nil || result.failure.code != "agent_access_policy_ask" {
		t.Fatalf("the new classes were not enforced: %+v", result.failure)
	}

	discoverPayload, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "sessionUid": "session-custom", "configGeneration": 2, "configEnv": map[string]string{},
		"connections": []any{discoverEntry(next, map[string]any{"operationClasses": []any{map[string]any{"match": map[string]any{"methods": []string{"GET"}}, "class": "admin"}}})},
	})
	var discover agentapi.DiscoverResponse
	if err := json.Unmarshal(discoverPayload, &discover); err != nil {
		t.Fatal(err)
	}
	if err := state.applyTrustedDiscoverAuthorization(&discover); err != nil {
		t.Fatalf("discover read operationClasses as drift: %v", err)
	}
	if !strings.Contains(string(mustJSON(t, discover)), `"operationClasses":[{"class":"admin","match":{"methods":["GET"]}}]`) {
		t.Fatal("discover no longer relays operationClasses")
	}
}

// An operation rule on a Connection that is not the aws service cannot be
// enforced, so that Connection is unavailable.
func TestOperationRuleOnANonAWSConnectionMakesItUnavailable(t *testing.T) {
	rule := map[string]any{"operation": "ec2:TerminateInstances", "effect": "block"}
	state, proxy, upstream := policyProxy(t, packagedHTTPPayload(policyDocument("allow", []any{rule}), nil))
	result := processThrough(proxy, githubRequest(t, http.MethodGet, "/user", "Bearer "+packagedDecoy))
	if result.failure == nil || result.failure.code != "agent_access_policy_unsupported" || upstream.calls.Load() != 0 {
		t.Fatalf("a non-AWS Connection with an operation rule was used: %+v", result.failure)
	}
	details := state.connectionDetails(time.Now(), "connection-github")
	if len(details) != 1 || details[0].State != "unavailable" || details[0].StateReason != "access_policy_unsupported" {
		t.Fatalf("connection detail = %+v", details)
	}
}

// operationClasses on an AWS Connection are ignored: its calls are classified
// by action.
func TestAWSConnectionIgnoresOperationClasses(t *testing.T) {
	connection := awsPolicyConnection(policyDocument("allow", []any{classRule("delete", "block")}))
	connection["operationClasses"] = []any{map[string]any{"match": map[string]any{"methods": []string{"POST"}}, "class": "read"}}
	_, proxy, upstream := policyProxy(t, connection)
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
	terminate := signedAWSRequest(t, http.MethodPost, "https://ec2.aws.example.test/", "ec2", "Action=TerminateInstances&InstanceId.1=i-0abc&Version=2016-11-15", form)
	if result := processThrough(proxy, terminate); result.failure == nil || result.failure.details["class"] != "delete" || upstream.calls.Load() != 0 {
		t.Fatalf("an AWS delete was classified by operationClasses: %+v", result.failure)
	}
}

// An operation rule and a temporary allow on AWS: the allow covers the one
// action it names and not another action of the same class.
func TestAWSOperationAllowCoversOnlyThatAction(t *testing.T) {
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	policy := policyDocument("allow", []any{classRule("delete", "ask")},
		map[string]any{"id": "allow-ec2", "operation": "ec2:TerminateInstances", "expiresAt": future})
	_, proxy, upstream := policyProxy(t, awsPolicyConnection(policy))
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
	terminate := signedAWSRequest(t, http.MethodPost, "https://ec2.aws.example.test/", "ec2", "Action=TerminateInstances&InstanceId.1=i-0abc&Version=2016-11-15", form)
	if result := processThrough(proxy, terminate); result.failure != nil || upstream.calls.Load() != 1 {
		t.Fatalf("the allowed action was stopped: %+v", result.failure)
	}
	deleteVolume := signedAWSRequest(t, http.MethodPost, "https://ec2.aws.example.test/", "ec2", "Action=DeleteVolume&VolumeId=vol-1&Version=2016-11-15", form)
	result := processThrough(proxy, deleteVolume)
	if result.failure == nil || result.failure.code != "agent_access_policy_ask" || upstream.calls.Load() != 1 {
		t.Fatalf("another delete was allowed: %+v", result.failure)
	}
	request, _ := json.Marshal(result.failure.details["request"])
	if !strings.Contains(string(request), `"allow":{"operation":"ec2:DeleteVolume"}`) || !strings.Contains(string(request), `"operation":"ec2:DeleteVolume"`) {
		t.Fatalf("ask request = %s", request)
	}
}
