package aiproxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
)

const (
	packagedDecoy = "ghp_phasedecoy0123456789abcdefghijkl"
	packagedLive  = "ghp_liveproxyonlyvalue0123456789abcd"
)

// packagedHTTPPayload is a packaged HTTP service that attaches when absent,
// as the Console compiles it: one header injection, an integration credential
// in the resolved material, a decoy and environment bindings. It is not a
// custom Connection and has no definition.
func packagedHTTPPayload(policy map[string]any) map[string]any {
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
	return connection
}

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
	policy := policyDocument("allow", []any{classRule("create", "ask"), classRule("delete", "block")})
	_, proxy, upstream := policyProxy(t, packagedHTTPPayload(policy))

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

	// The single GraphQL endpoint is a create by its method, a query or not.
	asked := processThrough(proxy, githubRequest(t, http.MethodPost, "/graphql", "Bearer "+packagedDecoy))
	if asked.failure == nil || asked.failure.code != "agent_access_policy_ask" || asked.failure.details["class"] != "create" || upstream.calls.Load() != before {
		t.Fatalf("GraphQL POST = %+v", asked.failure)
	}
	if rule, _ := asked.event.Detail["rule"].(agentapi.PolicyRule); rule.Class != "create" || asked.event.ProxyDecision != "ask" {
		t.Fatalf("event = %+v", asked.event)
	}
	// An update is allowed by the default.
	if result := processThrough(proxy, githubRequest(t, http.MethodPatch, "/repos/acme/x/issues/1", "Bearer "+packagedDecoy)); result.failure != nil {
		t.Fatalf("an update was refused: %+v", result.failure)
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

// A policy this CLI cannot enforce in full (a higher version, or a class,
// effect or rule kind it does not know) makes only that Connection
// unavailable, AWS included, and its calls say to update the Phase CLI.
func TestPolicyThisCLIDoesNotKnowAsksForANewerCLI(t *testing.T) {
	for name, policy := range map[string]map[string]any{
		"a higher version":     {"version": 2, "default": "allow", "rules": []any{classRule("delete", "block")}},
		"an unknown class":     policyDocument("allow", []any{classRule("admin", "block")}),
		"an unknown effect":    policyDocument("allow", []any{classRule("delete", "audit")}),
		"an unknown default":   policyDocument("deny", nil),
		"an unknown rule kind": policyDocument("allow", []any{map[string]any{"operation": "ec2:TerminateInstances", "effect": "block"}}),
	} {
		for _, aws := range []bool{false, true} {
			connection := packagedHTTPPayload(policy)
			request := githubRequest(t, http.MethodGet, "/user", "Bearer "+packagedDecoy)
			if aws {
				connection = awsPolicyConnection(policy)
				request = signedAWSRequest(t, http.MethodGet, "https://bucket.s3.aws.example.test/key", "s3", "", nil)
			}
			state, proxy, upstream := policyProxy(t, connection)
			result := processThrough(proxy, request)
			if result.failure == nil || result.failure.code != "agent_access_policy_unsupported" || upstream.calls.Load() != 0 ||
				!strings.Contains(result.failure.message, "Update the Phase CLI.") {
				t.Fatalf("%s (aws=%t): failure = %+v", name, aws, result.failure)
			}
			details := state.connectionDetails(time.Now(), "")
			if len(details) != 1 || details[0].State != "unavailable" || details[0].StateReason != "access_policy_unsupported" {
				t.Fatalf("%s (aws=%t): connection detail = %+v", name, aws, details)
			}
		}
	}
}

// A secret guard this CLI cannot read in full makes only that Connection
// unavailable, and the refusal names the guard, not the access policy.
func TestSecretGuardThisCLICannotReadAsksForANewerCLI(t *testing.T) {
	connection := awsPolicyConnection(nil)
	connection["secretGuard"] = map[string]any{"operations": map[string]any{"sts": []string{"AssumeRole"}}, "bodyFields": []string{"token"}}
	state, proxy, upstream := policyProxy(t, connection)
	result := processThrough(proxy, signedAWSRequest(t, http.MethodGet, "https://bucket.s3.aws.example.test/key", "s3", "", nil))
	if result.failure == nil || result.failure.code != "agent_connection_unsupported" || upstream.calls.Load() != 0 || result.event.Reason != "secret_guard_unsupported" ||
		!strings.HasPrefix(result.failure.message, "This Phase CLI cannot apply this Connection's secret guard") || !strings.HasSuffix(result.failure.message, " Update the Phase CLI.") {
		t.Fatalf("failure = %+v", result.failure)
	}
	if code, _ := awsErrorBody(t, result.failure); code != "PhaseAccessDenied" {
		t.Fatalf("AWS error code = %s", code)
	}
	details := state.connectionDetails(time.Now(), "")
	if len(details) != 1 || details[0].State != "unavailable" || details[0].StateReason != "secret_guard_unsupported" {
		t.Fatalf("connection detail = %+v", details)
	}
}

const registryWithServices = `{"schemaVersion":1,"capabilities":{},"services":{` +
	`"gitlab":{"serviceType":"gitlab","displayName":"GitLab","credentialProviders":["gitlab"],"hosts":[{"match":"exact","value":"gitlab.com","port":443,"path":"/api/*"}]},` +
	`"aws":{"serviceType":"aws","displayName":"AWS","credentialProviders":["aws"],"hosts":[{"match":"suffix","value":".amazonaws.com"}]},` +
	`"vercel":{"serviceType":"vercel","displayName":"Vercel","credentialProviders":["vercel"],"hosts":[]},` +
	`"broken":"not an object"},"presets":[` +
	`{"id":"datadog","name":"Datadog","hostsEditable":true,"hosts":[{"match":"suffix","value":".datadoghq.com"}]}]}`

func TestHintsNameAPackagedServiceForItsHosts(t *testing.T) {
	console := newPresetConsole(t)
	console.body = registryWithServices
	state, proxy := console.proxy(t, false)
	state.noteConnectionNeeded("upstream_rejected_unbound_host", "gitlab.com", 443, http.StatusUnauthorized)
	state.noteConnectionNeeded("upstream_rejected_unbound_host", "s3.eu-west-1.amazonaws.com", 443, http.StatusForbidden)
	state.noteConnectionNeeded("upstream_rejected_unbound_host", "app.datadoghq.com", 443, http.StatusForbidden)
	state.noteConnectionNeeded("upstream_rejected_unbound_host", "api.internal.example.test", 443, http.StatusForbidden)
	state.hints.noteUnboundHost("gitlab.com", 443)

	var hints remoteapi.HintsResponse
	listed := controlGet(t, proxy, "runtime-presets", "/v1/hints")
	if err := json.Unmarshal(listed.Body.Bytes(), &hints); err != nil || len(hints.Hints) != 4 {
		t.Fatalf("hints: %s err=%v", listed.Body.String(), err)
	}
	byHost := map[string]remoteapi.Hint{}
	for _, hint := range hints.Hints {
		byHost[hint.Host] = hint
	}
	want := `{"credentialName":"GitLab for this Workflow","credentialProvider":"gitlab","kind":"setup","markdown":"Calls to gitlab.com need a GitLab Connection.","serviceType":"gitlab","title":"Connect GitLab"}`
	if got := byHost["gitlab.com"]; got.Service != "gitlab" || got.Preset != "" || !sameJSON(t, got.Request, []byte(want)) {
		t.Fatalf("service hint = %+v request=%s", got, got.Request)
	}
	if got := byHost["app.datadoghq.com"]; got.Preset != "datadog" || got.Service != "" || !strings.Contains(string(got.Request), `"preset":"datadog"`) {
		t.Fatalf("preset hint = %+v", got)
	}
	// AWS hosts are not hinted by service, and an unknown host gets the
	// custom definition.
	for _, host := range []string{"s3.eu-west-1.amazonaws.com", "api.internal.example.test"} {
		got := byHost[host]
		if got.Service != "" || got.Preset != "" || !strings.Contains(string(got.Request), `"definition"`) {
			t.Fatalf("%s hint = %+v", host, got)
		}
	}
	// The request is one the proxy's own request route accepts.
	requests := newRequestConsole(t)
	_, requestProxy := requests.state(t, "runtime-requests")
	if recorder := postControlRequest(requestProxy, "runtime-requests", string(byHost["gitlab.com"].Request)); recorder.Code != http.StatusCreated {
		t.Fatalf("the service request was refused: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestLockdownAnswerNamesAPackagedServiceAndNeverWaitsForTheRegistry(t *testing.T) {
	console := newPresetConsole(t)
	console.body = registryWithServices
	state, proxy := console.proxy(t, true)
	blocked := func() map[string]any {
		request, _ := http.NewRequest(http.MethodGet, "http://gitlab.com/api/v4/user", nil)
		result := processThrough(proxy, request)
		if result.failure == nil || result.failure.code != "unbound_host_blocked" {
			t.Fatalf("lockdown answer = %+v", result.failure)
		}
		return result.failure.details
	}
	if details := blocked(); details["request"] != nil {
		t.Fatalf("a cold answer guessed a request: %v", details)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, held := state.presets.lookup("gitlab.com", 443); held {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the registry was never read in the background")
		}
		time.Sleep(5 * time.Millisecond)
	}
	details := blocked()
	request, _ := json.Marshal(details["request"])
	if details["service"] != "gitlab" || details["preset"] != nil || !strings.Contains(string(request), `"serviceType":"gitlab"`) ||
		!strings.Contains(string(request), `"credentialProvider":"gitlab"`) {
		t.Fatalf("service lockdown answer = %v", details)
	}
}

// With the registry unreachable the hints fall back to the custom definition.
func TestHintsFallBackSafelyWhenTheRegistryIsUnreachable(t *testing.T) {
	console := newPresetConsole(t)
	console.fail.Store(true)
	state, proxy := console.proxy(t, false)
	state.noteConnectionNeeded("upstream_rejected_unbound_host", "gitlab.com", 443, http.StatusUnauthorized)
	listed := controlGet(t, proxy, "runtime-presets", "/v1/hints")
	var hints remoteapi.HintsResponse
	if err := json.Unmarshal(listed.Body.Bytes(), &hints); err != nil || listed.Code != http.StatusOK || len(hints.Hints) != 1 ||
		hints.Hints[0].Service != "" || !strings.Contains(string(hints.Hints[0].Request), `"definition"`) {
		t.Fatalf("hints: %d %s err=%v", listed.Code, listed.Body.String(), err)
	}
}
