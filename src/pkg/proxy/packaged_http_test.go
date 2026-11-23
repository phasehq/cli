package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/agentapi"
)

// packagedConnection is a packaged HTTP service as the Console compiles it
// for the services that attach when absent: one header injection, an
// integration credential in the resolved material, a decoy.
func packagedConnection(t *testing.T, serviceType, headerName, valueFormat, policy string) agentapi.Connection {
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
	return withProviderRules(t, connection)
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
			connection := packagedConnection(t, serviceType, service.header, service.format, "")
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

// Policy for a packaged service: the method decides the class, its single
// GraphQL endpoint included, and the secret guard comes ahead of the policy.
func TestPackagedHTTPServicePolicyUsesTheMethodAndTheGuard(t *testing.T) {
	policy := `{"version":1,"default":"allow","rules":[{"class":"create","effect":"ask"},{"class":"delete","effect":"block"}],"temporaryAllows":[]}`
	connection := packagedConnection(t, "github", "Authorization", "Bearer {value}", policy)
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
	if d := decide(http.MethodPost, "https://api.github.com/graphql"); d.Effect != agentapi.PolicyAsk || d.Class != agentapi.ClassCreate {
		t.Fatalf("GraphQL POST = %+v, want an ask as create", d)
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

// valueFormatsConnection is a header service whose primary form is Bearer and
// which also accepts the "token" scheme.
func valueFormatsConnection(t *testing.T, decoy, live string, alternates ...string) agentapi.Connection {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"serviceType": "github", "protocol": "http",
		"injection": map[string]any{
			"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}", "valueFormats": alternates, "whenAbsent": "attach",
			"valueFrom": map[string]any{"source": "credential", "field": "token"},
		},
		"identifiers": map[string]string{}, "decoyMaterial": map[string]string{"token": decoy},
		"agentEnv": map[string]string{}, "secretMaterial": map[string]string{"token": live},
	})
	if err != nil {
		t.Fatal(err)
	}
	var connection agentapi.Connection
	if err := json.Unmarshal(payload, &connection); err != nil {
		t.Fatal(err)
	}
	return connection
}

func TestAlternateValueFormatsSwapInTheFormPresented(t *testing.T) {
	const decoy, live = "ghp_decoyvalue0123456789abcdef", "ghp_livevalue0123456789abcdefgh"
	connection := valueFormatsConnection(t, decoy, live, "token {value}")
	apply := func(live, presented agentapi.Connection, authorization string) (string, error) {
		request := policyRequest(t, http.MethodGet, "https://api.github.com/user")
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		_, err := ApplyHTTPInjectionPresenting(context.Background(), request, live, presented)
		return request.Header.Get("Authorization"), err
	}
	if got, err := apply(connection, connection, "Bearer "+decoy); err != nil || got != "Bearer "+live {
		t.Fatalf("primary: %q %v", got, err)
	}
	if got, err := apply(connection, connection, "token "+decoy); err != nil || got != "token "+live {
		t.Fatalf("alternate: %q %v", got, err)
	}
	if got, err := apply(connection, connection, ""); err != nil || got != "Bearer "+live {
		t.Fatalf("attach must use the primary form: %q %v", got, err)
	}
	if got, err := apply(connection, connection, "Basic "+decoy); injectionCode(err) != InjectionSwapMiss || strings.Contains(got, live) {
		t.Fatalf("a third form: %q %v", got, err)
	}
	if got, err := apply(connection, connection, "token someone-else"); injectionCode(err) != InjectionSwapMiss || strings.Contains(got, live) {
		t.Fatalf("another value in the alternate form: %q %v", got, err)
	}
	// An earlier generation's decoy, presented in the alternate form.
	older := valueFormatsConnection(t, "ghp_olderdecoy0123456789abcdefgh", live, "token {value}")
	if got, err := apply(connection, older, "token ghp_olderdecoy0123456789abcdefgh"); err != nil || got != "token "+live {
		t.Fatalf("older generation: %q %v", got, err)
	}
}

func TestMalformedAlternateValueFormatInvalidatesTheInjection(t *testing.T) {
	for name, alternates := range map[string][]string{
		"no placeholder":   {"token"},
		"two placeholders": {"{value}{value}"},
		"too many":         {"a {value}", "b {value}", "c {value}", "d {value}", "e {value}"},
		"one bad of two":   {"token {value}", "nothing"},
	} {
		connection := valueFormatsConnection(t, "ghp_decoyvalue0123456789abcdef", "ghp_livevalue0123456789abcdefgh", alternates...)
		request := policyRequest(t, http.MethodGet, "https://api.github.com/user")
		request.Header.Set("Authorization", "Bearer ghp_decoyvalue0123456789abcdef")
		if _, err := ApplyHTTPInjection(context.Background(), request, connection); injectionCode(err) != InjectionInvalidTemplate {
			t.Errorf("%s: err=%v", name, err)
		}
		if request.Header.Get("Authorization") != "Bearer ghp_decoyvalue0123456789abcdef" {
			t.Errorf("%s: the request was rewritten", name)
		}
	}
}

func TestAlternateValueFormatsApplyToQueryParameters(t *testing.T) {
	payload := `{"serviceType":"x","protocol":"http","injection":{"action":"set_param","name":"k","valueFormat":"{value}","valueFormats":["tok-{value}"],"valueFrom":{"source":"credential","field":"token"}},"identifiers":{},"decoyMaterial":{"token":"dd0123456789"},"agentEnv":{},"secretMaterial":{"token":"ll0123456789"}}`
	var connection agentapi.Connection
	if err := json.Unmarshal([]byte(payload), &connection); err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{"https://x.test/?k=dd0123456789": "ll0123456789", "https://x.test/?k=tok-dd0123456789": "tok-ll0123456789"} {
		request := policyRequest(t, http.MethodGet, target)
		if _, err := ApplyHTTPInjection(context.Background(), request, connection); err != nil || request.URL.Query().Get("k") != want {
			t.Errorf("%s: %v %q", target, err, request.URL.RawQuery)
		}
	}
}
