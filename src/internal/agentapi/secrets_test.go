package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type recordedCall struct {
	method, path, query, authorization, body string
}

func appSecretsServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *[]recordedCall) {
	t.Helper()
	var calls []recordedCall
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, recordedCall{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), string(body)})
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func TestAppSecretsCallsUseThePublicSecretsAPIWithTheAgentToken(t *testing.T) {
	server, calls := appSecretsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/agents/app-access/"):
			_, _ = w.Write([]byte(`{"schemaVersion":1,"apps":[{"connectionId":"c1","connectionName":"orders","grantId":"g1","app":{"id":"app-1","name":"orders"},"environments":[{"id":"e1","name":"Development","envType":"dev"}],"access":{"read":{"effect":"allow"}},"grantExpiresAt":null}],"expired":[]}`))
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[{"id":"s1","key":"API_KEY","value":"live-value","comment":"","path":"/","tags":["backend"],"type":"secret","lifecycle":"static","environment":"e1"}]`))
		default:
			_, _ = w.Write([]byte(`[{"id":"s1","key":"API_KEY","value":"echoed-live-value"}]`))
		}
	})
	client, err := NewClient(server.URL, testToken("pss_agent", 1, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	access, err := client.AppAccess(ctx)
	if err != nil || len(access.Apps) != 1 || access.Apps[0].Environments[0].Name != "Development" {
		t.Fatalf("app access = %+v, %v", access, err)
	}
	secrets, err := client.ListAppSecrets(ctx, AppSecretsQuery{AppID: "app-1", Env: "Development", Path: "/backend", Key: "API_KEY", Raw: true})
	if err != nil || len(secrets) != 1 || secrets[0].ID != "s1" || secrets[0].Value != "live-value" || secrets[0].Tags[0] != "backend" {
		t.Fatalf("secrets = %+v, %v", secrets, err)
	}
	if formatted := secrets[0].String(); strings.Contains(formatted, "live-value") {
		t.Fatalf("a secret formatted its value: %s", formatted)
	}
	if _, err := client.ListAppSecrets(ctx, AppSecretsQuery{AppID: "app-1", Env: "Development"}); err != nil {
		t.Fatal(err)
	}
	value := "new-value"
	if err := client.CreateAppSecrets(ctx, "app-1", "Development", []AppSecretWrite{{Key: "NEW", Value: &value, Path: "/", Type: "config"}}); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateAppSecrets(ctx, "app-1", "Development", []AppSecretWrite{{ID: "s1", Path: "/moved"}}); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteAppSecrets(ctx, "app-1", "Development", []string{"s1", "s2"}); err != nil {
		t.Fatal(err)
	}

	want := []recordedCall{
		{method: "GET", path: "/service/public/v1/agents/app-access/", query: ""},
		{method: "GET", path: "/service/public/v1/secrets/", query: "app_id=app-1&env=Development&key=API_KEY&path=%2Fbackend&raw=true"},
		{method: "GET", path: "/service/public/v1/secrets/", query: "app_id=app-1&env=Development"},
		{method: "POST", path: "/service/public/v1/secrets/", query: "app_id=app-1&env=Development", body: `{"secrets":[{"key":"NEW","value":"new-value","path":"/","type":"config"}]}`},
		{method: "PUT", path: "/service/public/v1/secrets/", query: "app_id=app-1&env=Development", body: `{"secrets":[{"id":"s1","path":"/moved"}]}`},
		{method: "DELETE", path: "/service/public/v1/secrets/", query: "app_id=app-1&env=Development", body: `{"secrets":["s1","s2"]}`},
	}
	if len(*calls) != len(want) {
		t.Fatalf("calls = %+v", *calls)
	}
	for index, call := range *calls {
		expected := want[index]
		if call.method != expected.method || call.path != expected.path || call.query != expected.query || call.body != expected.body ||
			call.authorization != "Bearer Agent "+strings.Repeat("a", 64) {
			t.Fatalf("call %d = %+v, want %+v", index, call, expected)
		}
	}
}

func TestAppAccessRefusesOtherTokensAndUnknownSchemas(t *testing.T) {
	server, calls := appSecretsServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"schemaVersion":2,"apps":[],"expired":[]}`))
	})
	user, err := NewClient(server.URL, testToken("pss_user", 1, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := user.AppAccess(context.Background()); err == nil || len(*calls) != 0 {
		t.Fatalf("a personal token listed app access: %v calls=%d", err, len(*calls))
	}
	agent, err := NewClient(server.URL, testToken("pss_agent", 1, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.AppAccess(context.Background()); err == nil {
		t.Fatal("an unknown schema version was accepted")
	}
}

func TestAppSecretsErrorsKeepTheSentenceAndRequestOnly(t *testing.T) {
	const liveValue = "live-secret-value-sentinel"
	tests := []struct {
		name, body          string
		status              int
		retryAfter          string
		code, message       string
		request             string
		connectionName, cls string
		wantRetry           time.Duration
	}{
		{
			name: "grant missing", status: 403,
			body: `{"error":"No access to orders in Production.","code":"agent_grant_missing","request":{"kind":"setup","action":{"type":"agent_connection.app_access","version":1,"appId":"a","environments":["Production"],"access":"read"}},"value":"` + liveValue + `"}`,
			code: "agent_grant_missing", message: "No access to orders in Production.",
			request: `{"kind":"setup","action":{"type":"agent_connection.app_access","version":1,"appId":"a","environments":["Production"],"access":"read"}}`,
		},
		{
			name: "blocked", status: 403,
			body: `{"error":"Deleting is blocked.","code":"agent_access_blocked","connectionName":"orders secrets","class":"delete"}`,
			code: "agent_access_blocked", message: "Deleting is blocked.", connectionName: "orders secrets", cls: "delete",
		},
		{
			name: "invalid token in the Agent envelope", status: 401,
			body: `{"error":{"code":"invalid_token","message":"The Agent token is not valid.","retryable":false}}`,
			code: "invalid_token", message: "The Agent token is not valid.",
		},
		{
			name: "throttled", status: 429, retryAfter: "7",
			body:    `{"detail":"Request was throttled."}`,
			message: "Request was throttled.", wantRetry: 7 * time.Second,
		},
		{
			name: "not JSON", status: 502,
			body: `<html>` + liveValue + `</html>`, message: "Bad Gateway",
		},
		{
			name: "credential-shaped text", status: 403,
			body: `{"error":"Bad token pss_agent:v1:` + strings.Repeat("a", 64) + `:x","code":"agent_grant_missing","request":{"kind":"setup","title":"pss_user:v1:abc"}}`,
			code: "agent_grant_missing", message: "Bad token [REDACTED]",
			request: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, _ := appSecretsServer(t, func(w http.ResponseWriter, r *http.Request) {
				if test.retryAfter != "" {
					w.Header().Set("Retry-After", test.retryAfter)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			})
			client, err := NewClient(server.URL, testToken("pss_agent", 1, ""), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ListAppSecrets(context.Background(), AppSecretsQuery{AppID: "a", Env: "Production"})
			var refusal *AppSecretsError
			if !errors.As(err, &refusal) {
				t.Fatalf("error = %T %v", err, err)
			}
			if refusal.StatusCode != test.status || refusal.Code != test.code || refusal.Message != test.message ||
				string(refusal.Request) != test.request || refusal.ConnectionName != test.connectionName ||
				refusal.Class != test.cls || refusal.RetryAfter != test.wantRetry {
				t.Fatalf("refusal = %+v request=%s", refusal, refusal.Request)
			}
			if strings.Contains(err.Error(), liveValue) || strings.Contains(string(refusal.Request), liveValue) {
				t.Fatalf("a refusal carried a response value: %v", err)
			}
		})
	}
}

func TestAppSecretsNeverFollowRedirects(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer target.Close()
	server, _ := appSecretsServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/service/public/v1/secrets/", http.StatusTemporaryRedirect)
	})
	client, err := NewClient(server.URL, testToken("pss_agent", 1, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListAppSecrets(context.Background(), AppSecretsQuery{AppID: "a", Env: "dev"})
	var refusal *AppSecretsError
	if !errors.As(err, &refusal) || refusal.StatusCode != http.StatusTemporaryRedirect || targetHits.Load() != 0 {
		t.Fatalf("redirect: err=%v target hits=%d", err, targetHits.Load())
	}
	value := "x"
	if err := client.CreateAppSecrets(context.Background(), "a", "dev", []AppSecretWrite{{Key: "K", Value: &value}}); err == nil || targetHits.Load() != 0 {
		t.Fatalf("a write followed a redirect: err=%v target hits=%d", err, targetHits.Load())
	}
}

// The secrets calls share the Agent API transport, so inside a Phase AI
// session they never go through the data-plane proxy.
func TestAppSecretsTransportSkipsTheProxyInsideASession(t *testing.T) {
	for _, enabled := range []string{"1", ""} {
		t.Setenv("PHASE_AI_ENABLED", enabled)
		client, err := NewClient("https://console.phase.invalid", testToken("pss_agent", 1, ""), nil)
		if err != nil {
			t.Fatal(err)
		}
		transport, ok := client.httpClient.Transport.(*http.Transport)
		if !ok || (transport.Proxy == nil) != (enabled == "1") || client.httpClient.CheckRedirect == nil {
			t.Fatalf("PHASE_AI_ENABLED=%q: proxy set=%t", enabled, ok && transport.Proxy != nil)
		}
	}
}

func TestAppSecretsResponseIsCapped(t *testing.T) {
	server, _ := appSecretsServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"key":"BIG","value":"` + strings.Repeat("x", maxResponseBytes) + `"}]`))
	})
	client, err := NewClient(server.URL, testToken("pss_agent", 1, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListAppSecrets(context.Background(), AppSecretsQuery{AppID: "a", Env: "dev"}); err == nil ||
		!strings.Contains(err.Error(), "4 MiB") {
		t.Fatalf("oversized response: %v", err)
	}
}

func TestRefusalRequestMustBeABoundedObject(t *testing.T) {
	for _, raw := range []string{``, `null`, `"text"`, `[1]`, `{"a":`, `{"a":"` + strings.Repeat("x", maxRefusalRequestBytes) + `"}`} {
		if got := refusalRequest(json.RawMessage(raw)); got != nil {
			t.Fatalf("refusalRequest(%.40q) = %s", raw, got)
		}
	}
	for _, raw := range []string{
		`{"kind":"setup"}`,
		`{"kind":"setup","action":{"type":"agent_connection.unknown","version":1}}`,
		`{"kind":"access_change","action":{"type":"agent_connection.app_access","version":1,"appId":"a","environments":["dev"],"access":"read"}}`,
		`{"kind":"setup","action":{"type":"agent_connection.app_access","version":1,"appId":"a","environments":["dev"],"access":"read","value":"pasted"}}`,
		`{"kind":"setup","title":"line\nbreak","action":{"type":"agent_connection.app_access","version":1,"appId":"a","environments":["dev"],"access":"read"}}`,
	} {
		if got := refusalRequest(json.RawMessage(raw)); got != nil {
			t.Fatalf("refusalRequest kept a request the control API refuses: %s", raw)
		}
	}
	valid := " {\n \"kind\": \"access_change\", \"action\": {\"type\": \"agent_grant.renew\", \"version\": 1, \"connectionId\": \"c1\"}}"
	if got := refusalRequest(json.RawMessage(valid)); string(got) != `{"kind":"access_change","action":{"type":"agent_grant.renew","version":1,"connectionId":"c1"}}` {
		t.Fatalf("refusalRequest compacted = %s", got)
	}
}
