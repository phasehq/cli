package phase

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/pkg/ai"
)

func agentBackendForTest(t *testing.T, access string) *AgentBackend {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(access))
	}))
	t.Cleanup(server.Close)
	t.Setenv("PHASE_SERVICE_TOKEN", testToken("pss_agent:"))
	t.Setenv("PHASE_HOST", server.URL)
	t.Setenv("PHASE_OFFLINE", "")
	t.Cleanup(func() { ai.SetAgentLogin(false) })
	backend, err := NewBackend()
	if err != nil {
		t.Fatal(err)
	}
	agent, ok := backend.(*AgentBackend)
	if !ok || !ai.AgentLogin() {
		t.Fatalf("backend = %T, Agent login recorded = %t", backend, ai.AgentLogin())
	}
	return agent
}

// Several app Connections may cover one app; apps list, init and selection
// see one app with every environment once.
func TestAgentUserDataMergesConnectionsOfOneApp(t *testing.T) {
	backend := agentBackendForTest(t, `{"schemaVersion":1,"apps":[`+
		`{"connectionId":"c1","connectionName":"one","grantId":"g1","app":{"id":"app-1","name":"orders"},"environments":[{"id":"e1","name":"Development","envType":"dev"}],"access":{},"grantExpiresAt":null},`+
		`{"connectionId":"c2","connectionName":"two","grantId":"g2","app":{"id":"app-1","name":"orders"},"environments":[{"id":"e1","name":"Development","envType":"dev"},{"id":"e3","name":"Production","envType":"prod"}],"access":{},"grantExpiresAt":null},`+
		`{"connectionId":"c3","connectionName":"three","grantId":"g3","app":{"id":"app-2","name":"orders-legacy"},"environments":[{"id":"e4","name":"Development","envType":"dev"}],"access":{},"grantExpiresAt":null}`+
		`],"expired":[]}`)
	data, err := UserData(backend)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Apps) != 2 || len(data.Apps[0].EnvironmentKeys) != 2 || data.Apps[0].EnvironmentKeys[1].Environment.EnvType != "PROD" {
		t.Fatalf("user data = %+v", data.Apps)
	}
	// Names match exactly, ignoring case.
	if app, env := ResolveNames(backend, "ORDERS", "production", ""); app != "orders" || env != "Production" {
		t.Fatalf("resolved %q / %q", app, env)
	}
	if app, env := ResolveNames(backend, "", "Staging", "app-unknown"); app != "app-unknown" || env != "Staging" {
		t.Fatalf("an app ID not listed resolved to %q / %q", app, env)
	}
	target, err := backend.target("", "staging", "app-1", "read")
	if err != nil || target.appID != "app-1" || target.env != "staging" || target.appLabel != "orders" {
		t.Fatalf("an environment not listed is still sent as given: %+v %v", target, err)
	}
	_, err = backend.target("billing", "", "", "read")
	var refusal *AgentRefusal
	if !errors.As(err, &refusal) || !strings.Contains(string(refusal.Request), `"appName":"billing"`) ||
		!strings.Contains(string(refusal.Request), `"environments":["Development"]`) {
		t.Fatalf("unknown app name: %v", err)
	}
	if _, err := backend.target("", "", "", "read"); err == nil || err.Error() != "no application context provided" {
		t.Fatalf("no app: %v", err)
	}
}

// A name that is only part of a granted app's or environment's name never
// selects it: a delete for --app api must not land on payments-api.
func TestAgentTargetMatchesNamesExactly(t *testing.T) {
	backend := agentBackendForTest(t, `{"schemaVersion":1,"apps":[`+
		`{"connectionId":"c1","connectionName":"one","grantId":"g1","app":{"id":"app-1","name":"payments-api"},"environments":[{"id":"e1","name":"Preprod","envType":"staging"}],"access":{},"grantExpiresAt":null}`+
		`],"expired":[`+
		`{"connectionId":"c2","connectionName":"two","grantId":"g2","app":{"id":"app-9","name":"billing-old"},"expiredAt":"2026-01-01T00:00:00Z"}`+
		`]}`)
	_, err := backend.target("api", "Preprod", "", "read_write")
	var refusal *AgentRefusal
	if !errors.As(err, &refusal) || !strings.Contains(refusal.Message, `apps it can use: "payments-api"`) {
		t.Fatalf("--app api: %v", err)
	}
	if _, err := backend.target("billing", "", "", "read"); !errors.As(err, &refusal) {
		t.Fatalf("--app billing took the expired billing-old grant: %v", err)
	}
	if target, err := backend.target("BILLING-OLD", "", "", "read"); err != nil || target.appID != "app-9" {
		t.Fatalf("expired grant by exact name: %+v %v", target, err)
	}
	target, err := backend.target("Payments-API", "prod", "", "read_write")
	if err != nil || target.appID != "app-1" || target.env != "prod" || target.envLabel != "prod" {
		t.Fatalf("--env prod with only Preprod granted: %+v %v", target, err)
	}
	if target, err := backend.target("payments-api", "PREPROD", "", "read"); err != nil || target.env != "Preprod" {
		t.Fatalf("--env PREPROD: %+v %v", target, err)
	}
}

func TestAgentRefusalNamesHowToSendTheRequest(t *testing.T) {
	refusal := &AgentRefusal{&agentapi.AppSecretsError{
		StatusCode: 403, Code: "agent_access_ask", Message: "Writing secrets needs approval.",
		Request: []byte(`{"kind":"access_change"}`),
	}}
	t.Setenv("PHASE_AI_ENABLED", "1")
	if got := refusal.Error(); got != "Writing secrets needs approval.\nTo ask a member for it, send this JSON unchanged to POST http://phase.invalid/v1/requests, show the human the approvalUrl, and run the command again once the request is approved:\n{\"kind\":\"access_change\"}" {
		t.Fatalf("in a session: %q", got)
	}
	t.Setenv("PHASE_AI_ENABLED", "")
	if got := refusal.Error(); !strings.HasPrefix(got, "Writing secrets needs approval.\nA member can grant it through a request, which is filed from inside a Phase AI session") ||
		!strings.HasSuffix(got, "POST http://phase.invalid/v1/requests:\n{\"kind\":\"access_change\"}") {
		t.Fatalf("outside a session: %q", got)
	}
}

func TestActiveLoginIsAgent(t *testing.T) {
	isolateHarness(t, "", "")
	t.Setenv("PHASE_SERVICE_TOKEN", testToken("pss_agent:"))
	if !ActiveLoginIsAgent() {
		t.Fatal("an Agent token in PHASE_SERVICE_TOKEN was not recognised")
	}
	if _, err := NewPhase(true, "", ""); err == nil || !strings.Contains(err.Error(), "not available to an Agent login") {
		t.Fatalf("NewPhase with an Agent login: %v", err)
	}
	t.Setenv("PHASE_SERVICE_TOKEN", testToken("pss_user:"))
	if ActiveLoginIsAgent() {
		t.Fatal("a personal token was taken for an Agent login")
	}
	t.Setenv("PHASE_OFFLINE", "1")
	t.Setenv("PHASE_SERVICE_TOKEN", testToken("pss_agent:"))
	if _, err := NewBackend(); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("offline Agent backend: %v", err)
	}
}
