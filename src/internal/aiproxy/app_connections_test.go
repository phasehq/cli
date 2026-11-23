package aiproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

func appConnectionPayload(id, name string, grantExpiresAt any) map[string]any {
	return map[string]any{
		"connectionId": id, "connectionName": name, "grantId": "grant-" + id,
		"app": map[string]any{"id": "app-orders", "name": "orders-service"},
		"environments": []any{
			map[string]any{"id": "env-dev", "name": "Development", "envType": "dev"},
			map[string]any{"id": "env-staging", "name": "Staging", "envType": "staging"},
		},
		"access": map[string]any{
			"read":   map[string]any{"effect": "allow"},
			"create": map[string]any{"effect": "allow", "until": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
			"update": map[string]any{"effect": "ask"},
			"delete": map[string]any{"effect": "block"},
		},
		"grantExpiresAt": grantExpiresAt,
	}
}

func getControl(t *testing.T, proxy *httpProxy, capability, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+path, nil)
	setProxyCapability(request, capability)
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	return recorder
}

func appConnectionsState(t *testing.T, payload map[string]any) *httpProxy {
	t.Helper()
	console := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(console.Close)
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, payload, "runtime-apps")
	t.Cleanup(state.destroy)
	return &httpProxy{state: state, control: &controlHandler{state: state}}
}

// App Connections are listed for the Agent beside the proxy's own, never
// routed: the session's Connections and environment are untouched by them.
func TestAppConnectionsAreListedByConnectionsAndStatus(t *testing.T) {
	expiresLater := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	expiredBefore := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	payload := controlAccessSessionPayload("backend-apps", 1)
	payload["appConnections"] = []any{
		appConnectionPayload("connection-orders", "orders-service secrets (Development, Staging)", nil),
		appConnectionPayload("connection-orders-timed", "orders-service timed", expiresLater),
		appConnectionPayload("connection-orders-ended", "orders-service ended", expiredBefore),
	}
	payload["expiredConnections"] = []any{map[string]any{
		"connectionId": "connection-billing", "connectionName": "billing secrets (Production)", "serviceType": "phase_app",
		"expiredAt": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}, map[string]any{
		// Listed as expired but live again: renewed since the last listing.
		"connectionId": "connection-orders", "connectionName": "orders-service secrets (Development, Staging)", "serviceType": "phase_app",
		"expiredAt": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}}
	proxy := appConnectionsState(t, payload)

	recorder := getControl(t, proxy, "runtime-apps", "/v1/connections")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var listed remoteapi.ConnectionsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	byID := map[string]remoteapi.ConnectionDetail{}
	for _, detail := range listed.Connections {
		if _, repeated := byID[detail.ID]; repeated {
			t.Fatalf("connection %s listed twice: %s", detail.ID, recorder.Body.String())
		}
		byID[detail.ID] = detail
	}
	if len(byID) != 5 || byID["connection-pg"].ServiceType != "postgres" {
		t.Fatalf("connections = %s", recorder.Body.String())
	}
	active := byID["connection-orders"]
	if active.ServiceType != agentapi.PhaseAppServiceType || active.State != "active" || active.StateReason != "" ||
		active.App == nil || active.App.Name != "orders-service" || len(active.Environments) != 2 ||
		active.Environments[1].Name != "Staging" || active.Access["delete"].Effect != "block" ||
		active.Access["create"].Until == nil || active.GrantExpiresAt != nil || active.Request != nil {
		t.Fatalf("active app connection = %+v", active)
	}
	if timed := byID["connection-orders-timed"]; timed.State != "active" || timed.GrantExpiresAt == nil {
		t.Fatalf("time-limited app connection = %+v", timed)
	}
	for _, id := range []string{"connection-orders-ended", "connection-billing"} {
		ended := byID[id]
		if ended.ServiceType != agentapi.PhaseAppServiceType || ended.State != "expired" || ended.StateReason != agentapi.AccessExpired ||
			ended.ExpiredAt == nil || !strings.Contains(string(ended.Request), `"agent_grant.renew"`) ||
			!strings.Contains(string(ended.Request), `"connectionId":"`+id+`"`) {
			t.Fatalf("%s = %+v request=%s", id, ended, ended.Request)
		}
	}

	one := getControl(t, proxy, "runtime-apps", "/v1/connections/connection-orders")
	if one.Code != http.StatusOK || !strings.Contains(one.Body.String(), `"serviceType":"phase_app"`) ||
		!strings.Contains(one.Body.String(), `"name":"orders-service"`) {
		t.Fatalf("single app connection: status=%d body=%s", one.Code, one.Body.String())
	}

	status := getControl(t, proxy, "runtime-apps", "/v1/status")
	var statusResponse remoteapi.StatusResponse
	if err := json.Unmarshal(status.Body.Bytes(), &statusResponse); err != nil || status.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
	}
	states := map[string]remoteapi.StatusConnection{}
	for _, connection := range statusResponse.Connections {
		states[connection.ConnectionID] = connection
	}
	if states["connection-orders"].State != "active" || states["connection-orders"].App == nil ||
		states["connection-orders-ended"].State != "expired" || states["connection-pg"].State != "ready" {
		t.Fatalf("status connections = %s", status.Body.String())
	}
	if strings.Contains(status.Body.String(), "pg-live") || strings.Contains(status.Body.String(), "backend-apps") {
		t.Fatalf("status leaked session material: %s", status.Body.String())
	}
}

// A session payload from before app Connections still opens and lists only
// what it carries.
func TestSessionWithoutAppConnectionsStillWorks(t *testing.T) {
	proxy := appConnectionsState(t, controlAccessSessionPayload("backend-old", 1))
	recorder := getControl(t, proxy, "runtime-apps", "/v1/connections")
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "phase_app") ||
		!strings.Contains(recorder.Body.String(), `"connection-pg"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

// A refreshed configuration replaces the app Connections in place: they are
// not part of the Agent's environment, so no new session is needed.
func TestRefreshReplacesAppConnectionsInPlace(t *testing.T) {
	proxy := appConnectionsState(t, controlAccessSessionPayload("backend-refresh", 1))
	next := controlAccessSessionPayload("backend-refresh", 2)
	next["appConnections"] = []any{appConnectionPayload("connection-orders", "orders-service secrets", nil)}
	config := decodeTestSession(t, next).SessionConfig
	if err := proxy.state.replaceConfig(&config); err != nil {
		t.Fatalf("a new app Connection needed a new session: %v", err)
	}
	recorder := getControl(t, proxy, "runtime-apps", "/v1/connections/connection-orders")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"state":"active"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestControlRequestsForwardAppAccessAndClassesAllows(t *testing.T) {
	tests := []struct{ name, kind, action string }{
		{"app access by id", "setup", `{"type":"agent_connection.app_access","version":1,"appId":"app-orders","environments":["development","staging"],"access":"read"}`},
		{"app access by name", "setup", `{"type":"agent_connection.app_access","version":1,"appName":"orders-service","environments":["Production"],"access":"read_write"}`},
		{"allow several classes", "access_change", `{"type":"agent_grant.allow","version":1,"connectionId":"connection-orders","allow":{"classes":["create","update","delete"]}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			console := newRequestConsole(t)
			_, proxy := console.state(t, "runtime-requests")
			body := `{"kind":"` + test.kind + `","title":"Read secrets in orders-service","durationSeconds":3600,"action":` + test.action + `}`
			recorder := postControlRequest(proxy, "runtime-requests", body)
			if recorder.Code != http.StatusCreated || console.creates.Load() != 1 {
				t.Fatalf("status=%d creates=%d body=%.300s", recorder.Code, console.creates.Load(), recorder.Body.String())
			}
			forwarded := *console.lastBody.Load()
			if !sameJSON(t, forwarded["action"], []byte(test.action)) || string(forwarded["kind"]) != `"`+test.kind+`"` {
				t.Fatalf("forwarded request = %.300s", mustJSON(t, forwarded))
			}
		})
	}

	refused := map[string]string{
		"unknown action type":       `{"kind":"setup","action":{"type":"agent_connection.app_secrets","version":1,"appId":"app-orders","environments":["dev"],"access":"read"}}`,
		"app access under a change": `{"kind":"access_change","action":{"type":"agent_connection.app_access","version":1,"appId":"app-orders","environments":["dev"],"access":"read"}}`,
		"app access without access": `{"kind":"setup","action":{"type":"agent_connection.app_access","version":1,"appId":"app-orders","environments":["dev"]}}`,
		"app access with a value":   `{"kind":"setup","action":{"type":"agent_connection.app_access","version":1,"appId":"app-orders","environments":["dev"],"access":"read","value":"sk-live-pasted"}}`,
		"empty classes":             `{"kind":"access_change","action":{"type":"agent_grant.allow","version":1,"connectionId":"connection-orders","allow":{"classes":[]}}}`,
		"classes beside a class":    `{"kind":"access_change","action":{"type":"agent_grant.allow","version":1,"connectionId":"connection-orders","allow":{"classes":["create"],"class":"delete"}}}`,
	}
	for name, body := range refused {
		console := newRequestConsole(t)
		_, proxy := console.state(t, "runtime-requests")
		recorder := postControlRequest(proxy, "runtime-requests", body)
		if recorder.Code != http.StatusBadRequest || console.creates.Load() != 0 ||
			!strings.Contains(recorder.Body.String(), "invalid_control_request") || strings.Contains(recorder.Body.String(), "sk-live-pasted") {
			t.Errorf("%s: status=%d creates=%d body=%s", name, recorder.Code, console.creates.Load(), recorder.Body.String())
		}
	}
}
