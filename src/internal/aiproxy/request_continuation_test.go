package aiproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/agentapi"
)

func TestSetupAndCredentialUpdateRequestShapes(t *testing.T) {
	valid := []agentapi.CreateRequestRequest{
		{Kind: "setup", ServiceType: "postgres", CredentialProvider: "postgres", CredentialName: "Postgres production"},
		{Kind: "credential_update", ConnectionID: "pg-prod", CredentialID: "credential-pg", CredentialProvider: "postgres", CredentialName: "Postgres production", RelatedRequestID: "request-first"},
	}
	for _, r := range valid {
		if !validCreateRequest(r) {
			t.Errorf("valid request kind %s rejected", r.Kind)
		}
	}
	invalid := []agentapi.CreateRequestRequest{
		{Kind: "setup", ServiceType: "aws", ConnectionID: "existing", CredentialProvider: "aws", CredentialName: "AWS"},
		{Kind: "setup", ServiceType: "aws", CredentialProvider: "aws"},
		{Kind: "credential_update", ConnectionID: "pg-prod", CredentialProvider: "postgres", CredentialName: "Postgres"},
		{Kind: "access", ConnectionID: "pg-prod", CredentialProvider: "postgres", CredentialName: "Postgres"},
	}
	for _, r := range invalid {
		if validCreateRequest(r) {
			t.Errorf("invalid request kind %s accepted", r.Kind)
		}
	}
}

func TestPendingRequestResumesWithCurrentSessionAndCancellationIsExplicit(t *testing.T) {
	var credentials []string
	cancelled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credentials = append(credentials, r.Header.Get(agentapi.SessionCredentialHeader))
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/requests/") {
			if cancelled {
				t.Error("unexpected list after cancel")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "requests": []any{map[string]any{
				"id": "setup-1", "kind": "setup", "status": "pending", "serviceType": "postgres",
				"approvalUrl":        "https://console.example/org/agents/requests?request=setup-1",
				"credentialProvider": "postgres", "credentialName": "Postgres production",
				"markdown": "Configure Postgres production",
				"progress": map[string]string{"stage": "configuring_credential", "credentialId": "credential-1"},
			}}})
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/setup-1/cancel/") {
			cancelled = true
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "id": "setup-1", "kind": "setup", "status": "cancelled"})
			return
		}
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer server.Close()
	client, err := agentapi.NewClient(server.URL, durableTestToken(), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := selectionState(t)
	state.client = client
	control := &controlHandler{state: state}
	proxy := &httpProxy{state: state, control: control}
	for _, credential := range []agentapi.SensitiveString{"backend-first", "backend-successor"} {
		state.setBackendCredential(credential)
		request := httptest.NewRequest(http.MethodGet, "http://phase.invalid/v1/requests", nil)
		setProxyCapability(request, "runtime-test")
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"credentialId":"credential-1"`) ||
			!strings.Contains(recorder.Body.String(), `"markdown":"Configure Postgres production"`) ||
			!strings.Contains(recorder.Body.String(), `"pollUrl":"http://phase.invalid/v1/requests/setup-1"`) {
			t.Fatalf("continuation failed: %d %s", recorder.Code, recorder.Body.String())
		}
	}
	if cancelled {
		t.Fatal("listing cancelled request")
	}
	request := httptest.NewRequest(http.MethodPost, "http://phase.invalid/v1/requests/setup-1/cancel", strings.NewReader("{}"))
	setProxyCapability(request, "runtime-test")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !cancelled || !strings.Contains(recorder.Body.String(), `"status":"cancelled"`) {
		t.Fatal("explicit cancellation failed")
	}
	if len(credentials) != 3 || credentials[0] != "backend-first" || credentials[1] != "backend-successor" || credentials[2] != "backend-successor" {
		t.Fatal("request continuation used stale backend authorization")
	}
	select {
	case <-state.fatal:
		t.Fatal("cancelled setup unnecessarily recycled runtime")
	default:
	}
}
