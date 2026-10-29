package aiproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

func TestControlStatusIsAuthenticatedSafePrintableAndNoStore(t *testing.T) {
	console := httptest.NewServer(http.NotFoundHandler())
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := decodeTestSession(t, map[string]any{
		"schemaVersion": 1, "sessionUid": "sensitive-session", "sessionCredential": "sensitive-backend-capability",
		"expiresAt": time.Now().Add(2 * time.Hour).UTC(), "maxExpiresAt": time.Now().Add(3 * time.Hour).UTC(),
		"configGeneration": 1, "configEnv": map[string]string{"SENSITIVE_CONFIG": "do-not-print"},
		"connections": []any{map[string]any{
			"grantId": "sensitive-grant", "connectionId": "connection-pg", "connectionName": "console-dev-pg",
			"credentialId": "sensitive-credential", "credentialName": "Postgres production", "credentialProvider": "postgres", "credentialRevision": "credential-v1", "serviceType": "postgres", "protocol": "postgres",
			"hosts":         []any{map[string]any{"match": "exact", "value": "sensitive.db.internal", "port": 5432}},
			"injection":     map[string]any{"action": "pg_handshake"},
			"identifiers":   map[string]string{"username": "sensitive-user"},
			"decoyMaterial": map[string]string{"password": "sensitive-decoy"}, "agentEnv": map[string]string{"PGPASSWORD": "sensitive-decoy"},
			"secretMaterial": map[string]string{"password": "sensitive-live-password"},
			"authorization":  map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
		}},
	})
	ca, _, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(&airuntime.ProxySession{Config: session, Client: client, CA: ca}, "runtime-status-capability")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	proxy := &httpProxy{state: state, control: &controlHandler{state: state}}

	request := httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/status", nil)
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/status", nil)
	setProxyCapability(request, "runtime-status-capability")
	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	var response remoteapi.StatusResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != 1 || response.Kind != "phase.ai.status" || !response.SafeToPrint || len(response.Connections) != 1 {
		t.Fatalf("status projection=%+v", response)
	}
	connection := response.Connections[0]
	if connection.ConnectionID != "connection-pg" || connection.Name != "console-dev-pg" || connection.ServiceType != "postgres" ||
		connection.Protocol != "postgres" || connection.CredentialID != "sensitive-credential" || connection.CredentialName != "Postgres production" ||
		connection.CredentialProvider != "postgres" || connection.CredentialRevision != "credential-v1" || connection.State != "ready" || connection.ExpiresAt != nil {
		t.Fatalf("connection status=%+v", connection)
	}
	if response.Links != publicControlLinks() {
		t.Fatalf("status links=%+v", response.Links)
	}
	for _, forbidden := range []string{
		"sensitive-session", "sensitive-backend-capability", "sensitive-grant", "sensitive.db.internal",
		"sensitive-user", "sensitive-decoy", "sensitive-live-password", "sensitive-approval", "sensitive-request", "SENSITIVE_CONFIG", "do-not-print",
		"hosts", "identifiers", "agentEnv", "decoyMaterial", "grantId", "sessionUid", "caCertificate",
	} {
		if strings.Contains(recorder.Body.String(), forbidden) {
			t.Fatalf("safe status leaked %q: %s", forbidden, recorder.Body.String())
		}
	}
	if strings.Contains(recorder.Body.String(), "refresh") {
		t.Fatalf("safe status advertised refresh: %s", recorder.Body.String())
	}
}

func TestControlCapabilitiesAreRegistryDerivedAndCredentialFree(t *testing.T) {
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !strings.HasSuffix(request.URL.Path, "/sessions/session-123/capabilities/") {
			http.NotFound(w, request)
			return
		}
		if got := request.Header.Get(agentapi.SessionCredentialHeader); got != "backend-capability" {
			t.Errorf("session credential = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schemaVersion":        1,
			"matcherSchemaVersion": 1,
			"kind":                 "phase.ai.capabilities",
			"sessionUid":           "session-123",
			"services": []any{map[string]any{
				"serviceType": "postgres", "displayName": "PostgreSQL",
				"credentialProviders": []string{"postgres"},
				"clientMatchers":      []any{map[string]any{"kind": "executable", "values": []string{"psql"}}},
				"connectionIds":       []string{"connection-pg"},
			}},
		})
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, controlAccessSessionPayload("backend-capability", 1), "runtime-capability")
	defer state.destroy()
	proxy := &httpProxy{state: state, control: &controlHandler{state: state}}

	request := httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/capabilities", nil)
	setProxyCapability(request, "runtime-capability")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"serviceType":"postgres"`) ||
		strings.Contains(recorder.Body.String(), "pg-live") || strings.Contains(recorder.Body.String(), "backend-capability") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestControlContextAcceptsOnlyOneServiceType(t *testing.T) {
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !strings.HasSuffix(request.URL.Path, "/sessions/session-123/context/") || request.URL.Query().Get("serviceType") != "postgres" {
			http.NotFound(w, request)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "session-123", "serviceType": "postgres", "markdown": "PostgreSQL context"})
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, controlAccessSessionPayload("backend-context", 1), "runtime-context")
	defer state.destroy()
	proxy := &httpProxy{state: state, control: &controlHandler{state: state}}

	request := httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/context?serviceType=postgres", nil)
	setProxyCapability(request, "runtime-context")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "PostgreSQL context") ||
		!strings.Contains(recorder.Body.String(), `"serviceType":"postgres"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/context?serviceType=postgres&serviceType=aws", nil)
	setProxyCapability(request, "runtime-context")
	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_context_query") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/context?serviceType="+strings.Repeat("p", 65), nil)
	setProxyCapability(request, "runtime-context")
	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_context_query") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestLocalDiscoverRejectsLiveMaterialBeforeRelay(t *testing.T) {
	const live = "pg-live"
	tests := map[string]map[string]any{
		"config env": {
			"schemaVersion": 1, "sessionUid": "session-123", "configGeneration": 1,
			"configEnv": map[string]string{"UNSAFE": "prefix-" + live}, "connections": []any{},
		},
		"agent env": {
			"schemaVersion": 1, "sessionUid": "session-123", "configGeneration": 1,
			"configEnv": map[string]string{}, "connections": []any{map[string]any{
				"grantId": "grant-pg", "agentEnv": map[string]string{"UNSAFE": "prefix-" + live},
			}},
		},
	}
	for name, discover := range tests {
		t.Run(name, func(t *testing.T) {
			console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if !strings.HasSuffix(request.URL.Path, "/sessions/session-123/discover/") {
					http.NotFound(w, request)
					return
				}
				_ = json.NewEncoder(w).Encode(discover)
			}))
			defer console.Close()
			client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
			if err != nil {
				t.Fatal(err)
			}
			state := controlRuntimeState(t, client, controlAccessSessionPayload("backend-discover", 1), "discover-runtime")
			defer state.destroy()
			proxy := &httpProxy{state: state, control: &controlHandler{state: state}}
			request := httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/discover", nil)
			setProxyCapability(request, "discover-runtime")
			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "unsafe_agent_discover_response") ||
				strings.Contains(recorder.Body.String(), live) {
				t.Fatalf("unsafe discover relay status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestAWSCredentialRevisionHotSwapsLiveAccessKeyIDWithStableAgentPlan(t *testing.T) {
	const (
		fakeAccessKeyID = "AKIAPHASEDECOY000000"
		oldAccessKeyID  = "AKIAOLDLIVEEXAMPLE00"
		newAccessKeyID  = "AKIANEWLIVEEXAMPLE00"
	)
	console := httptest.NewServer(http.NotFoundHandler())
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	payload := func(generation int, revision, materialGeneration, liveAccessKeyID, fakeID string) map[string]any {
		return map[string]any{
			"schemaVersion": 1, "sessionUid": "aws-rotation", "sessionCredential": "backend-only",
			"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
			"configGeneration": generation, "configEnv": map[string]string{"AWS_REGION": "us-east-1"},
			"connections": []any{map[string]any{
				"grantId": "grant-aws", "connectionId": "connection-aws", "connectionName": "Production AWS", "credentialId": "credential-aws",
				"credentialName": "AWS - EC2, RDS, S3 full access", "credentialProvider": "aws", "credentialRevision": revision, "materialGeneration": materialGeneration,
				"serviceType": "aws", "protocol": "http", "hosts": []any{map[string]any{"match": "suffix", "value": ".amazonaws.com", "port": 443}},
				"injection":   map[string]any{"action": "aws_sigv4", "serviceFrom": "host", "regionFrom": "host", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"accessKeyId": "access_key_id", "secretAccessKey": "secret_access_key"}}},
				"identifiers": map[string]string{"accessKeyId": fakeID}, "decoyMaterial": map[string]string{"secretAccessKey": "phase-decoy-secret"},
				"agentEnv":       map[string]string{"AWS_ACCESS_KEY_ID": fakeID, "AWS_SECRET_ACCESS_KEY": "phase-decoy-secret"},
				"secretMaterial": map[string]string{"accessKeyId": liveAccessKeyID, "secretAccessKey": "live-" + revision},
				"authorization":  map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
			}},
		}
	}
	state := controlRuntimeState(t, client, payload(1, "credential-v1", "material-v1", oldAccessKeyID, fakeAccessKeyID), "runtime-only")
	defer state.destroy()
	oldBinding := state.bindings[0]
	inFlight, err := state.protocolBinding("grant-aws", "http")
	if err != nil {
		t.Fatal(err)
	}

	rotated := decodeTestSession(t, payload(2, "credential-v2", "material-v2", newAccessKeyID, fakeAccessKeyID))
	if err := state.replaceConfig(&rotated.SessionConfig); err != nil {
		t.Fatalf("live-only AWS rotation required a process restart: %v", err)
	}
	if _, retained := oldBinding.connection.SecretMaterial.Get("access_key_id"); retained {
		t.Fatal("superseded runtime state retained the old live AWS identity")
	}
	if retained, ok := inFlight.binding.connection.SecretMaterial.Get("access_key_id"); !ok || retained != oldAccessKeyID {
		t.Fatal("active request snapshot lost its immutable live AWS identity")
	}
	inFlight.release()
	if _, retained := inFlight.binding.connection.SecretMaterial.Get("access_key_id"); retained {
		t.Fatal("completed request snapshot retained the old live AWS identity")
	}
	binding, err := state.findBinding("sts.amazonaws.com", 443, "/")
	if err != nil {
		t.Fatal(err)
	}
	liveID, _ := binding.connection.SecretMaterial.Get("access_key_id")
	agentID, _ := binding.connection.AgentEnv.Get("AWS_ACCESS_KEY_ID")
	if liveID != newAccessKeyID || agentID != fakeAccessKeyID || binding.connection.CredentialRevision != "credential-v2" {
		t.Fatalf("rotation did not separate hot-swapped live ID from stable Agent ID: live=%q agent=%q revision=%q", liveID, agentID, binding.connection.CredentialRevision)
	}
	printable, err := json.Marshal(state.statusConnections(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(printable, []byte(oldAccessKeyID)) || bytes.Contains(printable, []byte(newAccessKeyID)) {
		t.Fatalf("printable status leaked an AWS live access-key ID: %s", printable)
	}

	changedAgentPlan := decodeTestSession(t, payload(3, "credential-v3", "material-v3", newAccessKeyID, "AKIAPHASEDECOY999999"))
	if err := state.replaceConfig(&changedAgentPlan.SessionConfig); !errors.Is(err, airuntime.ErrSessionReprovisionRequired) {
		t.Fatalf("changed Agent-visible AWS ID did not require restart: %v", err)
	}
}

func TestControlRequestWaitReturnsPollURLAndRefreshesCredentialUpdate(t *testing.T) {
	const backendCredential = "backend-wait-capability"
	var approvalURL string
	initialPayload := controlAccessSessionPayload(backendCredential, 1)
	refreshedPayload := controlAccessSessionPayload("", 2)
	delete(refreshedPayload, "sessionCredential")
	var createCalls, pollCalls, refreshCalls atomic.Int32
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/requests/"):
			createCalls.Add(1)
			var body map[string]any
			_ = json.NewDecoder(req.Body).Decode(&body)
			if body["kind"] == "setup" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"schemaVersion": 1, "id": "request-credential", "status": "approved", "kind": "setup",
					"credentialProvider": "github", "credentialName": "GitHub production", "serviceType": "github", "credentialId": "credential-github",
					"connectionId": "connection-github", "grantId": "grant-github", "runtimeAction": "restart_required",
				})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"id":"request-1","approvalUrl":"`+approvalURL+`","status":"pending","kind":"credential_update","credentialId":"credential-pg","credentialProvider":"postgres","credentialName":"Postgres production","connectionId":"connection-pg","grantId":"grant-pg"}`)
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/requests/request-1/"):
			pollCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "request-1", "status": "approved", "kind": "credential_update", "credentialId": "credential-pg", "credentialProvider": "postgres", "credentialName": "Postgres production", "connectionId": "connection-pg", "grantId": "grant-pg",
				"approvalUrl": approvalURL,
			})
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/config/"):
			refreshCalls.Add(1)
			_ = json.NewEncoder(w).Encode(refreshedPayload)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	approvalURL = console.URL + "/Agent%20REST%20org/agents/requests?request=request-1&action=setup"
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, initialPayload, "runtime-wait-capability")
	defer state.destroy()
	proxy := &httpProxy{state: state, control: &controlHandler{state: state}}
	approvalURLJSON := strings.ReplaceAll(approvalURL, "&", `\u0026`)

	request := httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/requests", strings.NewReader(`{"kind":"credential_update","connectionId":"connection-pg","credentialId":"credential-pg","credentialProvider":"postgres","credentialName":"Postgres production","markdown":"update database credential"}`))
	request.Header.Set("Content-Type", "application/json")
	setProxyCapability(request, "runtime-wait-capability")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || !strings.Contains(recorder.Body.String(), `"pollUrl":"http://phase.invalid/v1/requests/request-1"`) ||
		!strings.Contains(recorder.Body.String(), `"approvalUrl":"`+approvalURLJSON+`"`) ||
		pollCalls.Load() != 0 || refreshCalls.Load() != 0 {
		t.Fatalf("non-wait response status=%d polls=%d refreshes=%d body=%s", recorder.Code, pollCalls.Load(), refreshCalls.Load(), recorder.Body.String())
	}

	previousInterval := controlPollInterval
	controlPollInterval = time.Millisecond
	t.Cleanup(func() { controlPollInterval = previousInterval })
	request = httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/requests?wait=1", strings.NewReader(`{"kind":"credential_update","connectionId":"connection-pg","credentialId":"credential-pg","credentialProvider":"postgres","credentialName":"Postgres production","markdown":"update database credential"}`))
	request.Header.Set("Content-Type", "application/json")
	setProxyCapability(request, "runtime-wait-capability")
	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || !strings.Contains(recorder.Body.String(), `"status":"approved"`) ||
		!strings.Contains(recorder.Body.String(), `"runtimeAction":"retry"`) ||
		!strings.Contains(recorder.Body.String(), `"approvalUrl":"`+approvalURLJSON+`"`) ||
		strings.Contains(recorder.Body.String(), "pollUrl") || pollCalls.Load() != 1 || refreshCalls.Load() != 1 || createCalls.Load() != 2 {
		t.Fatalf("wait response status=%d creates=%d polls=%d refreshes=%d body=%s", recorder.Code, createCalls.Load(), pollCalls.Load(), refreshCalls.Load(), recorder.Body.String())
	}
	boundaryRequest := httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/requests/request-1?wait=300", nil)
	if wait, err := controlWait(boundaryRequest); err != nil || wait != 300*time.Second {
		t.Fatalf("maximum control wait = %s, err=%v", wait, err)
	}
	for _, target := range []string{
		phaseproxy.ControlURL + "/v1/requests?wait=301",
		phaseproxy.ControlURL + "/v1/requests?wait=1&other=1",
		phaseproxy.ControlURL + "/v1/requests?wait=1&wait=2",
	} {
		request = httptest.NewRequest(http.MethodPost, target, bytes.NewReader([]byte(`{"kind":"credential_update","connectionId":"connection-pg","credentialId":"credential-pg","credentialProvider":"postgres","credentialName":"Postgres production","markdown":"update database credential"}`)))
		request.Header.Set("Content-Type", "application/json")
		setProxyCapability(request, "runtime-wait-capability")
		recorder = httptest.NewRecorder()
		proxy.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "0 through 300") {
			t.Fatalf("invalid wait %q status=%d body=%s", target, recorder.Code, recorder.Body.String())
		}
	}
	if createCalls.Load() != 2 {
		t.Fatalf("invalid wait reached backend: creates=%d", createCalls.Load())
	}

	request = httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/requests?wait=1", strings.NewReader(`{"kind":"setup","credentialProvider":"github","credentialName":"GitHub production","serviceType":"github","markdown":"need an API key"}`))
	request.Header.Set("Content-Type", "application/json")
	setProxyCapability(request, "runtime-wait-capability")
	recorder = httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"kind":"setup"`) ||
		!strings.Contains(recorder.Body.String(), `"credentialId":"credential-github"`) ||
		!strings.Contains(recorder.Body.String(), `"connectionId":"connection-github"`) ||
		!strings.Contains(recorder.Body.String(), `"grantId":"grant-github"`) ||
		!strings.Contains(recorder.Body.String(), `"runtimeAction":"restart_required"`) || refreshCalls.Load() != 1 {
		t.Fatalf("credential approval triggered connection refresh: status=%d refreshes=%d body=%s", recorder.Code, refreshCalls.Load(), recorder.Body.String())
	}
	select {
	case err := <-state.fatal:
		if !errors.Is(err, airuntime.ErrSessionReprovisionRequired) {
			t.Fatalf("credential fulfillment fatal error = %v", err)
		}
	default:
		t.Fatal("credential fulfillment did not require process reprovision")
	}
}

func TestDefaultControlPollIntervalIsThreeSeconds(t *testing.T) {
	if defaultControlPollInterval != 3*time.Second {
		t.Fatalf("default control poll interval = %s, want 3s", defaultControlPollInterval)
	}
	previousInterval := controlPollInterval
	controlPollInterval = 0
	t.Cleanup(func() { controlPollInterval = previousInterval })
	delay := controlPollInterval
	if delay <= 0 {
		delay = defaultControlPollInterval
	}
	if delay != 3*time.Second {
		t.Fatalf("fallback control poll interval = %s, want 3s", delay)
	}
}

func TestApprovedCredentialReplayOnFreshRuntimeReturnsRetryWithoutReprovision(t *testing.T) {
	console := httptest.NewServer(http.NotFoundHandler())
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, controlAccessSessionPayload("backend-capability", 1), "runtime-capability")
	defer state.destroy()
	handler := &controlHandler{state: state}
	request := httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/requests/request-credential", nil)
	response, err := handler.finishRequestWithin(request, &agentapi.RequestResponse{
		SchemaVersion: agentapi.SchemaVersion, ID: "request-credential", Status: "approved", Kind: "setup",
		CredentialProvider: "postgres", CredentialName: "Postgres production", ServiceType: "postgres", CredentialID: "credential-pg",
		ConnectionID: "connection-pg", GrantID: "grant-pg", RuntimeAction: agentapi.RequestRuntimeActionRestartRequired,
	}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if response.RuntimeAction != agentapi.RequestRuntimeActionRetry {
		t.Fatalf("runtime action = %q, want retry", response.RuntimeAction)
	}
	handler.applyRequestRuntimeAction(response, nil)
	select {
	case fatal := <-state.fatal:
		t.Fatalf("fresh runtime was terminated on approved request replay: %v", fatal)
	default:
	}
}

func TestValidApprovalURL(t *testing.T) {
	const requestID = "request-1"
	for _, test := range []struct {
		name        string
		value       string
		requestKind string
		want        bool
	}{
		{name: "canonical encoded organisation", value: "https://console.example/R%26D%20%2F%20Ops/agents/requests?request=request-1", requestKind: "setup", want: true},
		{name: "arbitrary canonical https origin", value: "https://ui.other-origin.example/phase/agents/requests?request=request-1", requestKind: "credential_update", want: true},
		{name: "loopback development", value: "http://localhost:3000/phase/agents/requests?request=request-1", requestKind: "setup", want: true},
		{name: "setup fulfillment action", value: "https://console.example/phase/agents/requests?request=request-1&action=setup", requestKind: "setup", want: true},
		{name: "setup fulfillment action on update", value: "https://console.example/phase/agents/requests?request=request-1&action=setup", requestKind: "credential_update", want: true},
		{name: "setup action on unknown request kind", value: "https://console.example/phase/agents/requests?request=request-1&action=setup", requestKind: "unsupported"},
		{name: "plain link on unknown request kind", value: "https://console.example/phase/agents/requests?request=request-1", requestKind: "unsupported"},
		{name: "unknown credential action", value: "https://console.example/phase/agents/requests?request=request-1&action=create", requestKind: "setup"},
		{name: "non-loopback http", value: "http://console.example/phase/agents/requests?request=request-1", requestKind: "setup"},
		{name: "credentials", value: "https://user:password@console.example/phase/agents/requests?request=request-1", requestKind: "setup"},
		{name: "wrong route", value: "https://console.example/phase/agents/all?request=request-1", requestKind: "setup"},
		{name: "wrong request", value: "https://console.example/phase/agents/requests?request=request-2", requestKind: "setup"},
		{name: "extra query", value: "https://console.example/phase/agents/requests?request=request-1&token=secret", requestKind: "setup"},
		{name: "fragment", value: "https://console.example/phase/agents/requests?request=request-1#secret", requestKind: "setup"},
		{name: "non web scheme", value: "javascript:alert(1)", requestKind: "setup"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validApprovalURL(test.value, requestID, test.requestKind); got != test.want {
				t.Fatalf("validApprovalURL(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

func TestPendingRequestRequiresApprovalURL(t *testing.T) {
	err := validateRequestApprovalURL(&agentapi.RequestResponse{
		ID: "request-1", Status: "pending",
	}, "request-1", true)
	if err == nil || !strings.Contains(err.Error(), "without an approval URL") {
		t.Fatalf("missing pending approval URL error = %v", err)
	}
	if err := validateRequestApprovalURL(&agentapi.RequestResponse{
		ID: "request-1", Status: "approved",
	}, "request-1", true); err != nil {
		t.Fatalf("resolved response unexpectedly required approval URL: %v", err)
	}
}

func TestControlPollRejectsChangedApprovalURL(t *testing.T) {
	const backendCredential = "backend-invalid-approval-url"
	payload := controlAccessSessionPayload(backendCredential, 1)
	var approvalURL string
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/requests/"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          "request-1",
				"status":      "pending",
				"approvalUrl": approvalURL,
			})
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/requests/request-1/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          "request-1",
				"status":      "pending",
				"approvalUrl": "https://console.example/phase/agents/requests?request=request-2",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	approvalURL = console.URL + "/phase/agents/requests?request=request-1"
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, payload, "runtime-invalid-approval-url")
	defer state.destroy()
	proxy := &httpProxy{state: state, control: &controlHandler{state: state}}
	previousInterval := controlPollInterval
	controlPollInterval = time.Millisecond
	t.Cleanup(func() { controlPollInterval = previousInterval })

	request := httptest.NewRequest(
		http.MethodPost,
		phaseproxy.ControlURL+"/v1/requests?wait=1",
		strings.NewReader(`{"kind":"credential_update","connectionId":"connection-pg","credentialId":"credential-pg","credentialProvider":"postgres","credentialName":"Postgres production","markdown":"update database credential"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	setProxyCapability(request, "runtime-invalid-approval-url")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), "console.example") {
		t.Fatalf("invalid changed approval URL was relayed: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestApprovedCredentialUpdateRefreshFailureFailsClosed(t *testing.T) {
	const backendCredential = "backend-failed-refresh-capability"
	payload := controlAccessSessionPayload(backendCredential, 1)
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/requests/request-1/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "request-1", "status": "approved", "kind": "credential_update", "credentialId": "credential-pg", "credentialProvider": "postgres", "credentialName": "Postgres production", "connectionId": "connection-pg", "grantId": "grant-pg",
			})
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/config/"):
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":{"code":"agent_config_unavailable","message":"unavailable","retryable":true,"details":{}}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, payload, "runtime-failed-refresh-capability")
	defer state.destroy()
	proxy := &httpProxy{state: state, control: &controlHandler{state: state}}

	request := httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/requests/request-1", nil)
	setProxyCapability(request, "runtime-failed-refresh-capability")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), `"code":"approved_request_refresh_failed"`) {
		t.Fatalf("failed approval refresh status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if state.availability() == nil {
		t.Fatal("failed approval refresh left the proxy available")
	}
}

func TestApprovedCredentialUpdateRefreshRejectsSubstitutedTarget(t *testing.T) {
	for _, test := range []struct {
		name              string
		malformedResponse bool
		config            func() map[string]any
	}{
		{
			name: "credential maps to a different identity",
			config: func() map[string]any {
				payload := controlAccessSessionPayload("", 2)
				connections := payload["connections"].([]any)
				connections[0].(map[string]any)["credentialId"] = "credential-substituted"
				return payload
			},
		},
		{
			name: "grant maps to a different connection",
			config: func() map[string]any {
				payload := controlAccessSessionPayload("", 2)
				connections := payload["connections"].([]any)
				connections[0].(map[string]any)["connectionId"] = "connection-substituted"
				return payload
			},
		},
		{
			name:              "approved response omits target mapping",
			malformedResponse: true,
			config: func() map[string]any {
				return controlAccessSessionPayload("", 2)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			const backendCredential = "backend-target-check-capability"
			initial := controlAccessSessionPayload(backendCredential, 1)
			refreshed := test.config()
			delete(refreshed, "sessionCredential")
			var refreshCalls atomic.Int32
			console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch {
				case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/requests/request-1/"):
					connectionID, grantID := "connection-pg", "grant-pg"
					if test.malformedResponse {
						connectionID, grantID = "", ""
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"id": "request-1", "status": "approved", "kind": "credential_update", "credentialId": "credential-pg", "credentialProvider": "postgres", "credentialName": "Postgres production", "connectionId": connectionID, "grantId": grantID,
					})
				case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/config/"):
					refreshCalls.Add(1)
					_ = json.NewEncoder(w).Encode(refreshed)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer console.Close()
			client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
			if err != nil {
				t.Fatal(err)
			}
			state := controlRuntimeState(t, client, initial, "runtime-target-check-capability")
			defer state.destroy()
			proxy := &httpProxy{state: state, control: &controlHandler{state: state}}

			request := httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/requests/request-1", nil)
			setProxyCapability(request, "runtime-target-check-capability")
			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), `"code":"approved_request_refresh_failed"`) {
				t.Fatalf("inactive target status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if state.availability() == nil {
				t.Fatal("inactive or substituted approval target left the proxy available")
			}
			if test.malformedResponse && refreshCalls.Load() != 0 {
				t.Fatalf("malformed approval response triggered %d config refreshes", refreshCalls.Load())
			}
		})
	}
}

func TestControlPollWaitDeadlineAndCallerCancellation(t *testing.T) {
	previousInterval := controlPollInterval
	controlPollInterval = time.Millisecond
	t.Cleanup(func() { controlPollInterval = previousInterval })

	for _, test := range []struct {
		name       string
		cancel     bool
		wantStatus int
	}{
		{name: "local wait deadline returns pending", wantStatus: http.StatusOK},
		{name: "caller cancellation aborts", cancel: true, wantStatus: http.StatusBadGateway},
	} {
		t.Run(test.name, func(t *testing.T) {
			const backendCredential = "backend-poll-wait-capability"
			payload := controlAccessSessionPayload(backendCredential, 1)
			blocked := make(chan struct{}, 1)
			backendCanceled := make(chan struct{}, 1)
			console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodGet || !strings.HasSuffix(req.URL.Path, "/requests/request-1/") {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				blocked <- struct{}{}
				<-req.Context().Done()
				backendCanceled <- struct{}{}
			}))
			defer console.Close()
			client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
			if err != nil {
				t.Fatal(err)
			}
			state := controlRuntimeState(t, client, payload, "runtime-poll-wait-capability")
			defer state.destroy()
			proxy := &httpProxy{state: state, control: &controlHandler{state: state}}
			request := httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/requests/request-1?wait=1", nil)
			setProxyCapability(request, "runtime-poll-wait-capability")
			if test.cancel {
				ctx, cancel := context.WithCancel(request.Context())
				request = request.WithContext(ctx)
				go func() {
					<-blocked
					cancel()
				}()
			}
			started := time.Now()
			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, request)
			elapsed := time.Since(started)
			if recorder.Code != test.wantStatus {
				t.Fatalf("poll wait status=%d want=%d body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			select {
			case <-backendCanceled:
			case <-time.After(time.Second):
				t.Fatal("in-flight backend poll was not canceled")
			}
			if test.cancel {
				if strings.Contains(recorder.Body.String(), "pollUrl") || elapsed >= time.Second {
					t.Fatalf("caller cancellation was converted to pending or delayed: elapsed=%s body=%s", elapsed, recorder.Body.String())
				}
			} else {
				if elapsed < 900*time.Millisecond || elapsed > 1500*time.Millisecond ||
					!strings.Contains(recorder.Body.String(), `"status":"pending"`) || !strings.Contains(recorder.Body.String(), `"pollUrl":"http://phase.invalid/v1/requests/request-1"`) {
					t.Fatalf("local wait bound elapsed=%s body=%s", elapsed, recorder.Body.String())
				}
			}
		})
	}
}

func TestControlRefreshCompatibilityAcceptsZeroBodyAndEmptyObject(t *testing.T) {
	const backendCredential = "backend-refresh-capability"
	payload := controlAccessSessionPayload(backendCredential, 1)
	responsePayload := controlAccessSessionPayload("", 1)
	delete(responsePayload, "sessionCredential")
	var refreshCalls atomic.Int32
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/config/") {
			refreshCalls.Add(1)
			_ = json.NewEncoder(w).Encode(responsePayload)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, payload, "runtime-refresh-capability")
	defer state.destroy()
	proxy := &httpProxy{state: state, control: &controlHandler{state: state}}

	for _, body := range []string{"", "{}", " \n { } \t"} {
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		request := httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/refresh", reader)
		setProxyCapability(request, "runtime-refresh-capability")
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("compatible refresh body=%q status=%d response=%s", body, recorder.Code, recorder.Body.String())
		}
	}
	for _, body := range []string{"null", "[]", `{"unexpected":true}`, "{} {}"} {
		request := httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/refresh", strings.NewReader(body))
		setProxyCapability(request, "runtime-refresh-capability")
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid refresh body=%q status=%d response=%s", body, recorder.Code, recorder.Body.String())
		}
	}
	if refreshCalls.Load() != 3 {
		t.Fatalf("refresh backend calls=%d", refreshCalls.Load())
	}
}

func TestRuntimeConfigRefreshesAreSerialized(t *testing.T) {
	var calls, active, maximum atomic.Int32
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || !strings.HasSuffix(req.URL.Path, "/config/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		calls.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schemaVersion": 1, "sessionUid": "session-123", "expiresAt": time.Now().Add(time.Hour).UTC(),
			"maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(), "configGeneration": 1,
			"configEnv": map[string]string{}, "connections": []any{},
		})
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(emptyProxySession(t, client, "backend-serialized-capability"), "runtime-serialized-capability")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()

	var wait sync.WaitGroup
	errors := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := state.refreshConfig(t.Context())
			errors <- err
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 || maximum.Load() != 1 {
		t.Fatalf("refresh calls=%d maximum concurrent=%d", calls.Load(), maximum.Load())
	}
}

func controlAccessSessionPayload(credential string, generation int) map[string]any {
	authorization := map[string]any{
		"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed",
	}
	return map[string]any{
		"schemaVersion": 1, "sessionUid": "session-123", "sessionCredential": credential,
		"expiresAt": time.Now().Add(2 * time.Hour).UTC(), "maxExpiresAt": time.Now().Add(3 * time.Hour).UTC(),
		"configGeneration": generation, "configEnv": map[string]string{},
		"connections": []any{map[string]any{
			"grantId": "grant-pg", "connectionId": "connection-pg", "connectionName": "console-dev-pg", "credentialId": "credential-pg",
			"credentialName": "Postgres production", "credentialProvider": "postgres", "credentialRevision": "credential-v1", "materialGeneration": "material-v1",
			"serviceType": "postgres", "protocol": "postgres",
			"hosts":     []any{map[string]any{"match": "exact", "value": "db.example", "port": 5432}},
			"injection": map[string]any{"action": "pg_handshake"}, "identifiers": map[string]string{"username": "db-user"},
			"decoyMaterial": map[string]string{"password": "pg-decoy"}, "agentEnv": map[string]string{},
			"secretMaterial": map[string]string{"username": "db-user", "password": "pg-live"}, "authorization": authorization,
		}},
	}
}

func controlRuntimeState(t *testing.T, client *agentapi.Client, payload map[string]any, capability string) *runtimeState {
	t.Helper()
	session := decodeTestSession(t, payload)
	ca, _, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(&airuntime.ProxySession{Config: session, Client: client, CA: ca}, agentapi.SensitiveString(capability))
	if err != nil {
		t.Fatal(err)
	}
	return state
}
