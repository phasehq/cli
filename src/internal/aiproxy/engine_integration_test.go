package aiproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

func durableTestToken() string {
	return "pss_user:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
}

func TestExecutableProxyCONNECTInjectionPolicyControlAndEventRedaction(t *testing.T) {
	const (
		sessionCredential = "psx_sess_test_capability_0123456789"
		decoyToken        = "ghp_phx_decoy_01234567890123456789012345678901"
		liveToken         = "ghp_live_proxy_only_012345678901234567890123"
	)
	var upstreamAuthorization, upstreamExpect, upstreamBody atomic.Value
	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		upstreamAuthorization.Store(r.Header.Get("Authorization"))
		upstreamExpect.Store(r.Header.Get("Expect"))
		body, _ := io.ReadAll(r.Body)
		upstreamBody.Store(string(body))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHost, upstreamPort, _ := net.SplitHostPort(upstreamURL.Host)
	var explicitAuthorization atomic.Value
	explicitUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		explicitAuthorization.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer explicitUpstream.Close()
	explicitURL, _ := url.Parse(explicitUpstream.URL)
	_, explicitPort, _ := net.SplitHostPort(explicitURL.Host)

	var mu sync.Mutex
	var eventBodies [][]byte
	var relayedRequests int
	var approvalOrigin string
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/events/"):
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			eventBodies = append(eventBodies, body)
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"schemaVersion":1,"accepted":1,"duplicates":0}`))
		case strings.HasSuffix(r.URL.Path, "/context/"):
			if r.Header.Get(agentapi.SessionCredentialHeader) != sessionCredential {
				t.Errorf("backend context did not receive current #1")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "session-123", "markdown": "safe context"})
		case strings.HasSuffix(r.URL.Path, "/requests/"):
			mu.Lock()
			relayedRequests++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "request-1", "status": "pending",
				"approvalUrl": approvalOrigin + "/phase/agents/requests?request=request-1",
			})
		default:
			t.Errorf("unexpected console route: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	approvalOrigin = console.URL
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}

	session := decodeTestSession(t, map[string]any{
		"schemaVersion": 1, "sessionUid": "session-123", "sessionCredential": sessionCredential,
		"expiresAt":        time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		"maxExpiresAt":     time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339Nano),
		"configGeneration": 1, "configEnv": map[string]string{},
		"connections": []any{map[string]any{
			"grantId": "grant-github", "connectionId": "connection-github", "credentialId": "credential-github",
			"serviceType": "github", "protocol": "http",
			"hosts":       []any{map[string]any{"match": "exact", "value": upstreamHost, "port": mustPort(t, upstreamPort)}},
			"injection":   map[string]any{"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}", "valueFrom": map[string]any{"source": "credential", "field": "access_token"}},
			"identifiers": map[string]string{}, "decoyMaterial": map[string]string{"access_token": decoyToken},
			"configEnv": map[string]string{}, "agentEnv": map[string]string{"GITHUB_TOKEN": decoyToken},
			"environmentBindings": []any{map[string]any{"name": "GITHUB_TOKEN", "action": "set", "source": "decoy", "sourceField": "access_token", "sensitive": true, "systemManaged": true}},
			"secretMaterial":      map[string]string{"access_token": liveToken},
		}, map[string]any{
			"grantId": "grant-explicit", "connectionId": "connection-explicit", "credentialId": "credential-explicit",
			"serviceType": "github", "protocol": "http",
			"hosts":       []any{map[string]any{"match": "exact", "value": upstreamHost, "port": mustPort(t, explicitPort)}},
			"injection":   map[string]any{"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}", "valueFrom": map[string]any{"source": "credential", "field": "access_token"}},
			"identifiers": map[string]string{}, "decoyMaterial": map[string]string{"access_token": decoyToken},
			"configEnv": map[string]string{}, "agentEnv": map[string]string{}, "environmentBindings": []any{},
			"secretMaterial": map[string]string{"access_token": liveToken},
		}},
	})
	ca, certPEM, _, err := phaseproxy.GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caDirectory := t.TempDir()
	certificatePath := filepath.Join(caDirectory, "ca.pem")
	bundlePath := filepath.Join(caDirectory, "ca-bundle.pem")
	if err := os.WriteFile(certificatePath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	proxySession := &airuntime.ProxySession{Config: session, Client: client, CA: ca, CAPaths: phaseproxy.CAPaths{Certificate: certificatePath, Bundle: bundlePath}}

	engine := New()
	engine.ListenAddress = unusedTestListenAddresses(t, "127.0.0.1")[0]
	engine.RefreshInterval = time.Hour
	engine.EventFlushInterval = 20 * time.Millisecond
	engine.EventSpoolDirectory = t.TempDir()
	engine.Transport = upstream.Client().Transport
	started := make(chan Endpoints, 1)
	engine.OnStarted = func(endpoints Endpoints) { started <- endpoints }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Serve(ctx, proxySession) }()
	var endpoints Endpoints
	select {
	case endpoints = <-started:
	case err := <-done:
		t.Fatalf("proxy engine stopped before start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("proxy engine did not start")
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append proxy CA")
	}
	proxyURL, _ := url.Parse(endpoints.ProxyURL.Reveal())
	runtimeCapability, _ := proxyURL.User.Password()
	if runtimeCapability == "" || runtimeCapability == sessionCredential {
		t.Fatal("proxy did not use a distinct process-local runtime capability")
	}
	httpClient := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}

	request, _ := http.NewRequest(http.MethodGet, upstream.URL+"/allowed", nil)
	request.Header.Set("Authorization", "Bearer "+decoyToken)
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("allowed status = %d", response.StatusCode)
	}
	if got, _ := upstreamAuthorization.Load().(string); got != "Bearer "+liveToken {
		t.Fatalf("upstream authorization was not injected: %q", got)
	}
	explicitRequest, _ := http.NewRequest(http.MethodGet, explicitUpstream.URL+"/explicit", nil)
	explicitRequest.Header.Set("Authorization", "Bearer "+decoyToken)
	explicitResponse, err := httpClient.Do(explicitRequest)
	if err != nil {
		t.Fatal(err)
	}
	explicitResponse.Body.Close()
	if explicitResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("explicit proxy status = %d", explicitResponse.StatusCode)
	}
	if got, _ := explicitAuthorization.Load().(string); got != "Bearer "+liveToken {
		t.Fatalf("explicit proxy did not inject credential: %q", got)
	}

	denied, _ := http.NewRequest(http.MethodGet, upstream.URL+"/blocked", nil)
	denied.Header.Set("Authorization", "Bearer "+decoyToken)
	response, err = httpClient.Do(denied)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("connection-authorized status = %d, want 200", response.StatusCode)
	}
	// Every managed request hands its Console event ID back to the client so
	// a CLI invocation can be correlated with the proxy's record of it.
	successEventID := response.Header.Get("X-Phase-Event-Id")
	if !strings.HasPrefix(successEventID, "event-") {
		t.Fatalf("proxied response event ID = %q", successEventID)
	}

	const withheldBody = "body held back until the tunnel answers 100 Continue"
	assertTunnelAnswersExpectContinue(t, endpoints.ProxyAddress, proxyURL, roots, upstreamHost, upstreamPort, decoyToken, withheldBody)
	if got, _ := upstreamBody.Load().(string); got != withheldBody {
		t.Fatalf("upstream body after 100-continue = %q", got)
	}
	if got, _ := upstreamExpect.Load().(string); got != "" {
		t.Fatalf("Expect header was forwarded upstream: %q", got)
	}
	if got, _ := upstreamAuthorization.Load().(string); got != "Bearer "+liveToken {
		t.Fatalf("100-continue upload was not re-credentialed: %q", got)
	}

	hitsBeforeMinting := upstreamHits.Load()
	minting, _ := http.NewRequest(http.MethodPost, upstream.URL+"/app/installations/42/access_tokens", strings.NewReader("{}"))
	minting.Header.Set("Authorization", "Bearer "+decoyToken)
	response, err = httpClient.Do(minting)
	if err != nil {
		t.Fatal(err)
	}
	mintingBody, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || !strings.Contains(string(mintingBody), "credential_minting_blocked") ||
		!strings.Contains(string(mintingBody), "mint a new credential") {
		t.Fatalf("credential minting status = %d body=%s", response.StatusCode, mintingBody)
	}
	if upstreamHits.Load() != hitsBeforeMinting {
		t.Fatal("credential-minting request reached the upstream")
	}
	if blockedEventID := response.Header.Get("X-Phase-Event-Id"); !strings.HasPrefix(blockedEventID, "event-") || blockedEventID == successEventID {
		t.Fatalf("refused request event ID = %q (success was %q)", blockedEventID, successEventID)
	}

	assertInvalidCONNECTCapability(t, endpoints.ProxyAddress, upstreamURL.Host)
	assertControlContextAndIDOR(t, endpoints.ProxyURL.Reveal(), &relayedRequests, &mu)

	time.Sleep(60 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("engine shutdown: %v", err)
	}
	mu.Lock()
	joinedEvents := bytes.Join(eventBodies, nil)
	mu.Unlock()
	if len(joinedEvents) == 0 {
		t.Fatal("expected proxy audit events")
	}
	for _, forbidden := range []string{sessionCredential, runtimeCapability, liveToken} {
		if bytes.Contains(joinedEvents, []byte(forbidden)) {
			t.Fatalf("event batch leaked secret %q: %s", forbidden, joinedEvents)
		}
	}
}

func decodeTestSession(t *testing.T, value map[string]any) *agentapi.OpenSessionResponse {
	t.Helper()
	if connections, ok := value["connections"].([]any); ok {
		for _, raw := range connections {
			if connection, ok := raw.(map[string]any); ok {
				service, _ := connection["serviceType"].(string)
				if _, present := connection["credentialProvider"]; !present {
					connection["credentialProvider"] = service
				}
				if _, present := connection["credentialName"]; !present {
					connection["credentialName"] = "Test " + service + " credential"
				}
				if _, present := connection["credentialRevision"]; !present {
					connection["credentialRevision"] = "credential-v1"
				}
				if _, present := connection["authorization"]; !present {
					connection["authorization"] = map[string]any{
						"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed",
					}
				}
			}
		}
	}
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var session agentapi.OpenSessionResponse
	if err := json.Unmarshal(payload, &session); err != nil {
		t.Fatal(err)
	}
	return &session
}

func mustPort(t *testing.T, value string) int {
	t.Helper()
	var port int
	if _, err := fmt.Sscanf(value, "%d", &port); err != nil {
		t.Fatal(err)
	}
	return port
}

func assertInvalidCONNECTCapability(t *testing.T, proxyAddress, target string) {
	t.Helper()
	connection, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	wrong := base64.StdEncoding.EncodeToString([]byte("phase:wrong-session"))
	_, _ = fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, wrong)
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("invalid #1 CONNECT status = %d", response.StatusCode)
	}
}

func assertControlContextAndIDOR(t *testing.T, rawProxyURL string, relayedRequests *int, mu *sync.Mutex) {
	t.Helper()
	proxyURL, err := url.Parse(rawProxyURL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	request, _ := http.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/context", nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("safe context")) {
		t.Fatalf("control context status=%d body=%s", response.StatusCode, body)
	}

	idorBody := strings.NewReader(`{"sessionUid":"another-session","connectionId":"connection-github","markdown":"scope"}`)
	request, _ = http.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/requests", idorBody)
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("control IDOR status = %d", response.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if *relayedRequests != 0 {
		t.Fatal("cross-session control request reached Console")
	}
}

func TestRefreshPollFailsClosedOnRevocation(t *testing.T) {
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/config/") {
			t.Errorf("route = %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"agent_session_revoked","message":"revoked","retryable":false,"details":{}}}`))
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	proxySession := emptyProxySession(t, client, "old-capability")
	state, err := newRuntimeStateWithCapability(proxySession, "monitor-runtime-capability")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	engine := New()
	engine.RefreshInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.monitor(ctx, state)
	select {
	case err := <-state.fatal:
		if !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("fatal = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh revocation did not stop session")
	}
	if err := state.availability(); err == nil {
		t.Fatal("revoked refresh left binding healthy")
	}
}

func TestControlRotateKeepsBackendCredentialProxyOnly(t *testing.T) {
	const newCredential = "new-scoped-session-capability"
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/rotate/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "session-123", "sessionCredential": newCredential,
				"expiresAt": time.Now().Add(time.Hour).UTC(), "configGeneration": 2,
			})
		case strings.HasSuffix(r.URL.Path, "/context/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "session-123", "markdown": "ok"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(emptyProxySession(t, client, "old-capability"), "runtime-capability")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	proxyHandler := &httpProxy{state: state, control: &controlHandler{state: state}}
	rotate := httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/rotate", nil)
	setProxyCapability(rotate, "runtime-capability")
	recorder := httptest.NewRecorder()
	proxyHandler.ServeHTTP(recorder, rotate)
	body := recorder.Body.Bytes()
	if recorder.Code != http.StatusOK || bytes.Contains(body, []byte(newCredential)) || bytes.Contains(body, []byte("sessionCredential")) {
		t.Fatalf("rotate status=%d body=%s", recorder.Code, body)
	}

	for credential, want := range map[string]int{"old-capability": http.StatusProxyAuthRequired, newCredential: http.StatusProxyAuthRequired, "runtime-capability": http.StatusOK} {
		request := httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/context", nil)
		setProxyCapability(request, credential)
		recorder := httptest.NewRecorder()
		proxyHandler.ServeHTTP(recorder, request)
		if recorder.Code != want {
			t.Fatalf("credential %q status=%d want=%d", credential, recorder.Code, want)
		}
	}
}

func TestControlRequestAPIRejectsBrowserSessionScopeAndUnsafeContext(t *testing.T) {
	const backendCredential = "backend-control-only"
	var requestCalls atomic.Int32
	var relayed map[string]any
	var approvalOrigin string
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/requests/"):
			requestCalls.Add(1)
			relayed = nil
			_ = json.NewDecoder(r.Body).Decode(&relayed)
			if relayed["kind"] == "setup" {
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "request-credential", "status": "pending", "kind": "setup",
					"credentialProvider": "github", "credentialName": "GitHub production", "serviceType": "github",
					"approvalUrl": approvalOrigin + "/phase/agents/requests?request=request-credential&action=setup",
				})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "request-1", "status": "pending", "kind": "credential_update",
				"connectionId": "connection-1", "credentialId": "credential-1", "credentialProvider": "aws", "credentialName": "AWS production", "grantId": "grant-1",
				"markdown":    "Update AWS deployment permissions",
				"approvalUrl": approvalOrigin + "/phase/agents/requests?request=request-1&action=setup",
			})
		case strings.HasSuffix(r.URL.Path, "/context/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "session-123", "markdown": "unsafe " + backendCredential,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	approvalOrigin = console.URL
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(emptyProxySession(t, client, backendCredential), "runtime-control-only")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	proxyHandler := &httpProxy{state: state, control: &controlHandler{state: state}}

	request := httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/requests", strings.NewReader(`{"kind":"credential_update","connectionId":"connection-1","credentialId":"credential-1","credentialProvider":"aws","credentialName":"AWS production","markdown":"update deployment permissions"}`))
	setProxyCapability(request, "runtime-control-only")
	recorder := httptest.NewRecorder()
	proxyHandler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnsupportedMediaType || requestCalls.Load() != 0 {
		t.Fatalf("missing content type status=%d calls=%d", recorder.Code, requestCalls.Load())
	}

	request = httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/requests", strings.NewReader(`{"kind":"credential_update","connectionId":"connection-1","credentialId":"credential-1","credentialProvider":"aws","credentialName":"AWS production","markdown":"update deployment permissions"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://untrusted.example")
	setProxyCapability(request, "runtime-control-only")
	recorder = httptest.NewRecorder()
	proxyHandler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || requestCalls.Load() != 0 {
		t.Fatalf("browser mutation status=%d calls=%d", recorder.Code, requestCalls.Load())
	}

	request = httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/requests", strings.NewReader(`{"sessionUid":"session-123","kind":"credential_update","connectionId":"connection-1","credentialId":"credential-1","credentialProvider":"aws","credentialName":"AWS production","markdown":"update deployment permissions"}`))
	request.Header.Set("Content-Type", "application/json")
	setProxyCapability(request, "runtime-control-only")
	recorder = httptest.NewRecorder()
	proxyHandler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || requestCalls.Load() != 0 {
		t.Fatalf("client session scope status=%d calls=%d", recorder.Code, requestCalls.Load())
	}

	request = httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/requests", strings.NewReader(`{"kind":"credential_update","connectionId":"connection-1","credentialId":"credential-1","credentialProvider":"aws","credentialName":"AWS production","markdown":"update deployment permissions","dedupKey":"deploy-1"}`))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	setProxyCapability(request, "runtime-control-only")
	recorder = httptest.NewRecorder()
	proxyHandler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || requestCalls.Load() != 1 || relayed["schemaVersion"] != float64(agentapi.SchemaVersion) || relayed["connectionId"] != "connection-1" {
		t.Fatalf("valid request status=%d calls=%d relayed=%v body=%s", recorder.Code, requestCalls.Load(), relayed, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"connectionId":"connection-1"`) ||
		!strings.Contains(recorder.Body.String(), `"grantId":"grant-1"`) ||
		!strings.Contains(recorder.Body.String(), `"markdown":"Update AWS deployment permissions"`) ||
		!strings.Contains(recorder.Body.String(), `"kind":"credential_update"`) ||
		!strings.Contains(recorder.Body.String(), `\u0026action=setup`) {
		t.Fatalf("request response contract was not relayed faithfully: %s", recorder.Body.String())
	}
	if _, exists := relayed["sessionUid"]; exists {
		t.Fatalf("proxy relayed forbidden sessionUid: %v", relayed)
	}
	for _, removed := range []string{"requested", "applyOnApprove", "serviceType"} {
		if _, exists := relayed[removed]; exists {
			t.Fatalf("field %s was unexpectedly relayed for credential update: %v", removed, relayed)
		}
	}

	request = httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/requests", strings.NewReader(`{"kind":"setup","credentialProvider":"github","credentialName":"GitHub production","serviceType":"github","markdown":"Password access is required","dedupKey":"github-password"}`))
	request.Header.Set("Content-Type", "application/json")
	setProxyCapability(request, "runtime-control-only")
	recorder = httptest.NewRecorder()
	proxyHandler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || requestCalls.Load() != 2 ||
		relayed["schemaVersion"] != float64(agentapi.SchemaVersion) ||
		relayed["kind"] != "setup" || relayed["credentialProvider"] != "github" || relayed["credentialName"] != "GitHub production" ||
		relayed["serviceType"] != "github" {
		t.Fatalf("credential request status=%d calls=%d relayed=%v body=%s", recorder.Code, requestCalls.Load(), relayed, recorder.Body.String())
	}
	if _, exists := relayed["connectionId"]; exists {
		t.Fatalf("setup request relayed a connectionId: %v", relayed)
	}
	if !strings.Contains(recorder.Body.String(), `"kind":"setup"`) ||
		!strings.Contains(recorder.Body.String(), `"id":"request-credential"`) ||
		!strings.Contains(recorder.Body.String(), `"credentialProvider":"github"`) ||
		!strings.Contains(recorder.Body.String(), `"credentialName":"GitHub production"`) ||
		!strings.Contains(recorder.Body.String(), `"serviceType":"github"`) ||
		!strings.Contains(recorder.Body.String(), `\u0026action=setup`) {
		t.Fatalf("credential response contract was not relayed faithfully: %s", recorder.Body.String())
	}

	for _, body := range []string{
		`{"kind":"setup","connectionId":"connection-1","credentialProvider":"github","credentialName":"GitHub","serviceType":"github","markdown":"need a key"}`,
		`{"kind":"setup","credentialProvider":"github/oauth","credentialName":"GitHub","serviceType":"github","markdown":"need a key"}`,
		`{"kind":"setup","credentialProvider":"github","credentialName":"GitHub","serviceType":"github","markdown":"need a key","sessionUid":"session-123"}`,
		`{"kind":"setup","credentialProvider":"github","credentialName":"GitHub","serviceType":"github/enterprise","markdown":"need a key"}`,
		`{"kind":"setup ","credentialProvider":"github","credentialName":"GitHub","serviceType":"github","markdown":"need a key"}`,
		`{"kind":"setup","credentialProvider":" github","credentialName":"GitHub","serviceType":"github","markdown":"need a key"}`,
		`{"kind":"setup","credentialProvider":"github","credentialName":" GitHub","serviceType":"github","markdown":"need a key"}`,
		`{"kind":"setup","credentialProvider":"github","credentialName":"GitHub","serviceType":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","markdown":"need a key"}`,
		`{"kind":"unsupported","connectionId":"connection-1","credentialProvider":"aws","credentialName":"AWS","markdown":"need access"}`,
		`{"kind":"credential_update","connectionId":"connection/1","credentialId":"credential-1","credentialProvider":"aws","credentialName":"AWS","markdown":"need access"}`,
		`{"kind":"credential_update","connectionId":"connection-1","credentialId":"credential-1","credentialProvider":"aws","credentialName":"AWS","markdown":"need access","dedupKey":"invalid/key"}`,
		`{"kind":"credential_update","connectionId":"connection-1","credentialId":"credential-1","credentialProvider":"aws","credentialName":"AWS","markdown":"need access","unexpected":true}`,
	} {
		request = httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/requests", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		setProxyCapability(request, "runtime-control-only")
		recorder = httptest.NewRecorder()
		proxyHandler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest || requestCalls.Load() != 2 {
			t.Fatalf("unsafe request body=%s status=%d calls=%d response=%s", body, recorder.Code, requestCalls.Load(), recorder.Body.String())
		}
	}

	request = httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/context", nil)
	setProxyCapability(request, "runtime-control-only")
	recorder = httptest.NewRecorder()
	proxyHandler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), backendCredential) {
		t.Fatalf("unsafe context status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func emptyProxySession(t *testing.T, client *agentapi.Client, credential string) *airuntime.ProxySession {
	t.Helper()
	session := decodeTestSession(t, map[string]any{
		"schemaVersion": 1, "sessionUid": "session-123", "sessionCredential": credential,
		"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
		"configGeneration": 1, "configEnv": map[string]string{}, "connections": []any{},
	})
	ca, _, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &airuntime.ProxySession{Config: session, Client: client, CA: ca}
}

// assertTunnelAnswersExpectContinue behaves like the AWS CLI: it sends the
// headers of an upload with Expect: 100-continue and does not send the body
// until the tunnel answers with 100 Continue.
func assertTunnelAnswersExpectContinue(t *testing.T, proxyAddress string, proxyURL *url.URL, roots *x509.CertPool, upstreamHost, upstreamPort, decoyToken, body string) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	target := net.JoinHostPort(upstreamHost, upstreamPort)
	capability, _ := proxyURL.User.Password()
	basic := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + capability))
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, basic); err != nil {
		t.Fatal(err)
	}
	connectResponse, err := http.ReadResponse(bufio.NewReader(raw), nil)
	if err != nil || connectResponse.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %v err=%v", connectResponse, err)
	}
	tunnel := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: upstreamHost, MinVersion: tls.VersionTLS12})
	if err := tunnel.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(tunnel, "POST /upload HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nExpect: 100-continue\r\n\r\n", target, decoyToken, len(body)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(tunnel)
	interim, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("tunnel did not answer Expect: 100-continue: %v", err)
	}
	if interim.StatusCode != http.StatusContinue {
		t.Fatalf("interim status = %d, want 100 before the body is sent", interim.StatusCode)
	}
	if _, err := io.WriteString(tunnel, body); err != nil {
		t.Fatal(err)
	}
	final, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := final.Header.Get("X-Phase-Event-Id"); !strings.HasPrefix(got, "event-") {
		t.Fatalf("tunnelled response event ID = %q", got)
	}
	defer final.Body.Close()
	payload, _ := io.ReadAll(final.Body)
	if final.StatusCode != http.StatusOK || string(payload) != "ok" {
		t.Fatalf("final status = %d body=%q", final.StatusCode, payload)
	}
}
