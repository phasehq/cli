package aiproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/phasehq/golang-sdk/v2/phase/crypto"
)

const (
	customDecoyToken = "sk-phx-decoy-0123456789abcdef0123"
	customLiveToken  = "sk-live-proxy-only-0123456789abcd"
)

func customDefinition() map[string]any {
	return map[string]any{
		"specVersion": 1,
		"hosts":       []any{map[string]any{"match": "exact", "value": "api.example.test", "port": 443, "path": "/v1/*"}},
		"fields": []any{
			map[string]any{"name": "token", "kind": "secret", "source": map[string]any{"type": "sealed"}, "env": "EXAMPLE_API_KEY", "decoyPrefix": "sk-"},
			map[string]any{"name": "username", "kind": "identifier", "value": "alice"},
		},
		"injections": []any{map[string]any{"type": "header", "name": "Authorization", "prefix": "Bearer ", "field": "token", "whenAbsent": "attach"}},
		"preset":     "bearer",
	}
}

func bearerAttachInjection() map[string]any {
	return map[string]any{
		"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}",
		"valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach",
	}
}

// customConnectionPayload is a custom HTTP Connection as the Console sends it
// on the resolved lane.
func customConnectionPayload(decoy, live string) map[string]any {
	return map[string]any{
		"grantId": "grant-example", "connectionId": "connection-example", "connectionName": "Example API",
		"credentialId": "connection-example", "credentialName": "Example API", "credentialProvider": "http",
		"credentialRevision": "3", "materialGeneration": "2.3", "serviceType": "http", "protocol": "http",
		"hosts":            []any{map[string]any{"match": "exact", "value": "api.example.test", "port": 443, "path": "/v1/*"}},
		"connectionConfig": customDefinition(),
		"configEnv":        map[string]string{},
		"injections":       []any{bearerAttachInjection()},
		"identifiers":      map[string]string{"username": "alice"},
		"decoyMaterial":    map[string]string{"token": decoy},
		"agentEnv":         map[string]string{"EXAMPLE_API_KEY": decoy},
		"environmentBindings": []any{map[string]any{
			"name": "EXAMPLE_API_KEY", "action": "set", "source": "decoy", "sourceField": "token", "sensitive": true, "systemManaged": false,
		}},
		"secretMaterial": map[string]string{"token": live},
		"authorization":  map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
	}
}

func customSessionPayload(credential string, generation int, connections ...map[string]any) map[string]any {
	list := make([]any, 0, len(connections))
	for _, connection := range connections {
		list = append(list, connection)
	}
	payload := map[string]any{
		"schemaVersion": 1, "sessionUid": "session-custom",
		"expiresAt": time.Now().Add(2 * time.Hour).UTC(), "maxExpiresAt": time.Now().Add(3 * time.Hour).UTC(),
		"configGeneration": generation, "configEnv": map[string]string{}, "connections": list,
	}
	if credential != "" {
		payload["sessionCredential"] = credential
	}
	return payload
}

func packagedPostgresPayload() map[string]any {
	return map[string]any{
		"grantId": "grant-pg", "connectionId": "connection-pg", "connectionName": "console-dev-pg", "credentialId": "credential-pg",
		"credentialName": "Postgres production", "credentialProvider": "postgres", "credentialRevision": "credential-v1", "materialGeneration": "material-v1",
		"serviceType": "postgres", "protocol": "postgres",
		"hosts":     []any{map[string]any{"match": "exact", "value": "db.example", "port": 5432}},
		"injection": map[string]any{"action": "pg_handshake"}, "identifiers": map[string]string{"username": "db-user"},
		"decoyMaterial": map[string]string{"password": "pg-decoy-0123456789"}, "agentEnv": map[string]string{},
		"configEnv": map[string]string{}, "environmentBindings": []any{},
		"secretMaterial": map[string]string{"username": "db-user", "password": "pg-live-0123456789"},
		"authorization":  map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
	}
}

func unreachableConsoleClient(t *testing.T) *agentapi.Client {
	t.Helper()
	console := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(console.Close)
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// recordingUpstream answers every forwarded request with status and keeps the
// last request the proxy sent.
type recordingUpstream struct {
	status atomic.Int32
	calls  atomic.Int32
	last   atomic.Pointer[http.Request]
}

func (u *recordingUpstream) RoundTrip(request *http.Request) (*http.Response, error) {
	u.calls.Add(1)
	u.last.Store(request)
	status := int(u.status.Load())
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: http.NoBody}, nil
}

func processThrough(proxy *httpProxy, request *http.Request) processedResponse {
	result := proxy.process(request, nil)
	if result.response != nil && result.response.Body != nil {
		result.response.Body.Close()
	}
	return result
}

func TestCustomConnectionBindingsAreValidated(t *testing.T) {
	parse := func(mutate func(map[string]any)) error {
		connection := customConnectionPayload(customDecoyToken, customLiveToken)
		mutate(connection)
		session := decodeTestSession(t, customSessionPayload("backend", 1, connection))
		_, err := parseBindings(session.Connections)
		return err
	}
	accepted := map[string]func(map[string]any){
		"injection list": func(map[string]any) {},
		"header, basic and query together": func(c map[string]any) {
			c["decoyMaterial"] = map[string]string{"token": customDecoyToken, "password": "decoy-password-0123456789"}
			c["secretMaterial"] = map[string]string{"token": customLiveToken, "password": "live-password-0123456789"}
			c["injections"] = []any{
				map[string]any{"action": "basic_auth", "name": "Authorization", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}}, "whenAbsent": "attach"},
				map[string]any{"action": "set_header", "name": "X-Api-Key", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "block"},
				map[string]any{"action": "set_param", "name": "api_key", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}},
			}
		},
		"first list entry repeated as the single injection": func(c map[string]any) { c["injection"] = bearerAttachInjection() },
		"single basic injection": func(c map[string]any) {
			delete(c, "injections")
			c["injection"] = map[string]any{"action": "basic_auth", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "token"}}, "whenAbsent": "attach"}
		},
	}
	for name, mutate := range accepted {
		if err := parse(mutate); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	refused := map[string]func(map[string]any){
		"request signing in a list": func(c map[string]any) {
			c["injections"] = []any{map[string]any{"action": "aws_sigv4", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"accessKeyId": "token", "secretAccessKey": "token"}}}}
		},
		"database handshake in a list": func(c map[string]any) {
			c["injections"] = []any{map[string]any{"action": "pg_handshake"}}
		},
		"unknown action in a list": func(c map[string]any) {
			c["injections"] = []any{bearerAttachInjection(), map[string]any{"action": "set_cookie", "name": "session"}}
		},
		"single injection names another finalizer": func(c map[string]any) {
			c["injection"] = map[string]any{"action": "aws_sigv4", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"accessKeyId": "token", "secretAccessKey": "token"}}}
		},
		"injection list on a database Connection": func(c map[string]any) { c["protocol"] = "postgres" },
		"no injection at all":                     func(c map[string]any) { delete(c, "injections") },
	}
	for name, mutate := range refused {
		if err := parse(mutate); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A whenAbsent newer than this client is parsed; only its Connection is
	// unavailable.
	connection := customConnectionPayload(customDecoyToken, customLiveToken)
	injection := bearerAttachInjection()
	injection["whenAbsent"] = "always"
	connection["injections"] = []any{injection}
	session := decodeTestSession(t, customSessionPayload("backend", 1, connection))
	if bindings, err := parseBindings(session.Connections); err != nil || len(bindings) != 1 ||
		bindings[0].connection.AccessPolicyFailure() != agentapi.WhenAbsentUnsupported {
		t.Errorf("unknown whenAbsent: err=%v", err)
	}
}

func TestCustomConnectionAttachesSwapsAndBlocksThroughTheProxy(t *testing.T) {
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-custom", 1,
		customConnectionPayload(customDecoyToken, customLiveToken)), "runtime-custom")
	defer state.destroy()
	upstream := &recordingUpstream{}
	proxy := &httpProxy{state: state, transport: upstream}

	attached, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
	result := processThrough(proxy, attached)
	if result.failure != nil || upstream.last.Load().Header.Get("Authorization") != "Bearer "+customLiveToken ||
		result.event.CredentialAction != "set_header" || result.event.Provider != "http" || result.event.ProxyDecision != "allow" {
		t.Fatalf("attach failed: failure=%v event=%+v", result.failure, result.event)
	}
	if attached.Header.Get("Authorization") != "" {
		t.Fatal("the Agent's own request object was given the live value")
	}

	swapped, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
	swapped.Header.Set("Authorization", "Bearer "+customDecoyToken)
	if result := processThrough(proxy, swapped); result.failure != nil || upstream.last.Load().Header.Get("Authorization") != "Bearer "+customLiveToken {
		t.Fatalf("swap failed: %v", result.failure)
	}

	calls := upstream.calls.Load()
	other, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
	other.Header.Set("Authorization", "Bearer something-else")
	result = processThrough(proxy, other)
	if result.failure == nil || result.failure.status != http.StatusForbidden || result.failure.code != "agent_credential_injection_failed" ||
		result.failure.reason != "credential_swap_failed" || result.event.CredentialAction != "set_header" || upstream.calls.Load() != calls {
		t.Fatalf("a request carrying another value was not blocked: %+v calls=%d", result.failure, upstream.calls.Load())
	}

	// The path rule is part of the binding: outside it the request is ordinary
	// unbound traffic and nothing is attached.
	outside, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v2/items", nil)
	if result := processThrough(proxy, outside); result.failure != nil || upstream.last.Load().Header.Get("Authorization") != "" {
		t.Fatalf("a credential was attached outside the Connection's path rule: %v", result.failure)
	}
}

// A custom Connection whose value arrived on neither lane is reported as
// unavailable instead of ready, and its requests are blocked.
func TestCustomConnectionWithoutAValueIsUnavailable(t *testing.T) {
	connection := customConnectionPayload(customDecoyToken, customLiveToken)
	delete(connection, "secretMaterial")
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-empty", 1, connection, packagedPostgresPayload()), "runtime-empty")
	defer state.destroy()
	upstream := &recordingUpstream{}
	proxy := &httpProxy{state: state, transport: upstream, control: &controlHandler{state: state}}
	request, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
	result := processThrough(proxy, request)
	if result.failure == nil || result.failure.code != "agent_credential_injection_failed" ||
		result.failure.message != (&phaseproxy.InjectionError{Code: phaseproxy.InjectionMissingMaterial}).Error() || upstream.calls.Load() != 0 {
		t.Fatalf("a Connection without a value forwarded a request: %+v", result.failure)
	}
	var listed remoteapi.ConnectionsResponse
	if err := json.Unmarshal(controlGet(t, proxy, "runtime-empty", "/v1/connections").Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Connections) != 2 || listed.Connections[0].State != "unavailable" || listed.Connections[0].StateReason != agentapi.MaterialFailureMissing ||
		listed.Connections[1].State != "ready" || listed.Connections[1].StateReason != "" {
		t.Fatalf("connections = %+v", listed.Connections)
	}
	if status := state.statusConnections(time.Now()); status[0].State != "unavailable" || status[1].State != "ready" {
		t.Fatalf("status = %+v", status)
	}
}

func TestPackagedHeaderConnectionStillBlocksAMissingDecoy(t *testing.T) {
	session := headerInjectionSession(t, "backend-packaged", "packaged-decoy")
	state, err := newRuntimeStateWithCapability(session, "runtime-packaged")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	upstream := &recordingUpstream{}
	upstream.status.Store(http.StatusUnauthorized)
	proxy := &httpProxy{state: state, transport: upstream}

	absent, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/me", nil)
	result := processThrough(proxy, absent)
	if result.failure == nil || result.failure.code != "agent_credential_injection_failed" ||
		result.failure.message != (&phaseproxy.InjectionError{Code: phaseproxy.InjectionSwapMiss}).Error() || upstream.calls.Load() != 0 {
		t.Fatalf("a packaged Connection without its decoy was forwarded: %+v", result.failure)
	}
	presented, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/me", nil)
	presented.Header.Set("Authorization", "Bearer packaged-decoy")
	result = processThrough(proxy, presented)
	if result.failure != nil || upstream.last.Load().Header.Get("Authorization") != "Bearer live-token" || result.event.CredentialAction != "set_header" {
		t.Fatalf("packaged swap changed: %+v", result.failure)
	}
	// A refusal from a packaged service's upstream never asks for a refresh.
	select {
	case <-state.refreshRequests:
		t.Fatal("a packaged Connection requested an extra config refresh")
	default:
	}
}

func TestInjectionListAcceptsPreviouslyIssuedDecoys(t *testing.T) {
	connection := func(tokenDecoy, passwordDecoy, username string) map[string]any {
		payload := customConnectionPayload(tokenDecoy, customLiveToken)
		payload["identifiers"] = map[string]string{"username": username}
		payload["decoyMaterial"] = map[string]string{"token": tokenDecoy, "password": passwordDecoy}
		payload["agentEnv"] = map[string]string{"EXAMPLE_API_KEY": tokenDecoy}
		payload["secretMaterial"] = map[string]string{"token": customLiveToken, "password": "live-password-0123456789"}
		payload["injections"] = []any{
			map[string]any{"action": "basic_auth", "name": "Authorization", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}}, "whenAbsent": "attach"},
			map[string]any{"action": "set_header", "name": "X-Api-Key", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "block"},
		}
		return payload
	}
	basic := func(userpass string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(userpass)) }
	engine := New()
	earlier := decodeTestSession(t, customSessionPayload("backend-one", 1, connection("sk-decoy-generation-one-0123", "password-decoy-one-0123", "alice")))
	engine.decoyHistory().remember(earlier.Connections)
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-two", 1,
		connection("sk-decoy-generation-two-0123", "password-decoy-two-0123", "alice")), "runtime-history")
	defer state.destroy()
	state.decoys = engine.decoyHistory()
	state.decoys.remember([]agentapi.Connection{state.bindings[0].connection})
	live := state.bindings[0].connection
	apply := func(mutate func(*http.Request)) (*http.Request, error) {
		request, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
		mutate(request)
		_, err := applyHTTPInjectionWithHistory(request, live, state.previousDecoyViews(live))
		return request, err
	}

	for name, mutate := range map[string]func(*http.Request){
		"current generation": func(r *http.Request) {
			r.Header.Set("Authorization", basic("alice:password-decoy-two-0123"))
			r.Header.Set("X-Api-Key", "sk-decoy-generation-two-0123")
		},
		"earlier generation": func(r *http.Request) {
			r.Header.Set("Authorization", basic("alice:password-decoy-one-0123"))
			r.Header.Set("X-Api-Key", "sk-decoy-generation-one-0123")
		},
		"earlier generation with one injection attached": func(r *http.Request) { r.Header.Set("X-Api-Key", "sk-decoy-generation-one-0123") },
	} {
		request, err := apply(mutate)
		if err != nil || request.Header.Get("Authorization") != basic("alice:live-password-0123456789") || request.Header.Get("X-Api-Key") != customLiveToken {
			t.Fatalf("%s: err=%v headers=%v", name, err, request.Header)
		}
	}
	// A request never mixes generations, and an unknown decoy stays blocked
	// with the request untouched.
	for name, mutate := range map[string]func(*http.Request){
		"mixed generations": func(r *http.Request) {
			r.Header.Set("Authorization", basic("alice:password-decoy-one-0123"))
			r.Header.Set("X-Api-Key", "sk-decoy-generation-two-0123")
		},
		"never issued": func(r *http.Request) { r.Header.Set("X-Api-Key", "sk-decoy-never-issued-0123") },
	} {
		request, err := apply(mutate)
		before := http.Header{}
		mutate(&http.Request{Header: before})
		if !staleDecoyInjectionFailure(err) || !reflect.DeepEqual(request.Header, before) {
			t.Fatalf("%s: err=%v headers=%v", name, err, request.Header)
		}
	}
}

func TestEngineAdvertisesListInjectionFeatures(t *testing.T) {
	capabilities := New().Capabilities()
	if want := []string{"set_header", "replace_header", "remove_header", "set_param", "set_path", "replace_path_regex", "aws_sigv4", "pg_handshake", "basic_auth"}; !reflect.DeepEqual(capabilities.InjectionActions, want) {
		t.Fatalf("injection actions = %v", capabilities.InjectionActions)
	}
	if want := []string{"injection_list", "when_absent", "sealed_material", "access_policy", "provider_rules"}; !reflect.DeepEqual(capabilities.Features, want) {
		t.Fatalf("features = %v", capabilities.Features)
	}
	if !reflect.DeepEqual(capabilities.Protocols, []string{"http", "postgres"}) {
		t.Fatalf("protocols = %v", capabilities.Protocols)
	}
}

func TestUpstreamRejectionRefreshIsRateLimitedPerSession(t *testing.T) {
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-rate", 1,
		customConnectionPayload(customDecoyToken, customLiveToken)), "runtime-rate")
	defer state.destroy()
	start := time.Now()
	if !state.requestRefreshAfterRejection(start) {
		t.Fatal("the first rejection did not request a refresh")
	}
	<-state.refreshRequests
	for _, later := range []time.Duration{0, time.Second, 29 * time.Second} {
		if state.requestRefreshAfterRejection(start.Add(later)) {
			t.Fatalf("a second refresh was requested %s after the first", later)
		}
	}
	if !state.requestRefreshAfterRejection(start.Add(30 * time.Second)) {
		t.Fatal("a refresh was refused after the interval passed")
	}
	// A request that is still waiting for the monitor is not queued twice.
	if state.requestRefreshAfterRejection(start.Add(2 * time.Minute)) {
		t.Fatal("a second refresh was queued behind a pending one")
	}
	other := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-other", 1,
		customConnectionPayload(customDecoyToken, customLiveToken)), "runtime-other")
	defer other.destroy()
	if !other.requestRefreshAfterRejection(start) {
		t.Fatal("the limit is per session")
	}
}

func TestUpstreamRejectionTriggersOneBackgroundRefresh(t *testing.T) {
	var refreshes atomic.Int32
	release := make(chan struct{})
	refreshed := customSessionPayload("", 2, customConnectionPayload(customDecoyToken, "sk-live-replaced-in-the-console-01"))
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/sessions/session-custom/config/") {
			http.NotFound(w, request)
			return
		}
		refreshes.Add(1)
		<-release
		_ = json.NewEncoder(w).Encode(refreshed)
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	packaged := map[string]any{
		"grantId": "grant-packaged", "connectionId": "connection-packaged", "credentialId": "credential-packaged", "credentialName": "Packaged",
		"credentialProvider": "example", "credentialRevision": "credential-v1", "serviceType": "example", "protocol": "http",
		"authorization": map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
		"hosts":         []any{map[string]any{"match": "exact", "value": "packaged.example.test", "port": 443}},
		"injection":     map[string]any{"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}},
		"identifiers":   map[string]string{}, "decoyMaterial": map[string]string{"token": "packaged-decoy-0123456789"},
		"configEnv": map[string]string{}, "agentEnv": map[string]string{}, "environmentBindings": []any{},
		"secretMaterial": map[string]string{"token": "packaged-live-0123456789"},
	}
	refreshed["connections"] = append(refreshed["connections"].([]any), packaged)
	state := controlRuntimeState(t, client, customSessionPayload("backend-refresh", 1,
		customConnectionPayload(customDecoyToken, customLiveToken), packaged), "runtime-refresh")
	defer state.destroy()
	state.decoys = newDecoyHistory()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		(&Engine{RefreshInterval: time.Hour}).monitor(ctx, state)
	}()
	upstream := &recordingUpstream{}
	proxy := &httpProxy{state: state, transport: upstream}
	custom := func() *http.Request {
		request, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
		return request
	}
	waitForRefreshes := func(want int32) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for refreshes.Load() != want {
			if time.Now().After(deadline) {
				t.Fatalf("config refreshes = %d, want %d", refreshes.Load(), want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	settle := func() { time.Sleep(60 * time.Millisecond) }

	// Nothing but a 401 or 403 on a custom Connection's injected request asks
	// for a refresh.
	for _, status := range []int{http.StatusOK, http.StatusNotFound, http.StatusInternalServerError} {
		upstream.status.Store(int32(status))
		processThrough(proxy, custom())
	}
	upstream.status.Store(http.StatusUnauthorized)
	onPackaged, _ := http.NewRequest(http.MethodGet, "https://packaged.example.test/", nil)
	onPackaged.Header.Set("Authorization", "Bearer packaged-decoy-0123456789")
	if result := processThrough(proxy, onPackaged); result.failure != nil {
		t.Fatal(result.failure)
	}
	unbound, _ := http.NewRequest(http.MethodGet, "https://elsewhere.example.test/", nil)
	processThrough(proxy, unbound)
	blocked := custom()
	blocked.Header.Set("Authorization", "Bearer not-the-decoy")
	if result := processThrough(proxy, blocked); result.failure == nil {
		t.Fatal("a swap miss was forwarded")
	}
	settle()
	if refreshes.Load() != 0 {
		t.Fatalf("config refreshes = %d before any custom Connection was refused", refreshes.Load())
	}

	// The refusal reaches the Agent at once: the Console is still holding the
	// refresh open when the proxied response comes back, unchanged.
	result := processThrough(proxy, custom())
	if result.failure != nil || result.response.StatusCode != http.StatusUnauthorized || upstream.last.Load().Header.Get("Authorization") != "Bearer "+customLiveToken {
		t.Fatalf("the refused request was not returned as it was: %+v", result.failure)
	}
	callsAfterRefusal := upstream.calls.Load()
	waitForRefreshes(1)
	if upstream.calls.Load() != callsAfterRefusal {
		t.Fatal("the refused request was retried")
	}

	// More refusals inside the interval, 403 included, add nothing.
	upstream.status.Store(http.StatusForbidden)
	for range 5 {
		processThrough(proxy, custom())
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		request := custom()
		processThrough(proxy, request)
		if upstream.last.Load().Header.Get("Authorization") == "Bearer sk-live-replaced-in-the-console-01" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the refreshed value was never used")
		}
		time.Sleep(5 * time.Millisecond)
	}
	settle()
	if refreshes.Load() != 1 {
		t.Fatalf("config refreshes = %d inside one interval, want 1", refreshes.Load())
	}

	// Once the interval has passed, the next refusal asks again.
	state.rejectionMu.Lock()
	state.lastRejectionRefresh = time.Now().Add(-upstreamRejectionRefreshInterval - time.Second)
	state.rejectionMu.Unlock()
	processThrough(proxy, custom())
	waitForRefreshes(2)
	settle()
	if refreshes.Load() != 2 || state.availability() != nil {
		t.Fatalf("refreshes=%d availability=%v", refreshes.Load(), state.availability())
	}
	stop()
	<-monitorDone
}

func TestFailedExtraRefreshLeavesTheSessionAsItWas(t *testing.T) {
	var refreshes atomic.Int32
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		refreshes.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, customSessionPayload("backend-transient", 1,
		customConnectionPayload(customDecoyToken, customLiveToken)), "runtime-transient")
	defer state.destroy()
	if stop := refreshFromMonitor(context.Background(), state, false); stop || refreshes.Load() != 1 || state.availability() != nil {
		t.Fatalf("an extra refresh that could not reach the Console changed the session: stop=%t availability=%v", stop, state.availability())
	}
	// The periodic refresh keeps deciding health exactly as before.
	if stop := refreshFromMonitor(context.Background(), state, true); stop || state.availability() == nil {
		t.Fatalf("the periodic refresh no longer marks an unvalidated session: stop=%t availability=%v", stop, state.availability())
	}
}

func controlGet(t *testing.T, proxy *httpProxy, capability, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+path, nil)
	setProxyCapability(request, capability)
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	return recorder
}

func TestControlConnectionsAreReadFromTheSessionWithoutSecrets(t *testing.T) {
	var consoleCalls atomic.Int32
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		consoleCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, customSessionPayload("backend-connections", 4,
		customConnectionPayload(customDecoyToken, customLiveToken), packagedPostgresPayload()), "runtime-connections")
	defer state.destroy()
	proxy := &httpProxy{state: state, control: &controlHandler{state: state}}

	unauthenticated := httptest.NewRecorder()
	proxy.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/connections", nil))
	if unauthenticated.Code != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}

	list := controlGet(t, proxy, "runtime-connections", "/v1/connections")
	if list.Code != http.StatusOK || list.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%s", list.Code, list.Header(), list.Body.String())
	}
	var response remoteapi.ConnectionsResponse
	if err := json.Unmarshal(list.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != 1 || response.Kind != "phase.ai.connections" || len(response.Connections) != 2 {
		t.Fatalf("connections = %+v", response)
	}
	custom, packaged := response.Connections[0], response.Connections[1]
	if custom.ID != "connection-example" || custom.Name != "Example API" || custom.ServiceType != "http" || custom.State != "ready" ||
		custom.StateReason != "" || custom.ValueRevision == nil || *custom.ValueRevision != 3 || custom.KeyVersion == nil || *custom.KeyVersion != 2 {
		t.Fatalf("custom Connection = %+v", custom)
	}
	wantDefinition, _ := json.Marshal(customDefinition())
	gotDefinition, _ := json.Marshal(custom.Definition)
	if !bytes.Equal(wantDefinition, gotDefinition) {
		t.Fatalf("definition = %s", gotDefinition)
	}
	if packaged.ID != "connection-pg" || packaged.ServiceType != "postgres" || packaged.State != "ready" ||
		packaged.Definition != nil || packaged.ValueRevision != nil || packaged.KeyVersion != nil {
		t.Fatalf("packaged Connection = %+v", packaged)
	}
	if !strings.Contains(list.Body.String(), `"valueRevision":3`) || !strings.Contains(list.Body.String(), `"keyVersion":2`) {
		t.Fatalf("counters are not on the wire: %s", list.Body.String())
	}

	one := controlGet(t, proxy, "runtime-connections", "/v1/connections/connection-example")
	var detail remoteapi.ConnectionResponse
	if err := json.Unmarshal(one.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if one.Code != http.StatusOK || detail.Kind != "phase.ai.connection" || detail.ID != "connection-example" || detail.State != "ready" ||
		!strings.Contains(one.Body.String(), `"id":"connection-example"`) || !strings.Contains(one.Body.String(), `"definition":{`) {
		t.Fatalf("status=%d body=%s", one.Code, one.Body.String())
	}

	for _, body := range []string{list.Body.String(), one.Body.String()} {
		for _, forbidden := range []string{
			customLiveToken, customDecoyToken, "pg-live-0123456789", "pg-decoy-0123456789", "backend-connections", "runtime-connections",
			"session-custom", "grant-example", "grant-pg", "db.example", "db-user", "secretMaterial", "decoyMaterial", "agentEnv", "identifiers",
		} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("connection read leaked %q: %s", forbidden, body)
			}
		}
	}

	if missing := controlGet(t, proxy, "runtime-connections", "/v1/connections/connection-unknown"); missing.Code != http.StatusNotFound ||
		!strings.Contains(missing.Body.String(), "connection_unavailable") {
		t.Fatalf("unknown Connection: status=%d body=%s", missing.Code, missing.Body.String())
	}
	for _, path := range []string{"/v1/connections/", "/v1/connections/a/b", "/v1/connections/bad%20id"} {
		if invalid := controlGet(t, proxy, "runtime-connections", path); invalid.Code != http.StatusBadRequest ||
			!strings.Contains(invalid.Body.String(), "invalid_connection_id") {
			t.Fatalf("%s: status=%d body=%s", path, invalid.Code, invalid.Body.String())
		}
	}
	if query := controlGet(t, proxy, "runtime-connections", "/v1/connections?verbose=1"); query.Code != http.StatusBadRequest {
		t.Fatalf("query string status = %d", query.Code)
	}
	// The existing per-Connection environment route keeps its own handler.
	if environment := controlGet(t, proxy, "runtime-connections", "/v1/connections/connection-example/environment"); environment.Code != http.StatusNotFound ||
		!strings.Contains(environment.Body.String(), "The Connection environment is unavailable.") {
		t.Fatalf("environment route: status=%d body=%s", environment.Code, environment.Body.String())
	}
	post := httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/connections", strings.NewReader("{}"))
	setProxyCapability(post, "runtime-connections")
	written := httptest.NewRecorder()
	proxy.ServeHTTP(written, post)
	if written.Code != http.StatusNotFound {
		t.Fatalf("a write to the read route was routed: %d", written.Code)
	}
	status := controlGet(t, proxy, "runtime-connections", "/v1/status")
	var printable remoteapi.StatusResponse
	if err := json.Unmarshal(status.Body.Bytes(), &printable); err != nil {
		t.Fatal(err)
	}
	if len(printable.Connections) != 2 || printable.Connections[0].ServiceType != "http" || printable.Connections[0].Protocol != "http" ||
		printable.Connections[0].Name != "Example API" || printable.Connections[0].CredentialProvider != "http" ||
		printable.Connections[0].CredentialRevision != "3" || printable.Connections[0].State != "ready" ||
		printable.Links.Connections != phaseproxy.ControlURL+"/v1/connections" ||
		printable.Links.Connection != phaseproxy.ControlURL+"/v1/connections/{connectionId}" {
		t.Fatalf("status = %+v", printable)
	}
	if strings.Contains(status.Body.String(), customLiveToken) || strings.Contains(status.Body.String(), customDecoyToken) ||
		strings.Contains(status.Body.String(), "api.example.test") {
		t.Fatalf("status leaked Connection material: %s", status.Body.String())
	}
	if consoleCalls.Load() != 0 {
		t.Fatalf("connection reads called the Console %d times", consoleCalls.Load())
	}
}

func TestControlConnectionsRefuseADefinitionCarryingProxyOnlyMaterial(t *testing.T) {
	for name, leaked := range map[string]string{"live value": customLiveToken, "decoy": customDecoyToken} {
		t.Run(name, func(t *testing.T) {
			connection := customConnectionPayload(customDecoyToken, customLiveToken)
			definition := customDefinition()
			definition["fields"] = []any{map[string]any{"name": "token", "kind": "secret", "source": map[string]any{"type": "sealed"}, "note": leaked}}
			connection["connectionConfig"] = definition
			state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-unsafe", 1, connection), "runtime-unsafe")
			defer state.destroy()
			proxy := &httpProxy{state: state, control: &controlHandler{state: state}}
			for _, path := range []string{"/v1/connections", "/v1/connections/connection-example"} {
				recorder := controlGet(t, proxy, "runtime-unsafe", path)
				if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "unsafe_connection_response") ||
					strings.Contains(recorder.Body.String(), leaked) {
					t.Fatalf("%s: status=%d body=%s", path, recorder.Code, recorder.Body.String())
				}
			}
		})
	}
}

func TestDiscoverForwardsInjectionListsAndRequiresThemToMatch(t *testing.T) {
	discoverConnection := func() map[string]any {
		connection := customConnectionPayload(customDecoyToken, customLiveToken)
		delete(connection, "secretMaterial")
		return connection
	}
	serve := func(t *testing.T, discover map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if !strings.HasSuffix(request.URL.Path, "/sessions/session-custom/discover/") {
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
		state := controlRuntimeState(t, client, customSessionPayload("backend-discover", 1,
			customConnectionPayload(customDecoyToken, customLiveToken)), "runtime-discover")
		defer state.destroy()
		return controlGet(t, &httpProxy{state: state, control: &controlHandler{state: state}}, "runtime-discover", "/v1/discover")
	}
	matching := customSessionPayload("", 1, discoverConnection())
	matching["connections"].([]any)[0].(map[string]any)["sealedMaterial"] = map[string]any{"version": 1, "ciphertext": "ph:v1:aa:bb", "wrappedKey": "ph:v1:cc:dd"}
	matching["agentKey"] = map[string]any{"wrappedKeyShare": "feedfacefeedface"}
	relayed := serve(t, matching)
	if relayed.Code != http.StatusOK || !strings.Contains(relayed.Body.String(), `"injections":[{"action":"set_header"`) ||
		!strings.Contains(relayed.Body.String(), `"whenAbsent":"attach"`) || strings.Contains(relayed.Body.String(), `"injection":{`) {
		t.Fatalf("status=%d body=%s", relayed.Code, relayed.Body.String())
	}
	for _, forbidden := range []string{"sealedMaterial", "wrappedKey", "agentKey", "feedfacefeedface", "ph:v1:", customLiveToken, "secretMaterial"} {
		if strings.Contains(relayed.Body.String(), forbidden) {
			t.Fatalf("discover relayed %q: %s", forbidden, relayed.Body.String())
		}
	}

	changed := discoverConnection()
	changed["injections"] = []any{map[string]any{
		"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}",
		"valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "block",
	}}
	if drifted := serve(t, customSessionPayload("", 1, changed)); drifted.Code != http.StatusBadGateway ||
		!strings.Contains(drifted.Body.String(), "unsafe_agent_discover_response") {
		t.Fatalf("a discover response with different injections was relayed: %d %s", drifted.Code, drifted.Body.String())
	}
}

// requestConsole records what the proxy forwards to the Console's request
// endpoint and answers as the Console would.
type requestConsole struct {
	server   *httptest.Server
	creates  atomic.Int32
	configs  atomic.Int32
	lastBody atomic.Pointer[map[string]json.RawMessage]
	respond  func(body map[string]json.RawMessage) (int, map[string]any)
	config   func() map[string]any
}

func newRequestConsole(t *testing.T) *requestConsole {
	t.Helper()
	console := &requestConsole{}
	console.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/requests/"):
			console.creates.Add(1)
			var body map[string]json.RawMessage
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("forwarded request is not JSON: %v", err)
			}
			console.lastBody.Store(&body)
			status, response := http.StatusCreated, map[string]any{
				"schemaVersion": 1, "id": "request-custom", "status": "pending",
				"approvalUrl": console.server.URL + "/acme/agents/requests?request=request-custom",
			}
			for _, member := range []string{"kind", "title", "action", "markdown"} {
				if raw, present := body[member]; present {
					response[member] = raw
				}
			}
			if console.respond != nil {
				status, response = console.respond(body)
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(response)
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/config/") && console.config != nil:
			console.configs.Add(1)
			_ = json.NewEncoder(w).Encode(console.config())
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(console.server.Close)
	return console
}

func (c *requestConsole) state(t *testing.T, capability string) (*runtimeState, *httpProxy) {
	t.Helper()
	client, err := agentapi.NewClient(c.server.URL, durableTestToken(), c.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, customSessionPayload("backend-requests", 1,
		customConnectionPayload(customDecoyToken, customLiveToken)), capability)
	t.Cleanup(state.destroy)
	return state, &httpProxy{state: state, control: &controlHandler{state: state}}
}

func postControlRequest(proxy *httpProxy, capability, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/requests", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	setProxyCapability(request, capability)
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	return recorder
}

func sameJSON(t *testing.T, left, right []byte) bool {
	t.Helper()
	var leftValue, rightValue any
	if err := json.Unmarshal(left, &leftValue); err != nil {
		t.Fatalf("invalid JSON %s: %v", left, err)
	}
	if err := json.Unmarshal(right, &rightValue); err != nil {
		t.Fatalf("invalid JSON %s: %v", right, err)
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func TestControlRequestsForwardTitleAndActionUntouched(t *testing.T) {
	definition, _ := json.Marshal(customDefinition())
	tests := []struct {
		name   string
		kind   string
		action string
		title  string
		reason string
	}{
		{
			name: "request a new custom Connection", kind: "setup", title: "Connect the Example API", reason: "The task reads invoices from the Example API.",
			action: `{"type":"agent_connection.create","version":1,"serviceType":"http","name":"Example API","definition":` + string(definition) + `}`,
		},
		{
			name: "request a change", kind: "connection_update", title: "Allow /v2 on the Example API", reason: "The v2 endpoints replaced v1.",
			action: `{"type":"agent_connection.update","version":1,"connectionId":"connection-example","name":"Example API v2","definition":` + string(definition) + `}`,
		},
		{
			name: "ask for a new secret", kind: "credential_update", title: "Replace the Example API key", reason: "The upstream answers 401.",
			action: `{"type":"agent_connection.secret_update","version":1,"connectionId":"connection-example"}`,
		},
		{
			name: "ask to remove the grant", kind: "connection_removal", title: "Remove the Example API", reason: "The task is finished.",
			action: `{"type":"agent_connection.remove","version":1,"connectionId":"connection-example"}`,
		},
		{
			// Members this client does not know are the Console's to judge.
			name: "member added by a later Console", kind: "connection_update",
			action: `{"type":"agent_connection.update","version":1,"connectionId":"connection-example","name":"Example API","access":{"durationSeconds":3600,"reviewers":["ops"]},"note":null}`,
		},
		{
			// The action is what a member reviews; a title and a reason are optional.
			name: "no title and no reason", kind: "credential_update",
			action: `{"type":"agent_connection.secret_update","version":1,"connectionId":"connection-example"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			console := newRequestConsole(t)
			_, proxy := console.state(t, "runtime-requests")
			body := map[string]any{"kind": test.kind, "action": json.RawMessage(test.action), "dedupKey": "custom-" + test.kind}
			if test.title != "" {
				body["title"] = test.title
			}
			if test.reason != "" {
				body["markdown"] = test.reason
			}
			encoded, _ := json.Marshal(body)
			recorder := postControlRequest(proxy, "runtime-requests", string(encoded))
			if recorder.Code != http.StatusCreated || console.creates.Load() != 1 {
				t.Fatalf("status=%d creates=%d body=%s", recorder.Code, console.creates.Load(), recorder.Body.String())
			}
			forwarded := *console.lastBody.Load()
			if !sameJSON(t, forwarded["action"], []byte(test.action)) {
				t.Fatalf("forwarded action = %s", forwarded["action"])
			}
			if string(forwarded["kind"]) != `"`+test.kind+`"` || string(forwarded["schemaVersion"]) != "1" ||
				string(forwarded["dedupKey"]) != `"custom-`+test.kind+`"` {
				t.Fatalf("forwarded request = %v", forwarded)
			}
			wantReason, _ := json.Marshal(test.reason)
			if !bytes.Equal(forwarded["markdown"], wantReason) {
				t.Fatalf("forwarded markdown = %s, want %s", forwarded["markdown"], wantReason)
			}
			if _, present := forwarded["title"]; present != (test.title != "") {
				t.Fatalf("forwarded title = %s", forwarded["title"])
			}
			for _, legacy := range []string{"credentialProvider", "credentialName", "serviceType", "connectionId", "credentialId"} {
				if _, present := forwarded[legacy]; present {
					t.Fatalf("an action request was forwarded with an invented %s: %s", legacy, forwarded[legacy])
				}
			}
			var response map[string]json.RawMessage
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if !sameJSON(t, response["action"], []byte(test.action)) || string(response["kind"]) != `"`+test.kind+`"` ||
				string(response["pollUrl"]) != `"http://phase.invalid/v1/requests/request-custom"` || string(response["status"]) != `"pending"` {
				t.Fatalf("relayed response = %s", recorder.Body.String())
			}
			if test.title != "" && string(response["title"]) != `"`+test.title+`"` {
				t.Fatalf("relayed title = %s", response["title"])
			}
		})
	}
}

func TestControlRequestsRefuseInvalidActionsBeforeTheConsole(t *testing.T) {
	definition, _ := json.Marshal(customDefinition())
	secretDefinition := `{"specVersion":1,"fields":[{"name":"token","kind":"secret","source":{"type":"sealed"},"value":"sk-live-pasted-by-the-agent"}]}`
	tests := map[string]string{
		"unknown action type":                 `{"kind":"setup","markdown":"why","action":{"type":"agent_connection.rotate","version":1}}`,
		"unknown action version":              `{"kind":"connection_update","markdown":"why","action":{"type":"agent_connection.update","version":2,"connectionId":"connection-example","name":"x"}}`,
		"action version missing":              `{"kind":"connection_update","markdown":"why","action":{"type":"agent_connection.update","connectionId":"connection-example","name":"x"}}`,
		"action version as text":              `{"kind":"connection_update","markdown":"why","action":{"type":"agent_connection.update","version":"1","connectionId":"connection-example","name":"x"}}`,
		"action type missing":                 `{"kind":"connection_update","markdown":"why","action":{"version":1,"connectionId":"connection-example"}}`,
		"action is not an object":             `{"kind":"connection_update","markdown":"why","action":"agent_connection.update"}`,
		"create under the wrong kind":         `{"kind":"connection_update","markdown":"why","action":{"type":"agent_connection.create","version":1,"serviceType":"http","name":"x","definition":` + string(definition) + `}}`,
		"update under the wrong kind":         `{"kind":"setup","markdown":"why","action":{"type":"agent_connection.update","version":1,"connectionId":"connection-example","name":"x"}}`,
		"removal under the wrong kind":        `{"kind":"credential_update","markdown":"why","action":{"type":"agent_connection.remove","version":1,"connectionId":"connection-example"}}`,
		"new kind without an action":          `{"kind":"connection_update","markdown":"why","connectionId":"connection-example","credentialProvider":"http","credentialName":"Example API"}`,
		"removal kind without an action":      `{"kind":"connection_removal","markdown":"why","connectionId":"connection-example","credentialId":"connection-example","credentialProvider":"http","credentialName":"Example API"}`,
		"secret value in a definition field":  `{"kind":"setup","markdown":"why","action":{"type":"agent_connection.create","version":1,"serviceType":"http","name":"x","definition":` + secretDefinition + `}}`,
		"secret value in a field source":      `{"kind":"setup","markdown":"why","action":{"type":"agent_connection.create","version":1,"serviceType":"http","name":"x","definition":{"fields":[{"name":"token","kind":"secret","source":{"type":"sealed","value":"sk-live-pasted"}}]}}}`,
		"value on a field without a kind":     `{"kind":"setup","markdown":"why","action":{"type":"agent_connection.create","version":1,"serviceType":"http","name":"x","definition":{"fields":[{"name":"token","value":"sk-live-pasted"}]}}}`,
		"value on a secret update":            `{"kind":"credential_update","markdown":"why","action":{"type":"agent_connection.secret_update","version":1,"connectionId":"connection-example","value":"sk-live-pasted"}}`,
		"definition is not an object":         `{"kind":"setup","markdown":"why","action":{"type":"agent_connection.create","version":1,"serviceType":"http","name":"x","definition":"token=sk-live-pasted"}}`,
		"definition fields are not a list":    `{"kind":"setup","markdown":"why","action":{"type":"agent_connection.create","version":1,"serviceType":"http","name":"x","definition":{"fields":{"token":"sk-live-pasted"}}}}`,
		"title too long":                      `{"kind":"connection_removal","title":"` + strings.Repeat("t", 121) + `","action":{"type":"agent_connection.remove","version":1,"connectionId":"connection-example"}}`,
		"title with a line break":             `{"kind":"connection_removal","title":"Remove\nnow","action":{"type":"agent_connection.remove","version":1,"connectionId":"connection-example"}}`,
		"reason too long":                     `{"kind":"connection_removal","markdown":"` + strings.Repeat("m", 16<<10+1) + `","action":{"type":"agent_connection.remove","version":1,"connectionId":"connection-example"}}`,
		"secret member beside the action":     `{"kind":"credential_update","secret":"sk-live-pasted","action":{"type":"agent_connection.secret_update","version":1,"connectionId":"connection-example"}}`,
		"packaged setup without a reason":     `{"kind":"setup","credentialProvider":"github","credentialName":"GitHub","serviceType":"github"}`,
		"packaged setup with an empty reason": `{"kind":"setup","credentialProvider":"github","credentialName":"GitHub","serviceType":"github","markdown":"  "}`,
		"packaged update with a null action":  `{"kind":"credential_update","connectionId":"connection-example","credentialId":"connection-example","credentialProvider":"http","credentialName":"Example API","action":null}`,
	}
	console := newRequestConsole(t)
	_, proxy := console.state(t, "runtime-refused")
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			recorder := postControlRequest(proxy, "runtime-refused", body)
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_control_request") ||
				strings.Contains(recorder.Body.String(), "sk-live-pasted") {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
	if console.creates.Load() != 0 {
		t.Fatalf("%d refused requests reached the Console", console.creates.Load())
	}

	// The packaged shapes are unchanged: the same request with its reason is
	// forwarded, and a null action counts as no action.
	accepted := postControlRequest(proxy, "runtime-refused", `{"kind":"credential_update","connectionId":"connection-example","credentialId":"connection-example","credentialProvider":"http","credentialName":"Example API","markdown":"expired","action":null,"title":"Renew the key"}`)
	forwarded := *console.lastBody.Load()
	if accepted.Code != http.StatusCreated || console.creates.Load() != 1 || string(forwarded["title"]) != `"Renew the key"` ||
		string(forwarded["credentialName"]) != `"Example API"` {
		t.Fatalf("status=%d body=%s forwarded=%v", accepted.Code, accepted.Body.String(), forwarded)
	}
	if _, present := forwarded["action"]; present {
		t.Fatalf("a null action was forwarded: %s", forwarded["action"])
	}
}

// An approved change that leaves the Agent's environment alone is applied to
// the running session and answered with retry. Only a change to what the
// Agent process was given still needs a fresh session.
func TestApprovedConnectionChangeIsAppliedInPlaceWhenTheEnvironmentHolds(t *testing.T) {
	approved := func(kind, consoleAction string) func(map[string]json.RawMessage) (int, map[string]any) {
		return func(map[string]json.RawMessage) (int, map[string]any) {
			response := map[string]any{
				"schemaVersion": 1, "id": "request-custom", "status": "approved", "kind": kind,
				"connectionId": "connection-example", "grantId": "grant-example",
			}
			if consoleAction != "" {
				response["runtimeAction"] = consoleAction
			}
			return http.StatusOK, response
		}
	}
	with := func(mutate func(map[string]any)) func() map[string]any {
		return func() map[string]any {
			connection := customConnectionPayload(customDecoyToken, customLiveToken)
			mutate(connection)
			return customSessionPayload("", 2, connection)
		}
	}
	const update = `{"type":"agent_connection.update","version":1,"connectionId":"connection-example","definition":{"specVersion":1}}`
	const remove = `{"type":"agent_connection.remove","version":1,"connectionId":"connection-example"}`
	seenAt := func(t *testing.T, proxy *httpProxy, target string) (string, *requestFailure) {
		t.Helper()
		upstream := &recordingUpstream{}
		proxy.transport = upstream
		request, _ := http.NewRequest(http.MethodGet, target, nil)
		result := processThrough(proxy, request)
		if upstream.last.Load() == nil {
			return "", result.failure
		}
		return upstream.last.Load().Header.Get("Authorization"), result.failure
	}
	tests := []struct {
		name          string
		kind          string
		action        string
		consoleAction string
		config        func() map[string]any
		refreshFirst  bool
		wantAction    string
		wantFatal     bool
		check         func(*testing.T, *runtimeState, *httpProxy)
	}{
		{
			name: "rename", kind: "connection_update", action: update, wantAction: "retry",
			config: with(func(c map[string]any) { c["connectionName"] = "Example API (renamed)" }),
			check: func(t *testing.T, state *runtimeState, _ *httpProxy) {
				if state.statusConnections(time.Now())[0].Name != "Example API (renamed)" {
					t.Fatal("the renamed Connection was not picked up")
				}
			},
		},
		{
			// The Console may still say restart; the proxy knows it applied it.
			name: "new path", kind: "connection_update", action: update, consoleAction: "restart_required", wantAction: "retry",
			config: with(func(c map[string]any) {
				c["hosts"] = []any{map[string]any{"match": "exact", "value": "api.example.test", "port": 443, "path": "/v2/*"}}
				definition := customDefinition()
				definition["hosts"] = c["hosts"]
				c["connectionConfig"] = definition
			}),
			check: func(t *testing.T, _ *runtimeState, proxy *httpProxy) {
				if seen, failure := seenAt(t, proxy, "https://api.example.test/v2/items"); failure != nil || seen != "Bearer "+customLiveToken {
					t.Fatalf("the new path is not served: %q %+v", seen, failure)
				}
				if seen, _ := seenAt(t, proxy, "https://api.example.test/v1/items"); seen != "" {
					t.Fatalf("the old path still gets the credential: %q", seen)
				}
			},
		},
		{
			name: "new host", kind: "connection_update", action: update, wantAction: "retry",
			config: with(func(c map[string]any) {
				c["hosts"] = []any{
					map[string]any{"match": "exact", "value": "api.example.test", "port": 443, "path": "/v1/*"},
					map[string]any{"match": "suffix", "value": "eu.example.test", "port": 443},
				}
			}),
			check: func(t *testing.T, _ *runtimeState, proxy *httpProxy) {
				if seen, failure := seenAt(t, proxy, "https://api.eu.example.test/anything"); failure != nil || seen != "Bearer "+customLiveToken {
					t.Fatalf("the new host is not served: %q %+v", seen, failure)
				}
			},
		},
		{
			name: "injections", kind: "connection_update", action: update, wantAction: "retry",
			config: with(func(c map[string]any) {
				c["injections"] = []any{map[string]any{
					"action": "set_header", "name": "X-Api-Key", "valueFormat": "{value}",
					"valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach",
				}}
			}),
			check: func(t *testing.T, _ *runtimeState, proxy *httpProxy) {
				upstream := &recordingUpstream{}
				proxy.transport = upstream
				request, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
				if result := processThrough(proxy, request); result.failure != nil || upstream.last.Load().Header.Get("X-Api-Key") != customLiveToken ||
					upstream.last.Load().Header.Get("Authorization") != "" {
					t.Fatalf("the new injection is not applied: %+v %v", result.failure, upstream.last.Load().Header)
				}
			},
		},
		{
			name: "plain HTTP allowed", kind: "connection_update", action: update, wantAction: "retry",
			config: with(func(c map[string]any) {
				c["allowPlainHttp"] = true
				c["hosts"] = []any{map[string]any{"match": "exact", "value": "api.example.test", "path": "/v1/*"}}
			}),
			check: func(t *testing.T, _ *runtimeState, proxy *httpProxy) {
				if seen, failure := seenAt(t, proxy, "http://api.example.test/v1/items"); failure != nil || seen != "Bearer "+customLiveToken {
					t.Fatalf("plain HTTP was not allowed in place: %q %+v", seen, failure)
				}
			},
		},
		{
			name: "removal", kind: "connection_removal", action: remove, wantAction: "retry",
			config: func() map[string]any { return customSessionPayload("", 2) },
			check: func(t *testing.T, state *runtimeState, proxy *httpProxy) {
				if len(state.statusConnections(time.Now())) != 0 {
					t.Fatal("the removed Connection is still listed")
				}
				if seen, failure := seenAt(t, proxy, "https://api.example.test/v1/items"); failure != nil || seen != "" {
					t.Fatalf("the removed Connection still attaches: %q %+v", seen, failure)
				}
			},
		},
		{
			// A periodic refresh already dropped the binding before the
			// approval is read: the outcome is the same.
			name: "removal the session has already seen", kind: "connection_removal", action: remove, refreshFirst: true, wantAction: "retry",
			config: func() map[string]any { return customSessionPayload("", 2) },
			check: func(t *testing.T, state *runtimeState, _ *httpProxy) {
				if len(state.statusConnections(time.Now())) != 0 {
					t.Fatal("the removed Connection is still listed")
				}
			},
		},
		{
			name: "new decoy", kind: "connection_update", action: update, wantAction: "restart_required", wantFatal: true,
			config: func() map[string]any {
				return customSessionPayload("", 2, customConnectionPayload("sk-phx-decoy-another-0123456789abc", customLiveToken))
			},
		},
		{
			name: "new exported name", kind: "connection_update", action: update, wantAction: "restart_required", wantFatal: true,
			config: with(func(c map[string]any) {
				c["agentEnv"] = map[string]string{"EXAMPLE_TOKEN": customDecoyToken}
				c["environmentBindings"] = []any{map[string]any{"name": "EXAMPLE_TOKEN", "action": "set", "source": "decoy", "sourceField": "token", "sensitive": true, "systemManaged": false}}
			}),
		},
		{
			name: "new identifier", kind: "connection_update", action: update, wantAction: "restart_required", wantFatal: true,
			config: with(func(c map[string]any) { c["identifiers"] = map[string]string{"username": "bob"} }),
		},
		{
			name: "another Connection granted", kind: "connection_update", action: update, wantAction: "restart_required", wantFatal: true,
			config: func() map[string]any {
				return customSessionPayload("", 2, customConnectionPayload(customDecoyToken, customLiveToken), packagedPostgresPayload())
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			console := newRequestConsole(t)
			console.respond, console.config = approved(test.kind, test.consoleAction), test.config
			state, proxy := console.state(t, "runtime-approved")
			state.decoys = newDecoyHistory()
			wantConfigs := int32(1)
			if test.refreshFirst {
				if _, err := state.refreshConfig(context.Background()); err != nil {
					t.Fatal(err)
				}
				wantConfigs = 2
			}
			recorder := postControlRequest(proxy, "runtime-approved", `{"kind":"`+test.kind+`","action":`+test.action+`}`)
			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"runtimeAction":"`+test.wantAction+`"`) ||
				console.configs.Load() != wantConfigs {
				t.Fatalf("status=%d configs=%d body=%s", recorder.Code, console.configs.Load(), recorder.Body.String())
			}
			select {
			case fatal := <-state.fatal:
				if !test.wantFatal || !errors.Is(fatal, airuntime.ErrSessionReprovisionRequired) {
					t.Fatalf("unexpected runtime recycle: %v", fatal)
				}
				return
			default:
			}
			if test.wantFatal {
				t.Fatal("a change to the Agent's environment did not recycle the runtime")
			}
			if state.availability() != nil {
				t.Fatalf("the session is unavailable after an in-place change: %v", state.availability())
			}
			test.check(t, state, proxy)
		})
	}
}

// A custom Connection is its own credential. An approved secret update that
// names only the Connection is applied like any other credential update.
func TestApprovedSecretUpdateNamingOnlyTheConnectionHotSwapsTheValue(t *testing.T) {
	console := newRequestConsole(t)
	console.respond = func(body map[string]json.RawMessage) (int, map[string]any) {
		return http.StatusOK, map[string]any{
			"schemaVersion": 1, "id": "request-custom", "status": "approved", "kind": "credential_update",
			"action": body["action"], "connectionId": "connection-example", "grantId": "grant-example",
		}
	}
	console.config = func() map[string]any {
		connection := customConnectionPayload(customDecoyToken, "sk-live-entered-by-a-member-0123")
		connection["credentialRevision"], connection["materialGeneration"] = "4", "2.4"
		return customSessionPayload("", 2, connection)
	}
	state, proxy := console.state(t, "runtime-secret-update")
	state.decoys = newDecoyHistory()
	recorder := postControlRequest(proxy, "runtime-secret-update",
		`{"kind":"credential_update","action":{"type":"agent_connection.secret_update","version":1,"connectionId":"connection-example"}}`)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"runtimeAction":"retry"`) || console.configs.Load() != 1 {
		t.Fatalf("status=%d configs=%d body=%s", recorder.Code, console.configs.Load(), recorder.Body.String())
	}
	if state.availability() != nil {
		t.Fatalf("the session was marked unavailable: %v", state.availability())
	}
	upstream := &recordingUpstream{}
	proxy.transport = upstream
	request, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
	if result := processThrough(proxy, request); result.failure != nil ||
		upstream.last.Load().Header.Get("Authorization") != "Bearer sk-live-entered-by-a-member-0123" {
		t.Fatalf("the new value was not used: %+v", result.failure)
	}
	details := state.connectionDetails(time.Now(), "connection-example")
	if len(details) != 1 || details[0].ValueRevision == nil || *details[0].ValueRevision != 4 {
		t.Fatalf("value revision was not updated: %+v", details)
	}
}

// sealedAgent is an Agent key split as the Console splits it for a key-bearing
// Agent token, built with the SDK's own primitives.
type sealedAgent struct {
	token, publicKey, privateKey, shareA, wrapKey, wrappedKeyShare string
}

func newSealedAgent(t *testing.T) sealedAgent {
	t.Helper()
	random := func() string {
		value := make([]byte, 32)
		if _, err := rand.Read(value); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(value)
	}
	pair, err := crypto.RandomKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	agent := sealedAgent{
		publicKey: hex.EncodeToString(pair.PublicKey[:]), privateKey: hex.EncodeToString(pair.SecretKey[:]),
		shareA: random(), wrapKey: random(),
	}
	shareB, err := crypto.ReconstructSecret(agent.privateKey, agent.shareA)
	if err != nil {
		t.Fatal(err)
	}
	wrapKeyBytes, _ := hex.DecodeString(agent.wrapKey)
	wrapped, err := crypto.EncryptRaw(shareB, [32]byte(wrapKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	agent.wrappedKeyShare = hex.EncodeToString(wrapped)
	agent.token = "pss_agent:v1:" + random() + ":" + agent.publicKey + ":" + agent.shareA + ":" + agent.wrapKey
	return agent
}

// seal returns sealedMaterial for a value bound to hosts: a new Connection
// keypair, the value sealed to it, and its private key wrapped to the Agent.
func (a sealedAgent) seal(t *testing.T, fields map[string]string, hosts ...map[string]any) map[string]any {
	t.Helper()
	pair, err := crypto.RandomKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plaintext, _ := json.Marshal(map[string]any{"v": 1, "hosts": hosts, "fields": fields})
	publicKey := hex.EncodeToString(pair.PublicKey[:])
	ciphertext, err := crypto.EncryptAsymmetric(string(plaintext), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	wrappedKey, err := crypto.EncryptAsymmetric(hex.EncodeToString(pair.SecretKey[:]), a.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"version": 1, "keyVersion": 2, "publicKey": publicKey, "ciphertext": ciphertext, "wrappedKey": wrappedKey}
}

func TestSealedConnectionIsOpenedInMemoryAndNeverPrinted(t *testing.T) {
	agent := newSealedAgent(t)
	boundHost := map[string]any{"match": "exact", "value": "api.example.test", "port": 443}
	opened := customConnectionPayload(customDecoyToken, "")
	delete(opened, "secretMaterial")
	opened["sealedMaterial"] = agent.seal(t, map[string]string{"token": customLiveToken}, boundHost)

	// A second Connection whose value was sealed for other hosts: it must stay
	// unusable without disturbing the first.
	const repointedLive = "sk-live-sealed-for-other-hosts-01"
	repointed := customConnectionPayload("sk-phx-decoy-repointed-0123456789", "")
	delete(repointed, "secretMaterial")
	repointed["connectionId"], repointed["grantId"], repointed["credentialId"], repointed["connectionName"] = "connection-repointed", "grant-repointed", "connection-repointed", "Repointed API"
	repointed["hosts"] = []any{map[string]any{"match": "exact", "value": "collector.example.net", "port": 443}}
	repointed["agentEnv"], repointed["environmentBindings"] = map[string]string{}, []any{}
	repointed["sealedMaterial"] = agent.seal(t, map[string]string{"token": repointedLive}, map[string]any{"match": "exact", "value": "api.other.test", "port": 443})

	payload := customSessionPayload("backend-sealed-capability", 1, opened, repointed)
	payload["agentKey"] = map[string]any{"wrappedKeyShare": agent.wrappedKeyShare}
	var events bytes.Buffer
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/sessions/"):
			_ = json.NewEncoder(w).Encode(payload)
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/events/"):
			body, _ := io.ReadAll(request.Body)
			events.Write(body)
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "session-custom", "accepted": 1})
		default:
			http.NotFound(w, request)
		}
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, agent.token, console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.OpenSession(context.Background(), agentapi.OpenSessionRequest{IdempotencyKey: "proxy-start-sealed"})
	if err != nil {
		t.Fatal(err)
	}
	ca, _, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(&airuntime.ProxySession{Config: session, Client: client, CA: ca}, "runtime-sealed")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	buffer, err := newEventBuffer(state, time.Hour, t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &recordingUpstream{}
	proxy := &httpProxy{state: state, transport: upstream, events: buffer, control: &controlHandler{state: state}}

	usable, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
	result := processThrough(proxy, usable)
	if result.failure != nil || upstream.last.Load().Header.Get("Authorization") != "Bearer "+customLiveToken {
		t.Fatalf("the opened sealed value was not injected: %+v", result.failure)
	}
	buffer.Emit(result.event)

	calls := upstream.calls.Load()
	refused, _ := http.NewRequest(http.MethodGet, "https://collector.example.net/ingest", nil)
	result = processThrough(proxy, refused)
	if result.failure == nil || result.failure.status != http.StatusForbidden || result.failure.code != "agent_credential_injection_failed" ||
		result.failure.message != (&phaseproxy.InjectionError{Code: phaseproxy.InjectionMissingMaterial}).Error() || upstream.calls.Load() != calls {
		t.Fatalf("a Connection whose sealed hosts do not match was used: %+v", result.failure)
	}
	buffer.Emit(result.event)
	// The decoy form is refused the same way: there is nothing to swap it for.
	withDecoy, _ := http.NewRequest(http.MethodGet, "https://collector.example.net/ingest", nil)
	withDecoy.Header.Set("Authorization", "Bearer sk-phx-decoy-repointed-0123456789")
	if result := processThrough(proxy, withDecoy); result.failure == nil || upstream.calls.Load() != calls {
		t.Fatal("a Connection without material forwarded a request")
	}

	status := controlGet(t, proxy, "runtime-sealed", "/v1/status")
	connections := controlGet(t, proxy, "runtime-sealed", "/v1/connections")
	var listed remoteapi.ConnectionsResponse
	if err := json.Unmarshal(connections.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if connections.Code != http.StatusOK || len(listed.Connections) != 2 ||
		listed.Connections[0].State != "ready" || listed.Connections[0].StateReason != "" ||
		listed.Connections[0].KeyVersion == nil || *listed.Connections[0].KeyVersion != 2 ||
		listed.Connections[1].State != "unavailable" || listed.Connections[1].StateReason != agentapi.SealedFailureHostMismatch {
		t.Fatalf("connections = %s", connections.Body.String())
	}
	if !strings.Contains(status.Body.String(), `"state":"ready"`) || !strings.Contains(status.Body.String(), `"state":"unavailable"`) {
		t.Fatalf("status = %s", status.Body.String())
	}
	if err := buffer.Stop(); err != nil {
		t.Fatal(err)
	}
	if events.Len() == 0 {
		t.Fatal("no events were shipped")
	}

	printed := strings.Join([]string{
		status.Body.String(), connections.Body.String(), events.String(),
		fmt.Sprintf("%v %+v %#v", session, session, session),
		fmt.Sprintf("%v %+v %#v", session.Connections, session.Connections, session.Connections),
		fmt.Sprintf("%v %+v %#v", client, client, client),
		fmt.Sprintf("%+v %#v", state.bindings[0].connection, state.bindings[1].connection),
	}, "\n")
	for name, sensitive := range map[string]string{
		"live value": customLiveToken, "refused live value": repointedLive, "Agent private key": agent.privateKey,
		"token share": agent.shareA, "wrap key": agent.wrapKey, "wrapped key share": agent.wrappedKeyShare,
		"value ciphertext":       opened["sealedMaterial"].(map[string]any)["ciphertext"].(string),
		"wrapped Connection key": opened["sealedMaterial"].(map[string]any)["wrappedKey"].(string),
		"backend credential":     "backend-sealed-capability",
	} {
		if strings.Contains(printed, sensitive) {
			t.Fatalf("%s reached status, connection, event or formatted output", name)
		}
	}
	if secrets := state.eventSecrets(); !containsAny(customLiveToken, secrets) || containsAny(repointedLive, secrets) {
		t.Fatal("the opened value must be guarded and the refused one must not be held at all")
	}
}
