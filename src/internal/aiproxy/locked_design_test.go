package aiproxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

func TestLockedDefaultPortsAndOccupiedListenerDoesNotFallback(t *testing.T) {
	engine := New()
	if engine.ListenAddress != DefaultProxyListenAddress {
		t.Fatalf("proxy default = %q", engine.ListenAddress)
	}
	if DefaultProxyListenAddress != "127.0.0.1:9543" || DefaultPostgresListenAddress != "127.0.0.1:9544" {
		t.Fatalf("unexpected fixed ports: %q %q", DefaultProxyListenAddress, DefaultPostgresListenAddress)
	}

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	engine.ListenAddress = occupied.Addr().String()
	var started atomic.Bool
	engine.OnStarted = func(Endpoints) { started.Store(true) }
	console := httptest.NewServer(http.NotFoundHandler())
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	err = engine.Serve(context.Background(), emptyProxySession(t, client, "backend-one"))
	if err == nil || !strings.Contains(err.Error(), "listen for Phase AI HTTP proxy") {
		t.Fatalf("occupied listener error = %v", err)
	}
	if started.Load() {
		t.Fatal("engine silently selected another port")
	}
}

func TestEngineRejectsRandomListenerPorts(t *testing.T) {
	for _, configure := range []func(*Engine){
		func(engine *Engine) { engine.ListenAddress = "127.0.0.1:0" },
		func(engine *Engine) { engine.PostgresListenAddress = "127.0.0.1:0" },
	} {
		engine := New()
		configure(engine)
		if err := engine.Ready(); err == nil || !strings.Contains(err.Error(), "port 0/random") {
			t.Fatalf("random listener validation error = %v", err)
		}
	}
}

func TestEnvironmentBindingMetadataChangeRequiresReprovision(t *testing.T) {
	base := agentapi.Connection{
		GrantID: "grant", ServiceType: "github", Protocol: "http",
		Hosts:            []agentapi.HostRule{{Match: "exact", Value: "api.github.com", Port: 443}},
		ConnectionConfig: map[string]any{"tenant": "github.com"}, Injection: agentapi.Injection{Action: "set_header"},
		EnvironmentBindings: []agentapi.EnvironmentBinding{{
			Name: "GITHUB_TOKEN", Action: agentapi.EnvironmentBindingSet, Source: agentapi.EnvironmentSourceDecoy,
			SourceField: "access_token", Sensitive: true, SystemManaged: true,
		}},
	}
	changed := base
	changed.EnvironmentBindings = append([]agentapi.EnvironmentBinding(nil), base.EnvironmentBindings...)
	changed.EnvironmentBindings[0].Name = "GH_TOKEN"
	if !requiresEnvironmentReprovision([]*binding{{connection: base}}, []*binding{{connection: changed}}, nil, nil) {
		t.Fatal("changed environment binding metadata did not require process reprovision")
	}
	if requiresEnvironmentReprovision([]*binding{{connection: base}}, []*binding{{connection: base}}, nil, nil) {
		t.Fatal("identical environment binding metadata required reprovision")
	}

	clone := func() agentapi.Connection {
		candidate := base
		candidate.Hosts = append([]agentapi.HostRule(nil), base.Hosts...)
		candidate.ConnectionConfig = map[string]any{"tenant": base.ConnectionConfig["tenant"]}
		candidate.EnvironmentBindings = append([]agentapi.EnvironmentBinding(nil), base.EnvironmentBindings...)
		return candidate
	}
	for name, mutate := range map[string]func(*agentapi.Connection){
		"service type": func(candidate *agentapi.Connection) { candidate.ServiceType = "gitlab" },
		"host":         func(candidate *agentapi.Connection) { candidate.Hosts[0].Value = "github.example.com" },
		"config":       func(candidate *agentapi.Connection) { candidate.ConnectionConfig["tenant"] = "github.example.com" },
		"injection":    func(candidate *agentapi.Connection) { candidate.Injection.Action = "replace_header" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clone()
			mutate(&candidate)
			if !requiresEnvironmentReprovision([]*binding{{connection: base}}, []*binding{{connection: candidate}}, nil, nil) {
				t.Fatalf("changed %s did not require process reprovision", name)
			}
		})
	}
}

func TestDiscoverRejectsProcessVisibleEnvironmentDrift(t *testing.T) {
	environmentBindings := []agentapi.EnvironmentBinding{{
		Name: "GITHUB_TOKEN", Action: agentapi.EnvironmentBindingSet, Source: agentapi.EnvironmentSourceDecoy,
		SourceField: "access_token", Sensitive: true, SystemManaged: true,
	}}
	runtimeConnection := agentapi.Connection{
		GrantID: "grant", ConnectionID: "connection", ServiceType: "github", Protocol: "http",
		Hosts:     []agentapi.HostRule{{Match: "exact", Value: "api.github.com", Port: 443}},
		Injection: agentapi.Injection{Action: "set_header"}, Identifiers: map[string]string{},
		DecoyMaterial: map[string]string{"access_token": "decoy"}, EnvironmentBindings: environmentBindings,
	}
	if err := json.Unmarshal([]byte(`{"GITHUB_TOKEN":"decoy"}`), &runtimeConnection.AgentEnv); err != nil {
		t.Fatal(err)
	}
	state := &runtimeState{
		generation: 1, configEnv: map[string]string{"SAFE": "value"},
		bindings: []*binding{{connection: runtimeConnection}},
	}
	discover := &agentapi.DiscoverResponse{
		ConfigGeneration: 1, ConfigEnv: map[string]string{"SAFE": "value"},
		Connections: []agentapi.DiscoverConnection{{
			GrantID: "grant", ConnectionID: "connection", ServiceType: "github", Protocol: "http",
			Hosts: runtimeConnection.Hosts, Injection: runtimeConnection.Injection, Identifiers: map[string]string{},
			DecoyMaterial: map[string]string{"access_token": "decoy"}, AgentEnv: map[string]string{"GITHUB_TOKEN": "decoy"},
			EnvironmentBindings: append([]agentapi.EnvironmentBinding(nil), environmentBindings...),
		}},
	}
	if err := state.applyTrustedDiscoverAuthorization(discover); err != nil {
		t.Fatalf("matching discover response rejected: %v", err)
	}
	discover.Connections[0].AgentEnv["GITHUB_TOKEN"] = "other-decoy"
	if err := state.applyTrustedDiscoverAuthorization(discover); err == nil {
		t.Fatal("discover response with changed Agent environment was accepted")
	}
	discover.Connections[0].AgentEnv["GITHUB_TOKEN"] = "decoy"
	discover.Connections[0].EnvironmentBindings[0].Name = "GH_TOKEN"
	if err := state.applyTrustedDiscoverAuthorization(discover); err == nil {
		t.Fatal("discover response with changed environment binding metadata was accepted")
	}
}

func TestUnboundTunnelClosesWhenSessionBecomesUnhealthy(t *testing.T) {
	console := httptest.NewServer(http.NotFoundHandler())
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := emptyProxySession(t, client, "backend-only")
	state, err := newRuntimeStateWithCapability(session, "runtime-only")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()

	clientProxy, clientPeer := net.Pipe()
	upstreamProxy, upstreamPeer := net.Pipe()
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	stop := make(chan struct{})
	proxy := &httpProxy{state: state}
	go proxy.watchUnboundTunnel(context.Background(), clientProxy, upstreamProxy, stop)

	state.setUnhealthy()
	_ = clientPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientPeer.Read(make([]byte, 1)); err == nil {
		close(stop)
		t.Fatal("client side of unbound tunnel remained open")
	}
	_ = upstreamPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := upstreamPeer.Read(make([]byte, 1)); err == nil {
		close(stop)
		t.Fatal("upstream side of unbound tunnel remained open")
	}
}

func TestEngineRuntimeCapabilityIsStablePerEngineAndDistinctAcrossEngines(t *testing.T) {
	engine := New()
	first, err := engine.processRuntimeCapability("backend-one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.processRuntimeCapability("backend-two")
	if err != nil {
		t.Fatal(err)
	}
	if first.Reveal() == "" || first != second || first.Reveal() == "backend-one" || first.Reveal() == "backend-two" {
		t.Fatalf("runtime capabilities were not stable and distinct: %q %q", first.Reveal(), second.Reveal())
	}
	fresh, err := New().processRuntimeCapability("backend-three")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Reveal() == "" || fresh == first || fresh.Reveal() == "backend-three" {
		t.Fatalf("fresh Engine reused or exposed a backend capability: first=%q fresh=%q", first.Reveal(), fresh.Reveal())
	}
}

func TestLocalProxyAuthenticatesUnboundHTTPAndCONNECTBeforeEgress(t *testing.T) {
	console := httptest.NewServer(http.NotFoundHandler())
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := emptyProxySession(t, client, "backend-only")
	state, err := newRuntimeStateWithCapability(session, "runtime-only")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	var roundTrips, dials atomic.Int32
	proxy := &httpProxy{
		state: state,
		ca:    session.CA,
		unboundTransport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			roundTrips.Add(1)
			return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
		}),
		unboundDial: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("unexpected dial")
		},
	}

	for name, credential := range map[string]string{"missing": "", "wrong": "wrong", "backend": "backend-only"} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://unbound.example/resource", nil)
			if credential != "" {
				setProxyCapability(request, credential)
			}
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, request)
			if response.Code != http.StatusProxyAuthRequired {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	connect := httptest.NewRequest(http.MethodConnect, "http://proxy.invalid", nil)
	connect.Host = "unbound.example:443"
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, connect)
	if response.Code != http.StatusProxyAuthRequired {
		t.Fatalf("CONNECT status=%d", response.Code)
	}
	if roundTrips.Load() != 0 || dials.Load() != 0 {
		t.Fatalf("unauthenticated traffic reached egress: roundTrips=%d dials=%d", roundTrips.Load(), dials.Load())
	}

	authenticated := httptest.NewRequest(http.MethodGet, "http://unbound.example/resource", nil)
	setProxyCapability(authenticated, "runtime-only")
	response = httptest.NewRecorder()
	proxy.ServeHTTP(response, authenticated)
	if response.Code != http.StatusNoContent || roundTrips.Load() != 1 {
		t.Fatalf("authenticated status=%d roundTrips=%d", response.Code, roundTrips.Load())
	}
}

func TestManifestIsExactAuthenticatedAndNeverEgresses(t *testing.T) {
	const (
		backendCapability = "backend-manifest-only"
		runtimeCapability = "runtime-manifest-only"
		liveSecret        = "live-upstream-secret"
	)
	var discoverCalls, roundTrips, dials atomic.Int32
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasSuffix(req.URL.Path, "/discover/"):
			discoverCalls.Add(1)
			if req.Header.Get(agentapi.SessionCredentialHeader) != backendCapability {
				t.Errorf("backend discover credential = %q", req.Header.Get(agentapi.SessionCredentialHeader))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "session-123", "configGeneration": 1,
				"configEnv": map[string]string{"SAFE": "value"}, "connections": []any{},
			})
		case strings.HasSuffix(req.URL.Path, "/events/"):
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"schemaVersion":1,"accepted":1,"duplicates":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := emptyProxySession(t, client, backendCapability)
	session.Config.ConfigEnv = map[string]string{"SAFE": "value"}
	state, err := newRuntimeStateWithCapability(session, runtimeCapability)
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	events, err := newEventBuffer(state, time.Hour, t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Stop()
	manifest := &manifestHandler{
		state: state, ca: session.CA, proxy: remoteapi.Endpoint{Host: "127.0.0.1", Port: 9543}, events: events,
		providerEnvironment: phaseproxy.ProcessEnvironmentPlan{
			Set: map[string]string{"SAFE": "value"}, Unset: []string{"PHASE_AGENT_TOKEN", "PHASE_SERVICE_TOKEN"},
		},
		processEnvironment: phaseproxy.ProcessEnvironmentPlan{
			Set: map[string]string{
				"SAFE": "value", "HTTP_PROXY": "http://phase:runtime-manifest-only@127.0.0.1:9543",
				"HTTPS_PROXY": "http://phase:runtime-manifest-only@127.0.0.1:9543", "PHASE_AI_CA_BUNDLE": "/stable/phase-ca-bundle.pem",
			},
			Unset: []string{"PHASE_AGENT_TOKEN", "PHASE_SERVICE_TOKEN"},
		},
	}
	proxy := &httpProxy{
		state: state, ca: session.CA, manifest: manifest, events: events,
		transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			roundTrips.Add(1)
			return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
		}),
		unboundTransport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			roundTrips.Add(1)
			return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
		}),
		unboundDial: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("reserved origin reached dial")
		},
	}

	request := httptest.NewRequest(http.MethodGet, ManifestURL, nil)
	setProxyCapability(request, runtimeCapability)
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("manifest status=%d body=%s", response.Code, response.Body.String())
	}
	var decoded remoteapi.ManifestResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.ProcessEnvironment, manifest.processEnvironment) {
		t.Fatalf("manifest process environment diverged from launch plan: got=%+v want=%+v", decoded.ProcessEnvironment, manifest.processEnvironment)
	}
	for _, forbidden := range []string{backendCapability, liveSecret, "PRIVATE KEY", "secretMaterial", "sessionCredential"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("manifest leaked %q: %s", forbidden, response.Body.String())
		}
	}
	for _, required := range []string{
		`"status":"http://phase.invalid/v1/status"`,
		`"context":"http://phase.invalid/v1/context"`,
		`"createRequest":"http://phase.invalid/v1/requests"`,
		`"pollRequest":"http://phase.invalid/v1/requests/{requestId}"`,
		`"processEnvironment"`, `"SAFE":"value"`, `"HTTP_PROXY":"http://phase:runtime-manifest-only@127.0.0.1:9543"`,
		`"PHASE_AI_CA_BUNDLE":"/stable/phase-ca-bundle.pem"`, `"PHASE_AGENT_TOKEN"`, `"PHASE_SERVICE_TOKEN"`,
	} {
		if !strings.Contains(response.Body.String(), required) {
			t.Fatalf("manifest missing %q: %s", required, response.Body.String())
		}
	}
	if strings.Contains(response.Body.String(), `"refresh"`) {
		t.Fatalf("manifest still advertised manual refresh: %s", response.Body.String())
	}
	if discoverCalls.Load() != 1 || roundTrips.Load() != 0 || dials.Load() != 0 {
		t.Fatalf("manifest boundary calls discover=%d roundTrips=%d dials=%d", discoverCalls.Load(), roundTrips.Load(), dials.Load())
	}

	invalid := []struct {
		name       string
		method     string
		target     string
		credential string
		status     int
		directHost string
	}{
		{name: "missing auth", method: http.MethodGet, target: ManifestURL, status: http.StatusProxyAuthRequired},
		{name: "wrong auth", method: http.MethodGet, target: ManifestURL, credential: "wrong", status: http.StatusProxyAuthRequired},
		{name: "wrong path", method: http.MethodGet, target: "http://phase.invalid/.well-known/other", credential: runtimeCapability, status: http.StatusNotFound},
		{name: "wrong method", method: http.MethodPost, target: ManifestURL, credential: runtimeCapability, status: http.StatusBadRequest},
		{name: "query", method: http.MethodGet, target: ManifestURL + "?x=1", credential: runtimeCapability, status: http.StatusBadRequest},
		{name: "alternate port", method: http.MethodGet, target: "http://phase.invalid:80/.well-known/agents", credential: runtimeCapability, status: http.StatusNotFound},
		{name: "direct origin", method: http.MethodGet, target: ManifestPath, credential: runtimeCapability, status: http.StatusBadRequest, directHost: ManifestHost},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.target, nil)
			if test.directHost != "" {
				req.Host = test.directHost
			}
			if test.credential != "" {
				setProxyCapability(req, test.credential)
			}
			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, req)
			if recorder.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, test.status, recorder.Body.String())
			}
		})
	}
	connect := &http.Request{
		Method: http.MethodConnect, Host: "phase.invalid:443", URL: &url.URL{}, Header: make(http.Header), RemoteAddr: "127.0.0.1:12345",
	}
	setProxyCapability(connect, runtimeCapability)
	response = httptest.NewRecorder()
	proxy.ServeHTTP(response, connect)
	if response.Code != http.StatusForbidden {
		t.Fatalf("reserved CONNECT status=%d body=%s", response.Code, response.Body.String())
	}
	if discoverCalls.Load() != 1 || roundTrips.Load() != 0 || dials.Load() != 0 {
		t.Fatalf("invalid manifest request escaped boundary: discover=%d roundTrips=%d dials=%d", discoverCalls.Load(), roundTrips.Load(), dials.Load())
	}
}

func emptyProxySessionWithConfig(t *testing.T, client *agentapi.Client, config *agentapi.OpenSessionResponse) *airuntime.ProxySession {
	t.Helper()
	base := emptyProxySession(t, client, config.SessionCredential.Reveal())
	base.Config = config
	return base
}

func setProxyCapability(request *http.Request, credential string) {
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("phase:"+credential)))
}
