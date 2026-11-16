package aiproxy

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// exportlessConnectionPayload is a custom HTTP Connection that puts nothing
// into the Agent's environment: its credential is only ever attached.
func exportlessConnectionPayload(id, host, live string) map[string]any {
	payload := customConnectionPayload("sk-phx-decoy-"+id+"-0123456789abcdef", live)
	payload["grantId"], payload["connectionId"], payload["credentialId"] = "grant-"+id, "connection-"+id, "connection-"+id
	payload["connectionName"], payload["credentialName"] = id, id
	payload["hosts"] = []any{map[string]any{"match": "exact", "value": host, "port": 443}}
	payload["connectionConfig"] = map[string]any{"specVersion": 1, "preset": "bearer"}
	payload["identifiers"], payload["agentEnv"], payload["environmentBindings"] = map[string]string{}, map[string]string{}, []any{}
	return payload
}

func bindingFor(t *testing.T, payload map[string]any) *binding {
	t.Helper()
	session := decodeTestSession(t, customSessionPayload("backend", 1, payload))
	bindings, err := parseBindings(session.Connections)
	if err != nil {
		t.Fatal(err)
	}
	return bindings[0]
}

// Only a custom HTTP Connection may change shape or leave while the session
// runs, and only as long as nothing the Agent process was given changes.
func TestConfigChangeClassification(t *testing.T) {
	custom := func(mutate func(map[string]any)) *binding {
		payload := customConnectionPayload(customDecoyToken, customLiveToken)
		if mutate != nil {
			mutate(payload)
		}
		return bindingFor(t, payload)
	}
	packaged := func(mutate func(map[string]any)) *binding {
		payload := packagedPostgresPayload()
		if mutate != nil {
			mutate(payload)
		}
		return bindingFor(t, payload)
	}
	classify := func(before, after []*binding) configChange {
		return classifyConfigChange(before, after, map[string]string{}, map[string]string{})
	}

	inPlace := map[string]func(map[string]any){
		"hosts": func(c map[string]any) {
			c["hosts"] = []any{map[string]any{"match": "suffix", "value": "example.test", "port": 443}}
		},
		"definition": func(c map[string]any) { c["connectionConfig"] = map[string]any{"specVersion": 1, "preset": "headers"} },
		"injections": func(c map[string]any) {
			injection := bearerAttachInjection()
			injection["whenAbsent"] = "block"
			c["injections"] = []any{injection}
		},
		"single injection mirror": func(c map[string]any) { c["injection"] = bearerAttachInjection() },
		"plain HTTP":              func(c map[string]any) { c["allowPlainHttp"] = true },
	}
	for name, mutate := range inPlace {
		change := classify([]*binding{custom(nil), packaged(nil)}, []*binding{custom(mutate), packaged(nil)})
		if change.reprovision || !change.reshaped || len(change.removed) != 0 {
			t.Errorf("custom %s change = %+v, want an in-place reshape", name, change)
		}
		// The same change on anything but a custom HTTP Connection recycles.
		asPackaged := func(c map[string]any) {
			mutate(c)
			c["serviceType"], c["credentialProvider"] = "example", "example"
		}
		before := custom(func(c map[string]any) { c["serviceType"], c["credentialProvider"] = "example", "example" })
		if change := classify([]*binding{before}, []*binding{custom(asPackaged)}); !change.reprovision {
			t.Errorf("packaged %s change was applied in place", name)
		}
	}

	needsRestart := map[string]func(map[string]any){
		"decoy": func(c map[string]any) {
			c["decoyMaterial"] = map[string]string{"token": "sk-phx-decoy-other-0123456789abcdef"}
		},
		"identifier": func(c map[string]any) { c["identifiers"] = map[string]string{"username": "bob"} },
		"agent env":  func(c map[string]any) { c["agentEnv"] = map[string]string{} },
		"environment bindings": func(c map[string]any) {
			c["environmentBindings"] = []any{map[string]any{"name": "EXAMPLE_API_KEY", "action": "set", "source": "decoy", "sourceField": "token", "sensitive": false, "systemManaged": false}}
		},
		"config env":   func(c map[string]any) { c["configEnv"] = map[string]string{"EXAMPLE_REGION": "eu"} },
		"connection":   func(c map[string]any) { c["connectionId"], c["credentialId"] = "connection-other", "connection-other" },
		"service type": func(c map[string]any) { c["serviceType"] = "example" },
	}
	for name, mutate := range needsRestart {
		if change := classify([]*binding{custom(nil)}, []*binding{custom(mutate)}); !change.reprovision {
			t.Errorf("a changed %s was applied in place", name)
		}
	}

	if change := classify([]*binding{custom(nil), packaged(nil)}, []*binding{packaged(nil)}); change.reprovision || !change.reshaped ||
		len(change.removed) != 1 || change.removed[0].connection.ConnectionID != "connection-example" {
		t.Errorf("removed custom Connection = %+v, want an in-place removal", change)
	}
	if change := classify([]*binding{custom(nil), packaged(nil)}, []*binding{custom(nil)}); !change.reprovision {
		t.Error("a removed packaged Connection was applied in place")
	}
	if change := classify([]*binding{packaged(nil)}, []*binding{custom(nil), packaged(nil)}); !change.reprovision {
		t.Error("a newly granted Connection that exports a variable was applied in place")
	}
	// A new custom Connection that exports nothing gives the Agent's
	// processes nothing new, so it may simply start being served.
	exportless := bindingFor(t, exportlessConnectionPayload("audit", "audit.example.test", "sk-live-audit-0123456789abcdefgh"))
	if change := classify([]*binding{custom(nil)}, []*binding{custom(nil), exportless}); change.reprovision || !change.reshaped || len(change.removed) != 0 {
		t.Errorf("an added Connection that exports nothing = %+v, want an in-place addition", change)
	}
	for name, mutate := range map[string]func(map[string]any){
		"an exported decoy": func(c map[string]any) {
			c["agentEnv"] = map[string]string{"AUDIT_API_KEY": "sk-phx-decoy-audit-0123456789abcdef"}
			c["environmentBindings"] = []any{map[string]any{"name": "AUDIT_API_KEY", "action": "set", "source": "decoy", "sourceField": "token", "sensitive": true, "systemManaged": false}}
		},
		"a configuration variable": func(c map[string]any) { c["configEnv"] = map[string]string{"AUDIT_REGION": "eu"} },
		"a cleanup binding": func(c map[string]any) {
			c["environmentBindings"] = []any{map[string]any{"name": "AUDIT_TOKEN", "action": "unset", "source": "runtime", "sourceField": "token", "sensitive": false, "systemManaged": true}}
		},
		"a packaged service type": func(c map[string]any) { c["serviceType"], c["credentialProvider"] = "example", "example" },
	} {
		payload := exportlessConnectionPayload("audit", "audit.example.test", "sk-live-audit-0123456789abcdefgh")
		mutate(payload)
		if change := classify([]*binding{custom(nil)}, []*binding{custom(nil), bindingFor(t, payload)}); !change.reprovision {
			t.Errorf("an added Connection with %s was applied in place", name)
		}
	}
	emptyPostgres := packaged(func(c map[string]any) {
		c["agentEnv"], c["configEnv"], c["environmentBindings"] = map[string]string{}, map[string]string{}, []any{}
	})
	if change := classify([]*binding{custom(nil)}, []*binding{custom(nil), emptyPostgres}); !change.reprovision {
		t.Error("an added packaged Connection was applied in place")
	}
	if change := classify([]*binding{custom(nil)}, []*binding{custom(nil)}); change.reprovision || change.reshaped {
		t.Errorf("an unchanged configuration = %+v", change)
	}
	if change := classifyConfigChange([]*binding{custom(nil)}, []*binding{custom(nil)}, map[string]string{}, map[string]string{"REGION": "eu"}); !change.reprovision {
		t.Error("a changed session environment was applied in place")
	}
	// A value-only change stays the hot swap it always was.
	rotated := custom(func(c map[string]any) {
		c["secretMaterial"], c["credentialRevision"], c["materialGeneration"] = map[string]string{"token": "sk-live-rotated-0123456789"}, "4", "2.4"
	})
	if change := classify([]*binding{custom(nil)}, []*binding{rotated}); change.reprovision || change.reshaped {
		t.Errorf("a value change = %+v", change)
	}
}

func environmentCompiler(t *testing.T, base []string, connections ...map[string]any) (*connectionEnvironmentCompiler, phaseproxy.ProcessEnvironmentPlan) {
	t.Helper()
	session := decodeTestSession(t, customSessionPayload("backend-environment", 1, connections...))
	proxySession := &airuntime.ProxySession{
		Config: session, CAPaths: phaseproxy.CAPaths{Certificate: "/stable/phase-ca.pem", Bundle: "/stable/phase-ca-bundle.pem"},
	}
	compiler := &connectionEnvironmentCompiler{session: proxySession, proxyURL: "http://phase:runtime-capability@127.0.0.1:9543", base: base}
	baseline, err := proxySession.CompileProcessEnvironment(compiler.proxyURL, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	return compiler, baseline
}

// The engine compiles the environment a refreshed configuration would give a
// new process. A reshape stays in place only if a running process already has
// all of it.
func TestEnvironmentCheckDecidesWhetherAReshapeStaysInPlace(t *testing.T) {
	second := func(environmentName string) map[string]any {
		payload := customConnectionPayload("sk-phx-decoy-second-0123456789abcd", "sk-live-second-0123456789abcdef")
		payload["grantId"], payload["connectionId"], payload["credentialId"] = "grant-second", "connection-second", "connection-second"
		payload["hosts"] = []any{map[string]any{"match": "exact", "value": "second.example.test", "port": 443}}
		payload["agentEnv"] = map[string]string{environmentName: "sk-phx-decoy-second-0123456789abcd"}
		payload["environmentBindings"] = []any{map[string]any{"name": environmentName, "action": "set", "source": "decoy", "sourceField": "token", "sensitive": true, "systemManaged": false}}
		return payload
	}
	configOf := func(connections ...map[string]any) *agentapi.SessionConfig {
		return &decodeTestSession(t, customSessionPayload("", 2, connections...)).SessionConfig
	}
	first := func(mutate func(map[string]any)) map[string]any {
		payload := customConnectionPayload(customDecoyToken, customLiveToken)
		if mutate != nil {
			mutate(payload)
		}
		return payload
	}
	hosts := func(values ...string) func(map[string]any) {
		return func(c map[string]any) {
			rules := make([]any, 0, len(values))
			for _, value := range values {
				rules = append(rules, map[string]any{"match": "exact", "value": value, "port": 443})
			}
			c["hosts"] = rules
		}
	}

	compiler, baseline := environmentCompiler(t, []string{"NO_PROXY=.internal.test,build.cache.test"}, first(nil), second("SECOND_API_KEY"))
	if baseline.Set["EXAMPLE_API_KEY"] != customDecoyToken || baseline.Set["SECOND_API_KEY"] == "" ||
		!strings.Contains(baseline.Set["NO_PROXY"], ".internal.test") {
		t.Fatalf("baseline environment = %v", baseline.Set)
	}
	holds := compiler.holdsFor(baseline, "")
	for name, test := range map[string]struct {
		config *agentapi.SessionConfig
		want   bool
	}{
		"nothing changed":                         {configOf(first(nil), second("SECOND_API_KEY")), true},
		"host outside any NO_PROXY entry":         {configOf(first(hosts("api.example.test", "eu.example.test")), second("SECOND_API_KEY")), true},
		"Connection removed":                      {configOf(first(nil)), true},
		"every Connection removed":                {configOf(), true},
		"host an inherited NO_PROXY entry covers": {configOf(first(hosts("api.internal.test")), second("SECOND_API_KEY")), false},
		"Connection added that exports nothing": {configOf(first(nil), second("SECOND_API_KEY"),
			exportlessConnectionPayload("audit", "audit.example.test", "sk-live-audit-0123456789abcdefgh")), true},
		"Connection added on a host NO_PROXY covers": {configOf(first(nil), second("SECOND_API_KEY"),
			exportlessConnectionPayload("audit", "audit.internal.test", "sk-live-audit-0123456789abcdefgh")), false},
		"host that is an inherited NO_PROXY entry": {configOf(first(hosts("build.cache.test")), second("SECOND_API_KEY")), false},
	} {
		if got := holds(test.config); got != test.want {
			t.Errorf("%s: environment holds = %t, want %t", name, got, test.want)
		}
	}

	// Two Connections that disagree on one name export neither. Removing one
	// frees the name for the other, which a running process does not have.
	contested, contestedBaseline := environmentCompiler(t, nil, first(nil), second("EXAMPLE_API_KEY"))
	if _, exported := contestedBaseline.Set["EXAMPLE_API_KEY"]; exported {
		t.Fatalf("a contested name was exported: %v", contestedBaseline.Set)
	}
	if contested.holdsFor(contestedBaseline, "")(configOf(first(nil))) {
		t.Error("a removal that newly exports a variable was applied in place")
	}

	// A session pinned to one Connection cannot outlive it.
	pinned := compiler.holdsFor(baseline, "connection-second")
	if !pinned(configOf(first(hosts("eu.example.test")), second("SECOND_API_KEY"))) || pinned(configOf(first(nil))) {
		t.Error("the pinned Connection's presence was not required")
	}

	// replaceConfig asks only when custom Connections were reshaped, and
	// recycles when the answer is no.
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-check", 1, first(nil)), "runtime-check")
	defer state.destroy()
	state.decoys = newDecoyHistory()
	var asked atomic.Int32
	answer := true
	state.setEnvironmentCheck(func(*agentapi.SessionConfig) bool {
		asked.Add(1)
		return answer
	})
	rotated := first(func(c map[string]any) {
		c["secretMaterial"] = map[string]string{"token": "sk-live-rotated-0123456789abcd"}
	})
	if err := state.replaceConfig(configOf(rotated)); err != nil || asked.Load() != 0 {
		t.Fatalf("a value change consulted the environment: err=%v asked=%d", err, asked.Load())
	}
	if err := state.replaceConfig(configOf(first(hosts("eu.example.test")))); err != nil || asked.Load() != 1 {
		t.Fatalf("a reshape the environment allows was refused: err=%v asked=%d", err, asked.Load())
	}
	answer = false
	if err := state.replaceConfig(configOf(first(hosts("api.internal.test")))); !errors.Is(err, airuntime.ErrSessionReprovisionRequired) || asked.Load() != 2 {
		t.Fatalf("a reshape the environment does not allow: err=%v asked=%d", err, asked.Load())
	}
	if bound, _ := state.hasBoundHost("eu.example.test", 443); !bound {
		t.Fatal("a refused configuration replaced the running one")
	}
}

// A sealed value is bound to its hosts. A host change applied in place leaves
// the Connection unusable until a member has entered the secret for the new
// hosts; the session itself keeps running.
func TestSealedHostChangeInPlaceStillNeedsTheSecretAgain(t *testing.T) {
	agent := newSealedAgent(t)
	oldHost := map[string]any{"match": "exact", "value": "api.example.test", "port": 443}
	newHost := map[string]any{"match": "exact", "value": "api.example.org", "port": 443}
	sealedConnection := func(routed, sealedFor map[string]any, live string) map[string]any {
		payload := customConnectionPayload(customDecoyToken, "")
		delete(payload, "secretMaterial")
		payload["hosts"] = []any{routed}
		payload["sealedMaterial"] = agent.seal(t, map[string]string{"token": live}, sealedFor)
		return payload
	}
	var config atomic.Pointer[map[string]any]
	opened := customSessionPayload("backend-sealed-reshape", 1, sealedConnection(oldHost, oldHost, customLiveToken))
	opened["agentKey"] = map[string]any{"wrappedKeyShare": agent.wrappedKeyShare}
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/sessions/") {
			_ = json.NewEncoder(w).Encode(opened)
			return
		}
		if strings.HasSuffix(request.URL.Path, "/config/") {
			_ = json.NewEncoder(w).Encode(*config.Load())
			return
		}
		http.NotFound(w, request)
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, agent.token, console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.OpenSession(context.Background(), agentapi.OpenSessionRequest{IdempotencyKey: "proxy-start-reshape"})
	if err != nil {
		t.Fatal(err)
	}
	ca, _, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(&airuntime.ProxySession{Config: session, Client: client, CA: ca}, "runtime-sealed-reshape")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	state.decoys = newDecoyHistory()
	upstream := &recordingUpstream{}
	proxy := &httpProxy{state: state, transport: upstream}
	get := func(target string) processedResponse {
		request, _ := http.NewRequest(http.MethodGet, target, nil)
		return processThrough(proxy, request)
	}
	if result := get("https://api.example.test/v1/items"); result.failure != nil {
		t.Fatalf("the sealed Connection did not work before the change: %+v", result.failure)
	}

	// The host moves but the value is still the one sealed for the old host.
	moved := customSessionPayload("", 2, sealedConnection(newHost, oldHost, customLiveToken))
	config.Store(&moved)
	if _, err := state.refreshConfig(context.Background()); err != nil {
		t.Fatalf("the host change was not applied in place: %v", err)
	}
	calls := upstream.calls.Load()
	result := get("https://api.example.org/v1/items")
	if result.failure == nil || result.failure.code != "agent_credential_injection_failed" || upstream.calls.Load() != calls {
		t.Fatalf("a value sealed for other hosts was used on the new host: %+v", result.failure)
	}
	details := state.connectionDetails(time.Now(), "connection-example")
	if state.availability() != nil || len(details) != 1 || details[0].State != "unavailable" || details[0].StateReason != agentapi.SealedFailureHostMismatch {
		t.Fatalf("availability=%v details=%+v", state.availability(), details)
	}

	// A member enters the secret again for the new host.
	resealed := customSessionPayload("", 3, sealedConnection(newHost, newHost, "sk-live-entered-for-the-new-host-01"))
	config.Store(&resealed)
	if _, err := state.refreshConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := get("https://api.example.org/v1/items"); result.failure != nil ||
		upstream.last.Load().Header.Get("Authorization") != "Bearer sk-live-entered-for-the-new-host-01" {
		t.Fatalf("the re-entered secret was not used: %+v", result.failure)
	}
	select {
	case fatal := <-state.fatal:
		t.Fatalf("the session was recycled: %v", fatal)
	default:
	}
}

// A removed custom Connection leaves its variable behind in processes that
// already run. The manifest accepts exactly that difference from the
// environment the session started with, and still recycles on any other.
func TestManifestToleratesOnlyVariablesOfRemovedCustomConnections(t *testing.T) {
	discoverOf := func(generation int, connections ...map[string]any) map[string]any {
		discover := customSessionPayload("", generation, connections...)
		for _, connection := range connections {
			delete(connection, "secretMaterial")
		}
		return discover
	}
	other := func() map[string]any {
		payload := customConnectionPayload("sk-phx-decoy-other-0123456789abcde", "sk-live-other-0123456789abcdefgh")
		payload["grantId"], payload["connectionId"], payload["credentialId"] = "grant-other", "connection-other", "connection-other"
		payload["hosts"] = []any{map[string]any{"match": "exact", "value": "other.example.test", "port": 443}}
		payload["agentEnv"] = map[string]string{"OTHER_API_KEY": "sk-phx-decoy-other-0123456789abcde"}
		payload["environmentBindings"] = []any{map[string]any{"name": "OTHER_API_KEY", "action": "set", "source": "decoy", "sourceField": "token", "sensitive": true, "systemManaged": false}}
		return payload
	}
	var discover atomic.Pointer[map[string]any]
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/discover/") {
			_ = json.NewEncoder(w).Encode(*discover.Load())
			return
		}
		http.NotFound(w, request)
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := decodeTestSession(t, customSessionPayload("backend-manifest", 1, customConnectionPayload(customDecoyToken, customLiveToken), other()))
	ca, _, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	proxySession := &airuntime.ProxySession{Config: session, Client: client, CA: ca}
	state, err := newRuntimeStateWithCapability(proxySession, "runtime-manifest")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	state.decoys = newDecoyHistory()
	providerEnvironment, err := proxySession.ProviderProcessEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	processEnvironment := phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{
		"EXAMPLE_API_KEY": customDecoyToken, "OTHER_API_KEY": "sk-phx-decoy-other-0123456789abcde",
		"HTTPS_PROXY": "http://phase:runtime-manifest@127.0.0.1:9543",
	}}
	manifest := &manifestHandler{
		state: state, ca: ca, proxy: remoteapi.Endpoint{Host: "127.0.0.1", Port: 9543},
		providerEnvironment: providerEnvironment, processEnvironment: processEnvironment,
	}
	serve := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		manifest.ServeManifestHTTP(recorder, httptest.NewRequest(http.MethodGet, ManifestURL, nil))
		return recorder
	}

	before := discoverOf(1, customConnectionPayload(customDecoyToken, customLiveToken), other())
	discover.Store(&before)
	if response := serve(); response.Code != http.StatusOK {
		t.Fatalf("manifest before the removal: %d %s", response.Code, response.Body.String())
	}

	removed := decodeTestSession(t, customSessionPayload("", 2, other()))
	if err := state.replaceConfig(&removed.SessionConfig); err != nil {
		t.Fatalf("the removal was not applied in place: %v", err)
	}
	after := discoverOf(2, other())
	discover.Store(&after)
	response := serve()
	var served remoteapi.ManifestResponse
	if err := json.Unmarshal(response.Body.Bytes(), &served); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(served.Discover.Connections) != 1 || served.Discover.Connections[0].ConnectionID != "connection-other" ||
		served.ProcessEnvironment.Set["OTHER_API_KEY"] == "" {
		t.Fatalf("manifest after the removal: %d %s", response.Code, response.Body.String())
	}
	select {
	case fatal := <-state.fatal:
		t.Fatalf("the in-place removal recycled the session at the next manifest read: %v", fatal)
	default:
	}

	// A variable that vanished without its Connection having been removed is
	// still drift.
	manifest.providerEnvironment.Set["UNEXPLAINED"] = "value"
	if response := serve(); response.Code != http.StatusServiceUnavailable || response.Header().Get("X-Phase-Error-Code") != ManifestRefreshRequiredCode {
		t.Fatalf("unexplained drift was accepted: %d %s", response.Code, response.Body.String())
	}
}

// A raw tunnel opened while its target was unbound is closed once a
// Connection binds that target, so the client's next request is intercepted.
func TestRawTunnelClosesOnceItsTargetIsBound(t *testing.T) {
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-tunnel", 1,
		customConnectionPayload(customDecoyToken, customLiveToken)), "runtime-tunnel")
	defer state.destroy()
	state.decoys = newDecoyHistory()
	proxy := &httpProxy{state: state}
	open := func(host string) (net.Conn, net.Conn, chan struct{}) {
		clientProxy, clientPeer := net.Pipe()
		upstreamProxy, upstreamPeer := net.Pipe()
		stop := make(chan struct{})
		go proxy.watchUnboundTunnel(context.Background(), clientProxy, upstreamProxy, stop, func() bool {
			bound, err := state.hasBoundHost(host, 443, "")
			return err == nil && !bound
		})
		return clientPeer, upstreamPeer, stop
	}
	closed := func(peer net.Conn, wait time.Duration) bool {
		_ = peer.SetReadDeadline(time.Now().Add(wait))
		_, err := peer.Read(make([]byte, 1))
		var timeout net.Error
		return err != nil && !(errors.As(err, &timeout) && timeout.Timeout())
	}
	becomingBound, becomingBoundUpstream, stopBound := open("eu.example.test")
	unrelated, unrelatedUpstream, stopUnrelated := open("elsewhere.example.test")
	defer close(stopUnrelated)
	defer becomingBound.Close()
	defer becomingBoundUpstream.Close()
	defer unrelated.Close()
	defer unrelatedUpstream.Close()

	// A refresh that changes nothing about these hosts leaves both open.
	same := decodeTestSession(t, customSessionPayload("", 2, customConnectionPayload(customDecoyToken, customLiveToken)))
	if err := state.replaceConfig(&same.SessionConfig); err != nil {
		t.Fatal(err)
	}
	if closed(becomingBound, 100*time.Millisecond) || closed(unrelated, 100*time.Millisecond) {
		close(stopBound)
		t.Fatal("an ordinary refresh closed a pass-through tunnel")
	}

	reshaped := customConnectionPayload(customDecoyToken, customLiveToken)
	reshaped["hosts"] = []any{
		map[string]any{"match": "exact", "value": "api.example.test", "port": 443, "path": "/v1/*"},
		map[string]any{"match": "exact", "value": "eu.example.test", "port": 443},
	}
	bound := decodeTestSession(t, customSessionPayload("", 3, reshaped))
	if err := state.replaceConfig(&bound.SessionConfig); err != nil {
		t.Fatal(err)
	}
	if !closed(becomingBound, time.Second) || !closed(becomingBoundUpstream, time.Second) {
		close(stopBound)
		t.Fatal("the tunnel to a newly bound host stayed open")
	}
	if closed(unrelated, 100*time.Millisecond) {
		t.Fatal("a tunnel to an unrelated host was closed")
	}
}

// A member-entered value that also appears in something the Agent can see is
// withheld; the refresh that brought it is applied and the session runs on.
func TestExposedCustomValueIsWithheldOnRefreshWithoutEndingTheSession(t *testing.T) {
	var config atomic.Pointer[map[string]any]
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/sessions/"):
			_ = json.NewEncoder(w).Encode(customSessionPayload("backend-exposed", 1,
				customConnectionPayload(customDecoyToken, customLiveToken), packagedPostgresPayload()))
		case strings.HasSuffix(request.URL.Path, "/config/"):
			_ = json.NewEncoder(w).Encode(*config.Load())
		default:
			http.NotFound(w, request)
		}
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.OpenSession(context.Background(), agentapi.OpenSessionRequest{WorkflowID: "workflow-1", IdempotencyKey: "proxy-start-exposed"})
	if err != nil {
		t.Fatal(err)
	}
	ca, _, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(&airuntime.ProxySession{Config: session, Client: client, CA: ca}, "runtime-exposed")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	state.decoys = newDecoyHistory()
	upstream := &recordingUpstream{}
	proxy := &httpProxy{state: state, transport: upstream}
	get := func() processedResponse {
		request, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
		return processThrough(proxy, request)
	}
	if result := get(); result.failure != nil {
		t.Fatal(result.failure)
	}

	// A member replaces the value with one that is part of the decoy the
	// Agent already holds for this Connection.
	const overlapping = "phx-decoy-0123456789"
	insideDecoy := customSessionPayload("", 2, customConnectionPayload(customDecoyToken, overlapping), packagedPostgresPayload())
	config.Store(&insideDecoy)
	if _, err := state.refreshConfig(context.Background()); err != nil {
		t.Fatalf("a refresh carrying an exposed custom value ended the session: %v", err)
	}
	calls := upstream.calls.Load()
	result := get()
	if result.failure == nil || result.failure.code != "agent_credential_injection_failed" ||
		result.failure.message != (&phaseproxy.InjectionError{Code: phaseproxy.InjectionMissingMaterial}).Error() || upstream.calls.Load() != calls {
		t.Fatalf("the exposed value was used: %+v", result.failure)
	}
	details := state.connectionDetails(time.Now(), "")
	if state.availability() != nil || len(details) != 2 || details[0].State != "unavailable" || details[0].StateReason != agentapi.MaterialFailureExposed ||
		details[1].State != "ready" {
		t.Fatalf("availability=%v details=%+v", state.availability(), details)
	}
	if containsAny(overlapping, state.eventSecrets()) {
		t.Fatal("the withheld value is still held")
	}

	// A safe value on the next refresh brings the Connection back.
	safe := customSessionPayload("", 3, customConnectionPayload(customDecoyToken, "sk-live-entered-again-0123456789"), packagedPostgresPayload())
	config.Store(&safe)
	if _, err := state.refreshConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := get(); result.failure != nil || upstream.last.Load().Header.Get("Authorization") != "Bearer sk-live-entered-again-0123456789" {
		t.Fatalf("the Connection did not recover: %+v", result.failure)
	}

	// A packaged service in the same position still ends the session.
	leakingPostgres := packagedPostgresPayload()
	leakingPostgres["agentEnv"] = map[string]string{"PGAPPNAME": "app-pg-live-0123456789"}
	leakingPostgres["environmentBindings"] = []any{}
	leaking := customSessionPayload("", 4, customConnectionPayload(customDecoyToken, "sk-live-entered-again-0123456789"), leakingPostgres)
	config.Store(&leaking)
	if _, err := state.refreshConfig(context.Background()); !errors.Is(err, errRefreshedConfigRejected) ||
		!errors.Is(err, agentapi.ErrUnsafeAgentVisibleEnvironment) {
		t.Fatalf("a packaged value inside an Agent-visible value was accepted: %v", err)
	}
}

func TestHTTPConnectionRefusesPlainHTTPUnlessAllowed(t *testing.T) {
	anyPort := func(allow bool) map[string]any {
		payload := customConnectionPayload(customDecoyToken, customLiveToken)
		payload["hosts"] = []any{map[string]any{"match": "exact", "value": "api.example.test"}}
		if allow {
			payload["allowPlainHttp"] = true
		}
		return payload
	}
	run := func(t *testing.T, allow bool, target string, presentDecoy bool) (processedResponse, *recordingUpstream) {
		t.Helper()
		state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-plain", 1, anyPort(allow)), "runtime-plain")
		t.Cleanup(state.destroy)
		upstream := &recordingUpstream{}
		request, _ := http.NewRequest(http.MethodGet, target, nil)
		if presentDecoy {
			request.Header.Set("Authorization", "Bearer "+customDecoyToken)
		}
		return processThrough(&httpProxy{state: state, transport: upstream}, request), upstream
	}
	for name, presentDecoy := range map[string]bool{"attach": false, "swap": true} {
		t.Run(name, func(t *testing.T) {
			result, upstream := run(t, false, "http://api.example.test/v1/items", presentDecoy)
			if result.failure == nil || result.failure.status != http.StatusForbidden || result.failure.code != "agent_credential_injection_failed" ||
				result.failure.reason != "credential_swap_failed" || !strings.Contains(result.failure.message, "HTTPS") || upstream.calls.Load() != 0 {
				t.Fatalf("a credential went out over plain HTTP: %+v calls=%d", result.failure, upstream.calls.Load())
			}
			if result, upstream := run(t, false, "https://api.example.test/v1/items", presentDecoy); result.failure != nil ||
				upstream.last.Load().Header.Get("Authorization") != "Bearer "+customLiveToken {
				t.Fatalf("HTTPS stopped working: %+v", result.failure)
			}
			if result, upstream := run(t, true, "http://api.example.test/v1/items", presentDecoy); result.failure != nil ||
				upstream.last.Load().Header.Get("Authorization") != "Bearer "+customLiveToken {
				t.Fatalf("plain HTTP was refused although the Connection allows it: %+v", result.failure)
			}
		})
	}

	// A packaged header service is held to the same rule: HTTPS only unless
	// the Connection allows plain HTTP.
	for _, allow := range []bool{false, true} {
		session := headerInjectionSession(t, "backend-packaged-plain", "packaged-decoy")
		session.Config.Connections[0].Hosts[0].Port = 0
		session.Config.Connections[0].AllowPlainHTTP = allow
		state, err := newRuntimeStateWithCapability(session, "runtime-packaged-plain")
		if err != nil {
			t.Fatal(err)
		}
		upstream := &recordingUpstream{}
		request, _ := http.NewRequest(http.MethodGet, "http://api.example.test/v1/me", nil)
		request.Header.Set("Authorization", "Bearer packaged-decoy")
		result := processThrough(&httpProxy{state: state, transport: upstream}, request)
		if allow && (result.failure != nil || upstream.last.Load().Header.Get("Authorization") != "Bearer live-token") {
			t.Fatalf("a packaged service allowing plain HTTP was refused: %+v", result.failure)
		}
		if !allow && (result.failure == nil || upstream.calls.Load() != 0 || !strings.Contains(result.failure.message, "HTTPS")) {
			t.Fatalf("a packaged service's credential went out over plain HTTP: %+v", result.failure)
		}
		state.destroy()
	}
}

func TestDiscoverMustAgreeOnPlainHTTP(t *testing.T) {
	runtime := customConnectionPayload(customDecoyToken, customLiveToken)
	runtime["allowPlainHttp"] = true
	serve := func(t *testing.T, discoverAllows bool) *httptest.ResponseRecorder {
		t.Helper()
		connection := customConnectionPayload(customDecoyToken, customLiveToken)
		delete(connection, "secretMaterial")
		if discoverAllows {
			connection["allowPlainHttp"] = true
		}
		console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(customSessionPayload("", 1, connection))
		}))
		defer console.Close()
		client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
		if err != nil {
			t.Fatal(err)
		}
		state := controlRuntimeState(t, client, customSessionPayload("backend-discover-plain", 1, runtime), "runtime-discover-plain")
		defer state.destroy()
		return controlGet(t, &httpProxy{state: state, control: &controlHandler{state: state}}, "runtime-discover-plain", "/v1/discover")
	}
	if matching := serve(t, true); matching.Code != http.StatusOK || !strings.Contains(matching.Body.String(), `"allowPlainHttp":true`) {
		t.Fatalf("status=%d body=%s", matching.Code, matching.Body.String())
	}
	if differing := serve(t, false); differing.Code != http.StatusBadGateway || !strings.Contains(differing.Body.String(), "unsafe_agent_discover_response") {
		t.Fatalf("a discover response that disagrees on plain HTTP was relayed: %d %s", differing.Code, differing.Body.String())
	}
}

const createAuditAction = `{"type":"agent_connection.create","version":1,"serviceType":"http","name":"audit","definition":{"specVersion":1}}`

func approvedCreate(body map[string]json.RawMessage) (int, map[string]any) {
	return http.StatusOK, map[string]any{
		"schemaVersion": 1, "id": "request-custom", "status": "approved", "kind": "setup",
		"action": body["action"], "connectionId": "connection-audit", "grantId": "grant-audit",
	}
}

// "The Agent asks for a host, a member approves and enters the secret, the
// Agent retries": a new custom Connection that exports nothing is served by
// the running session. Any other new grant still needs a fresh one.
func TestApprovedCreateIsServedInPlaceOnlyWhenItExportsNothing(t *testing.T) {
	const auditLive = "sk-live-audit-0123456789abcdefgh"
	existing := func() map[string]any { return customConnectionPayload(customDecoyToken, customLiveToken) }
	tests := []struct {
		name       string
		added      func() map[string]any
		refuse     bool
		wantAction string
	}{
		{name: "exports nothing", wantAction: "retry",
			added: func() map[string]any { return exportlessConnectionPayload("audit", "audit.example.test", auditLive) }},
		{name: "exports a decoy", wantAction: "restart_required", added: func() map[string]any {
			payload := exportlessConnectionPayload("audit", "audit.example.test", auditLive)
			payload["agentEnv"] = map[string]string{"AUDIT_API_KEY": "sk-phx-decoy-audit-0123456789abcdef"}
			payload["environmentBindings"] = []any{map[string]any{"name": "AUDIT_API_KEY", "action": "set", "source": "decoy", "sourceField": "token", "sensitive": true, "systemManaged": false}}
			return payload
		}},
		{name: "exports an identifier", wantAction: "restart_required", added: func() map[string]any {
			payload := exportlessConnectionPayload("audit", "audit.example.test", auditLive)
			payload["identifiers"] = map[string]string{"username": "auditor"}
			payload["agentEnv"] = map[string]string{"AUDIT_USER": "auditor"}
			payload["environmentBindings"] = []any{map[string]any{"name": "AUDIT_USER", "action": "set", "source": "identifier", "sourceField": "username", "sensitive": false, "systemManaged": false}}
			return payload
		}},
		{name: "packaged service", wantAction: "restart_required", added: func() map[string]any {
			payload := packagedPostgresPayload()
			payload["grantId"], payload["connectionId"], payload["credentialId"] = "grant-audit", "connection-audit", "connection-audit"
			return payload
		}},
		{name: "environment check refuses", wantAction: "restart_required", refuse: true,
			added: func() map[string]any { return exportlessConnectionPayload("audit", "audit.example.test", auditLive) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			console := newRequestConsole(t)
			console.respond = approvedCreate
			console.config = func() map[string]any { return customSessionPayload("", 2, existing(), test.added()) }
			state, proxy := console.state(t, "runtime-create")
			state.decoys = newDecoyHistory()
			if test.refuse {
				state.setEnvironmentCheck(func(*agentapi.SessionConfig) bool { return false })
			}
			recorder := postControlRequest(proxy, "runtime-create", `{"kind":"setup","action":`+createAuditAction+`}`)
			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"runtimeAction":"`+test.wantAction+`"`) || console.configs.Load() != 1 {
				t.Fatalf("status=%d configs=%d body=%s", recorder.Code, console.configs.Load(), recorder.Body.String())
			}
			if test.wantAction == "restart_required" {
				select {
				case fatal := <-state.fatal:
					if !errors.Is(fatal, airuntime.ErrSessionReprovisionRequired) {
						t.Fatalf("fatal = %v", fatal)
					}
				default:
					t.Fatal("a new grant that changes the environment did not recycle the runtime")
				}
				if len(state.statusConnections(time.Now())) != 1 {
					t.Fatal("a refused addition was applied to the running session")
				}
				return
			}
			select {
			case fatal := <-state.fatal:
				t.Fatalf("an addition that exports nothing recycled the runtime: %v", fatal)
			default:
			}
			upstream := &recordingUpstream{}
			proxy.transport = upstream
			added, _ := http.NewRequest(http.MethodGet, "https://audit.example.test/events", nil)
			if result := processThrough(proxy, added); result.failure != nil || upstream.last.Load().Header.Get("Authorization") != "Bearer "+auditLive {
				t.Fatalf("the added Connection is not served: %+v", result.failure)
			}
			kept, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
			if result := processThrough(proxy, kept); result.failure != nil || upstream.last.Load().Header.Get("Authorization") != "Bearer "+customLiveToken {
				t.Fatalf("the existing Connection stopped working: %+v", result.failure)
			}
			if status := state.statusConnections(time.Now()); len(status) != 2 || status[1].ConnectionID != "connection-audit" || status[1].State != "ready" {
				t.Fatalf("status = %+v", status)
			}
			// Reading the approval again does not fetch the configuration again.
			again := postControlRequest(proxy, "runtime-create", `{"kind":"setup","action":`+createAuditAction+`}`)
			if again.Code != http.StatusOK || !strings.Contains(again.Body.String(), `"runtimeAction":"retry"`) || console.configs.Load() != 1 {
				t.Fatalf("status=%d configs=%d body=%s", again.Code, console.configs.Load(), again.Body.String())
			}
		})
	}
}

// An addition that overlaps an existing Connection is applied whole or not at
// all. Once applied, the ambiguity rule refuses whatever both would serve,
// for both of them, and each still answers when it is selected by name.
func TestAmbiguousAdditionIsAppliedWholeAndRefusedPerRequest(t *testing.T) {
	const auditLive = "sk-live-audit-0123456789abcdefgh"
	console := newRequestConsole(t)
	console.respond = approvedCreate
	console.config = func() map[string]any {
		added := exportlessConnectionPayload("audit", "api.example.test", auditLive)
		added["hosts"] = []any{
			map[string]any{"match": "exact", "value": "api.example.test", "port": 443, "path": "/v1/reports/*"},
			map[string]any{"match": "exact", "value": "api.example.test", "port": 443, "path": "/audit/*"},
		}
		return customSessionPayload("", 2, customConnectionPayload(customDecoyToken, customLiveToken), added)
	}
	state, proxy := console.state(t, "runtime-ambiguous")
	state.decoys = newDecoyHistory()
	recorder := postControlRequest(proxy, "runtime-ambiguous", `{"kind":"setup","action":`+createAuditAction+`}`)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"runtimeAction":"retry"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(state.statusConnections(time.Now())) != 2 || state.availability() != nil {
		t.Fatalf("the addition was not applied whole: %+v", state.statusConnections(time.Now()))
	}
	upstream := &recordingUpstream{}
	proxy.transport = upstream
	send := func(target, selection string) (processedResponse, string) {
		request, _ := http.NewRequest(http.MethodGet, target, nil)
		var authentication *tunnelAuthentication
		if selection != "" {
			authentication = &tunnelAuthentication{connectionID: selection}
		}
		before := upstream.calls.Load()
		result := proxy.process(request, authentication)
		if result.response != nil {
			result.response.Body.Close()
		}
		if upstream.calls.Load() == before {
			return result, ""
		}
		return result, upstream.last.Load().Header.Get("Authorization")
	}

	// Both Connections match this request: neither credential is used.
	result, seen := send("https://api.example.test/v1/reports/monthly", "")
	if result.failure == nil || result.failure.status != http.StatusForbidden || result.failure.code != "ambiguous_agent_binding" || seen != "" {
		t.Fatalf("an ambiguous request was served: %+v seen=%q", result.failure, seen)
	}
	// Where only one of them matches, that one answers.
	if result, seen := send("https://api.example.test/v1/items", ""); result.failure != nil || seen != "Bearer "+customLiveToken {
		t.Fatalf("the existing Connection's own path: %+v seen=%q", result.failure, seen)
	}
	if result, seen := send("https://api.example.test/audit/events", ""); result.failure != nil || seen != "Bearer "+auditLive {
		t.Fatalf("the added Connection's own path: %+v seen=%q", result.failure, seen)
	}
	// Named explicitly, each serves the contested path with its own value.
	if result, seen := send("https://api.example.test/v1/reports/monthly", "connection-example"); result.failure != nil || seen != "Bearer "+customLiveToken {
		t.Fatalf("existing Connection selected: %+v seen=%q", result.failure, seen)
	}
	if result, seen := send("https://api.example.test/v1/reports/monthly", "connection-audit"); result.failure != nil || seen != "Bearer "+auditLive {
		t.Fatalf("added Connection selected: %+v seen=%q", result.failure, seen)
	}
	// A CONNECT names only the host, so with two Connections on one host the
	// tunnel itself needs the selection, as it always has.
	if _, err := state.hasBoundHost("api.example.test", 443); err == nil {
		t.Fatal("an unselected tunnel to a host two Connections share was accepted")
	}
	if bound, err := state.hasBoundHost("api.example.test", 443, "connection-audit"); err != nil || !bound {
		t.Fatalf("a selected tunnel was refused: %v", err)
	}
}
