package aiproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// Two custom HTTP Connections run through a real engine: credentials are
// attached inside the CONNECT tunnel, both decoys reach the process
// environment, and an upstream refusal brings the replaced value in.
func TestEngineServesCustomConnectionsEndToEnd(t *testing.T) {
	const (
		billingDecoy = "sk-phx-decoy-billing-0123456789abcd"
		searchDecoy  = "sk-phx-decoy-search-0123456789abcde"
		firstLive    = "sk-live-billing-first-0123456789ab"
		secondLive   = "sk-live-billing-second-0123456789a"
		searchLive   = "search-live-password-0123456789"
	)
	var billingSeen, searchSeen, searchQuery atomic.Value
	var refuseBilling atomic.Bool
	billing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		billingSeen.Store(r.Header.Get("Authorization"))
		if refuseBilling.Load() && r.Header.Get("Authorization") == "Bearer "+firstLive {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "key revoked")
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer billing.Close()
	search := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		searchSeen.Store(r.Header.Get("Authorization"))
		searchQuery.Store(r.URL.RawQuery)
		_, _ = io.WriteString(w, "ok")
	}))
	defer search.Close()
	hostPort := func(server *httptest.Server) (string, int) {
		parsed, _ := url.Parse(server.URL)
		host, port, _ := net.SplitHostPort(parsed.Host)
		return host, mustPort(t, port)
	}
	billingHost, billingPort := hostPort(billing)
	searchHost, searchPort := hostPort(search)

	connections := func(billingValue string) []any {
		return []any{
			map[string]any{
				"grantId": "grant-billing", "connectionId": "connection-billing", "connectionName": "Billing API",
				"credentialId": "connection-billing", "credentialName": "Billing API", "credentialProvider": "http",
				"credentialRevision": "1", "materialGeneration": "1.1", "serviceType": "http", "protocol": "http",
				"hosts":            []any{map[string]any{"match": "exact", "value": billingHost, "port": billingPort}},
				"connectionConfig": map[string]any{"specVersion": 1, "preset": "bearer"}, "configEnv": map[string]string{},
				"injections": []any{map[string]any{
					"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}",
					"valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach",
				}},
				"identifiers": map[string]string{}, "decoyMaterial": map[string]string{"token": billingDecoy},
				"agentEnv":            map[string]string{"BILLING_API_KEY": billingDecoy},
				"environmentBindings": []any{map[string]any{"name": "BILLING_API_KEY", "action": "set", "source": "decoy", "sourceField": "token", "sensitive": true, "systemManaged": false}},
				"secretMaterial":      map[string]string{"token": billingValue},
				"authorization":       map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
			},
			map[string]any{
				"grantId": "grant-search", "connectionId": "connection-search", "connectionName": "Search API",
				"credentialId": "connection-search", "credentialName": "Search API", "credentialProvider": "http",
				"credentialRevision": "1", "materialGeneration": "1.1", "serviceType": "http", "protocol": "http",
				"hosts":            []any{map[string]any{"match": "exact", "value": searchHost, "port": searchPort}},
				"connectionConfig": map[string]any{"specVersion": 1, "preset": "basic"}, "configEnv": map[string]string{},
				"injections": []any{
					map[string]any{"action": "basic_auth", "name": "Authorization", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}}, "whenAbsent": "attach"},
					map[string]any{"action": "set_param", "name": "api_key", "valueFormat": "{value}", "valueFrom": map[string]any{"source": "credential", "field": "password"}, "whenAbsent": "block"},
				},
				"identifiers": map[string]string{"username": "alice"}, "decoyMaterial": map[string]string{"password": searchDecoy},
				"agentEnv": map[string]string{"SEARCH_API_KEY": searchDecoy, "SEARCH_USER": "alice"},
				"environmentBindings": []any{
					map[string]any{"name": "SEARCH_API_KEY", "action": "set", "source": "decoy", "sourceField": "password", "sensitive": true, "systemManaged": false},
					map[string]any{"name": "SEARCH_USER", "action": "set", "source": "identifier", "sourceField": "username", "sensitive": false, "systemManaged": false},
				},
				"secretMaterial": map[string]string{"password": searchLive},
				"authorization":  map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
			},
		}
	}
	sessionPayload := func(credential string, generation int, billingValue string) map[string]any {
		payload := map[string]any{
			"schemaVersion": 1, "sessionUid": "session-e2e",
			"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
			"configGeneration": generation, "configEnv": map[string]string{}, "connections": connections(billingValue),
		}
		if credential != "" {
			payload["sessionCredential"] = credential
		}
		return payload
	}

	var refreshes atomic.Int32
	var eventsMu sync.Mutex
	var events strings.Builder
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/events/"):
			body, _ := io.ReadAll(r.Body)
			eventsMu.Lock()
			events.Write(body)
			eventsMu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"schemaVersion":1,"accepted":1,"duplicates":0}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/config/"):
			refreshes.Add(1)
			_ = json.NewEncoder(w).Encode(sessionPayload("", 2, secondLive))
		default:
			t.Errorf("unexpected console route: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := decodeTestSession(t, sessionPayload("psx_sess_custom_e2e_0123456789", 1, firstLive))
	running := serveCustomEngine(t, client, session, billing.Client().Transport)
	endpoints, httpClient, stop := running.endpoints, running.client, running.stop
	defer stop()

	// Each custom Connection exports its own decoy and identifier.
	environment := endpoints.ProcessEnvironment.Set
	if environment["BILLING_API_KEY"] != billingDecoy || environment["SEARCH_API_KEY"] != searchDecoy || environment["SEARCH_USER"] != "alice" {
		t.Fatal("the process environment does not carry both custom Connections' decoys")
	}
	for name, value := range environment {
		if strings.Contains(value, firstLive) || strings.Contains(value, searchLive) {
			t.Fatalf("process environment %s carries a live value", name)
		}
	}

	get := func(target string, mutate func(*http.Request)) (*http.Response, string) {
		t.Helper()
		request, _ := http.NewRequest(http.MethodGet, target, nil)
		if mutate != nil {
			mutate(request)
		}
		response, err := httpClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		return response, string(body)
	}

	// Nothing presented: the header is attached.
	if response, _ := get(billing.URL+"/v1/invoices", nil); response.StatusCode != http.StatusOK || billingSeen.Load() != "Bearer "+firstLive {
		t.Fatalf("status=%d upstream saw %q", response.StatusCode, billingSeen.Load())
	}
	// Basic auth is attached while the query parameter, which blocks when
	// absent, is swapped from the decoy in the same request.
	basicLive := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+searchLive))
	if response, _ := get(search.URL+"/v1/search?q=phase&api_key="+searchDecoy, nil); response.StatusCode != http.StatusOK ||
		searchSeen.Load() != basicLive || !strings.Contains(searchQuery.Load().(string), "api_key="+searchLive) {
		t.Fatalf("status=%d upstream saw %q %q", response.StatusCode, searchSeen.Load(), searchQuery.Load())
	}
	// Without the blocking parameter the whole request is refused and nothing
	// reaches the upstream, not even the attachable header.
	searchSeen.Store("")
	response, body := get(search.URL+"/v1/search?q=phase", nil)
	if response.StatusCode != http.StatusForbidden || response.Header.Get("X-Phase-Error-Code") != "agent_credential_injection_failed" ||
		response.Header.Get("X-Phase-Connection-Id") != "connection-search" || searchSeen.Load() != "" || strings.Contains(body, searchLive) {
		t.Fatalf("status=%d headers=%v upstream saw %q", response.StatusCode, response.Header, searchSeen.Load())
	}

	// The key is replaced in the Console. The upstream refuses the old one;
	// the refusal is passed back as it is and the proxy fetches the new value.
	refuseBilling.Store(true)
	response, body = get(billing.URL+"/v1/invoices", nil)
	if response.StatusCode != http.StatusUnauthorized || body != "key revoked" || response.Header.Get("X-Phase-Event-Id") == "" {
		t.Fatalf("the upstream refusal was not returned unchanged: status=%d body=%q", response.StatusCode, body)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if response, _ := get(billing.URL+"/v1/invoices", nil); response.StatusCode == http.StatusOK && billingSeen.Load() == "Bearer "+secondLive {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the replaced value was never used; upstream last saw %q", billingSeen.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if refreshes.Load() != 1 {
		t.Fatalf("config refreshes = %d, want exactly 1", refreshes.Load())
	}

	response, body = get(phaseproxy.ControlURL+"/v1/connections", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, `"id":"connection-billing"`) || !strings.Contains(body, `"id":"connection-search"`) ||
		strings.Count(body, `"state":"ready"`) != 2 {
		t.Fatalf("connections: status=%d body=%s", response.StatusCode, body)
	}
	stop()
	eventsMu.Lock()
	shipped := events.String()
	eventsMu.Unlock()
	if !strings.Contains(shipped, `"credentialAction":"set_header"`) || !strings.Contains(shipped, `"credentialAction":"basic_auth"`) ||
		!strings.Contains(shipped, `"reason":"credential_swap_failed"`) || !strings.Contains(shipped, `"statusCode":401`) {
		t.Fatalf("events = %s", shipped)
	}
	for _, sensitive := range []string{firstLive, secondLive, searchLive, billingDecoy, searchDecoy, "psx_sess_custom_e2e_0123456789"} {
		if strings.Contains(shipped, sensitive) || strings.Contains(body, sensitive) {
			t.Fatalf("an event or connection read carried %q", sensitive)
		}
	}
}

// Approved changes reach a running engine without recycling it: a new path is
// served, a removed Connection stops being served, a new one that exports
// nothing starts being served, and the manifest still answers. Only a change
// to what the Agent process was given ends the session.
func TestEngineReshapesCustomConnectionsInPlace(t *testing.T) {
	const (
		reportsDecoy = "sk-phx-decoy-reports-0123456789abc"
		reportsLive  = "sk-live-reports-0123456789abcdefg"
		metricsDecoy = "sk-phx-decoy-metrics-0123456789abc"
		metricsLive  = "sk-live-metrics-0123456789abcdefg"
	)
	var reportsSeen, metricsSeen atomic.Value
	reports := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reportsSeen.Store(r.URL.Path + " " + r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "ok")
	}))
	defer reports.Close()
	metrics := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metricsSeen.Store(r.Header.Get("X-Api-Key"))
		_, _ = io.WriteString(w, "ok")
	}))
	defer metrics.Close()
	hostPort := func(server *httptest.Server) (string, int) {
		parsed, _ := url.Parse(server.URL)
		host, port, _ := net.SplitHostPort(parsed.Host)
		return host, mustPort(t, port)
	}
	reportsHost, reportsPort := hostPort(reports)
	metricsHost, metricsPort := hostPort(metrics)

	connection := func(id, decoy, live, environmentName, header, valueFormat, host string, port int, paths ...string) map[string]any {
		rules := make([]any, 0, len(paths))
		for _, path := range paths {
			rules = append(rules, map[string]any{"match": "exact", "value": host, "port": port, "path": path})
		}
		return map[string]any{
			"grantId": "grant-" + id, "connectionId": "connection-" + id, "connectionName": id,
			"credentialId": "connection-" + id, "credentialName": id, "credentialProvider": "http",
			"credentialRevision": "1", "materialGeneration": "1.1", "serviceType": "http", "protocol": "http",
			"hosts": rules, "connectionConfig": map[string]any{"specVersion": 1, "paths": paths}, "configEnv": map[string]string{},
			"injections": []any{map[string]any{
				"action": "set_header", "name": header, "valueFormat": valueFormat,
				"valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach",
			}},
			"identifiers": map[string]string{}, "decoyMaterial": map[string]string{"token": decoy},
			"agentEnv":            map[string]string{environmentName: decoy},
			"environmentBindings": []any{map[string]any{"name": environmentName, "action": "set", "source": "decoy", "sourceField": "token", "sensitive": true, "systemManaged": false}},
			"secretMaterial":      map[string]string{"token": live},
			"authorization":       map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
		}
	}
	reportsConnection := func(decoy string, paths ...string) map[string]any {
		return connection("reports", decoy, reportsLive, "REPORTS_API_KEY", "Authorization", "Bearer {value}", reportsHost, reportsPort, paths...)
	}
	metricsConnection := func() map[string]any {
		return connection("metrics", metricsDecoy, metricsLive, "METRICS_API_KEY", "X-Api-Key", "{value}", metricsHost, metricsPort, "/*")
	}
	payload := func(credential string, generation int, connections ...map[string]any) map[string]any {
		list := make([]any, 0, len(connections))
		for _, entry := range connections {
			list = append(list, entry)
		}
		result := map[string]any{
			"schemaVersion": 1, "sessionUid": "session-reshape",
			"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
			"configGeneration": generation, "configEnv": map[string]string{}, "connections": list,
		}
		if credential != "" {
			result["sessionCredential"] = credential
		}
		return result
	}

	var current atomic.Pointer[map[string]any]
	publish := func(generation int, connections ...map[string]any) {
		config := payload("", generation, connections...)
		current.Store(&config)
	}
	publish(1, reportsConnection(reportsDecoy, "/v1/*"), metricsConnection())
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/events/"):
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"schemaVersion":1,"accepted":1,"duplicates":0}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/config/"):
			_ = json.NewEncoder(w).Encode(*current.Load())
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/discover/"):
			// Discover is the config response without the value lane.
			encoded, _ := json.Marshal(*current.Load())
			var discover map[string]any
			_ = json.Unmarshal(encoded, &discover)
			for _, entry := range discover["connections"].([]any) {
				delete(entry.(map[string]any), "secretMaterial")
			}
			_ = json.NewEncoder(w).Encode(discover)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revoke/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "session-reshape", "revokedAt": time.Now().UTC()})
		default:
			t.Errorf("unexpected console route: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := decodeTestSession(t, payload("psx_sess_reshape_e2e_0123456789", 1, reportsConnection(reportsDecoy, "/v1/*"), metricsConnection()))
	running := serveCustomEngine(t, client, session, reports.Client().Transport)
	defer running.stop()
	// Once a host is no longer bound the client talks to it directly through
	// a raw tunnel, so it has to trust the test servers' own certificate too.
	running.roots.AddCert(reports.Certificate())
	do := func(method, target string) (int, string, http.Header) {
		t.Helper()
		request, _ := http.NewRequest(method, target, strings.NewReader(""))
		response, err := running.client.Do(request)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		return response.StatusCode, string(body), response.Header
	}
	refresh := func() (int, string) {
		running.client.CloseIdleConnections()
		status, body, _ := do(http.MethodPost, phaseproxy.ControlURL+"/v1/refresh")
		return status, body
	}
	stillRunning := func(step string) {
		t.Helper()
		if err, stopped := running.wait(0); stopped {
			t.Fatalf("%s recycled the engine: %v", step, err)
		}
	}

	do(http.MethodGet, reports.URL+"/v1/monthly")
	if reportsSeen.Load() != "/v1/monthly Bearer "+reportsLive {
		t.Fatalf("upstream saw %q", reportsSeen.Load())
	}
	do(http.MethodGet, reports.URL+"/v2/monthly")
	if reportsSeen.Load() != "/v2/monthly " {
		t.Fatalf("a path outside the Connection got the credential: %q", reportsSeen.Load())
	}

	// An approved change adds /v2. The proxy applies it to the running session.
	publish(2, reportsConnection(reportsDecoy, "/v1/*", "/v2/*"), metricsConnection())
	if status, body := refresh(); status != http.StatusOK || !strings.Contains(body, `"configGeneration":2`) {
		t.Fatalf("refresh after the path change: %d %s", status, body)
	}
	stillRunning("a path change")
	do(http.MethodGet, reports.URL+"/v2/monthly")
	if reportsSeen.Load() != "/v2/monthly Bearer "+reportsLive {
		t.Fatalf("the new path is not served in place: %q", reportsSeen.Load())
	}

	// An approved removal drops the other Connection in place.
	do(http.MethodGet, metrics.URL+"/ingest")
	if metricsSeen.Load() != metricsLive {
		t.Fatalf("upstream saw %q", metricsSeen.Load())
	}
	publish(3, reportsConnection(reportsDecoy, "/v1/*", "/v2/*"))
	if status, body := refresh(); status != http.StatusOK {
		t.Fatalf("refresh after the removal: %d %s", status, body)
	}
	stillRunning("a removal")
	do(http.MethodGet, metrics.URL+"/ingest")
	if metricsSeen.Load() != "" {
		t.Fatalf("a removed Connection still attaches its credential: %q", metricsSeen.Load())
	}
	if status, body, _ := do(http.MethodGet, phaseproxy.ControlURL+"/v1/connections"); status != http.StatusOK ||
		!strings.Contains(body, `"id":"connection-reports"`) || strings.Contains(body, "connection-metrics") {
		t.Fatalf("connections after the removal: %d %s", status, body)
	}
	// The manifest still answers: the removed Connection's variable, left in
	// processes that already run, is not treated as drift.
	status, body, _ := do(http.MethodGet, ManifestURL)
	if status != http.StatusOK || !strings.Contains(body, `"REPORTS_API_KEY"`) || strings.Contains(body, reportsLive) {
		t.Fatalf("manifest after the removal: %d %s", status, body)
	}
	stillRunning("reading the manifest after a removal")
	do(http.MethodGet, reports.URL+"/v2/monthly")
	if reportsSeen.Load() != "/v2/monthly Bearer "+reportsLive {
		t.Fatalf("the remaining Connection stopped working: %q", reportsSeen.Load())
	}

	// A newly granted Connection that exports nothing is served in place too.
	audit := metricsConnection()
	audit["grantId"], audit["connectionId"], audit["credentialId"] = "grant-audit", "connection-audit", "connection-audit"
	audit["agentEnv"], audit["environmentBindings"] = map[string]string{}, []any{}
	publish(4, reportsConnection(reportsDecoy, "/v1/*", "/v2/*"), audit)
	if status, body := refresh(); status != http.StatusOK {
		t.Fatalf("refresh after the addition: %d %s", status, body)
	}
	stillRunning("an addition that exports nothing")
	do(http.MethodGet, metrics.URL+"/ingest")
	if metricsSeen.Load() != metricsLive {
		t.Fatalf("the added Connection is not served in place: %q", metricsSeen.Load())
	}
	if status, body, _ := do(http.MethodGet, ManifestURL); status != http.StatusOK || !strings.Contains(body, "connection-audit") {
		t.Fatalf("manifest after the addition: %d %s", status, body)
	}
	stillRunning("reading the manifest after an addition")

	// A new decoy is a different environment for the Agent: that still needs
	// a fresh session.
	publish(5, reportsConnection("sk-phx-decoy-reissued-0123456789ab", "/v1/*", "/v2/*"), audit)
	running.client.CloseIdleConnections()
	request, _ := http.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/refresh", strings.NewReader(""))
	if response, err := running.client.Do(request); err == nil {
		response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Fatal("a changed decoy was applied to the running session")
		}
	}
	if err, stopped := running.wait(10 * time.Second); !stopped {
		t.Fatal("a changed decoy did not recycle the engine")
	} else if !errors.Is(err, airuntime.ErrSessionReprovisionRequired) {
		t.Fatalf("engine stopped with %v, want a reprovision request", err)
	}
}

// runningEngine is a real engine serving one session on loopback, with an
// HTTP client that reaches it the way a harness process would.
type runningEngine struct {
	endpoints Endpoints
	client    *http.Client
	roots     *x509.CertPool
	done      chan error
	stop      func()
	ended     bool
}

// wait returns what the engine stopped with, if it stops in time; a zero
// timeout only looks. After that stop has nothing left to do.
func (r *runningEngine) wait(timeout time.Duration) (error, bool) {
	select {
	case err := <-r.done:
		r.ended = true
		return err, true
	default:
	}
	if timeout <= 0 {
		return nil, false
	}
	select {
	case err := <-r.done:
		r.ended = true
		return err, true
	case <-time.After(timeout):
		return nil, false
	}
}

func serveCustomEngine(t *testing.T, client *agentapi.Client, session *agentapi.OpenSessionResponse, upstream http.RoundTripper) *runningEngine {
	t.Helper()
	ca, certPEM, _, err := phaseproxy.GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caDirectory := t.TempDir()
	certificatePath, bundlePath := filepath.Join(caDirectory, "ca.pem"), filepath.Join(caDirectory, "ca-bundle.pem")
	for _, path := range []string{certificatePath, bundlePath} {
		if err := os.WriteFile(path, certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	proxySession := &airuntime.ProxySession{Config: session, Client: client, CA: ca, CAPaths: phaseproxy.CAPaths{Certificate: certificatePath, Bundle: bundlePath}}

	engine := New()
	engine.ListenAddress = unusedTestListenAddresses(t, "127.0.0.1")[0]
	engine.RefreshInterval = time.Hour
	engine.EventFlushInterval = 20 * time.Millisecond
	engine.EventSpoolDirectory = t.TempDir()
	engine.Transport = upstream
	started := make(chan Endpoints, 1)
	engine.OnStarted = func(endpoints Endpoints) { started <- endpoints }
	ctx, cancel := context.WithCancel(context.Background())
	running := &runningEngine{done: make(chan error, 1), roots: x509.NewCertPool()}
	go func() { running.done <- engine.Serve(ctx, proxySession) }()
	select {
	case running.endpoints = <-started:
	case err := <-running.done:
		cancel()
		t.Fatalf("proxy engine stopped before start: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("proxy engine did not start")
	}
	running.stop = func() {
		cancel()
		if running.ended {
			return
		}
		if err, stopped := running.wait(10 * time.Second); !stopped {
			t.Error("engine did not stop")
		} else if err != nil {
			t.Errorf("engine stopped with %v", err)
		}
	}
	if !running.roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append proxy CA")
	}
	proxyURL, _ := url.Parse(running.endpoints.ProxyURL.Reveal())
	running.client = &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: running.roots, MinVersion: tls.VersionTLS12},
	}}
	return running
}
