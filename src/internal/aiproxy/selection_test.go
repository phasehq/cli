package aiproxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

func selectionConnection(t *testing.T, id, protocol string) agentapi.Connection {
	t.Helper()
	c := agentapi.Connection{ConnectionID: id, GrantID: "grant-" + id, CredentialID: "credential-" + id, CredentialName: "Test " + protocol + " credential", CredentialProvider: protocol, CredentialRevision: "credential-v1", ServiceType: protocol, Protocol: protocol,
		Hosts:         []agentapi.HostRule{{Match: "exact", Value: "upstream.test", Port: 443}},
		Authorization: agentapi.ConnectionAuthorization{Version: 1, Mode: "connection", AccessMode: "allow", State: "allowed"},
		Identifiers:   map[string]string{"username": "same-user"}, DecoyMaterial: map[string]string{"password": "decoy-" + id},
		Injection: agentapi.Injection{Action: "pg_handshake", ValueFrom: agentapi.ValueFrom{Source: "credential", Fields: map[string]string{"username": "username", "password": "password"}}},
		ConfigEnv: map[string]string{},
		EnvironmentBindings: []agentapi.EnvironmentBinding{{
			Name: "PGUSER", Action: agentapi.EnvironmentBindingSet, Source: agentapi.EnvironmentSourceIdentifier, SourceField: "username", SystemManaged: true,
		}},
	}
	material, _ := json.Marshal(map[string]string{"username": "same-user", "password": "live-" + id})
	_ = json.Unmarshal(material, &c.SecretMaterial)
	env, _ := json.Marshal(map[string]string{"PGUSER": "same-user"})
	_ = json.Unmarshal(env, &c.AgentEnv)
	return c
}

func selectionState(t *testing.T, connections ...agentapi.Connection) *runtimeState {
	t.Helper()
	bindings, err := parseBindings(connections)
	if err != nil {
		t.Fatal(err)
	}
	return &runtimeState{bindings: bindings, sessionUID: "session-test", runtimeCapability: "runtime-test", backendCredential: "backend-test", healthy: true, expiresAt: time.Now().Add(time.Hour), generation: 1, changed: make(chan struct{}), fatal: make(chan error, 1), configEnv: map[string]string{}}
}

func TestConcurrentSelectedAWSConnectionsNeverShareRouting(t *testing.T) {
	connections := make([]agentapi.Connection, 2)
	for i, id := range []string{"aws-one", "aws-two"} {
		c := selectionConnection(t, id, "http")
		c.ServiceType = "aws"
		key := "AKIAPHASEDECOY0000" + strconv.Itoa(i)
		liveKey := "AKIALIVEEXAMPLE000" + strconv.Itoa(i)
		c.Identifiers = map[string]string{"access_key_id": key}
		c.DecoyMaterial = map[string]string{"secret_access_key": "decoy-" + id}
		c.ConnectionConfig = map[string]any{"service": "sts", "region": "us-east-1"}
		c.ConfigEnv = map[string]string{"AWS_REGION": "us-east-1"}
		environment, _ := json.Marshal(map[string]string{"AWS_ACCESS_KEY_ID": key, "AWS_SECRET_ACCESS_KEY": "decoy-" + id})
		_ = json.Unmarshal(environment, &c.AgentEnv)
		c.EnvironmentBindings = []agentapi.EnvironmentBinding{
			{Name: "AWS_ACCESS_KEY_ID", Action: agentapi.EnvironmentBindingSet, Source: agentapi.EnvironmentSourceIdentifier, SourceField: "access_key_id", SystemManaged: true},
			{Name: "AWS_SECRET_ACCESS_KEY", Action: agentapi.EnvironmentBindingSet, Source: agentapi.EnvironmentSourceDecoy, SourceField: "secret_access_key", Sensitive: true, SystemManaged: true},
			{Name: "AWS_REGION", Action: agentapi.EnvironmentBindingSet, Source: agentapi.EnvironmentSourceConnectionConfig, SourceField: "region", SystemManaged: true},
		}
		c.Injection = agentapi.Injection{Action: "aws_sigv4", ServiceFrom: "config", RegionFrom: "config", ValueFrom: agentapi.ValueFrom{Source: "credential", Fields: map[string]string{"accessKeyId": "access_key_id", "secretAccessKey": "secret_access_key"}}}
		data, _ := json.Marshal(map[string]string{"access_key_id": liveKey, "secret_access_key": "live-" + id})
		_ = json.Unmarshal(data, &c.SecretMaterial)
		connections[i] = c
	}
	state := selectionState(t, connections...)
	proxy := &httpProxy{state: state, transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy capability reached upstream")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(req.Header.Get("Authorization")))}, nil
	})}
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		for _, connection := range connections {
			wg.Add(1)
			go func(c agentapi.Connection) {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "https://upstream.test/", nil)
				hash := sha256.Sum256(nil)
				err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: c.Identifiers["access_key_id"], SecretAccessKey: c.DecoyMaterial["secret_access_key"]}, req, hex.EncodeToString(hash[:]), "sts", "us-east-1", time.Now())
				if err != nil {
					t.Error(err)
					return
				}
				req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("phase."+c.ConnectionID+":runtime-test")))
				recorder := httptest.NewRecorder()
				if !proxy.authenticateProxyRequest(recorder, req) {
					t.Errorf("auth rejected %d", recorder.Code)
					return
				}
				result := proxy.process(req, nil)
				if result.failure != nil {
					t.Errorf("selection failed: %s", result.failure.code)
					return
				}
				defer result.response.Body.Close()
				body, _ := io.ReadAll(result.response.Body)
				if !strings.Contains(string(body), "Credential="+c.Identifiers["access_key_id"]+"/") {
					t.Error("Connection identity crossed concurrent request")
				}
				liveKey, _ := c.SecretMaterial.Get("access_key_id")
				if strings.Contains(string(body), liveKey) {
					t.Error("live AWS access-key ID crossed response boundary")
				}
			}(connection)
		}
	}
	wg.Wait()
	req := httptest.NewRequest(http.MethodGet, "https://upstream.test/", nil)
	if result := proxy.process(req, nil); result.failure == nil || result.failure.code != "ambiguous_agent_binding" {
		t.Fatal("ambiguous unselected route did not fail closed")
	}
	bad := httptest.NewRequest(http.MethodGet, "https://upstream.test/", nil)
	bad.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("phase.aws-one:forged")))
	if proxy.authenticateProxyRequest(httptest.NewRecorder(), bad) {
		t.Fatal("selector bypassed capability authentication")
	}
	// Selection cannot bypass a missing allow attestation.
	state.bindings[0].connection.Authorization = agentapi.ConnectionAuthorization{}
	req = req.WithContext(context.WithValue(req.Context(), selectedConnectionContextKey{}, "aws-one"))
	if result := proxy.process(req, nil); result.failure == nil || result.failure.code != "agent_connection_denied" {
		t.Fatal("selected denied grant was used")
	}
}

func TestMultiplePostgresConnectionsAuthenticateOnOneListener(t *testing.T) {
	ca, pem, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	cert, err := ca.CertificateForHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	one, passOne, queryOne := startFakePostgres(t, cert)
	defer one.Close()
	two, passTwo, queryTwo := startFakePostgres(t, cert)
	defer two.Close()
	c1, c2 := selectionConnection(t, "pg-one", "postgres"), selectionConnection(t, "pg-two", "postgres")
	for i, listener := range []net.Listener{one, two} {
		host, port, _ := net.SplitHostPort(listener.Addr().String())
		rule := []agentapi.HostRule{{Match: "exact", Value: host, Port: mustPort(t, port)}}
		if i == 0 {
			c1.Hosts = rule
		} else {
			c2.Hosts = rule
		}
	}
	state := selectionState(t, c1, c2)
	engine := New()
	engine.PostgresListenAddress = "127.0.0.1:0"
	engine.UpstreamTLSConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	adapters, err := engine.startProtocolAdapters(ctx, state, nil, ca, (&net.Dialer{}).DialContext, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer adapters.Close()
	if adapters.environment["PGPASSWORD"] != "" {
		t.Fatal("multiple connections received a default password")
	}
	var wg sync.WaitGroup
	for _, c := range []agentapi.Connection{c1, c2} {
		wg.Add(1)
		go func(c agentapi.Connection) {
			defer wg.Done()
			runPostgresClient(t, adapters.postgresAddress, roots, "same-user", c.DecoyMaterial["password"], "app", "select 1")
		}(c)
	}
	wg.Wait()
	for _, observation := range []struct {
		password <-chan string
		query    <-chan string
		expected string
	}{{passOne, queryOne, "live-pg-one"}, {passTwo, queryTwo, "live-pg-two"}} {
		select {
		case value := <-observation.password:
			if value != observation.expected {
				t.Fatal("wrong upstream credential")
			}
		case <-time.After(time.Second):
			t.Fatal("missing upstream authentication")
		}
		select {
		case <-observation.query:
		case <-time.After(time.Second):
			t.Fatal("missing upstream query")
		}
	}
}

func TestSelectedEnvironmentContainsOneIdentityAndRejectsProxyOnlyMaterial(t *testing.T) {
	c1, c2 := selectionConnection(t, "pg-one", "postgres"), selectionConnection(t, "pg-two", "postgres")
	c1.ConfigEnv = map[string]string{"PGDATABASE": "one"}
	c2.ConfigEnv = map[string]string{"PGDATABASE": "two"}
	c1.ConnectionConfig = map[string]any{"database": "one"}
	c2.ConnectionConfig = map[string]any{"database": "two"}
	c1.EnvironmentBindings = append(c1.EnvironmentBindings, agentapi.EnvironmentBinding{Name: "PGDATABASE", Action: agentapi.EnvironmentBindingSet, Source: agentapi.EnvironmentSourceConnectionConfig, SourceField: "database", SystemManaged: true})
	c2.EnvironmentBindings = append(c2.EnvironmentBindings, agentapi.EnvironmentBinding{Name: "PGDATABASE", Action: agentapi.EnvironmentBindingSet, Source: agentapi.EnvironmentSourceConnectionConfig, SourceField: "database", SystemManaged: true})
	state := selectionState(t, c1, c2)
	ca, pem, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem, 0600); err != nil {
		t.Fatal(err)
	}
	session := &airuntime.ProxySession{Config: &agentapi.OpenSessionResponse{SessionConfig: agentapi.SessionConfig{Connections: []agentapi.Connection{c1, c2}, ConfigEnv: map[string]string{}}}, CA: ca, CAPaths: phaseproxy.CAPaths{Certificate: path, Bundle: path}}
	defaultPlan, err := session.ProviderProcessEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if defaultPlan.Set["PGUSER"] != "" {
		t.Fatal("ambiguous default identity")
	}
	compiler := &connectionEnvironmentCompiler{session: session, proxyURL: "http://phase:runtime-test@127.0.0.1:9543", adapters: map[string]string{"PGHOST": "127.0.0.1", "PGPORT": "9544", "PGSSLMODE": "verify-full"}}
	for _, id := range []string{"pg-one", "pg-two"} {
		result, err := compiler.compile(state, id)
		if err != nil {
			t.Fatal(err)
		}
		if result.ProcessEnvironment.Set["PGDATABASE"] != strings.TrimPrefix(id, "pg-") {
			t.Fatal("selected Connection configuration crossed identity")
		}
		if result.ProcessEnvironment.Set["PGPASSWORD"] != "decoy-"+id {
			t.Fatal("wrong decoy selected")
		}
		selected, _ := url.Parse(result.ProcessEnvironment.Set["HTTPS_PROXY"])
		if selected.User.Username() != "phase."+id {
			t.Fatal("proxy selection omitted")
		}
	}
	handler := &controlHandler{state: state, environments: compiler}
	state.bindings[0].connection.ConfigEnv["EXFIL"] = "live-pg-one"
	recorder := httptest.NewRecorder()
	handler.connectionEnvironment(recorder, httptest.NewRequest(http.MethodGet, "http://phase.invalid/v1/connections/pg-one/environment", nil), "pg-one")
	if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), "live-pg-one") ||
		!strings.Contains(recorder.Body.String(), `"code":"unsafe_connection_environment"`) ||
		!strings.Contains(recorder.Body.String(), `"retryable":false`) {
		t.Fatal("unsafe source material crossed selected environment boundary")
	}

	delete(state.bindings[0].connection.ConfigEnv, "EXFIL")
	encodedLive := "live<pg-one"
	encodedMaterial, _ := json.Marshal(map[string]string{"username": "same-user", "password": encodedLive})
	_ = json.Unmarshal(encodedMaterial, &state.bindings[0].connection.SecretMaterial)
	state.bindings[0].connection.DecoyMaterial["password"] = encodedLive
	recorder = httptest.NewRecorder()
	handler.connectionEnvironment(recorder, httptest.NewRequest(http.MethodGet, "http://phase.invalid/v1/connections/pg-one/environment", nil), "pg-one")
	if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), encodedLive) ||
		!strings.Contains(recorder.Body.String(), `"code":"unsafe_connection_environment"`) ||
		!strings.Contains(recorder.Body.String(), `"retryable":false`) {
		t.Fatal("JSON-escaped proxy-only material crossed selected environment boundary")
	}

	collidingMaterial, _ := json.Marshal(map[string]string{"username": "same-user", "password": "same-user"})
	_ = json.Unmarshal(collidingMaterial, &state.bindings[0].connection.SecretMaterial)
	state.bindings[0].connection.DecoyMaterial["password"] = "decoy-pg-one"
	recorder = httptest.NewRecorder()
	handler.connectionEnvironment(recorder, httptest.NewRequest(http.MethodGet, "http://phase.invalid/v1/connections/pg-one/environment", nil), "pg-one")
	if recorder.Code != http.StatusBadGateway ||
		!strings.Contains(recorder.Body.String(), `"code":"unsafe_connection_environment"`) ||
		!strings.Contains(recorder.Body.String(), `"retryable":false`) {
		t.Fatal("secret-bearing material equal to a username was misclassified as Agent-visible")
	}

	ambiguousLive := "ambiguous-live-password"
	ambiguousConnection := selectionConnection(t, "pg-ambiguous", "postgres")
	ambiguousConnection.Injection.ValueFrom.Fields = map[string]string{"password": "credential_password", "pass_word": "other"}
	if _, err := parseBindings([]agentapi.Connection{ambiguousConnection}); err == nil {
		t.Fatal("ambiguous credential role aliases were accepted by binding validation")
	}
	ambiguousMaterial, _ := json.Marshal(map[string]string{"username": "same-user", "credential_password": ambiguousLive})
	_ = json.Unmarshal(ambiguousMaterial, &state.bindings[0].connection.SecretMaterial)
	state.bindings[0].connection.Identifiers["credential_password"] = ambiguousLive
	state.bindings[0].connection.Injection.ValueFrom.Fields = map[string]string{"password": "credential_password", "pass_word": "other"}
	recorder = httptest.NewRecorder()
	handler.connectionEnvironment(recorder, httptest.NewRequest(http.MethodGet, "http://phase.invalid/v1/connections/pg-one/environment", nil), "pg-one")
	if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), ambiguousLive) ||
		!strings.Contains(recorder.Body.String(), `"code":"unsafe_connection_environment"`) ||
		!strings.Contains(recorder.Body.String(), `"retryable":false`) {
		t.Fatal("ambiguous credential role aliases bypassed proxy-only material classification")
	}

	safeMaterial, _ := json.Marshal(map[string]string{"username": "same-user", "password": "live-pg-one"})
	_ = json.Unmarshal(safeMaterial, &state.bindings[0].connection.SecretMaterial)
	delete(state.bindings[0].connection.Identifiers, "credential_password")
	state.bindings[0].connection.Injection.ValueFrom.Fields = map[string]string{"username": "username", "password": "password"}
	ordinaryCompiler := *compiler
	ordinaryCompiler.proxyURL = "%"
	handler.environments = &ordinaryCompiler
	recorder = httptest.NewRecorder()
	handler.connectionEnvironment(recorder, httptest.NewRequest(http.MethodGet, "http://phase.invalid/v1/connections/pg-one/environment", nil), "pg-one")
	if recorder.Code != http.StatusConflict ||
		!strings.Contains(recorder.Body.String(), `"code":"connection_environment_unavailable"`) ||
		!strings.Contains(recorder.Body.String(), `"retryable":true`) {
		t.Fatal("ordinary environment compilation failure changed classification")
	}
}

func TestCredentialExpiryClosesIdleProtocolWithoutRefresh(t *testing.T) {
	c := selectionConnection(t, "pg-expiring", "postgres")
	expires := time.Now().Add(40 * time.Millisecond)
	c.CredentialExpiresAt = &expires
	state := selectionState(t, c)
	adapter := &protocolAdapters{state: state}
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go adapter.watchProtocolRoute(ctx, server, c.GrantID, protocolRoute{protocol: "postgres", host: "upstream.test", port: 443}, 5432, done)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("expired source connection remained open")
	} else if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
		t.Fatal("source expiry did not close idle protocol")
	}
}
