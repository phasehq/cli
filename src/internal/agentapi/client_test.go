package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/golang-sdk/v2/phase/network"
)

func testToken(prefix string, version int, lookup string) string {
	if lookup == "" {
		lookup = strings.Repeat("a", 64)
	}
	return fmt.Sprintf("%s:v%d:%s:%s:%s:%s", prefix, version, lookup,
		strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64))
}

func TestParseDurableTokenCompatibility(t *testing.T) {
	tests := []struct {
		token string
		want  TokenType
	}{
		{testToken("pss_user", 1, ""), TokenUser},
		{testToken("pss_user", 2, ""), TokenUser},
		{testToken("pss_service", 1, ""), TokenService},
		{testToken("pss_service", 2, ""), TokenServiceAccount},
		{testToken("pss_agent", 2, ""), TokenAgent},
	}
	for _, test := range tests {
		got, lookup, err := ParseDurableToken(test.token)
		if err != nil {
			t.Fatalf("ParseDurableToken(%s): %v", test.want, err)
		}
		if got != test.want || len(lookup) != 64 {
			t.Fatalf("got (%s, %q), want (%s, 64-byte lookup)", got, lookup, test.want)
		}
	}
	for _, invalid := range []string{
		"",
		"pss_agent:v1:" + strings.Repeat("a:", 4) + "a",
		"pss_agent:v1:" + strings.Repeat("a", 64),
		"pss_user:v1:not-hex",
	} {
		if _, _, err := ParseDurableToken(invalid); err == nil {
			t.Fatalf("expected invalid token rejection for %q", invalid)
		}
	}
}

func TestClientBypassesDataPlaneProxyInsideManagedChild(t *testing.T) {
	t.Setenv("PHASE_AI_ENABLED", "1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	client, err := NewClient("https://console.phase.dev", testToken("pss_agent", 2, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("Agent control-plane client would send durable auth through the data-plane proxy")
	}
}

func TestClientSendsCapturedSharedUserAgentOnEveryAgentRoute(t *testing.T) {
	previousUserAgent := network.GetUserAgent()
	network.SetUserAgent("phase-cli/test shared-agent-api")
	t.Cleanup(func() { network.SetUserAgent(previousUserAgent) })

	var routes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "phase-cli/test shared-agent-api" {
			t.Errorf("%s %s User-Agent = %q", r.Method, r.URL.Path, got)
		}
		routes = append(routes, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, testToken("pss_agent", 2, ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	// NewClient deliberately captures the process identity so a later mutation
	// of the SDK global cannot change a running Agent session's attribution.
	network.SetUserAgent("phase-cli/changed-after-client-construction")

	ctx := context.Background()
	credential := SensitiveString("session-one")
	_, _ = client.Identity(ctx)
	_, _ = client.OpenSession(ctx, OpenSessionRequest{})
	_, _ = client.RefreshSession(ctx, "session-123", credential)
	_, _ = client.Context(ctx, "session-123", credential)
	_, _ = client.ContextForService(ctx, "session-123", credential, "aws")
	_, _ = client.Capabilities(ctx, "session-123", credential)
	_, _ = client.Discover(ctx, "session-123", credential)
	_, _ = client.RotateSessionCredential(ctx, "session-123", credential)
	_, _ = client.RevokeSession(ctx, "session-123", credential)
	_, _ = client.CreateRequest(ctx, CreateRequestRequest{ConnectionID: "connection-123", Markdown: "need connection"}, credential)
	_, _ = client.PollRequest(ctx, "request-123", credential)
	_, _ = client.ShipEvents(ctx, "session-123", EventBatchRequest{}, credential)

	want := []string{
		"GET /service/public/v1/agents/identity/",
		"POST /service/public/v1/agents/sessions/",
		"GET /service/public/v1/agents/sessions/session-123/config/",
		"GET /service/public/v1/agents/sessions/session-123/context/",
		"GET /service/public/v1/agents/sessions/session-123/context/?serviceType=aws",
		"GET /service/public/v1/agents/sessions/session-123/capabilities/",
		"GET /service/public/v1/agents/sessions/session-123/discover/",
		"POST /service/public/v1/agents/sessions/session-123/rotate/",
		"POST /service/public/v1/agents/sessions/session-123/revoke/",
		"POST /service/public/v1/agents/requests/",
		"GET /service/public/v1/agents/requests/request-123/",
		"POST /service/public/v1/agents/sessions/session-123/events/",
	}
	if fmt.Sprint(routes) != fmt.Sprint(want) {
		t.Fatalf("routes = %v, want %v", routes, want)
	}
}

func TestRequestRoutesUseSharedSDKWithoutChangingRelayContract(t *testing.T) {
	previousUserAgent := network.GetUserAgent()
	network.SetUserAgent("phase-cli/test sdk-request-adapter")
	t.Cleanup(func() { network.SetUserAgent(previousUserAgent) })

	var requestCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions/"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"session-123"}`))
		case strings.Contains(r.URL.Path, "/requests/"):
			requestCalls.Add(1)
			if got := r.Header.Get(SessionCredentialHeader); got != "session-one" {
				t.Errorf("session #1 = %q", got)
			}
			if got := r.Header.Get("User-Agent"); got != "phase-cli/test sdk-request-adapter" {
				t.Errorf("User-Agent = %q", got)
			}
			if got := r.Header.Get("X-Use-Camel-Case"); got != "true" {
				t.Errorf("shared SDK marker = %q", got)
			}
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/requests/") {
				_, _ = w.Write([]byte(`{"schemaVersion":1,"requests":[{"schemaVersion":1,"id":"request-123","status":"pending","kind":"setup","credentialProvider":"aws","credentialName":"AWS - EC2, RDS, S3 full access","serviceType":"aws","markdown":"Set up AWS deployment access","approvalUrl":"https://console.phase.dev/phase/agents/requests?request=request-123"}]}`))
				return
			}
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
			}
			_, _ = w.Write([]byte(`{"schemaVersion":1,"id":"request-123","status":"approved","kind":"setup","credentialProvider":"aws","credentialName":"AWS - EC2, RDS, S3 full access","serviceType":"aws","credentialId":"credential-123","connectionId":"connection-123","grantId":"grant-123","markdown":"Set up AWS deployment access","approvalUrl":"https://console.phase.dev/phase/agents/requests?request=request-123","runtimeAction":"restart_required"}`))
		default:
			t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, testToken("pss_agent", 2, ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.OpenSession(context.Background(), OpenSessionRequest{}); err != nil {
		t.Fatal(err)
	}
	credential := SensitiveString("session-one")
	created, statusCode, err := client.CreateRequestWithStatus(context.Background(), CreateRequestRequest{
		Kind: "setup", CredentialProvider: "aws", CredentialName: "AWS - EC2, RDS, S3 full access", ServiceType: "aws", Markdown: "need AWS",
	}, credential)
	if err != nil || statusCode != http.StatusCreated {
		t.Fatalf("CreateRequestWithStatus = %+v, %d, %v", created, statusCode, err)
	}
	if created.Markdown != "Set up AWS deployment access" {
		t.Fatalf("created request lost markdown: %+v", created)
	}
	polled, err := client.PollRequest(context.Background(), "request-123", credential)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := client.ListPendingRequests(context.Background(), credential)
	if err != nil {
		t.Fatal(err)
	}
	if requestCalls.Load() != 3 || polled.ApprovalURL == "" || polled.CredentialID != "credential-123" ||
		polled.ConnectionID != "connection-123" || polled.GrantID != "grant-123" ||
		polled.Markdown != "Set up AWS deployment access" || polled.RuntimeAction != RequestRuntimeActionRestartRequired {
		t.Fatalf("shared SDK response lost relay fields: %+v", polled)
	}
	if len(pending.Requests) != 1 || pending.Requests[0].Markdown != "Set up AWS deployment access" {
		t.Fatalf("shared SDK pending request lost markdown: %+v", pending)
	}
}

func TestSharedSDKRequestErrorIsBoundedAndMapped(t *testing.T) {
	secret := testToken("pss_agent", 2, "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/sessions/") {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"session-123"}`))
			return
		}
		w.Header().Set("Retry-After", "3")
		w.Header().Set("X-Request-ID", "request-id-123")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprintf(w, `{"error":{"code":"busy","message":"retry %s","retryable":true,"details":{"raw":"live-secret"}}}`, secret)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, secret, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.OpenSession(context.Background(), OpenSessionRequest{}); err != nil {
		t.Fatal(err)
	}
	_, statusCode, err := client.CreateRequestWithStatus(context.Background(), CreateRequestRequest{
		Kind: "setup", ServiceType: "aws", CredentialProvider: "aws", CredentialName: "AWS production", Markdown: "need access",
	}, SensitiveString("session-one"))
	var apiErr *Error
	if statusCode != http.StatusTooManyRequests || !errors.As(err, &apiErr) {
		t.Fatalf("error = %T %v, status=%d", err, err, statusCode)
	}
	if apiErr.Code != "busy" || !apiErr.Retryable || apiErr.RetryAfter != 3*time.Second || apiErr.RequestID != "request-id-123" {
		t.Fatalf("mapped error = %+v", apiErr)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "live-secret") {
		t.Fatalf("mapped SDK error leaked response details: %v", err)
	}
}

func TestClientNeverFollowsSameOrCrossOriginRedirects(t *testing.T) {
	for _, crossOrigin := range []bool{false, true} {
		name := "same-origin"
		if crossOrigin {
			name = "cross-origin"
		}
		t.Run(name, func(t *testing.T) {
			var targetCalls atomic.Int32
			var leakedAuthorization atomic.Value
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetCalls.Add(1)
				leakedAuthorization.Store(r.Header.Get("Authorization") + "|" + r.Header.Get(SessionCredentialHeader))
				_, _ = w.Write([]byte(`{}`))
			}))
			defer target.Close()
			var source *httptest.Server
			source = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/redirect-target") {
					targetCalls.Add(1)
					leakedAuthorization.Store(r.Header.Get("Authorization") + "|" + r.Header.Get(SessionCredentialHeader))
					_, _ = w.Write([]byte(`{}`))
					return
				}
				location := source.URL + "/redirect-target"
				if crossOrigin {
					location = target.URL
				}
				http.Redirect(w, r, location, http.StatusTemporaryRedirect)
			}))
			defer source.Close()

			originalRedirect := func(*http.Request, []*http.Request) error { return nil }
			supplied := &http.Client{Transport: source.Client().Transport, CheckRedirect: originalRedirect}
			client, err := NewClient(source.URL, testToken("pss_agent", 2, ""), supplied)
			if err != nil {
				t.Fatal(err)
			}
			if client.httpClient == supplied || supplied.CheckRedirect == nil {
				t.Fatal("NewClient mutated or reused the supplied http.Client")
			}
			_, err = client.Context(context.Background(), "session-1", SensitiveString("session-capability"))
			var apiErr *Error
			if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusTemporaryRedirect {
				t.Fatalf("redirect response = %T %v", err, err)
			}
			if targetCalls.Load() != 0 {
				t.Fatalf("redirect target was followed and received %q", leakedAuthorization.Load())
			}
		})
	}
}

func TestAgentAPIBasePathNormalization(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"https://console.phase.dev", "/service/public/v1/agents/sessions/"},
		{"https://example.test/phase", "/phase/service/public/v1/agents/sessions/"},
		{"https://example.test/phase/service/public", "/phase/service/public/v1/agents/sessions/"},
		{"https://example.test/phase/service/public/v1/agents", "/phase/service/public/v1/agents/sessions/"},
	}
	for _, test := range tests {
		client, err := NewClient(test.host, testToken("pss_agent", 2, ""), http.DefaultClient)
		if err != nil {
			t.Fatalf("NewClient(%q): %v", test.host, err)
		}
		endpoint, err := url.Parse(client.endpoint("sessions"))
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.Path != test.want {
			t.Fatalf("host %q path = %q, want %q", test.host, endpoint.Path, test.want)
		}
	}
	for _, invalid := range []string{
		"https://user:pass@example.test",
		"https://example.test?tenant=one",
		"https://example.test#fragment",
	} {
		if _, err := NewClient(invalid, testToken("pss_agent", 2, ""), http.DefaultClient); err == nil {
			t.Fatalf("expected unsafe host rejection for %q", invalid)
		}
	}
}

func TestAgentAPIRequiresHTTPSOutsideExplicitLoopback(t *testing.T) {
	tests := []struct {
		host    string
		allowed bool
	}{
		{"http://127.0.0.1:8080", true},
		{"http://[::1]:8080", true},
		{"http://localhost:8080", true},
		{"http://LOCALHOST.:8080", true},
		{"https://console.phase.dev", true},
		{"https://10.0.0.1", true},
		{"http://console.phase.dev", false},
		{"http://10.0.0.1", false},
		{"http://localhost.example.com", false},
	}
	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			_, err := NewClient(test.host, testToken("pss_agent", 2, ""), http.DefaultClient)
			if (err == nil) != test.allowed {
				t.Fatalf("NewClient(%q) error=%v, allowed=%t", test.host, err, test.allowed)
			}
		})
	}
}

func TestOpenSessionParsesConsoleGoldenContractAndRedacts(t *testing.T) {
	golden, err := os.ReadFile("testdata/open_session_response.json")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/service/public/v1/agents/sessions/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer User "+strings.Repeat("a", 64) {
			t.Errorf("authorization = %q", got)
		}
		var request OpenSessionRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.WorkflowID != "workflow-123" || request.SchemaVersion != 1 {
			t.Errorf("unexpected request: %+v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(golden)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, testToken("pss_user", 1, ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.OpenSession(context.Background(), OpenSessionRequest{
		WorkflowID: "workflow-123", IdempotencyKey: "proxy-start-12345678",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.SessionUID != "session-123" || response.SessionCredential.Reveal() == "" {
		t.Fatalf("unexpected response: %s", response)
	}
	if response.ConfigEnv["AWS_DEFAULT_REGION"] != "us-east-1" || response.Connections[0].ConfigEnv["AWS_DEFAULT_REGION"] != "us-east-1" ||
		response.Connections[0].ConnectionName != "Production AWS" ||
		len(response.Connections[0].EnvironmentBindings) != 15 {
		t.Fatalf("open-session environment contract was dropped: config=%v bindings=%v", response.ConfigEnv, response.Connections[0].EnvironmentBindings)
	}
	if response.Connections[0].CredentialProvider != "aws" || response.Connections[0].CredentialName != "AWS - EC2, RDS, S3 full access" ||
		response.Connections[0].CredentialRevision != "credential-revision-1" {
		t.Fatalf("open-session credential metadata was dropped: %+v", response.Connections[0])
	}
	if _, ok := response.Connections[0].AgentEnv.Get("AWS_IAM_USERNAME"); ok {
		t.Fatal("open-session fixture retained a generated Dynamic Secret identity")
	}
	if token, ok := response.Connections[0].AgentEnv.Get("AWS_SESSION_TOKEN"); !ok || token != "phx_aws_session_REDACTED_DECOY" {
		t.Fatalf("open-session fixture did not install the proxy-only AWS session token: %q, %t", token, ok)
	}
	if token, ok := LookupMaterial(response.Connections[0].DecoyMaterial, "session_token"); !ok || token != "phx_aws_session_REDACTED_DECOY" {
		t.Fatalf("open-session fixture did not retain AWS session-token decoy material: %q, %t", token, ok)
	}
	if response.Connections[0].Authorization.Version != 1 || response.Connections[0].Authorization.Mode != "connection" ||
		response.Connections[0].Authorization.AccessMode != "allow" || response.Connections[0].Authorization.State != "allowed" {
		t.Fatalf("open-session authorization was dropped: %+v", response.Connections[0].Authorization)
	}
	secret, ok := response.Connections[0].SecretMaterial.Get("secretAccessKey")
	if !ok || secret != "REDACTED_PROXY_ONLY" {
		t.Fatal("proxy-only secret material was not decoded")
	}
	secret, ok = response.Connections[0].SecretMaterial.Get("secret_access_key")
	if !ok || secret != "REDACTED_PROXY_ONLY" {
		t.Fatal("snake_case valueFrom did not resolve CamelCase Console material")
	}
	liveAccessKey, liveOK := response.Connections[0].SecretMaterial.Get("access_key_id")
	agentAccessKey, agentOK := response.Connections[0].AgentEnv.Get("AWS_ACCESS_KEY_ID")
	if !liveOK || !agentOK || liveAccessKey == "" || agentAccessKey == "" || liveAccessKey == agentAccessKey {
		t.Fatal("AWS live and Agent-visible access-key IDs were not separated")
	}
	formatted := fmt.Sprintf("%#v %#v %#v", response, response.SessionCredential, response.Connections[0].SecretMaterial)
	for _, secretValue := range []string{"psx_sess_REDACTED_REVEAL_ONCE", "REDACTED_PROXY_ONLY"} {
		if strings.Contains(formatted, secretValue) {
			t.Fatalf("formatted response leaked %q: %s", secretValue, formatted)
		}
	}
}

func TestLookupMaterialRejectsSemanticCollisions(t *testing.T) {
	values := map[string]string{
		"accessKeyId":   "first",
		"access_key_id": "second",
	}
	for _, name := range []string{"accessKeyId", "access_key_id", "ACCESS_KEY_ID"} {
		if value, ok := LookupMaterial(values, name); ok || value != "" {
			t.Fatalf("ambiguous %q resolved to %q", name, value)
		}
	}
	if value, ok := LookupMaterial(map[string]string{"accessKeyId": "only"}, "access_key_id"); !ok || value != "only" {
		t.Fatalf("unambiguous semantic lookup=(%q,%t)", value, ok)
	}
	if value, ok := LookupMaterial(map[string]string{"opaque-key": "exact"}, "opaque-key"); !ok || value != "exact" {
		t.Fatalf("exact opaque lookup=(%q,%t)", value, ok)
	}
}

func TestDiscoverParsesConsoleGoldenContractWithoutSecretMaterial(t *testing.T) {
	golden, err := os.ReadFile("testdata/discover_response.json")
	if err != nil {
		t.Fatal(err)
	}
	var response DiscoverResponse
	if err := json.Unmarshal(golden, &response); err != nil {
		t.Fatal(err)
	}
	if response.SessionUID != "session-123" || len(response.Connections) != 1 {
		t.Fatalf("unexpected discover response: %+v", response)
	}
	connection := response.Connections[0]
	if response.ConfigEnv["AWS_DEFAULT_REGION"] != "us-east-1" || connection.ConfigEnv["AWS_DEFAULT_REGION"] != "us-east-1" ||
		connection.ConnectionName != "Production AWS" || len(connection.EnvironmentBindings) != 15 {
		t.Fatalf("discover environment contract was dropped: config=%v connection=%+v", response.ConfigEnv, connection)
	}
	if connection.CredentialID != "credential-aws" || connection.CredentialProvider != "aws" || connection.CredentialName != "AWS - EC2, RDS, S3 full access" {
		t.Fatalf("discover credential metadata was dropped: %+v", connection)
	}
	if _, ok := connection.AgentEnv["AWS_IAM_USERNAME"]; ok {
		t.Fatal("discover fixture retained a generated Dynamic Secret identity")
	}
	if connection.AgentEnv["AWS_SESSION_TOKEN"] != "phx_aws_session_REDACTED_DECOY" ||
		connection.DecoyMaterial["sessionToken"] != "phx_aws_session_REDACTED_DECOY" {
		t.Fatalf("discover fixture dropped AWS session-token decoy state: %+v", connection)
	}
	if connection.Injection.Action != "aws_sigv4" || connection.OnRefresh != "none" || connection.ConnectionConfig["region"] != "us-east-1" {
		t.Fatalf("discover execution metadata was dropped: %+v", connection)
	}
	if connection.Authorization.Version != 1 || connection.Authorization.Mode != "connection" ||
		connection.Authorization.AccessMode != "allow" || connection.Authorization.State != "allowed" {
		t.Fatalf("discover connection authorization was dropped: %+v", connection.Authorization)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secretMaterial") || strings.Contains(string(encoded), "sessionCredential") {
		t.Fatalf("discover type exposed runtime-only fields: %s", encoded)
	}
}

func TestCheckedInAgentFixturesMatchConsoleCanonicalFixtures(t *testing.T) {
	consoleDir := filepath.Join("..", "..", "..", "..", "console", "backend", "ee", "integrations", "agents", "contracts", "v1")
	if _, err := os.Stat(consoleDir); err != nil {
		t.Skip("Console canonical fixture repository is not available")
	}

	for _, name := range []string{"open_session_response.json", "discover_response.json"} {
		t.Run(name, func(t *testing.T) {
			local, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatalf("read CLI fixture: %v", err)
			}
			canonical, err := os.ReadFile(filepath.Join(consoleDir, name))
			if err != nil {
				t.Fatalf("read Console fixture: %v", err)
			}
			var localValue any
			var canonicalValue any
			if err := json.Unmarshal(local, &localValue); err != nil {
				t.Fatalf("decode CLI fixture: %v", err)
			}
			if err := json.Unmarshal(canonical, &canonicalValue); err != nil {
				t.Fatalf("decode Console fixture: %v", err)
			}
			if !reflect.DeepEqual(localValue, canonicalValue) {
				t.Fatalf("CLI Agent fixture differs from Console canonical fixture\nCLI: %s\nConsole: %s", local, canonical)
			}
		})
	}
}

func TestAgentRuntimeSurfaceDoesNotExposeDynamicLeaseContract(t *testing.T) {
	if _, exists := reflect.TypeOf(Connection{}).FieldByName("Lease"); exists {
		t.Fatal("Connection must not expose an Agent-owned lease")
	}
	if _, exists := reflect.TypeOf((*Client)(nil)).MethodByName("RenewLease"); exists {
		t.Fatal("Client must not expose the removed Agent lease renewal endpoint")
	}

	fixture, err := os.ReadFile(filepath.Join("testdata", "open_session_response.json"))
	if err != nil {
		t.Fatalf("read open-session fixture: %v", err)
	}
	if bytes.Contains(fixture, []byte(`"lease"`)) {
		t.Fatal("open-session fixture must not grant Agent-owned provider lease management")
	}
}

func TestEnvironmentBindingWireIsValueFreeAndStrict(t *testing.T) {
	var binding EnvironmentBinding
	if err := json.Unmarshal([]byte(`{"name":"AWS_PROFILE","action":"unset","source":"runtime","sourceField":"secret_access_key","sensitive":false,"systemManaged":true}`), &binding); err != nil {
		t.Fatal(err)
	}
	if err := binding.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{
		`{"name":"AWS_PROFILE","action":"unset","source":"runtime","value":"forbidden","sensitive":false,"systemManaged":true}`,
		`{"name":"SAFE","action":"set","source":"future","sourceField":"value","sensitive":false,"systemManaged":true}`,
		`{"name":"aws_profile","action":"unset","source":"runtime","sourceField":"secret_access_key","sensitive":false,"systemManaged":true}`,
		`{"name":"AWS_PROFILE","action":"unset","source":"runtime","sensitive":false,"systemManaged":true}`,
	} {
		var candidate EnvironmentBinding
		if err := json.Unmarshal([]byte(payload), &candidate); err == nil {
			if validateErr := candidate.Validate(); validateErr == nil {
				t.Fatalf("unsafe environment binding was accepted: %s", payload)
			}
		}
	}
}

func TestResolvedEnvironmentBindingProvenanceIsFailClosed(t *testing.T) {
	bindings := []EnvironmentBinding{
		{Name: "AWS_ACCESS_KEY_ID", Action: EnvironmentBindingSet, Source: EnvironmentSourceIdentifier, SourceField: "access_key_id", SystemManaged: true},
		{Name: "AWS_SECRET_ACCESS_KEY", Action: EnvironmentBindingSet, Source: EnvironmentSourceDecoy, SourceField: "secret_access_key", Sensitive: true, SystemManaged: true},
		{Name: "AWS_REGION", Action: EnvironmentBindingSet, Source: EnvironmentSourceConnectionConfig, SourceField: "region", SystemManaged: true},
		{Name: "AWS_PROFILE", Action: EnvironmentBindingUnset, Source: EnvironmentSourceRuntime, SourceField: "secret_access_key", SystemManaged: true},
	}
	identifiers := map[string]string{"accessKeyId": "identifier"}
	decoys := map[string]string{"secretAccessKey": "decoy"}
	connectionConfig := map[string]any{"region": "us-east-1"}
	agentEnv := map[string]string{"AWS_ACCESS_KEY_ID": "identifier", "AWS_SECRET_ACCESS_KEY": "decoy"}
	configEnv := map[string]string{"AWS_REGION": "us-east-1"}
	if err := ValidateResolvedEnvironmentBindings(bindings, identifiers, decoys, connectionConfig, agentEnv, configEnv); err != nil {
		t.Fatal(err)
	}

	wrongPlane := append([]EnvironmentBinding(nil), bindings...)
	wrongPlane[0].Source = EnvironmentSourceConnectionConfig
	wrongPlane[0].SourceField = "region"
	if err := ValidateResolvedEnvironmentBindings(wrongPlane, identifiers, decoys, connectionConfig, agentEnv, configEnv); err == nil {
		t.Fatal("cross-plane environment provenance was accepted")
	}
	localOnly := append([]EnvironmentBinding(nil), bindings...)
	localOnly[0].Source = EnvironmentSourceProxy
	localOnly[0].SourceField = ""
	if err := ValidateResolvedEnvironmentBindings(localOnly, identifiers, decoys, connectionConfig, agentEnv, configEnv); err == nil {
		t.Fatal("CLI-local source was accepted from a provider response")
	}
	if err := ValidateResolvedEnvironmentBindings(bindings, identifiers, map[string]string{}, connectionConfig, agentEnv, configEnv); err == nil {
		t.Fatal("missing decoy provenance was accepted")
	}
}

func TestRequestResponseCarriesCredentialContextAndRequestExpiry(t *testing.T) {
	var response RequestResponse
	payload := []byte(`{"schemaVersion":1,"id":"request-1","status":"approved","kind":"setup","credentialProvider":"aws","credentialName":"AWS - EC2, RDS, S3 full access","serviceType":"aws","credentialId":"credential-1","connectionId":"connection-1","grantId":"grant-1","markdown":"Set up AWS deployment access","runtimeAction":"restart_required","cooldown":true,"resolutionNote":"go ahead","requestExpiresAt":"2026-07-20T00:00:00Z"}`)
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatal(err)
	}
	if response.RequestExpiresAt == nil ||
		response.SchemaVersion != SchemaVersion || response.Kind != "setup" || response.CredentialProvider != "aws" ||
		response.CredentialName != "AWS - EC2, RDS, S3 full access" ||
		response.ServiceType != "aws" || response.CredentialID != "credential-1" || response.ConnectionID != "connection-1" ||
		response.GrantID != "grant-1" || response.Markdown != "Set up AWS deployment access" || response.RuntimeAction != RequestRuntimeActionRestartRequired || !response.Cooldown {
		t.Fatalf("request credential context was lost: %+v", response)
	}
}

func TestCreateRequestRequestEncodesOnlyTheSelectedShape(t *testing.T) {
	tests := []struct {
		name      string
		request   CreateRequestRequest
		want      []string
		doNotWant []string
	}{
		{
			name: "setup",
			request: CreateRequestRequest{
				Kind: "setup", CredentialProvider: "github", CredentialName: "GitHub production", ServiceType: "github", Markdown: "need a key",
			},
			want:      []string{`"kind":"setup"`, `"credentialProvider":"github"`, `"credentialName":"GitHub production"`, `"serviceType":"github"`, `"markdown":"need a key"`},
			doNotWant: []string{`"connectionId"`, `"dedupKey"`},
		},
		{
			name: "credential update",
			request: CreateRequestRequest{
				Kind: "credential_update", ConnectionID: "connection-1", CredentialID: "credential-1",
				CredentialProvider: "aws", CredentialName: "AWS production", Markdown: "expand permissions",
			},
			want:      []string{`"kind":"credential_update"`, `"connectionId":"connection-1"`, `"credentialId":"credential-1"`, `"credentialProvider":"aws"`, `"credentialName":"AWS production"`},
			doNotWant: []string{`"serviceType"`},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.request)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range test.want {
				if !bytes.Contains(encoded, []byte(want)) {
					t.Fatalf("encoded request %s does not contain %s", encoded, want)
				}
			}
			for _, unwanted := range test.doNotWant {
				if bytes.Contains(encoded, []byte(unwanted)) {
					t.Fatalf("encoded request %s unexpectedly contains %s", encoded, unwanted)
				}
			}
		})
	}
}

func TestAgentIdentityUsesAgentOnlyEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/service/public/v1/agents/identity/" {
			t.Errorf("unexpected identity request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer Agent "+strings.Repeat("a", 64) {
			t.Errorf("authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"schemaVersion":1,
			"principalType":"agent",
			"agent":{"id":"agent-123","name":"Claude"},
			"workflow":{"id":"workflow-123","name":"Default"},
			"organization":{"id":"org-123","name":"Phase"}
		}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, testToken("pss_agent", 2, ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := client.Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if identity.Agent.Name != "Claude" || identity.Workflow.Name != "Default" || identity.Organization.Name != "Phase" {
		t.Fatalf("unexpected Agent identity: %+v", identity)
	}
}

func TestAgentIdentityRejectsNonAgentTokensAndIncompleteResponses(t *testing.T) {
	userClient, err := NewClient("https://console.phase.dev", testToken("pss_user", 2, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := userClient.Identity(context.Background()); err == nil {
		t.Fatal("expected User token identity lookup to fail locally")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schemaVersion":1,"principalType":"agent","agent":{"id":"agent-123","name":"Claude"}}`))
	}))
	defer server.Close()
	agentClient, err := NewClient(server.URL, testToken("pss_agent", 2, ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentClient.Identity(context.Background()); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("expected incomplete identity rejection, got %v", err)
	}
}

func TestRuntimeRoutesCarrySessionCredential(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.RequestURI())
		if got := r.Header.Get(SessionCredentialHeader); got != "session-one" {
			t.Errorf("session credential = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, testToken("pss_agent", 2, ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	credential := SensitiveString("session-one")
	_, _ = client.RefreshSession(ctx, "session-123", credential)
	_, _ = client.Context(ctx, "session-123", credential)
	_, _ = client.Discover(ctx, "session-123", credential)
	_, _ = client.RotateSessionCredential(ctx, "session-123", credential)
	_, _ = client.RevokeSession(ctx, "session-123", credential)
	_, _ = client.CreateRequest(ctx, CreateRequestRequest{ConnectionID: "connection-123", Markdown: "need connection"}, credential)
	_, _ = client.PollRequest(ctx, "request-123", credential)
	_, _ = client.ShipEvents(ctx, "session-123", EventBatchRequest{}, credential)

	want := []string{
		"GET /service/public/v1/agents/sessions/session-123/config/",
		"GET /service/public/v1/agents/sessions/session-123/context/",
		"GET /service/public/v1/agents/sessions/session-123/discover/",
		"POST /service/public/v1/agents/sessions/session-123/rotate/",
		"POST /service/public/v1/agents/sessions/session-123/revoke/",
		"POST /service/public/v1/agents/requests/",
		"GET /service/public/v1/agents/requests/request-123/",
		"POST /service/public/v1/agents/sessions/session-123/events/",
	}
	if fmt.Sprint(paths) != fmt.Sprint(want) {
		t.Fatalf("routes = %v, want %v", paths, want)
	}
}

func TestAPIErrorDropsDetailsAndRedactsCredentialShapedMessage(t *testing.T) {
	secret := testToken("pss_agent", 2, "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error":{"code":"denied","message":"bad %s","retryable":false,"details":{"raw":"live-secret"}}}`, secret)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, secret, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Identity(context.Background())
	if err == nil {
		t.Fatal("expected validation failure")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "live-secret") {
		t.Fatalf("error leaked credential material: %v", err)
	}
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Code != "denied" {
		t.Fatalf("expected typed API error, got %T %v", err, err)
	}
}

func TestAPIErrorCarriesRetryMetadata(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "canonical envelope", body: `{"error":{"code":"busy","message":"retry later","retryable":true}}`},
		{name: "malformed envelope", body: `not-json`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "7")
				w.Header().Set("X-Request-ID", "request-id-123")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			client, err := NewClient(server.URL, testToken("pss_agent", 2, ""), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Identity(context.Background())
			var apiErr *Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("error = %T %v, want *Error", err, err)
			}
			if apiErr.StatusCode != http.StatusTooManyRequests || apiErr.RetryAfter != 7*time.Second || apiErr.RequestID != "request-id-123" {
				t.Fatalf("retry metadata = %+v", apiErr)
			}
		})
	}
}

func TestConnectionAgentEnvironmentRedactsSessionCapability(t *testing.T) {
	const capability = "psx_sess_sensitive_capability_123456789"
	var connection Connection
	if err := json.Unmarshal([]byte(`{"agentEnv":{"PGUSER":"agent","PGPASSWORD":"`+capability+`"},"secretMaterial":{}}`), &connection); err != nil {
		t.Fatal(err)
	}
	if value, ok := connection.AgentEnv.Get("PGPASSWORD"); !ok || value != capability {
		t.Fatal("explicit AgentEnvironment access failed")
	}
	formatted := fmt.Sprintf("%+v %#v", connection, connection)
	encoded, err := json.Marshal(connection)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(formatted, capability) || bytes.Contains(encoded, []byte(capability)) {
		t.Fatalf("Agent environment leaked session capability: %s %s", formatted, encoded)
	}
}
