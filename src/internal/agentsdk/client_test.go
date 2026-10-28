package agentsdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/golang-sdk/v2/phase/network"
)

func TestClientRoutesStatusesAndDualAuthentication(t *testing.T) {
	openResponse := readFixture(t, "open_session_response.json")
	discoverResponse := readFixture(t, "discover_response.json")
	refreshResponse := readFixture(t, "refresh_session_response.json")
	events := fixtureRoundTrip[EventBatch](t, "events_request.json")

	const durableToken = "durable-token"
	const mintedSecret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const mintedFullToken = "pss_agent:v2:" + mintedSecret + ":" + mintedSecret + ":" + mintedSecret + ":" + mintedSecret
	const sessionCredential = "session-credential"
	session := SessionAuth{SessionUID: "session-123", Credential: SensitiveString(sessionCredential)}

	var mu sync.Mutex
	hits := make(map[string]int)
	sessionPaths := map[string]bool{
		"GET /v1/agents/sessions/session-123/config/":   true,
		"GET /v1/agents/sessions/session-123/context/":  true,
		"GET /v1/agents/sessions/session-123/discover/": true,
		"POST /v1/agents/sessions/session-123/rotate/":  true,
		"POST /v1/agents/sessions/session-123/revoke/":  true,
		"POST /v1/agents/requests/":                     true,
		"GET /v1/agents/requests/request-123/":          true,
		"POST /v1/agents/sessions/session-123/events/":  true,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		mu.Lock()
		hits[key]++
		mu.Unlock()

		if got := r.Header.Get("Authorization"); got != "Bearer Agent "+durableToken {
			t.Errorf("%s Authorization = %q", key, got)
		}
		if got := r.Header.Get(camelCaseHeader); got != "true" {
			t.Errorf("%s %s = %q", key, camelCaseHeader, got)
		}
		if got := r.Header.Get("User-Agent"); got != "agents-test/1" {
			t.Errorf("%s User-Agent = %q, want %q", key, got, "agents-test/1")
		}
		if sessionPaths[key] {
			if got := r.Header.Get(SessionCredentialHeader); got != sessionCredential {
				t.Errorf("%s session credential = %q", key, got)
			}
		} else if got := r.Header.Get(SessionCredentialHeader); got != "" {
			t.Errorf("%s unexpectedly sent session credential", key)
		}

		w.Header().Set("Content-Type", "application/json")
		switch key {
		case "POST /v1/agents/sessions/":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(openResponse)
		case "GET /v1/agents/sessions/session-123/config/":
			_, _ = w.Write(refreshResponse)
		case "GET /v1/agents/sessions/session-123/context/":
			_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"session-123","markdown":"Use the proxy."}`))
		case "GET /v1/agents/sessions/session-123/discover/":
			_, _ = w.Write(discoverResponse)
		case "POST /v1/agents/sessions/session-123/rotate/":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"session-123","sessionCredential":"rotated-session-credential"}`))
		case "POST /v1/agents/sessions/session-123/revoke/":
			w.WriteHeader(http.StatusNoContent)
		case "POST /v1/agents/requests/":
			var rawBody map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&rawBody); err != nil {
				t.Errorf("decode create request body: %v", err)
			}
			if _, exists := rawBody["sessionUid"]; exists {
				t.Error("create request must derive the session from authentication, not send sessionUid")
			}
			bodyBytes, err := json.Marshal(rawBody)
			if err != nil {
				t.Errorf("encode create request body: %v", err)
			}
			var body CreateRequestInput
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				t.Errorf("decode typed create request body: %v", err)
			}
			if body.Kind != RequestCredentialUpdate || body.ConnectionID != "connection-aws" || body.CredentialID != "credential-aws" ||
				body.CredentialProvider != "aws" || body.CredentialName != "Production AWS" || body.Markdown != "Update AWS permissions" {
				t.Errorf("create request body = %+v", body)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"id":"request-123","status":"pending"}`))
		case "GET /v1/agents/requests/request-123/":
			if r.URL.RawQuery != "" {
				t.Errorf("poll request unexpectedly sent query parameters: %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"id":"request-123","kind":"credential_update","grantId":"grant-aws","connectionId":"connection-aws","credentialId":"credential-aws","credentialProvider":"aws","credentialName":"Production AWS","status":"approved","cooldown":true,"resolutionNote":"AWS credential updated.","requestExpiresAt":"2026-07-19T08:00:00Z","runtimeAction":"retry"}`))
		case "POST /v1/agents/sessions/session-123/events/":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"session-123","accepted":1,"duplicates":0,"batchId":"batch-01J00000000000000000000000"}`))
		case "POST /v1/agents/agent-123/tokens/":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"token-123","agentId":"agent-123","workflowId":"workflow-123","name":"CI","fullToken":"` + mintedFullToken + `","bearerToken":"Agent ` + mintedSecret + `"}`))
		default:
			http.Error(w, "unexpected route", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AgentAuthentication(durableToken))
	ctx := context.Background()

	opened, err := client.OpenSession(ctx, OpenSessionRequest{WorkflowID: "workflow-123", Client: ClientCapabilities{Name: "test"}})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if opened.SessionUID != session.SessionUID {
		t.Fatalf("OpenSession UID = %q", opened.SessionUID)
	}
	if _, err := client.RefreshConfig(ctx, session); err != nil {
		t.Fatalf("RefreshConfig: %v", err)
	}
	contextResponse, err := client.Context(ctx, session)
	if err != nil || contextResponse.Markdown != "Use the proxy." {
		t.Fatalf("Context = %+v, %v", contextResponse, err)
	}
	if _, err := client.Discover(ctx, session); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	rotated, err := client.RotateSession(ctx, session)
	if err != nil || rotated.SessionCredential.Reveal() != "rotated-session-credential" {
		t.Fatalf("RotateSession = %+v, %v", rotated, err)
	}
	if err := client.RevokeSession(ctx, session); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	created, createStatus, err := client.CreateRequestWithStatus(ctx, session, CreateRequestInput{
		Kind: RequestCredentialUpdate, ConnectionID: "connection-aws", CredentialID: "credential-aws",
		CredentialProvider: "aws", CredentialName: "Production AWS", Markdown: "Update AWS permissions",
	})
	if err != nil || createStatus != http.StatusAccepted || created.Status != RequestPending {
		t.Fatalf("CreateRequestWithStatus = %+v, %d, %v", created, createStatus, err)
	}
	polled, err := client.PollRequest(ctx, session, "request-123")
	if err != nil || polled.Status != RequestApproved || !polled.Cooldown || polled.ResolutionNote != "AWS credential updated." {
		t.Fatalf("PollRequest = %+v, %v", polled, err)
	}
	shipped, err := client.ShipEvents(ctx, session, events)
	if err != nil || shipped.Accepted != 1 || shipped.Duplicates != 0 {
		t.Fatalf("ShipEvents = %+v, %v", shipped, err)
	}
	minted, err := client.MintAgentToken(ctx, "agent-123", MintAgentTokenRequest{WorkflowID: "workflow-123", Name: "CI"})
	if err != nil || minted.FullToken.Reveal() != mintedFullToken || minted.BearerToken.Reveal() != "Agent "+mintedSecret {
		t.Fatalf("MintAgentToken = %+v, %v", minted, err)
	}
	mintedAuthentication, err := minted.Authentication()
	if err != nil || mintedAuthentication.Type != AuthenticationAgent || mintedAuthentication.Token.Reveal() != mintedSecret {
		t.Fatalf("MintAgentToken Authentication = %+v, %v", mintedAuthentication, err)
	}

	wantRoutes := []string{
		"POST /v1/agents/sessions/",
		"GET /v1/agents/sessions/session-123/config/",
		"GET /v1/agents/sessions/session-123/context/",
		"GET /v1/agents/sessions/session-123/discover/",
		"POST /v1/agents/sessions/session-123/rotate/",
		"POST /v1/agents/sessions/session-123/revoke/",
		"POST /v1/agents/requests/",
		"GET /v1/agents/requests/request-123/",
		"POST /v1/agents/sessions/session-123/events/",
		"POST /v1/agents/agent-123/tokens/",
	}
	mu.Lock()
	defer mu.Unlock()
	for _, route := range wantRoutes {
		if hits[route] != 1 {
			t.Errorf("route %s hit %d times, want 1", route, hits[route])
		}
	}
}

func TestClientDefaultsToSharedSDKUserAgent(t *testing.T) {
	previous := network.GetUserAgent()
	network.SetUserAgent("shared-sdk-test/1")
	t.Cleanup(func() { network.SetUserAgent(previous) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "shared-sdk-test/1" {
			t.Errorf("User-Agent = %q, want %q", got, "shared-sdk-test/1")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"session-123","sessionCredential":"session-secret","expiresAt":"2026-07-12T10:00:00Z","configGeneration":1,"configEnv":{},"connections":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:        server.URL,
		Authentication: AgentAuthentication("durable-token"),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.OpenSession(context.Background(), OpenSessionRequest{Client: ClientCapabilities{Name: "test"}}); err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
}

func TestClientExplicitUserAgentOverridesSharedDefault(t *testing.T) {
	previous := network.GetUserAgent()
	network.SetUserAgent("shared-sdk-test/1")
	t.Cleanup(func() { network.SetUserAgent(previous) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "explicit-agent-client/2" {
			t.Errorf("User-Agent = %q, want %q", got, "explicit-agent-client/2")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"session-123","sessionCredential":"session-secret","expiresAt":"2026-07-12T10:00:00Z","configGeneration":1,"configEnv":{},"connections":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:        server.URL,
		Authentication: AgentAuthentication("durable-token"),
		UserAgent:      "explicit-agent-client/2",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.OpenSession(context.Background(), OpenSessionRequest{Client: ClientCapabilities{Name: "test"}}); err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
}

func TestCreateCredentialUpdateRequiresIdentityAndJustification(t *testing.T) {
	client := &Client{}
	session := SessionAuth{SessionUID: "session-123", Credential: "session-credential"}
	if _, err := client.CreateRequest(context.Background(), session, CreateRequestInput{
		Kind: RequestCredentialUpdate, ConnectionID: "connection-123", CredentialID: "credential-123",
		CredentialProvider: "aws", CredentialName: "Production AWS",
	}); err == nil || !strings.Contains(err.Error(), "justification") {
		t.Fatalf("missing justification error = %v", err)
	}
	if _, err := client.CreateRequest(context.Background(), session, CreateRequestInput{
		Kind: RequestCredentialUpdate, CredentialProvider: "aws", CredentialName: "Production AWS", Markdown: "Update permissions",
	}); err == nil || !strings.Contains(err.Error(), "connection and credential IDs") {
		t.Fatalf("missing target error = %v", err)
	}
	if _, err := client.CreateRequest(context.Background(), session, CreateRequestInput{
		Kind: RequestKind("future"), CredentialProvider: "aws", CredentialName: "Production AWS", Markdown: "Update permissions",
	}); err == nil || !strings.Contains(err.Error(), "request kind") {
		t.Fatalf("unknown kind error = %v", err)
	}
	if _, err := client.CreateRequest(context.Background(), session, CreateRequestInput{
		Kind: RequestCredentialUpdate, ConnectionID: "connection-123", CredentialID: "credential-123",
		CredentialProvider: "aws", CredentialName: "Production AWS", ServiceType: "aws", Markdown: "Update permissions",
	}); err == nil || !strings.Contains(err.Error(), "service type") {
		t.Fatalf("unexpected service type error = %v", err)
	}
}

func TestCreateSetupRequestRequiresProviderNameAndService(t *testing.T) {
	client := &Client{}
	session := SessionAuth{SessionUID: "session-123", Credential: "session-credential"}
	if _, err := client.CreateRequest(context.Background(), session, CreateRequestInput{
		Kind: RequestSetup, CredentialName: "Production GitHub", ServiceType: "github", Markdown: "Need a deployment credential",
	}); err == nil || !strings.Contains(err.Error(), "credential provider") {
		t.Fatalf("missing credential provider error = %v", err)
	}
	if _, err := client.CreateRequest(context.Background(), session, CreateRequestInput{
		Kind: RequestSetup, CredentialProvider: "github", ServiceType: "github", Markdown: "Need a deployment credential",
	}); err == nil || !strings.Contains(err.Error(), "credential name") {
		t.Fatalf("missing credential name error = %v", err)
	}
	for _, serviceType := range []string{"bad service", "bad/service", strings.Repeat("a", 65), "d\u00e9ploy"} {
		if _, err := client.CreateRequest(context.Background(), session, CreateRequestInput{
			Kind: RequestSetup, CredentialProvider: "github", CredentialName: "Production GitHub",
			ServiceType: serviceType, Markdown: "Need a deployment credential",
		}); err == nil || !strings.Contains(err.Error(), "service type") {
			t.Errorf("invalid service type %q error = %v", serviceType, err)
		}
	}
	if _, err := client.CreateRequest(context.Background(), session, CreateRequestInput{
		Kind: RequestSetup, CredentialProvider: "github", CredentialName: "Production GitHub", ServiceType: "github",
		ConnectionID: "connection-123", Markdown: "Need a deployment credential",
	}); err == nil || !strings.Contains(err.Error(), "connection and credential IDs") {
		t.Fatalf("unexpected connection error = %v", err)
	}
}

func TestCredentialRequestEndpointsPreserveStatusAndFulfillmentContract(t *testing.T) {
	const approvalURL = "https://console.example/phase/agents/requests?request=request-credential&action=setup"
	session := SessionAuth{SessionUID: "session-123", Credential: "session-credential"}
	var creates atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "agents-test/1" {
			t.Errorf("%s %s User-Agent = %q", r.Method, r.URL.Path, got)
		}
		if got := r.Header.Get(SessionCredentialHeader); got != session.Credential.Reveal() {
			t.Errorf("%s %s session credential = %q", r.Method, r.URL.Path, got)
		}
		w.Header().Set("Content-Type", "application/json")

		switch r.Method + " " + r.URL.Path {
		case "POST /v1/agents/requests/":
			var input CreateRequestInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Errorf("decode request: %v", err)
			}
			if input.SchemaVersion != CurrentSchemaVersion || input.Kind != RequestSetup ||
				input.CredentialProvider != "aws" || input.CredentialName != "AWS - EC2, RDS, S3 full access" || input.ServiceType != "aws" ||
				input.Markdown != "Need AWS credentials" {
				t.Errorf("credential request = %+v", input)
			}
			status := http.StatusCreated
			cooldown := ""
			if creates.Add(1) > 1 {
				status = http.StatusOK
				cooldown = `,"cooldown":true`
			}
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, `{"schemaVersion":1,"id":"request-credential","status":"pending","kind":"setup","credentialProvider":"aws","credentialName":"AWS - EC2, RDS, S3 full access","serviceType":"aws","approvalUrl":%q%s}`, approvalURL, cooldown)
		case "GET /v1/agents/requests/request-credential/":
			_, _ = fmt.Fprintf(w, `{"schemaVersion":1,"id":"request-credential","status":"approved","kind":"setup","credentialProvider":"aws","credentialName":"AWS - EC2, RDS, S3 full access","serviceType":"aws","credentialId":"credential-aws","connectionId":"connection-aws","grantId":"grant-aws","approvalUrl":%q,"runtimeAction":"restart_required"}`, approvalURL)
		default:
			http.Error(w, "unexpected route", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AgentAuthentication("durable-token"))
	input := CreateRequestInput{
		Kind: RequestSetup, CredentialProvider: "aws", CredentialName: "AWS - EC2, RDS, S3 full access",
		ServiceType: "aws", Markdown: "Need AWS credentials", DedupKey: "aws-credential",
	}
	created, statusCode, err := client.CreateRequestWithStatus(context.Background(), session, input)
	if err != nil || statusCode != http.StatusCreated || created.ApprovalURL != approvalURL {
		t.Fatalf("created request = %+v, status=%d, err=%v", created, statusCode, err)
	}
	deduplicated, statusCode, err := client.CreateRequestWithStatus(context.Background(), session, input)
	if err != nil || statusCode != http.StatusOK || !deduplicated.Cooldown {
		t.Fatalf("deduplicated request = %+v, status=%d, err=%v", deduplicated, statusCode, err)
	}
	fulfilled, err := client.PollRequest(context.Background(), session, "request-credential")
	if err != nil {
		t.Fatalf("PollRequest: %v", err)
	}
	if fulfilled.SchemaVersion != CurrentSchemaVersion || fulfilled.CredentialID != "credential-aws" ||
		fulfilled.ConnectionID != "connection-aws" || fulfilled.GrantID != "grant-aws" ||
		fulfilled.RuntimeAction != RequestRuntimeActionRestartRequired {
		t.Fatalf("fulfilled request = %+v", fulfilled)
	}
}

func TestClientReturnsTypedCanonicalAPIError(t *testing.T) {
	errorBody := readFixture(t, "error_response.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.Header().Set("X-Request-ID", "request-id-123")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write(errorBody)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AgentAuthentication("durable-token"))
	_, err := client.RefreshConfig(context.Background(), SessionAuth{SessionUID: "session-123", Credential: "session-secret"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %T %v, want *APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusConflict || apiErr.Code != "agent_session_revoked" || apiErr.Retryable {
		t.Fatalf("APIError = %+v", apiErr)
	}
	if apiErr.RetryAfter != 7*time.Second || apiErr.RequestID != "request-id-123" {
		t.Fatalf("APIError retry metadata = %+v", apiErr)
	}
}

func TestClientSupportsPrincipalBearerHeaders(t *testing.T) {
	tests := []struct {
		name string
		auth Authentication
		want string
	}{
		{name: "user", auth: UserAuthentication("user-token"), want: "Bearer User user-token"},
		{name: "service account", auth: ServiceAccountAuthentication("sa-token"), want: "Bearer ServiceAccount sa-token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != tt.want {
					t.Errorf("Authorization = %q, want %q", got, tt.want)
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"session-123","sessionCredential":"session-secret","expiresAt":"2026-07-12T10:00:00Z","configGeneration":1,"configEnv":{},"connections":[]}`))
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, tt.auth)
			if _, err := client.OpenSession(context.Background(), OpenSessionRequest{Client: ClientCapabilities{Name: "test"}}); err != nil {
				t.Fatalf("OpenSession: %v", err)
			}
		})
	}
}

func TestCapabilitiesAndServiceContextUseSessionContract(t *testing.T) {
	session := SessionAuth{SessionUID: "session-123", Credential: "session-credential"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(SessionCredentialHeader); got != session.Credential.Reveal() {
			t.Errorf("session credential = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/agents/sessions/session-123/capabilities/":
			_, _ = io.WriteString(w, `{"schemaVersion":1,"matcherSchemaVersion":1,"kind":"phase.ai.capabilities","sessionUid":"session-123","services":[{"serviceType":"aws","displayName":"Amazon Web Services","credentialProviders":["aws"],"clientMatchers":[{"kind":"executable","values":["aws"]}],"connectionIds":["connection-123"]}]}`)
		case "/v1/agents/sessions/session-123/context/":
			if got := r.URL.Query().Get("serviceType"); got != "aws" {
				t.Errorf("serviceType = %q", got)
			}
			_, _ = io.WriteString(w, `{"schemaVersion":1,"sessionUid":"session-123","serviceType":"aws","markdown":"AWS context"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AgentAuthentication("durable-token"))
	capabilities, err := client.Capabilities(context.Background(), session)
	if err != nil || capabilities.Kind != "phase.ai.capabilities" || len(capabilities.Services) != 1 || capabilities.Services[0].ClientMatchers[0].Values[0] != "aws" {
		t.Fatalf("Capabilities = %+v, err=%v", capabilities, err)
	}
	if err := capabilities.Validate(); err != nil {
		t.Fatalf("Capabilities.Validate: %v", err)
	}
	contextResponse, err := client.ContextForService(context.Background(), session, "AWS")
	if err != nil || contextResponse.ServiceType != "aws" || contextResponse.Markdown != "AWS context" {
		t.Fatalf("ContextForService = %+v, err=%v", contextResponse, err)
	}
	if _, err := client.ContextForService(context.Background(), session, "bad/service"); err == nil {
		t.Fatal("ContextForService accepted an invalid service type")
	}
}

func TestContextForServiceRejectsMismatchedResponseScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"schemaVersion":1,"sessionUid":"session-123","serviceType":"postgres","markdown":"wrong context"}`)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AgentAuthentication("durable-token"))
	_, err := client.ContextForService(
		context.Background(),
		SessionAuth{SessionUID: "session-123", Credential: "session-credential"},
		"aws",
	)
	if err == nil {
		t.Fatal("ContextForService accepted context for a different service")
	}
}

func TestCapabilitiesValidationRejectsExecutablePathsAndRegex(t *testing.T) {
	base := CapabilitiesResponse{
		SchemaVersion:        CurrentSchemaVersion,
		MatcherSchemaVersion: ClientMatcherSchemaVersion,
		Kind:                 "phase.ai.capabilities",
		SessionUID:           "session-123",
		Services: []CapabilityService{{
			ServiceType:         "aws",
			DisplayName:         "Amazon Web Services",
			CredentialProviders: []string{"aws"},
			ClientMatchers:      []ClientMatcher{{Kind: ClientMatcherExecutable, Values: []string{"aws"}}},
		}},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid capabilities rejected: %v", err)
	}
	for _, invalid := range []string{"/usr/bin/aws", "aws.*", "AWS", "aws command", "aws.exe", strings.Repeat("a", 65)} {
		candidate := base
		candidate.Services = append([]CapabilityService(nil), base.Services...)
		candidate.Services[0].ClientMatchers = []ClientMatcher{{Kind: ClientMatcherExecutable, Values: []string{invalid}}}
		if err := candidate.Validate(); err == nil {
			t.Fatalf("accepted unsafe matcher %q", invalid)
		}
	}
}

func TestCapabilitiesValidationMirrorsRegistryCollectionInvariants(t *testing.T) {
	base := CapabilitiesResponse{
		SchemaVersion:        CurrentSchemaVersion,
		MatcherSchemaVersion: ClientMatcherSchemaVersion,
		Kind:                 "phase.ai.capabilities",
		SessionUID:           "session-123",
		Services: []CapabilityService{{
			ServiceType:         "postgres",
			DisplayName:         "PostgreSQL",
			CredentialProviders: []string{"postgres"},
			ClientMatchers: []ClientMatcher{
				{Kind: ClientMatcherExecutable, Values: []string{"psql"}},
				{Kind: ClientMatcherURIScheme, Values: []string{"postgres"}},
			},
			ConnectionIDs: []string{"connection-1"},
		}},
	}
	mutations := []func(*CapabilitiesResponse){
		func(value *CapabilitiesResponse) { value.Services[0].CredentialProviders = nil },
		func(value *CapabilitiesResponse) { value.Services[0].ClientMatchers = nil },
		func(value *CapabilitiesResponse) {
			value.Services[0].CredentialProviders = []string{"postgres", "postgres"}
		},
		func(value *CapabilitiesResponse) {
			value.Services[0].ClientMatchers = []ClientMatcher{{Kind: ClientMatcherExecutable, Values: []string{"psql"}}, {Kind: ClientMatcherExecutable, Values: []string{"pg_dump"}}}
		},
		func(value *CapabilitiesResponse) {
			value.Services[0].ConnectionIDs = []string{"connection-1", "connection-1"}
		},
		func(value *CapabilitiesResponse) {
			value.Services[0].ClientMatchers = []ClientMatcher{{Kind: ClientMatcherURIScheme, Values: []string{"1postgres"}}}
		},
		func(value *CapabilitiesResponse) {
			value.Services[0].ClientMatchers = []ClientMatcher{{Kind: ClientMatcherURIScheme, Values: []string{strings.Repeat("p", 65)}}}
		},
	}
	for index, mutate := range mutations {
		candidate := base
		candidate.Services = append([]CapabilityService(nil), base.Services...)
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("mutation %d was accepted", index)
		}
	}
}

func TestClientDoesNotIncludeRawErrorBody(t *testing.T) {
	const sentinel = "LIVE_SECRET_MUST_NOT_APPEAR"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream debug dump " + sentinel))
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, AgentAuthentication("durable-token"))
	_, err := client.OpenSession(context.Background(), OpenSessionRequest{Client: ClientCapabilities{Name: "test"}})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(fmt.Sprintf("%+v", err), sentinel) {
		t.Fatalf("error leaked raw body: %v", err)
	}
}

func TestClientNeverFollowsRedirects(t *testing.T) {
	var targetHit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	client := newTestClient(t, origin.URL, AgentAuthentication("durable-token"))
	_, err := client.OpenSession(context.Background(), OpenSessionRequest{Client: ClientCapabilities{Name: "test"}})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect error = %T %v", err, err)
	}
	if targetHit.Load() {
		t.Fatal("redirect target was reached")
	}
}

func TestAuthenticationFromPhaseToken(t *testing.T) {
	lookup := strings.Repeat("a", 64)
	fullParts := []string{lookup, strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)}
	tests := []struct {
		kind  AuthenticationType
		token string
	}{
		{kind: AuthenticationAgent, token: "pss_agent:v2:" + strings.Join(fullParts, ":")},
		{kind: AuthenticationUser, token: "pss_user:v1:" + strings.Join(fullParts, ":")},
		{kind: AuthenticationServiceAccount, token: "pss_service:v2:" + strings.Join(fullParts, ":")},
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			auth, err := AuthenticationFromPhaseToken(tt.token)
			if err != nil {
				t.Fatalf("AuthenticationFromPhaseToken: %v", err)
			}
			if auth.Type != tt.kind || auth.Token.Reveal() != lookup {
				t.Fatalf("auth = %+v", auth)
			}
		})
	}
	if _, err := AuthenticationFromPhaseToken("pss_agent:v2:bad"); err == nil {
		t.Fatal("expected malformed token error")
	}
	if _, err := AuthenticationFromPhaseToken("pss_agent:v1:" + lookup); err == nil {
		t.Fatal("expected unsupported Agent token version error")
	}
	if _, err := AuthenticationFromPhaseToken("pss_agent:v2:" + lookup); err == nil {
		t.Fatal("expected Agent token without key shares to be rejected")
	}
	if _, err := AuthenticationFromPhaseToken("pss_user:v2:" + strings.Join(fullParts, ":")); err == nil {
		t.Fatal("expected unsupported PAT version error")
	}
}

func TestNewClientRejectsCredentialWhitespaceAndUnsafeBaseURL(t *testing.T) {
	tests := []ClientConfig{
		{BaseURL: "https://user:pass@example.com", Authentication: AgentAuthentication("token")},
		{BaseURL: "ftp://example.com", Authentication: AgentAuthentication("token")},
		{BaseURL: "http://api.example.com", Authentication: AgentAuthentication("token")},
		{BaseURL: "https://example.com?debug=1", Authentication: AgentAuthentication("token")},
		{BaseURL: "https://example.com", Authentication: AgentAuthentication("token\nInjected: value")},
	}
	for _, config := range tests {
		if _, err := NewClient(config); err == nil {
			t.Fatalf("NewClient(%q) unexpectedly succeeded", config.BaseURL)
		}
	}
}

func TestNewClientAllowsHTTPOnlyForLoopback(t *testing.T) {
	for _, baseURL := range []string{"http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"} {
		if _, err := NewClient(ClientConfig{
			BaseURL: baseURL, Authentication: AgentAuthentication("token"),
		}); err != nil {
			t.Fatalf("NewClient(%q): %v", baseURL, err)
		}
	}
}

func newTestClient(t *testing.T, baseURL string, authentication Authentication) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{
		BaseURL:        baseURL,
		HTTPClient:     &http.Client{Timeout: 2 * time.Second},
		Authentication: authentication,
		UserAgent:      "agents-test/1",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}
