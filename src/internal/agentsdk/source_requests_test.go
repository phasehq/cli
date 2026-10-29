package agentsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSetupRequestsResumeAndCancelThroughAuthenticatedTransport(t *testing.T) {
	var requestCount, cancellationCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer Agent durable" || r.Header.Get(SessionCredentialHeader) != "session-capability" {
			t.Error("request did not use both authentication credentials")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/agents/requests/":
			var input CreateRequestInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.Kind != RequestSetup || input.ServiceType != "postgres" || input.CredentialProvider != "postgres" || input.CredentialName != "Reporting database" || input.RelatedRequestID != "earlier-request" {
				t.Errorf("incorrect setup request: %+v", input)
			}
			requestCount++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"schemaVersion":1,"id":"setup-1","kind":"setup","credentialProvider":"postgres","credentialName":"Reporting database","status":"pending","relatedRequestId":"earlier-request","progress":{"revision":"draft-1","stage":"selecting_credential"}}`))
		case "GET /v1/agents/requests/":
			if r.URL.Query().Get("workflow_id") != "workflow&other=value" || len(r.URL.Query()) != 1 {
				t.Errorf("workflow query was not safely encoded: %v", r.URL.Query())
			}
			_, _ = w.Write([]byte(`{"schemaVersion":1,"requests":[{"id":"setup-1","kind":"setup","credentialProvider":"postgres","credentialName":"Reporting database","markdown":"Read the reporting database","status":"pending","progress":{"revision":"draft-2","stage":"ready_for_review","credentialId":"credential-1","credentialName":"Reporting database","credentialProvider":"postgres","credentialRevision":"credential-v1","connectionId":"connection-1","grantId":"grant-1"}}]}`))
		case "POST /v1/agents/requests/setup-1/cancel/":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 0 {
				t.Errorf("cancel should carry only an empty object: %v", err)
			}
			cancellationCount++
			_, _ = w.Write([]byte(`{"schemaVersion":1,"id":"setup-1","status":"cancelled","progress":{"revision":"draft-2","stage":"ready_for_review","credentialId":"credential-1"}}`))
		default:
			t.Errorf("unexpected endpoint: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{BaseURL: server.URL, Authentication: AgentAuthentication("durable")})
	if err != nil {
		t.Fatal(err)
	}
	session := SessionAuth{SessionUID: "session-1", Credential: "session-capability"}
	created, err := client.CreateRequest(context.Background(), session, CreateRequestInput{
		Kind: RequestSetup, ServiceType: "postgres", CredentialProvider: "postgres", CredentialName: "Reporting database",
		Markdown: "Read the reporting database", RelatedRequestID: "earlier-request",
	})
	if err != nil || created.ID != "setup-1" || created.Progress == nil || created.Progress.Revision != "draft-1" {
		t.Fatalf("create: %+v, %v", created, err)
	}
	pending, err := client.ListPendingRequests(context.Background(), session, "workflow&other=value")
	if err != nil || len(pending.Requests) != 1 || pending.Requests[0].Markdown != "Read the reporting database" ||
		pending.Requests[0].Progress.CredentialID != "credential-1" || pending.Requests[0].Progress.CredentialName != "Reporting database" ||
		pending.Requests[0].Progress.CredentialProvider != "postgres" || pending.Requests[0].Progress.CredentialRevision != "credential-v1" ||
		pending.Requests[0].Progress.ConnectionID != "connection-1" || pending.Requests[0].Progress.GrantID != "grant-1" {
		t.Fatalf("pending lookup: %+v, %v", pending, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		cancelled, err := client.CancelRequest(context.Background(), session, created.ID)
		if err != nil || cancelled.Status != RequestCancelled || cancelled.Progress.CredentialID != "credential-1" {
			t.Fatalf("cancel: %+v, %v", cancelled, err)
		}
	}
	if requestCount != 1 || cancellationCount != 2 {
		t.Fatalf("resuming or cancelling unexpectedly recreated the request: creates=%d cancels=%d", requestCount, cancellationCount)
	}
}

func TestSetupAndCredentialUpdateRequestValidation(t *testing.T) {
	var received []CreateRequestInput
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input CreateRequestInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		received = append(received, input)
		_, _ = w.Write([]byte(`{"id":"request-1","status":"pending"}`))
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{BaseURL: server.URL, Authentication: AgentAuthentication("durable")})
	if err != nil {
		t.Fatal(err)
	}
	session := SessionAuth{SessionUID: "session-1", Credential: "session-capability"}
	valid := []CreateRequestInput{
		{Kind: RequestSetup, ServiceType: "aws", CredentialProvider: "aws", CredentialName: "AWS - EC2, RDS, S3 full access", Markdown: "Set up deployment access"},
		{Kind: RequestCredentialUpdate, ConnectionID: "connection-1", CredentialID: "credential-1", CredentialProvider: "aws", CredentialName: "AWS - EC2, RDS, S3 full access", RelatedRequestID: "setup-1", Markdown: "Update AWS permissions"},
	}
	for _, input := range valid {
		if _, err := client.CreateRequest(context.Background(), session, input); err != nil {
			t.Fatalf("valid %s request rejected: %v", input.Kind, err)
		}
	}
	invalid := []CreateRequestInput{
		{Kind: RequestSetup, ServiceType: "aws", CredentialProvider: "aws", Markdown: "Missing credential name"},
		{Kind: RequestCredentialUpdate, ConnectionID: "connection-1", CredentialProvider: "aws", CredentialName: "AWS", Markdown: "Missing credential ID"},
		{Kind: RequestCredentialUpdate, CredentialID: "credential-1", CredentialProvider: "aws", CredentialName: "AWS", Markdown: "Missing Connection"},
		{Kind: RequestSetup, ServiceType: "aws", ConnectionID: "connection-1", CredentialProvider: "aws", CredentialName: "AWS", Markdown: "Unexpected Connection"},
		{Kind: RequestSetup, ServiceType: "aws", CredentialProvider: "aws/provider", CredentialName: "AWS", Markdown: "Invalid provider"},
	}
	for _, input := range invalid {
		if _, err := client.CreateRequest(context.Background(), session, input); err == nil {
			t.Fatalf("invalid %s request was transmitted", input.Kind)
		}
	}
	if len(received) != len(valid) || received[1].CredentialName != "AWS - EC2, RDS, S3 full access" {
		t.Fatalf("invalid requests reached transport or credential name was lost: %+v", received)
	}
	if _, err := client.CancelRequest(context.Background(), session, " "); err == nil {
		t.Fatal("empty cancellation ID accepted")
	}
	if _, err := client.ListPendingRequests(context.Background(), SessionAuth{}, ""); err == nil {
		t.Fatal("pending requests accepted without session authentication")
	}
}

func TestCredentialMetadataDoesNotExposeProducerCapabilitiesThroughDiscovery(t *testing.T) {
	raw := []byte(`{"connectionId":"connection-1","credentialId":"credential-1","credentialName":"AWS production","credentialProvider":"aws","credentialRevision":"credential-v2","materialGeneration":"generation-3","credentialExpiresAt":"2026-09-08T10:00:00Z","configEnv":{"AWS_REGION":"us-east-1"},"secretMaterial":{"secretAccessKey":"live-sentinel"},"lease":{"id":"lease-sentinel","renewalToken":"renewal-sentinel"},"producerCredentials":{"password":"root-sentinel"}}`)
	var connection DiscoverConnection
	if err := json.Unmarshal(raw, &connection); err != nil {
		t.Fatal(err)
	}
	if connection.CredentialID != "credential-1" || connection.CredentialRevision != "credential-v2" || connection.MaterialGeneration != "generation-3" || connection.CredentialExpiresAt == nil || connection.ConfigEnv["AWS_REGION"] != "us-east-1" {
		t.Fatalf("credential metadata did not decode: %+v", connection)
	}
	encoded, err := json.Marshal(connection)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"live-sentinel", "lease-sentinel", "renewal-sentinel", "root-sentinel", "secretMaterial", "producerCredentials"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("discovery retained producer capability %q", forbidden)
		}
	}
}

func TestPerConnectionConfigurationKeepsSameServiceRegionsSeparate(t *testing.T) {
	binding := EnvironmentBinding{Name: "AWS_REGION", Action: EnvironmentBindingSet, Source: EnvironmentSourceConnectionConfig, SourceField: "region"}
	for _, region := range []string{"us-east-1", "eu-west-1"} {
		connection := RuntimeConnection{
			ConnectionID: region, ServiceType: "aws", ConnectionConfig: map[string]interface{}{"region": region},
			ConfigEnv: StringMap{"AWS_REGION": region}, EnvironmentBindings: []EnvironmentBinding{binding},
		}
		if err := connection.ValidateEnvironmentBindings(); err != nil {
			t.Fatalf("per-Connection region rejected: %v", err)
		}
		discovery := DiscoverConnection{ConnectionConfig: connection.ConnectionConfig, ConfigEnv: connection.ConfigEnv, EnvironmentBindings: connection.EnvironmentBindings}
		if err := discovery.ValidateEnvironmentBindings(); err != nil {
			t.Fatalf("discovery did not use its own region: %v", err)
		}
		connection.ConfigEnv = StringMap{}
		encoded, err := json.Marshal(connection)
		if err != nil {
			t.Fatal(err)
		}
		var decoded RuntimeConnection
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.ConfigEnv == nil {
			t.Fatal("explicit empty configuration was omitted during JSON serialization")
		}
		if err := decoded.ValidateEnvironmentBindings(); err == nil {
			t.Fatal("explicit empty per-Connection configuration was not authoritative")
		}
	}
}

func TestV1ConnectionsRequirePerConnectionEnvironmentContract(t *testing.T) {
	connection := RuntimeConnection{AgentEnv: AgentEnvironment{}}
	if err := connection.ValidateEnvironmentBindings(); err == nil || !strings.Contains(err.Error(), "configEnv is required") {
		t.Fatalf("missing configEnv error = %v", err)
	}

	connection.ConfigEnv = StringMap{}
	if err := connection.ValidateEnvironmentBindings(); err == nil || !strings.Contains(err.Error(), "environmentBindings is required") {
		t.Fatalf("missing environmentBindings error = %v", err)
	}
}

func TestExpiredCredentialCannotBeUsed(t *testing.T) {
	// Injection itself lives in the CLI's proxy package; the wire type only
	// has to report an expired credential as unusable at its exact expiry.
	expired := time.Now().Add(-time.Second)
	connection := RuntimeConnection{
		CredentialExpiresAt: &expired,
		Authorization:       ConnectionAuthorization{Version: CurrentSchemaVersion, Mode: AuthorizationConnection, AccessMode: ConnectionAccessAllow, State: ConnectionAuthorizationAllowed},
		Protocol:            ProtocolHTTP, Hosts: []HostRule{{Match: "exact", Value: "api.example.com"}},
		Injection:     Injection{Action: InjectionSetHeader, Name: "Authorization", ValueFormat: "Bearer {value}", ValueFrom: &CredentialValueFrom{Source: "credential", Field: "token"}},
		DecoyMaterial: DecoyMaterial{"token": "decoy-sentinel"}, SecretMaterial: SecretMaterial{"token": "live-sentinel"},
	}
	if connection.AllowsUse(expired) {
		t.Fatal("credential remained valid at its exact expiration")
	}
	if connection.AllowsUse(time.Now()) {
		t.Fatal("expired credential was still usable")
	}
	if !connection.AllowsUse(expired.Add(-time.Minute)) {
		t.Fatal("credential was unusable before its expiry")
	}
}
