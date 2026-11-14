package agentsdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Each new action type is forwarded untouched under its own request kind;
// only the few members the contract checks locally are looked at.
func TestAccessAndContextActionsHaveLocalChecksAndStayOpaqueOtherwise(t *testing.T) {
	accepted := map[string]struct {
		kind   RequestKind
		action string
	}{
		"allow by match":           {RequestAccessChange, `{"type":"agent_grant.allow","version":1,"connectionId":"connection-1","allow":{"match":{"methods":["DELETE"],"path":"/repos/acme/x"}},"blockedCall":{"method":"DELETE","host":"api.github.com","path":"/repos/acme/x","class":"delete"}}`},
		"allow by class":           {RequestAccessChange, `{"type":"agent_grant.allow","version":1,"connectionId":"connection-1","allow":{"class":"delete"}}`},
		"allow with later members": {RequestAccessChange, `{"type":"agent_grant.allow","version":1,"connectionId":"connection-1","allow":{"class":"delete"},"blockedCall":{"anything":["at","all"]},"reviewers":["ops"]}`},
		"renew":                    {RequestAccessChange, `{"type":"agent_grant.renew","version":1,"connectionId":"connection-1"}`},
		"context update":           {RequestContextUpdate, `{"type":"agent_workflow.context_update","version":1,"markdown":"# Deploys\n\nUse the staging account first."}`},
		"empty context":            {RequestContextUpdate, `{"type":"agent_workflow.context_update","version":1,"markdown":""}`},
		"context at the size cap":  {RequestContextUpdate, `{"type":"agent_workflow.context_update","version":1,"markdown":"` + strings.Repeat("é", MaxWorkflowContextLength) + `"}`},
		"create from a preset":     {RequestSetup, `{"type":"agent_connection.create","version":1,"serviceType":"http","name":"GitHub","preset":"github"}`},
		"preset with hosts":        {RequestSetup, `{"type":"agent_connection.create","version":1,"serviceType":"http","name":"GitLab","preset":"gitlab","hosts":[{"match":"exact","value":"gitlab.example.com","port":443}]}`},
	}
	for name, test := range accepted {
		if err := ValidateRequestAction(test.kind, json.RawMessage(test.action)); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	refused := map[string]struct {
		kind   RequestKind
		action string
	}{
		"allow naming the secret guard's class": {RequestAccessChange, `{"type":"agent_grant.allow","version":1,"connectionId":"connection-1","allow":{"class":"credential_minting"}}`},
		"allow with class and match":            {RequestAccessChange, `{"type":"agent_grant.allow","version":1,"connectionId":"connection-1","allow":{"class":"delete","match":{"methods":["DELETE"]}}}`},
		"allow with neither":                    {RequestAccessChange, `{"type":"agent_grant.allow","version":1,"connectionId":"connection-1","allow":{}}`},
		"allow missing":                         {RequestAccessChange, `{"type":"agent_grant.allow","version":1,"connectionId":"connection-1"}`},
		"allow is text":                         {RequestAccessChange, `{"type":"agent_grant.allow","version":1,"connectionId":"connection-1","allow":"delete"}`},
		"allow class is not text":               {RequestAccessChange, `{"type":"agent_grant.allow","version":1,"connectionId":"connection-1","allow":{"class":7}}`},
		"allow under setup":                     {RequestSetup, `{"type":"agent_grant.allow","version":1,"connectionId":"connection-1","allow":{"class":"delete"}}`},
		"renew under connection_update":         {RequestConnectionUpdate, `{"type":"agent_grant.renew","version":1,"connectionId":"connection-1"}`},
		"renew carrying a value":                {RequestAccessChange, `{"type":"agent_grant.renew","version":1,"connectionId":"connection-1","value":"sk-live"}`},
		"context without markdown":              {RequestContextUpdate, `{"type":"agent_workflow.context_update","version":1}`},
		"context markdown is null":              {RequestContextUpdate, `{"type":"agent_workflow.context_update","version":1,"markdown":null}`},
		"context markdown is a list":            {RequestContextUpdate, `{"type":"agent_workflow.context_update","version":1,"markdown":["# Deploys"]}`},
		"context over the size cap":             {RequestContextUpdate, `{"type":"agent_workflow.context_update","version":1,"markdown":"` + strings.Repeat("a", MaxWorkflowContextLength+1) + `"}`},
		"context under access_change":           {RequestAccessChange, `{"type":"agent_workflow.context_update","version":1,"markdown":"# Deploys"}`},
		"preset and definition":                 {RequestSetup, `{"type":"agent_connection.create","version":1,"preset":"github","definition":{"specVersion":1}}`},
		"preset is not text":                    {RequestSetup, `{"type":"agent_connection.create","version":1,"preset":{"id":"github"}}`},
		"empty preset":                          {RequestSetup, `{"type":"agent_connection.create","version":1,"preset":""}`},
		"preset is not an ID":                   {RequestSetup, `{"type":"agent_connection.create","version":1,"preset":"git hub/../x"}`},
	}
	for name, test := range refused {
		err := ValidateRequestAction(test.kind, json.RawMessage(test.action))
		if err == nil {
			t.Errorf("%s was accepted", name)
		} else if strings.Contains(err.Error(), "sk-live") || strings.Contains(err.Error(), "propos") {
			t.Errorf("%s: unsuitable error text: %v", name, err)
		}
	}
}

func TestRequestedDurationIsValidOnlyOnRequestsThatEndInAccess(t *testing.T) {
	seconds := func(value int) *int { return &value }
	for kind, valid := range map[RequestKind]bool{
		RequestSetup: true, RequestAccessChange: true,
		RequestCredentialUpdate: false, RequestConnectionUpdate: false, RequestConnectionRemoval: false, RequestContextUpdate: false,
	} {
		if !ValidRequestDuration(kind, nil) {
			t.Errorf("%s without a duration was refused", kind)
		}
		if got := ValidRequestDuration(kind, seconds(3600)); got != valid {
			t.Errorf("%s with a duration: valid = %t", kind, got)
		}
		if RequestKindEndsInAccess(kind) != valid {
			t.Errorf("%s: ends in access = %t", kind, !valid)
		}
	}
	for _, value := range []int{0, -1, -3600} {
		if ValidRequestDuration(RequestAccessChange, seconds(value)) {
			t.Errorf("a duration of %d seconds was accepted", value)
		}
	}
	// The bounds are the organisation's: the Console states them when it
	// refuses a duration, so the client forwards any positive one.
	for _, value := range []int{1, 299, 300, 86400, 2592000, 2592001} {
		if !ValidRequestDuration(RequestSetup, seconds(value)) {
			t.Errorf("a duration of %d seconds was refused before the Console saw it", value)
		}
	}
}

func TestCreateRequestForwardsEachAccessActionAndItsDuration(t *testing.T) {
	session := SessionAuth{SessionUID: "session-123", Credential: "session-credential"}
	var forwarded map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = nil
		if err := json.NewDecoder(r.Body).Decode(&forwarded); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "id": "request-1", "status": "pending", "kind": forwarded["kind"], "action": forwarded["action"]})
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, AgentAuthentication("durable-token"))
	hour := 3600
	tests := map[string]CreateRequestInput{
		"allow":           {Kind: RequestAccessChange, Title: "Allow DELETE /repos/acme/x on GitHub", DurationSeconds: &hour, Action: json.RawMessage(`{"type":"agent_grant.allow","version":1,"connectionId":"connection-1","allow":{"match":{"methods":["DELETE"],"path":"/repos/acme/x"}},"blockedCall":{"method":"DELETE","host":"api.github.com","path":"/repos/acme/x","class":"delete"}}`)},
		"renew":           {Kind: RequestAccessChange, Action: json.RawMessage(`{"type":"agent_grant.renew","version":1,"connectionId":"connection-1"}`)},
		"context update":  {Kind: RequestContextUpdate, Action: json.RawMessage(`{"type":"agent_workflow.context_update","version":1,"markdown":"# Deploys"}`)},
		"preset":          {Kind: RequestSetup, DurationSeconds: &hour, Action: json.RawMessage(`{"type":"agent_connection.create","version":1,"serviceType":"http","name":"GitHub","preset":"github"}`)},
		"packaged, timed": {Kind: RequestSetup, DurationSeconds: &hour, CredentialProvider: "github", CredentialName: "GitHub", ServiceType: "github", Markdown: "why"},
	}
	for name, input := range tests {
		created, status, err := client.CreateRequestWithStatus(context.Background(), session, input)
		if err != nil || status != http.StatusCreated {
			t.Fatalf("%s: status=%d err=%v", name, status, err)
		}
		if string(forwarded["kind"]) != `"`+string(input.Kind)+`"` {
			t.Fatalf("%s: forwarded kind = %s", name, forwarded["kind"])
		}
		if input.Action != nil {
			var want, sent, relayed any
			_ = json.Unmarshal(input.Action, &want)
			_ = json.Unmarshal(forwarded["action"], &sent)
			_ = json.Unmarshal(created.Action, &relayed)
			if !reflect.DeepEqual(want, sent) || !reflect.DeepEqual(want, relayed) {
				t.Fatalf("%s: action was changed on the way: sent=%s relayed=%s", name, forwarded["action"], created.Action)
			}
		}
		duration, present := forwarded["durationSeconds"]
		if present != (input.DurationSeconds != nil) || (present && string(duration) != "3600") {
			t.Fatalf("%s: forwarded durationSeconds = %s (present=%t)", name, duration, present)
		}
	}

	forwarded = nil
	zero, negative := 0, -60
	for name, input := range map[string]CreateRequestInput{
		"zero duration":                   {Kind: RequestAccessChange, DurationSeconds: &zero, Action: tests["renew"].Action},
		"negative duration":               {Kind: RequestAccessChange, DurationSeconds: &negative, Action: tests["renew"].Action},
		"duration on a context update":    {Kind: RequestContextUpdate, DurationSeconds: &hour, Action: tests["context update"].Action},
		"duration on a credential update": {Kind: RequestCredentialUpdate, DurationSeconds: &hour, ConnectionID: "c", CredentialID: "k", CredentialProvider: "aws", CredentialName: "AWS", Markdown: "why"},
		"allow of the guard's class":      {Kind: RequestAccessChange, Action: json.RawMessage(`{"type":"agent_grant.allow","version":1,"connectionId":"connection-1","allow":{"class":"credential_minting"}}`)},
		"access kind without an action":   {Kind: RequestAccessChange, Markdown: "please"},
		"context kind without an action":  {Kind: RequestContextUpdate, Markdown: "# Deploys"},
	} {
		if _, _, err := client.CreateRequestWithStatus(context.Background(), session, input); err == nil {
			t.Errorf("%s was sent", name)
		}
	}
	if forwarded != nil {
		t.Fatalf("a refused request reached the server: %v", forwarded)
	}
}

func TestSessionMembersForPolicyAndTimeLimitsRoundTrip(t *testing.T) {
	const payload = `{"schemaVersion":1,"sessionUid":"session-1","sessionCredential":"psx_sess_REDACTED","expiresAt":"2026-11-14T12:00:00Z",` +
		`"configGeneration":3,"configEnv":{},"connections":[{` +
		`"grantId":"grant-1","connectionId":"connection-1","credentialId":"connection-1","credentialProvider":"http","serviceType":"http","protocol":"http",` +
		`"hosts":[{"match":"exact","value":"api.example.com","port":443}],"identifiers":{},"decoyMaterial":{},"agentEnv":{},"secretMaterial":null,` +
		`"authorization":{"version":1,"mode":"connection","accessMode":"allow","state":"allowed"},` +
		`"policy":{"version":1,"default":"allow","rules":[{"class":"delete","effect":"block"},{"class":"create","effect":"ask"},` +
		`{"match":{"methods":["POST"],"path":"/v1/charges/*"},"effect":"block"}],` +
		`"temporaryAllows":[{"id":"allow-1","class":"delete","expiresAt":"2026-11-15T10:00:00Z"},` +
		`{"id":"allow-2","match":{"methods":["DELETE"],"path":"/repos/acme/x"},"expiresAt":"2026-11-15T11:00:00Z"}],` +
		`"managed":[{"id":"secret_guard","locked":true,"rules":[{"class":"credential_minting","effect":"block"}]}]},` +
		`"operationClasses":[{"match":{"methods":["POST"],"path":"/graphql"},"class":"read"}],` +
		`"grantExpiresAt":"2026-11-15T10:00:00Z"}],` +
		`"expiredConnections":[{"connectionId":"connection-old","connectionName":"Staging AWS","serviceType":"aws","expiredAt":"2026-11-13T10:00:00Z"}]}`
	var response OpenSessionResponse
	if err := json.Unmarshal([]byte(payload), &response); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, []byte(payload), encoded)
	connection := response.Connections[0]
	if connection.Policy == nil || connection.Policy.Default != PolicyAllow || len(connection.Policy.Rules) != 3 ||
		connection.Policy.Rules[0].Class != ClassDelete || connection.Policy.Rules[0].Effect != PolicyBlock ||
		connection.Policy.Rules[2].Match.Path != "/v1/charges/*" || len(connection.Policy.TemporaryAllows) != 2 ||
		connection.Policy.Managed[0].ID != "secret_guard" || connection.Policy.Managed[0].Rules[0].Class != ClassCredentialMinting ||
		connection.OperationClasses[0].Class != ClassRead || len(response.ExpiredConnections) != 1 {
		t.Fatalf("decoded members = %+v", connection)
	}
	expiry := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	if !connection.AllowsUse(expiry.Add(-time.Second)) || connection.AllowsUse(expiry) {
		t.Fatal("the grant's time limit does not decide whether the Connection may be used")
	}

	features, err := json.Marshal(ClientCapabilities{Features: []ClientFeature{FeatureAccessPolicy}})
	if err != nil || !strings.Contains(string(features), `"features":["access_policy"]`) {
		t.Fatalf("features = %s err=%v", features, err)
	}
}
