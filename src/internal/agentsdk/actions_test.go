package agentsdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const proposedDefinition = `{"specVersion":1,"hosts":[{"match":"exact","value":"api.example.com","port":443,"path":"/v1/*"}],` +
	`"fields":[{"name":"token","kind":"secret","source":{"type":"sealed"},"env":"EXAMPLE_API_KEY"},{"name":"username","kind":"identifier","value":"alice"}],` +
	`"injections":[{"type":"header","name":"Authorization","prefix":"Bearer ","field":"token","whenAbsent":"attach"}],"preset":"bearer"}`

func TestRequestActionRegistryMapsEveryTypeToItsKind(t *testing.T) {
	want := map[RequestActionType]RequestKind{
		"agent_connection.create":        "setup",
		"agent_connection.update":        "connection_update",
		"agent_connection.secret_update": "credential_update",
		"agent_connection.remove":        "connection_removal",
	}
	if !reflect.DeepEqual(requestActionKinds, want) {
		t.Fatalf("action registry = %v", requestActionKinds)
	}
	for actionType, kind := range want {
		action := json.RawMessage(`{"type":"` + string(actionType) + `","version":1,"connectionId":"connection-1"}`)
		if err := ValidateRequestAction(kind, action); err != nil {
			t.Errorf("%s under %s: %v", actionType, kind, err)
		}
		for _, other := range []RequestKind{RequestSetup, RequestCredentialUpdate, RequestConnectionUpdate, RequestConnectionRemoval, "access"} {
			if other != kind && ValidateRequestAction(other, action) == nil {
				t.Errorf("%s was accepted under request kind %s", actionType, other)
			}
		}
	}
}

func TestRequestActionIsOpaqueApartFromTypeVersionAndSecrets(t *testing.T) {
	accepted := map[string]string{
		"create":                            `{"type":"agent_connection.create","version":1,"serviceType":"http","name":"Example API","definition":` + proposedDefinition + `}`,
		"members this client does not know": `{"type":"agent_connection.create","version":1,"access":{"durationSeconds":3600},"reviewers":["ops"],"definition":{"specVersion":7,"later":{"nested":[1,2,3]}}}`,
		"identifier value":                  `{"type":"agent_connection.create","version":1,"definition":{"fields":[{"name":"username","kind":"identifier","value":"alice"}]}}`,
		"host rule value":                   `{"type":"agent_connection.create","version":1,"definition":{"hosts":[{"match":"exact","value":"api.example.com"}],"fields":[]}}`,
		"no definition at all":              `{"type":"agent_connection.create","version":1}`,
	}
	for name, action := range accepted {
		if err := ValidateRequestAction(RequestSetup, json.RawMessage(action)); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	refused := map[string]string{
		"unknown type":                   `{"type":"agent_connection.rotate","version":1}`,
		"type of another case":           `{"type":"Agent_Connection.Create","version":1}`,
		"missing type":                   `{"version":1}`,
		"type is not text":               `{"type":7,"version":1}`,
		"version 2":                      `{"type":"agent_connection.create","version":2}`,
		"version 0":                      `{"type":"agent_connection.create","version":0}`,
		"missing version":                `{"type":"agent_connection.create"}`,
		"version as text":                `{"type":"agent_connection.create","version":"1"}`,
		"fractional version":             `{"type":"agent_connection.create","version":1.5}`,
		"not an object":                  `["agent_connection.create",1]`,
		"null":                           `null`,
		"empty":                          ``,
		"value on the action":            `{"type":"agent_connection.create","version":1,"value":"sk-live"}`,
		"value on a secret field":        `{"type":"agent_connection.create","version":1,"definition":{"fields":[{"name":"token","kind":"secret","value":"sk-live"}]}}`,
		"value on a field with no kind":  `{"type":"agent_connection.create","version":1,"definition":{"fields":[{"name":"token","value":"sk-live"}]}}`,
		"value on an unknown field kind": `{"type":"agent_connection.create","version":1,"definition":{"fields":[{"name":"token","kind":"password","value":"sk-live"}]}}`,
		"value inside a field's source":  `{"type":"agent_connection.create","version":1,"definition":{"fields":[{"name":"token","kind":"secret","source":{"type":"sealed","value":"sk-live"}}]}}`,
		"value nested deeper in a field": `{"type":"agent_connection.create","version":1,"definition":{"fields":[{"name":"token","kind":"secret","source":{"type":"sealed","options":[{"value":"sk-live"}]}}]}}`,
		"definition is text":             `{"type":"agent_connection.create","version":1,"definition":"token=sk-live"}`,
		"definition is null":             `{"type":"agent_connection.create","version":1,"definition":null}`,
		"fields is an object":            `{"type":"agent_connection.create","version":1,"definition":{"fields":{"token":"sk-live"}}}`,
		"a field is text":                `{"type":"agent_connection.create","version":1,"definition":{"fields":["sk-live"]}}`,
	}
	for name, action := range refused {
		err := ValidateRequestAction(RequestSetup, json.RawMessage(action))
		if err == nil {
			t.Errorf("%s was accepted", name)
		} else if strings.Contains(err.Error(), "sk-live") {
			t.Errorf("%s: the error repeats the value: %v", name, err)
		}
	}
	if NormalizeRequestAction(json.RawMessage(" null ")) != nil || NormalizeRequestAction(nil) != nil ||
		NormalizeRequestAction(json.RawMessage(`{}`)) == nil {
		t.Fatal("only an absent or null action counts as no action")
	}
}

func TestRequestTitleIsOptionalShortPlainText(t *testing.T) {
	for _, title := range []string{"", "Allow /v2 on the Example API", strings.Repeat("é", 120)} {
		if !ValidRequestTitle(title) {
			t.Errorf("title %q was refused", title)
		}
	}
	for _, title := range []string{strings.Repeat("t", 121), "two\nlines", "tab\there", " padded", "padded ", "nul\x00"} {
		if ValidRequestTitle(title) {
			t.Errorf("title %q was accepted", title)
		}
	}
}

func TestCreateRequestForwardsTitleAndActionAndRelaxesOnlyActionRequests(t *testing.T) {
	session := SessionAuth{SessionUID: "session-123", Credential: "session-credential"}
	var forwarded map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = nil
		if err := json.NewDecoder(r.Body).Decode(&forwarded); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		response := map[string]any{"schemaVersion": 1, "id": "request-1", "status": "pending", "kind": forwarded["kind"]}
		for _, member := range []string{"title", "action"} {
			if raw, present := forwarded[member]; present {
				response[member] = raw
			}
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, AgentAuthentication("durable-token"))

	update := json.RawMessage(`{"type":"agent_connection.update","version":1,"connectionId":"connection-1","definition":` + proposedDefinition + `,"access":{"durationSeconds":3600}}`)
	created, status, err := client.CreateRequestWithStatus(context.Background(), session, CreateRequestInput{
		Kind: RequestConnectionUpdate, Title: "Allow /v2 on the Example API", Markdown: "The v2 endpoints replaced v1.", Action: update,
	})
	if err != nil || status != http.StatusCreated {
		t.Fatalf("status=%d err=%v", status, err)
	}
	var wantAction, gotAction, relayedAction any
	_ = json.Unmarshal(update, &wantAction)
	_ = json.Unmarshal(forwarded["action"], &gotAction)
	_ = json.Unmarshal(created.Action, &relayedAction)
	if !reflect.DeepEqual(wantAction, gotAction) || !reflect.DeepEqual(wantAction, relayedAction) ||
		string(forwarded["title"]) != `"Allow /v2 on the Example API"` || created.Title != "Allow /v2 on the Example API" ||
		created.Kind != RequestConnectionUpdate {
		t.Fatalf("forwarded=%v created=%+v", forwarded, created)
	}
	for _, legacy := range []string{"credentialProvider", "credentialName", "serviceType", "connectionId", "credentialId"} {
		if _, present := forwarded[legacy]; present {
			t.Fatalf("an action request was sent with an empty %s", legacy)
		}
	}

	// A title and a reason are welcome but not required beside an action; the
	// reason is then sent as an empty string.
	remove := json.RawMessage(`{"type":"agent_connection.remove","version":1,"connectionId":"connection-1"}`)
	if _, _, err := client.CreateRequestWithStatus(context.Background(), session, CreateRequestInput{Kind: RequestConnectionRemoval, Action: remove}); err != nil {
		t.Fatal(err)
	}
	if string(forwarded["markdown"]) != `""` {
		t.Fatalf("markdown = %s, want an empty string", forwarded["markdown"])
	}
	if _, present := forwarded["title"]; present {
		t.Fatalf("an absent title was sent: %s", forwarded["title"])
	}

	forwarded = nil
	for name, input := range map[string]CreateRequestInput{
		"packaged request without a reason":   {Kind: RequestSetup, CredentialProvider: "github", CredentialName: "GitHub", ServiceType: "github"},
		"packaged request with a null action": {Kind: RequestSetup, CredentialProvider: "github", CredentialName: "GitHub", ServiceType: "github", Action: json.RawMessage("null")},
		"new kind without an action":          {Kind: RequestConnectionUpdate, CredentialProvider: "http", CredentialName: "Example API", ConnectionID: "connection-1", Markdown: "why"},
		"action under the wrong kind":         {Kind: RequestSetup, Action: remove, Markdown: "why"},
		"action carrying a secret":            {Kind: RequestCredentialUpdate, Markdown: "why", Action: json.RawMessage(`{"type":"agent_connection.secret_update","version":1,"connectionId":"connection-1","value":"sk-live"}`)},
		"title too long":                      {Kind: RequestConnectionRemoval, Action: remove, Title: strings.Repeat("t", 121)},
		"padded credential name":              {Kind: RequestConnectionRemoval, Action: remove, CredentialName: " Example API"},
		"invalid credential provider":         {Kind: RequestConnectionRemoval, Action: remove, CredentialProvider: "http/custom"},
	} {
		if _, _, err := client.CreateRequestWithStatus(context.Background(), session, input); err == nil {
			t.Errorf("%s was sent", name)
		}
	}
	if forwarded != nil {
		t.Fatalf("a refused request reached the server: %v", forwarded)
	}
}

func TestCustomConnectionSessionMembersRoundTrip(t *testing.T) {
	const payload = `{"schemaVersion":1,"sessionUid":"session-1","sessionCredential":"psx_sess_REDACTED","expiresAt":"2026-07-16T08:00:00Z",` +
		`"configGeneration":3,"configEnv":{},"agentKey":{"wrappedKeyShare":"feedface"},"connections":[{` +
		`"grantId":"grant-1","connectionId":"connection-1","credentialId":"connection-1","credentialProvider":"http","credentialRevision":"3",` +
		`"materialGeneration":"2.3","serviceType":"http","protocol":"http","hosts":[{"match":"exact","value":"api.example.com","port":443,"path":"/v1/*"}],` +
		`"injections":[{"action":"set_header","name":"Authorization","valueFormat":"Bearer {value}","valueFrom":{"source":"credential","field":"token"},"whenAbsent":"attach"},` +
		`{"action":"basic_auth","name":"Authorization","valueFrom":{"source":"credential","fields":{"password":"password","username":"username"}},"whenAbsent":"block"},` +
		`{"action":"set_param","name":"api_key","valueFormat":"{value}","valueFrom":{"source":"credential","field":"token"}}],` +
		`"identifiers":{"username":"alice"},"decoyMaterial":{"token":"decoy"},"agentEnv":{},"secretMaterial":null,` +
		`"sealedMaterial":{"version":1,"keyVersion":2,"publicKey":"aabb","ciphertext":"ph:v1:aa:bb","wrappedKey":"ph:v1:cc:dd"},` +
		`"authorization":{"version":1,"mode":"connection","accessMode":"allow","state":"allowed"}}]}`
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
	if len(connection.Injections) != 3 || connection.Injections[0].WhenAbsent != WhenAbsentAttach || connection.Injections[1].WhenAbsent != WhenAbsentBlock ||
		connection.Injections[2].WhenAbsent != "" || connection.Injections[1].Action != InjectionBasicAuth {
		t.Fatalf("injections = %+v", connection.Injections)
	}
	for _, injection := range connection.Injections {
		if err := injection.Validate(); err != nil {
			t.Fatalf("%s rejected: %v", injection.Action, err)
		}
	}
	if connection.SealedMaterial == nil || connection.SealedMaterial.KeyVersion != 2 || response.AgentKey == nil ||
		response.AgentKey.WrappedKeyShare.Reveal() != "feedface" {
		t.Fatalf("sealed members were dropped: %+v", connection.SealedMaterial)
	}
	printed := fmt.Sprintf("%v %+v %#v %+v %#v %+v %#v", response, response, response,
		*connection.SealedMaterial, *connection.SealedMaterial, *response.AgentKey, *response.AgentKey)
	for _, sensitive := range []string{"feedface", "ph:v1:aa:bb", "ph:v1:cc:dd"} {
		if strings.Contains(printed, sensitive) {
			t.Fatalf("formatting printed %q: %s", sensitive, printed)
		}
	}

	features, err := json.Marshal(ClientCapabilities{Features: []ClientFeature{FeatureInjectionList, FeatureWhenAbsent, FeatureSealedMaterial}})
	if err != nil || !strings.Contains(string(features), `"features":["injection_list","when_absent","sealed_material"]`) {
		t.Fatalf("features = %s err=%v", features, err)
	}
}
