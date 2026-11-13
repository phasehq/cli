package agentapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The runtime binds its session before any request is made, so requests
// travel through the shared SDK client. A title, an opaque action and an
// absent reason must survive that path in both directions.
func TestActionRequestsPassThroughTheSessionBoundClient(t *testing.T) {
	const action = `{"type":"agent_connection.update","version":1,"connectionId":"connection-example","name":"Example API","access":{"durationSeconds":3600}}`
	var forwarded map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/sessions/") {
			_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"session-123"}`))
			return
		}
		forwarded = nil
		if err := json.NewDecoder(r.Body).Decode(&forwarded); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"schemaVersion":1,"id":"request-1","status":"pending","kind":"connection_update","title":"Rename the Example API","action":` + action + `}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, testToken("pss_agent", 1, ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.OpenSession(context.Background(), OpenSessionRequest{}); err != nil {
		t.Fatal(err)
	}
	created, status, err := client.CreateRequestWithStatus(context.Background(), CreateRequestRequest{
		Kind: "connection_update", Action: json.RawMessage(action),
	}, "session-one")
	if err != nil || status != http.StatusCreated {
		t.Fatalf("status=%d err=%v", status, err)
	}
	var want, sent, relayed any
	_ = json.Unmarshal([]byte(action), &want)
	_ = json.Unmarshal(forwarded["action"], &sent)
	_ = json.Unmarshal(created.Action, &relayed)
	if fmt.Sprint(want) != fmt.Sprint(sent) || fmt.Sprint(want) != fmt.Sprint(relayed) || created.Title != "Rename the Example API" ||
		created.Kind != "connection_update" || string(forwarded["markdown"]) != `""` || string(forwarded["kind"]) != `"connection_update"` {
		t.Fatalf("forwarded=%v created=%+v", forwarded, created)
	}
	for _, absent := range []string{"title", "credentialProvider", "credentialName", "serviceType", "connectionId", "credentialId"} {
		if _, present := forwarded[absent]; present {
			t.Fatalf("an empty %s was sent: %s", absent, forwarded[absent])
		}
	}
	if _, _, err := client.CreateRequestWithStatus(context.Background(), CreateRequestRequest{
		Kind: "credential_update", Action: json.RawMessage(`{"type":"agent_connection.secret_update","version":1,"connectionId":"connection-example","value":"sk-live-pasted"}`),
	}, "session-one"); err == nil || strings.Contains(err.Error(), "sk-live-pasted") {
		t.Fatalf("an action carrying a value was sent, or the error repeated it: %v", err)
	}
}
