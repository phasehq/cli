package aiproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// A member pasted a token into a custom Connection's name. The value is
// withheld, and so is the name: status, the Connection reads and discovery
// show the Connection without it, and discovery, which the Console still
// answers with the name as written, does not read as a changed session.
func TestAConnectionNameThatHoldsItsValueIsShownNowhere(t *testing.T) {
	const token = "tok_ABCDEFGHIJKLMNOPQRSTUV123456"
	named := func() map[string]any {
		connection := customConnectionPayload(customDecoyToken, token)
		connection["connectionName"], connection["credentialName"] = "Billing "+token, "Billing "+token
		return connection
	}
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/sessions/"):
			_ = json.NewEncoder(w).Encode(customSessionPayload("backend-named", 1, named(), packagedPostgresPayload()))
		case strings.HasSuffix(request.URL.Path, "/sessions/session-custom/discover/"):
			discovered, packaged := named(), packagedPostgresPayload()
			delete(discovered, "secretMaterial")
			delete(packaged, "secretMaterial")
			_ = json.NewEncoder(w).Encode(customSessionPayload("", 1, discovered, packaged))
		default:
			http.NotFound(w, request)
		}
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.OpenSession(context.Background(), agentapi.OpenSessionRequest{WorkflowID: "workflow-1", IdempotencyKey: "proxy-start-named"})
	if err != nil {
		t.Fatal(err)
	}
	ca, _, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(&airuntime.ProxySession{Config: session, Client: client, CA: ca}, "runtime-named")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	proxy := &httpProxy{state: state, control: &controlHandler{state: state}}
	for _, path := range []string{"/v1/status", "/v1/connections", "/v1/connections/connection-example", "/v1/discover"} {
		answer := controlGet(t, proxy, "runtime-named", path)
		if answer.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", path, answer.Code, answer.Body.String())
		}
		if strings.Contains(answer.Body.String(), token) {
			t.Fatalf("%s shows the value in the Connection's name: %s", path, answer.Body.String())
		}
		if !strings.Contains(answer.Body.String(), `"`+agentapi.WithheldConnectionName+`"`) {
			t.Fatalf("%s does not show the Connection under its withheld name: %s", path, answer.Body.String())
		}
		// Every other Connection keeps its name.
		if path != "/v1/connections/connection-example" && !strings.Contains(answer.Body.String(), "console-dev-pg") {
			t.Fatalf("%s lost another Connection's name: %s", path, answer.Body.String())
		}
	}
	select {
	case fatal := <-state.fatal:
		t.Fatalf("a withheld name ended the session: %v", fatal)
	default:
	}
}
