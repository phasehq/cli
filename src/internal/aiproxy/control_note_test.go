package aiproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/agentapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// A member's note on a request is read by the Agent. One that holds a live
// credential value, or the session's own credential, is withheld; the
// request's outcome still arrives, and any other note arrives as written.
func TestResolutionNoteIsScreenedForLiveValues(t *testing.T) {
	const backendCredential = "backend-note-screen-capability"
	for name, c := range map[string]struct {
		note     string
		withheld bool
	}{
		"a plain note":               {"Use the existing deploy bot account instead.", false},
		"a live credential value":    {"The password is pg-live, use that.", true},
		"the session's credential":   {"session " + backendCredential, true},
		"the decoy, which is public": {"the placeholder is pg-decoy", false},
	} {
		t.Run(name, func(t *testing.T) {
			console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch {
				case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/requests/request-1/"):
					_ = json.NewEncoder(w).Encode(map[string]any{
						"id": "request-1", "status": "denied", "kind": "setup", "serviceType": "postgres",
						"credentialProvider": "postgres", "credentialName": "Postgres production", "resolutionNote": c.note,
					})
				case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/requests/request-1/cancel/"):
					_ = json.NewEncoder(w).Encode(map[string]any{
						"id": "request-1", "status": "cancelled", "kind": "setup", "serviceType": "postgres",
						"credentialProvider": "postgres", "credentialName": "Postgres production", "resolutionNote": c.note,
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer console.Close()
			client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
			if err != nil {
				t.Fatal(err)
			}
			state := controlRuntimeState(t, client, controlAccessSessionPayload(backendCredential, 1), "runtime-note-screen-capability")
			defer state.destroy()
			proxy := &httpProxy{state: state, control: &controlHandler{state: state}}
			for _, request := range []*http.Request{
				httptest.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/requests/request-1", nil),
				httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/requests/request-1/cancel", strings.NewReader("{}")),
			} {
				setProxyCapability(request, "runtime-note-screen-capability")
				request.Header.Set("Content-Type", "application/json")
				recorder := httptest.NewRecorder()
				proxy.ServeHTTP(recorder, request)
				var answer agentapi.RequestResponse
				if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &answer) != nil || answer.ID != "request-1" ||
					(answer.Status != "denied" && answer.Status != "cancelled") {
					t.Fatalf("%s %s: the request's outcome did not arrive: %d %s", request.Method, request.URL.Path, recorder.Code, recorder.Body.String())
				}
				want := c.note
				if c.withheld {
					want = withheldResolutionNote
				}
				if answer.ResolutionNote != want {
					t.Fatalf("%s %s: the note arrived as %q, want %q", request.Method, request.URL.Path, answer.ResolutionNote, want)
				}
				if c.withheld && (strings.Contains(recorder.Body.String(), "pg-live") || strings.Contains(recorder.Body.String(), backendCredential)) {
					t.Fatalf("%s %s: the answer holds the value: %s", request.Method, request.URL.Path, recorder.Body.String())
				}
			}
		})
	}
}
