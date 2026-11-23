package aiproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// The bodyless routes that end or change the session answer only a call the
// CLI marks, never a client that followed an upstream's redirect.
func TestSessionControlRoutesNeedTheControlIntentHeader(t *testing.T) {
	var revokes, rotates atomic.Int32
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/revoke/"):
			revokes.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "session-123", "revokedAt": time.Now().UTC()})
		case strings.HasSuffix(r.URL.Path, "/rotate/"):
			rotates.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "session-123", "sessionCredential": "rotated-backend-credential",
				"expiresAt": time.Now().Add(time.Hour).UTC(), "configGeneration": 2,
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
	state, err := newRuntimeStateWithCapability(emptyProxySession(t, client, "backend-credential"), "runtime-capability")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	// An upstream that sends every POST on to the revoke route.
	redirecting := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		header := http.Header{"Location": {phaseproxy.ControlURL + "/v1/revoke"}}
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: header, Body: http.NoBody, Request: req}, nil
	})
	proxy := &httpProxy{state: state, control: &controlHandler{state: state}, transport: redirecting}
	server := httptest.NewServer(proxy)
	defer server.Close()
	proxyURL := "http://phase:runtime-capability@" + strings.TrimPrefix(server.URL, "http://")

	for _, path := range []string{"/v1/revoke", "/v1/rotate"} {
		request := httptest.NewRequest(http.MethodPost, phaseproxy.ControlURL+path, nil)
		setProxyCapability(request, "runtime-capability")
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "control_intent_required") {
			t.Fatalf("%s without the header: %d %s", path, recorder.Code, recorder.Body.String())
		}
	}

	parsed, _ := url.Parse(proxyURL)
	following := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(parsed)}}
	response, err := following.Post("http://api.example.test/v1/items", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || revokes.Load() != 0 || rotates.Load() != 0 {
		t.Fatalf("a redirected POST reached the session: status %d, revokes %d, rotates %d", response.StatusCode, revokes.Load(), rotates.Load())
	}

	control, err := phaseproxy.ControlClient(proxyURL, time.Second, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rotate, _ := http.NewRequest(http.MethodPost, phaseproxy.ControlURL+"/v1/rotate", nil)
	rotate.Header.Set(phaseproxy.ControlIntentHeader, "1")
	response, err = control.Do(rotate)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || rotates.Load() != 1 {
		t.Fatalf("a marked rotate: status %d, rotates %d", response.StatusCode, rotates.Load())
	}
}
