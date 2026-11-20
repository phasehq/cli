package aiproxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

type manifestWriteOrderRecorder struct {
	*httptest.ResponseRecorder
	state                  *runtimeState
	wroteWhileStateHealthy bool
}

func (r *manifestWriteOrderRecorder) Write(payload []byte) (int, error) {
	r.state.mu.RLock()
	r.wroteWhileStateHealthy = r.state.healthy
	r.state.mu.RUnlock()
	return r.ResponseRecorder.Write(payload)
}

func TestManifestEnvironmentDriftRespondsBeforeRequestingRecycle(t *testing.T) {
	tests := []struct {
		name                string
		discoverGeneration  int
		discoverConnections []agentapi.DiscoverConnection
		providerEnvironment phaseproxy.ProcessEnvironmentPlan
	}{
		{
			name:               "new connection changes trusted discover",
			discoverGeneration: 2,
			discoverConnections: []agentapi.DiscoverConnection{{
				GrantID: "new-grant", ConnectionID: "new-connection", ServiceType: "aws", Protocol: "http",
			}},
		},
		{
			name:                "provider environment differs",
			discoverGeneration:  1,
			providerEnvironment: phaseproxy.ProcessEnvironmentPlan{Set: map[string]string{"STALE": "value"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			discover := agentapi.DiscoverResponse{
				SchemaVersion: agentapi.SchemaVersion, SessionUID: "session-123",
				ConfigGeneration: test.discoverGeneration, ConfigEnv: map[string]string{},
				Connections: test.discoverConnections,
			}
			console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Header.Get(agentapi.SessionCredentialHeader) != "backend-only" {
					t.Errorf("backend credential = %q", req.Header.Get(agentapi.SessionCredentialHeader))
				}
				_ = json.NewEncoder(w).Encode(discover)
			}))
			defer console.Close()
			client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
			if err != nil {
				t.Fatal(err)
			}
			state, err := newRuntimeStateWithCapability(emptyProxySession(t, client, "backend-only"), "runtime-only")
			if err != nil {
				t.Fatal(err)
			}
			defer state.destroy()
			handler := &manifestHandler{state: state, providerEnvironment: test.providerEnvironment}
			request := httptest.NewRequest(http.MethodGet, ManifestURL, nil)
			response := &manifestWriteOrderRecorder{ResponseRecorder: httptest.NewRecorder(), state: state}

			handler.ServeManifestHTTP(response, request)

			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if response.Header().Get("X-Phase-Error-Code") != ManifestRefreshRequiredCode {
				t.Fatalf("error code header = %q", response.Header().Get("X-Phase-Error-Code"))
			}
			if response.Header().Get("Retry-After") != "1" {
				t.Fatalf("Retry-After = %q", response.Header().Get("Retry-After"))
			}
			var payload struct {
				Error struct {
					Code      string         `json:"code"`
					Message   string         `json:"message"`
					Retryable bool           `json:"retryable"`
					Details   map[string]any `json:"details"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Error.Code != ManifestRefreshRequiredCode || !payload.Error.Retryable || payload.Error.Message == "" || payload.Error.Details == nil {
				t.Fatalf("payload=%+v", payload.Error)
			}
			if !response.wroteWhileStateHealthy {
				t.Fatal("runtime recycle was signaled before the manifest response body was written")
			}
			select {
			case fatal := <-state.fatal:
				if !errors.Is(fatal, airuntime.ErrSessionReprovisionRequired) {
					t.Fatalf("fatal=%v", fatal)
				}
			case <-time.After(time.Second):
				t.Fatal("manifest drift did not request runtime recycle")
			}
		})
	}
}

func TestInvalidManifestDiscoverDoesNotRequestRecycle(t *testing.T) {
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(agentapi.DiscoverResponse{
			SchemaVersion: agentapi.SchemaVersion + 1, SessionUID: "session-123",
			ConfigGeneration: 1, ConfigEnv: map[string]string{}, Connections: []agentapi.DiscoverConnection{},
		})
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(emptyProxySession(t, client, "backend-only"), "runtime-only")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	handler := &manifestHandler{state: state}
	response := httptest.NewRecorder()

	handler.ServeManifestHTTP(response, httptest.NewRequest(http.MethodGet, ManifestURL, nil))

	if response.Code != http.StatusBadGateway || response.Header().Get("X-Phase-Error-Code") != "invalid_agent_manifest_discover" {
		t.Fatalf("status=%d code=%q body=%s", response.Code, response.Header().Get("X-Phase-Error-Code"), response.Body.String())
	}
	select {
	case fatal := <-state.fatal:
		t.Fatalf("invalid backend response requested runtime recycle: %v", fatal)
	default:
	}
}
