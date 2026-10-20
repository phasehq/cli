package airuntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/pkg/proxy"
)

func TestUnavailableEngineFailsBeforeOpeningSession(t *testing.T) {
	runtime := &Runtime{Client: nil, WorkflowID: "workflow-123"}
	err := runtime.ServeManaged(context.Background(), UnavailableEngine{})
	if !errors.Is(err, ErrProxyEngineNotReady) {
		t.Fatalf("got %v, want ErrProxyEngineNotReady", err)
	}
	err = runtime.Run(context.Background(), UnavailableEngine{}, []string{"app"})
	if !errors.Is(err, ErrProxyEngineNotReady) {
		t.Fatalf("got %v, want ErrProxyEngineNotReady", err)
	}
}

func TestRuntimeRejectsLegacyServiceToken(t *testing.T) {
	token := "pss_service:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	client, err := agentapi.NewClient("https://console.phase.dev", token, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{Client: client, WorkflowID: "workflow-1"}
	if _, err := runtime.open(context.Background(), EngineCapabilities{}); err == nil || !strings.Contains(err.Error(), "Phase Service tokens") {
		t.Fatalf("legacy Service token error = %v", err)
	}
}

func TestSavedLoginRejectsObsoleteAgentTokenAsAuthenticationRequired(t *testing.T) {
	token := "pss_agent:v2:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	_, err := clientForSavedLogin("https://console.phase.dev", token)
	if !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("obsolete Agent token error = %v, want ErrAuthenticationRequired", err)
	}
}

func TestSavedLoginRejectsInvalidHostAsAuthenticationRequired(t *testing.T) {
	token := "pss_agent:v1:" + strings.Repeat("a", 64)
	_, err := clientForSavedLogin("not-a-url", token)
	if !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("invalid saved host error = %v, want ErrAuthenticationRequired", err)
	}
}

func TestAgentTokenRequiredEngineFailsBeforeSessionProvisioning(t *testing.T) {
	var opened atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		opened.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	token := "pss_user:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	client, err := agentapi.NewClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{Client: client, WorkflowID: "workflow-1"}
	if err := runtime.ServeManaged(context.Background(), requiresAgentTokenEngine{}); err == nil || !strings.Contains(err.Error(), "Agent-token") {
		t.Fatalf("remote auth error=%v", err)
	}
	if opened.Load() != 0 {
		t.Fatal("remote mode provisioned a session before rejecting non-Agent auth")
	}
}

func TestRuntimeClassifiesSessionAuthenticationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/sessions/") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Token expired or deleted"}`))
			return
		}
		http.NotFound(w, request)
	}))
	defer server.Close()

	token := "pss_user:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	client, err := agentapi.NewClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{Client: client, WorkflowID: "workflow-1"}
	err = runtime.Exec(context.Background(), countingServeEngine{calls: &atomic.Int32{}}, []string{"provider-command"})
	if !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("authentication error = %v, want ErrAuthenticationRequired", err)
	}
	for _, unwanted := range []string{"ai enable", "restart", "Token expired or deleted"} {
		if strings.Contains(err.Error(), unwanted) {
			t.Fatalf("authentication error contains %q: %v", unwanted, err)
		}
	}
}

func TestRuntimeRejectsUnsafeOpenSessionBeforeEngineHandoff(t *testing.T) {
	const live = "live-open-session-credential"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/sessions/") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "unsafe-session", "sessionCredential": "unsafe-backend-capability",
				"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
				"configGeneration": 1, "configEnv": map[string]string{"UNSAFE": "prefix-" + live},
				"connections": []any{map[string]any{
					"identifiers":    map[string]string{"account": "safe-account"},
					"secretMaterial": map[string]string{"access_token": live}, "agentEnv": map[string]string{},
				}},
			})
			return
		}
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/revoke/") {
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "unsafe-session", "revokedAt": time.Now().UTC()})
			return
		}
		http.NotFound(w, request)
	}))
	defer server.Close()
	client, err := agentapi.NewClient(server.URL, "pss_user:v1:"+strings.Repeat("a", 64)+":"+strings.Repeat("b", 64)+":"+strings.Repeat("c", 64)+":"+strings.Repeat("d", 64), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	runtime := &Runtime{Client: client, WorkflowID: "workflow-1"}
	err = runtime.ServeManaged(context.Background(), countingServeEngine{calls: &calls})
	if err == nil || calls.Load() != 0 || strings.Contains(err.Error(), live) {
		t.Fatalf("unsafe open session handoff: calls=%d err=%v", calls.Load(), err)
	}
}

type requiresAgentTokenEngine struct{ UnavailableEngine }

func (requiresAgentTokenEngine) Ready() error             { return nil }
func (requiresAgentTokenEngine) RequiresAgentToken() bool { return true }

type countingServeEngine struct{ calls *atomic.Int32 }

func (countingServeEngine) Ready() error { return nil }
func (countingServeEngine) Capabilities() EngineCapabilities {
	return EngineCapabilities{Protocols: []string{"http"}, InjectionActions: []string{"set_header"}}
}
func (engine countingServeEngine) Serve(context.Context, *ProxySession) error {
	engine.calls.Add(1)
	return nil
}
func (countingServeEngine) Run(context.Context, *ProxySession, []string) error { return nil }

// A managed serve drains exactly one session: on hard expiry it returns the
// lifecycle error to its supervisor instead of reopening a session behind the
// harness's back.
func TestManagedServeReturnsExpiryWithoutReopeningSession(t *testing.T) {
	var opens atomic.Int32
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions/") {
			index := opens.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": fmt.Sprintf("session-%d", index),
				"sessionCredential": fmt.Sprintf("capability-%d", index),
				"expiresAt":         time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
				"configGeneration": 1, "configEnv": map[string]string{}, "connections": []any{},
			})
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revoke/") {
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "revoked", "revokedAt": time.Now().UTC()})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer console.Close()
	token := "pss_user:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	client, err := agentapi.NewClient(console.URL, token, console.Client())
	if err != nil {
		t.Fatal(err)
	}
	engine := &expiryOnceEngine{}
	runtime := &Runtime{
		Client: client, WorkflowID: "workflow-1",
		CAStore: proxy.CAStore{Directory: t.TempDir(), Keyring: &memoryPrivateKeyStore{values: map[string]string{}}},
	}
	err = runtime.ServeManaged(context.Background(), engine)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("managed serve expiry error = %v", err)
	}
	if opens.Load() != 1 {
		t.Fatalf("opened sessions=%d, want 1", opens.Load())
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if len(engine.credentials) != 1 {
		t.Fatalf("serve silently replaced the external harness capability: %v", engine.credentials)
	}
}

func TestServeManagedReturnsRawReprovisionSentinelAfterOneSession(t *testing.T) {
	var opens atomic.Int32
	var revokes atomic.Int32
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions/"):
			opens.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "managed-session",
				"sessionCredential": "managed-session-capability",
				"expiresAt":         time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
				"configGeneration": 1, "configEnv": map[string]string{}, "connections": []any{},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revoke/"):
			revokes.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "managed-session", "revokedAt": time.Now().UTC(),
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	token := "pss_user:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	client, err := agentapi.NewClient(console.URL, token, console.Client())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		Client: client, WorkflowID: "workflow-1",
		CAStore: proxy.CAStore{Directory: t.TempDir(), Keyring: &memoryPrivateKeyStore{values: map[string]string{}}},
	}
	want := fmt.Errorf("managed proxy requested recycle: %w", ErrSessionReprovisionRequired)
	got := runtime.ServeManaged(context.Background(), fixedServeErrorEngine{err: want})
	if got != want || !errors.Is(got, ErrSessionReprovisionRequired) {
		t.Fatalf("ServeManaged error = %v, want unchanged wrapped sentinel %v", got, want)
	}
	for _, forbidden := range []string{"restart phase ai serve", "relaunch the harness", "external harness environment"} {
		if strings.Contains(strings.ToLower(got.Error()), forbidden) {
			t.Fatalf("ServeManaged added foreground restart guidance %q: %v", forbidden, got)
		}
	}
	if opens.Load() != 1 || revokes.Load() != 1 {
		t.Fatalf("managed lifecycle opens=%d revokes=%d, want one each", opens.Load(), revokes.Load())
	}
}

func TestRunReportsHarnessFromChildExecutable(t *testing.T) {
	var harnessLabel string
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions/"):
			var request agentapi.OpenSessionRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode open-session request: %v", err)
			}
			harnessLabel = request.HarnessLabel
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "session-child-harness",
				"sessionCredential": "capability-child-harness",
				"expiresAt":         time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
				"configGeneration": 1, "configEnv": map[string]string{}, "connections": []any{},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revoke/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "session-child-harness", "revokedAt": time.Now().UTC()})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CODEX", "1")
	token := "pss_user:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	client, err := agentapi.NewClient(console.URL, token, console.Client())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		Client: client, WorkflowID: "workflow-1",
		CAStore: proxy.CAStore{Directory: t.TempDir(), Keyring: &memoryPrivateKeyStore{values: map[string]string{}}},
	}
	if err := runtime.Run(context.Background(), &expiryOnceEngine{}, []string{"/usr/local/bin/claude"}); err != nil {
		t.Fatal(err)
	}
	if harnessLabel != "claude-code" {
		t.Fatalf("open-session harnessLabel = %q, want claude-code", harnessLabel)
	}
}

func TestExecReportsInvokingHarnessInsteadOfChildExecutable(t *testing.T) {
	var harnessLabel string
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions/"):
			var request agentapi.OpenSessionRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode open-session request: %v", err)
			}
			harnessLabel = request.HarnessLabel
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "session-exec-harness",
				"sessionCredential": "capability-exec-harness",
				"expiresAt":         time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
				"configGeneration": 1, "configEnv": map[string]string{}, "connections": []any{},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revoke/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "session-exec-harness", "revokedAt": time.Now().UTC()})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CODEX", "1")
	token := "pss_user:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	client, err := agentapi.NewClient(console.URL, token, console.Client())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		Client: client, WorkflowID: "workflow-1",
		CAStore: proxy.CAStore{Directory: t.TempDir(), Keyring: &memoryPrivateKeyStore{values: map[string]string{}}},
	}
	if err := runtime.Exec(context.Background(), &expiryOnceEngine{}, []string{"/usr/local/bin/claude"}); err != nil {
		t.Fatal(err)
	}
	if harnessLabel != "codex" {
		t.Fatalf("open-session harnessLabel = %q, want codex", harnessLabel)
	}
}

func TestExecReturnsTransientChildExitCodeUnwrapped(t *testing.T) {
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "session-exit-code",
				"sessionCredential": "capability-exit-code",
				"expiresAt":         time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
				"configGeneration": 1, "configEnv": map[string]string{}, "connections": []any{},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revoke/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "session-exit-code", "revokedAt": time.Now().UTC()})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	token := "pss_user:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	client, err := agentapi.NewClient(console.URL, token, console.Client())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		Client: client, WorkflowID: "workflow-1",
		CAStore: proxy.CAStore{Directory: t.TempDir(), Keyring: &memoryPrivateKeyStore{values: map[string]string{}}},
	}
	err = runtime.Exec(context.Background(), exitCodeEngine{code: 42}, []string{"provider-command"})
	var exitError interface{ ExitCode() int }
	if !errors.As(err, &exitError) || exitError.ExitCode() != 42 {
		t.Fatalf("transient exec error = %v", err)
	}
}

type exitCodeEngine struct{ code int }

func (exitCodeEngine) Ready() error { return nil }
func (exitCodeEngine) Capabilities() EngineCapabilities {
	return EngineCapabilities{}
}
func (exitCodeEngine) Serve(context.Context, *ProxySession) error { return nil }
func (e exitCodeEngine) Run(context.Context, *ProxySession, []string) error {
	return testExitError{code: e.code}
}

type testExitError struct{ code int }

func (e testExitError) Error() string { return "exit status" }
func (e testExitError) ExitCode() int { return e.code }

type expiryOnceEngine struct {
	mu          sync.Mutex
	credentials []string
}

func (*expiryOnceEngine) Ready() error { return nil }
func (*expiryOnceEngine) Capabilities() EngineCapabilities {
	return EngineCapabilities{Protocols: []string{"http"}, InjectionActions: []string{"set_header"}}
}
func (e *expiryOnceEngine) Serve(_ context.Context, session *ProxySession) error {
	e.mu.Lock()
	e.credentials = append(e.credentials, session.Config.SessionCredential.Reveal())
	count := len(e.credentials)
	e.mu.Unlock()
	if count == 1 {
		return fmt.Errorf("%w: test expiry", ErrSessionExpired)
	}
	return nil
}
func (*expiryOnceEngine) Run(context.Context, *ProxySession, []string) error { return nil }

type fixedServeErrorEngine struct{ err error }

func (fixedServeErrorEngine) Ready() error { return nil }
func (fixedServeErrorEngine) Capabilities() EngineCapabilities {
	return EngineCapabilities{Protocols: []string{"http"}, InjectionActions: []string{"set_header"}}
}
func (engine fixedServeErrorEngine) Serve(context.Context, *ProxySession) error  { return engine.err }
func (fixedServeErrorEngine) Run(context.Context, *ProxySession, []string) error { return nil }

func TestCanonicalOpenFixtureCompilesProviderProcessEnvironment(t *testing.T) {
	payload, err := os.ReadFile("../agentapi/testdata/open_session_response.json")
	if err != nil {
		t.Fatal(err)
	}
	var response agentapi.OpenSessionResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatal(err)
	}
	plan, err := (&ProxySession{Config: &response}).ProviderProcessEnvironment()
	if err != nil {
		t.Fatalf("canonical open-session environment contract is not executable: %v", err)
	}
	for key, want := range map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAPHASEDECOY000000",
		"AWS_SECRET_ACCESS_KEY": "PHX_REDACTED_DECOY",
		"AWS_REGION":            "us-east-1",
		"AWS_DEFAULT_REGION":    "us-east-1",
	} {
		if got := plan.Set[key]; got != want {
			t.Fatalf("provider environment %s=%q, want %q", key, got, want)
		}
	}
	if _, ok := plan.Set["AWS_IAM_USERNAME"]; ok {
		t.Fatal("canonical Integration credential environment retained a generated Dynamic Secret identity")
	}
	for _, key := range []string{"AWS_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"} {
		if !containsEnvironment(plan.Unset, key) {
			t.Fatalf("canonical provider environment did not clean up %s: %v", key, plan.Unset)
		}
	}
}

func TestProxySessionRejectsLiveMaterialInAgentVisibleEnvironment(t *testing.T) {
	const live = "live-upstream-credential-value"
	newSession := func(t *testing.T) *ProxySession {
		t.Helper()
		connection := agentapi.Connection{
			ConnectionID: "connection-test", ServiceType: "github",
			Injection:     agentapi.Injection{Action: "set_header"},
			Identifiers:   map[string]string{"account": "agent-visible-account"},
			DecoyMaterial: map[string]string{"access_token": "agent-visible-decoy"},
			ConfigEnv:     map[string]string{},
		}
		material, _ := json.Marshal(map[string]string{"access_token": live, "account": "agent-visible-account"})
		if err := json.Unmarshal(material, &connection.SecretMaterial); err != nil {
			t.Fatal(err)
		}
		environment, _ := json.Marshal(map[string]string{"GITHUB_TOKEN": "agent-visible-decoy", "ACCOUNT": "agent-visible-account"})
		if err := json.Unmarshal(environment, &connection.AgentEnv); err != nil {
			t.Fatal(err)
		}
		return &ProxySession{Config: &agentapi.OpenSessionResponse{SessionConfig: agentapi.SessionConfig{
			ConfigEnv: map[string]string{}, Connections: []agentapi.Connection{connection},
		}}}
	}
	tests := map[string]func(*ProxySession){
		"session config env": func(session *ProxySession) { session.Config.ConfigEnv["LEAK"] = "prefix-" + live },
		"connection config env": func(session *ProxySession) {
			session.Config.Connections[0].ConfigEnv["LEAK"] = live
		},
		"agent env": func(session *ProxySession) {
			environment, _ := json.Marshal(map[string]string{"LEAK": "prefix-" + live})
			_ = json.Unmarshal(environment, &session.Config.Connections[0].AgentEnv)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			session := newSession(t)
			mutate(session)
			_, err := session.ProviderProcessEnvironment()
			if err == nil || strings.Contains(err.Error(), live) {
				t.Fatalf("unsafe environment error = %v", err)
			}
		})
	}

	safe := newSession(t)
	if err := agentapi.ValidateAgentVisibleEnvironment(safe.Config.ConfigEnv, safe.Config.Connections); err != nil {
		t.Fatalf("explicit Agent-visible identifier was rejected: %v", err)
	}
}

func containsEnvironment(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type memoryPrivateKeyStore struct {
	mu     sync.Mutex
	values map[string]string
}

func (s *memoryPrivateKeyStore) Get(service, user string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[service+"/"+user]
	if !ok {
		return "", errors.New("not found")
	}
	return value, nil
}

func (s *memoryPrivateKeyStore) Set(service, user, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[service+"/"+user] = value
	return nil
}
