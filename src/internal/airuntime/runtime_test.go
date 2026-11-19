package airuntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/pkg/proxy"
	gokeyring "github.com/zalando/go-keyring"
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
	token := "pss_agent:v1:" + strings.Repeat("a", 64)
	_, err := clientForSavedLogin("https://console.phase.dev", token)
	if !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("obsolete Agent token error = %v, want ErrAuthenticationRequired", err)
	}
}

func TestSavedLoginRejectsInvalidHostAsAuthenticationRequired(t *testing.T) {
	token := "pss_agent:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	_, err := clientForSavedLogin("not-a-url", token)
	if !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("invalid saved host error = %v, want ErrAuthenticationRequired", err)
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

// The launch environment exports the session's provider credential names for
// phase run, and the AWS SDKs' trust variable for the SigV4 Connection.
func TestCanonicalOpenFixtureExportsReservedNamesAndScopedTrust(t *testing.T) {
	payload, err := os.ReadFile("../agentapi/testdata/open_session_response.json")
	if err != nil {
		t.Fatal(err)
	}
	var response agentapi.OpenSessionResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatal(err)
	}
	session := &ProxySession{Config: &response, CAPaths: proxy.CAPaths{Bundle: "/phase/runtime-ca-bundle.pem"}}
	plan, err := session.CompileProcessEnvironment("http://phase:capability@127.0.0.1:9543", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	value := plan.Set[proxy.ReservedEnvironmentKey]
	reserved := proxy.SplitReservedEnvironment(value)
	for _, name := range append(append([]string{}, response.Connections[0].CredentialEnvironment...), "AWS_CA_BUNDLE", "HTTPS_PROXY", "NO_PROXY") {
		if !containsEnvironment(reserved, name) {
			t.Fatalf("%s lacks %s: %q", proxy.ReservedEnvironmentKey, name, value)
		}
	}
	// It stays far below what an environment variable can carry.
	if len(value) > 2048 {
		t.Fatalf("%s is %d bytes", proxy.ReservedEnvironmentKey, len(value))
	}
	if plan.Set["AWS_CA_BUNDLE"] != "/phase/runtime-ca-bundle.pem" || plan.Set["PGSSLROOTCERT"] != "" {
		t.Fatalf("scoped trust = AWS_CA_BUNDLE %q PGSSLROOTCERT %q", plan.Set["AWS_CA_BUNDLE"], plan.Set["PGSSLROOTCERT"])
	}
	response.Connections[0].CredentialEnvironment = []string{"aws_lower_case"}
	if _, err := session.CompileProcessEnvironment("http://phase:capability@127.0.0.1:9543", nil, nil); err == nil {
		t.Fatal("an invalid credentialEnvironment name was exported")
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
		return "", gokeyring.ErrNotFound
	}
	return value, nil
}

func (s *memoryPrivateKeyStore) Set(service, user, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[service+"/"+user] = value
	return nil
}

type listInjectionEngine struct{ countingServeEngine }

func (listInjectionEngine) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		Protocols: []string{"http"}, InjectionActions: []string{"set_header", "basic_auth"},
		Features: []string{agentapi.FeatureInjectionList, agentapi.FeatureWhenAbsent, agentapi.FeatureSealedMaterial},
	}
}

// sealed_material is advertised only by a login the Agent key can be rebuilt
// from. Every other login keeps receiving values the Console resolved.
func TestOpenAdvertisesSealedMaterialOnlyWithAnAgentToken(t *testing.T) {
	keyShares := ":" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	tests := []struct {
		name     string
		token    string
		engine   Engine
		features string
	}{
		{name: "Agent token", token: "pss_agent:v1" + keyShares, engine: listInjectionEngine{}, features: `["injection_list","when_absent","sealed_material"]`},
		{name: "Personal Access Token", token: "pss_user:v1" + keyShares, engine: listInjectionEngine{}, features: `["injection_list","when_absent"]`},
		{name: "Service Account token", token: "pss_service:v2" + keyShares, engine: listInjectionEngine{}, features: `["injection_list","when_absent"]`},
		{name: "engine without features", token: "pss_agent:v1" + keyShares, engine: countingServeEngine{}, features: `[]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var client struct {
				Features         json.RawMessage `json:"features"`
				InjectionActions []string        `json:"injectionActions"`
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				var body struct {
					Client json.RawMessage `json:"client"`
				}
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if err := json.Unmarshal(body.Client, &client); err != nil {
					t.Error(err)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "session-features"})
			}))
			defer server.Close()
			apiClient, err := agentapi.NewClient(server.URL, test.token, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			runtime := &Runtime{Client: apiClient, WorkflowID: "workflow-1"}
			if _, err := runtime.open(context.Background(), test.engine.Capabilities()); err != nil {
				t.Fatal(err)
			}
			if string(client.Features) != test.features {
				t.Fatalf("features = %s, want %s", client.Features, test.features)
			}
			if len(client.InjectionActions) != len(test.engine.Capabilities().InjectionActions) {
				t.Fatalf("injection actions = %v", client.InjectionActions)
			}
		})
	}
}

func customEnvironmentConnection(t *testing.T, id, environmentName, decoy string) agentapi.Connection {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"grantId": "grant-" + id, "connectionId": id, "credentialId": id, "credentialName": id, "credentialProvider": "http",
		"serviceType": "http", "protocol": "http",
		"hosts": []any{map[string]any{"match": "exact", "value": id + ".example.test", "port": 443}},
		"injections": []any{map[string]any{
			"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}",
			"valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach",
		}},
		"identifiers": map[string]string{}, "decoyMaterial": map[string]string{"token": decoy},
		"configEnv": map[string]string{}, "agentEnv": map[string]string{environmentName: decoy},
		"environmentBindings": []any{map[string]any{
			"name": environmentName, "action": "set", "source": "decoy", "sourceField": "token", "sensitive": true, "systemManaged": false,
		}},
		"secretMaterial": map[string]string{"token": "live-" + id},
	})
	if err != nil {
		t.Fatal(err)
	}
	var connection agentapi.Connection
	if err := json.Unmarshal(payload, &connection); err != nil {
		t.Fatal(err)
	}
	return connection
}

// Custom HTTP Connections share one service type but are different services,
// so each exports its own decoy. Only a name two of them disagree on is left
// for explicit per-Connection selection.
func TestCustomConnectionsEachExportTheirEnvironment(t *testing.T) {
	plan := func(connections ...agentapi.Connection) map[string]string {
		t.Helper()
		session := &ProxySession{Config: &agentapi.OpenSessionResponse{SessionConfig: agentapi.SessionConfig{
			ConfigEnv: map[string]string{}, Connections: connections,
		}}}
		environment, err := session.ProviderProcessEnvironment()
		if err != nil {
			t.Fatal(err)
		}
		return environment.Set
	}
	billing := customEnvironmentConnection(t, "billing", "BILLING_API_KEY", "decoy-billing-0123456789")
	search := customEnvironmentConnection(t, "search", "SEARCH_API_KEY", "decoy-search-0123456789")
	if set := plan(billing, search); set["BILLING_API_KEY"] != "decoy-billing-0123456789" || set["SEARCH_API_KEY"] != "decoy-search-0123456789" {
		t.Fatalf("two custom Connections did not both export their decoys: %v", set)
	}

	clashing := customEnvironmentConnection(t, "clashing", "BILLING_API_KEY", "decoy-clashing-0123456789")
	set := plan(billing, search, clashing)
	if _, exported := set["BILLING_API_KEY"]; exported || set["SEARCH_API_KEY"] != "decoy-search-0123456789" {
		t.Fatalf("a contested name was exported, or an uncontested one was dropped: %v", set)
	}

	// Packaged services are unchanged: two Connections of one service never
	// pick a default identity.
	first := customEnvironmentConnection(t, "first", "EXAMPLE_TOKEN", "decoy-first-0123456789")
	second := customEnvironmentConnection(t, "second", "OTHER_TOKEN", "decoy-second-0123456789")
	first.ServiceType, second.ServiceType = "github", "github"
	if set := plan(first, second, search); len(set) != 1 || set["SEARCH_API_KEY"] == "" {
		t.Fatalf("packaged Connections of one service exported a default identity: %v", set)
	}
}

type capturingServeEngine struct {
	countingServeEngine
	served func(*ProxySession)
}

func (engine capturingServeEngine) Serve(_ context.Context, session *ProxySession) error {
	engine.calls.Add(1)
	engine.served(session)
	return nil
}

// A custom Connection's value that collides with something the Agent can see
// costs that Connection its material, not the Workflow its session. A
// packaged value in the same position still stops the session before the
// engine is reached.
func TestRuntimeServesWhenOnlyACustomValueIsExposed(t *testing.T) {
	const collidingValue = "member-entered-value-01"
	sessionWith := func(connections ...any) map[string]any {
		return map[string]any{
			"schemaVersion": 1, "sessionUid": "session-exposed", "sessionCredential": "backend-capability",
			"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
			"configGeneration": 1, "configEnv": map[string]string{}, "connections": connections,
		}
	}
	custom := map[string]any{
		"grantId": "grant-custom", "connectionId": "connection-custom", "credentialId": "connection-custom",
		"credentialName": "Example API", "credentialProvider": "http", "serviceType": "http", "protocol": "http",
		"hosts": []any{map[string]any{"match": "exact", "value": "api.example.test", "port": 443}},
		"injections": []any{map[string]any{
			"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}",
			"valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach",
		}},
		"identifiers": map[string]string{"account": "acct-" + collidingValue}, "decoyMaterial": map[string]string{"token": "sk-decoy-0123456789abcdef"},
		"configEnv": map[string]string{}, "agentEnv": map[string]string{}, "environmentBindings": []any{},
		"secretMaterial": map[string]string{"token": collidingValue},
	}
	packaged := map[string]any{
		"grantId": "grant-pg", "connectionId": "connection-pg", "credentialId": "credential-pg",
		"credentialName": "Postgres", "credentialProvider": "postgres", "serviceType": "postgres", "protocol": "postgres",
		"hosts":     []any{map[string]any{"match": "exact", "value": "db.example", "port": 5432}},
		"injection": map[string]any{"action": "pg_handshake"}, "identifiers": map[string]string{"username": "db-user"},
		"decoyMaterial": map[string]string{"password": "pg-decoy-0123456789"}, "agentEnv": map[string]string{},
		"configEnv": map[string]string{}, "environmentBindings": []any{},
		"secretMaterial": map[string]string{"username": "db-user", "password": "pg-live-0123456789"},
	}
	serve := func(t *testing.T, payload map[string]any, served func(*ProxySession)) (error, int32) {
		t.Helper()
		console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions/") {
				_ = json.NewEncoder(w).Encode(payload)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "session-exposed", "revokedAt": time.Now().UTC()})
		}))
		defer console.Close()
		client, err := agentapi.NewClient(console.URL, "pss_user:v1:"+strings.Repeat("a", 64)+":"+strings.Repeat("b", 64)+":"+strings.Repeat("c", 64)+":"+strings.Repeat("d", 64), console.Client())
		if err != nil {
			t.Fatal(err)
		}
		var calls atomic.Int32
		runtime := &Runtime{
			Client: client, WorkflowID: "workflow-1",
			CAStore: proxy.CAStore{Directory: t.TempDir(), Keyring: &memoryPrivateKeyStore{values: map[string]string{}}},
		}
		err = runtime.ServeManaged(context.Background(), capturingServeEngine{countingServeEngine: countingServeEngine{calls: &calls}, served: served})
		return err, calls.Load()
	}

	err, calls := serve(t, sessionWith(custom, packaged), func(session *ProxySession) {
		exposed, intact := session.Config.Connections[0], session.Config.Connections[1]
		if exposed.MaterialFailure() != agentapi.MaterialFailureExposed || len(exposed.SecretMaterial.Clone()) != 0 {
			t.Errorf("the exposed custom value reached the engine: %q", exposed.MaterialFailure())
		}
		if live, _ := intact.SecretMaterial.Get("password"); live != "pg-live-0123456789" {
			t.Error("the packaged Connection lost its material")
		}
		if _, err := session.ProviderProcessEnvironment(); err != nil {
			t.Errorf("the session environment no longer compiles: %v", err)
		}
	})
	if err != nil || calls != 1 {
		t.Fatalf("a custom value collision ended the session: calls=%d err=%v", calls, err)
	}

	leaking := map[string]any{}
	for key, value := range packaged {
		leaking[key] = value
	}
	leaking["identifiers"] = map[string]string{"username": "db-user", "note": "contains pg-live-0123456789"}
	err, calls = serve(t, sessionWith(leaking), func(*ProxySession) {})
	if !errors.Is(err, agentapi.ErrUnsafeAgentVisibleEnvironment) || calls != 0 || strings.Contains(err.Error(), "pg-live-0123456789") {
		t.Fatalf("a packaged value collision reached the engine: calls=%d err=%v", calls, err)
	}
}

// labelEngine keeps the harness label of each session it is handed.
type labelEngine struct {
	mu     sync.Mutex
	labels []string
}

func (*labelEngine) Ready() error { return nil }
func (*labelEngine) Capabilities() EngineCapabilities {
	return EngineCapabilities{Protocols: []string{"http"}, InjectionActions: []string{"set_header"}}
}
func (e *labelEngine) keep(session *ProxySession) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.labels = append(e.labels, session.HarnessLabel)
	return nil
}
func (e *labelEngine) Serve(_ context.Context, session *ProxySession) error { return e.keep(session) }
func (e *labelEngine) Run(_ context.Context, session *ProxySession, _ []string) error {
	return e.keep(session)
}

// A proxy started for one command is told which harness that command is, so
// it can name its clients' flows as that tool's. A proxy that serves whatever
// reaches it is told nothing, whatever harness happened to start it.
func TestTheEngineIsToldTheHarnessOnlyWhenItServesOne(t *testing.T) {
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "session-label", "sessionCredential": "capability-label",
				"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
				"configGeneration": 1, "configEnv": map[string]string{}, "connections": []any{},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revoke/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "session-label", "revokedAt": time.Now().UTC()})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CURSOR_AGENT", "")
	t.Setenv("OPENCODE", "")
	t.Setenv("AGENT", "")
	t.Setenv("CODEX", "1")
	token := "pss_user:v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
	client, err := agentapi.NewClient(console.URL, token, console.Client())
	if err != nil {
		t.Fatal(err)
	}
	newRuntime := func() *Runtime {
		return &Runtime{
			Client: client, WorkflowID: "workflow-1",
			CAStore: proxy.CAStore{Directory: t.TempDir(), Keyring: &memoryPrivateKeyStore{values: map[string]string{}}},
		}
	}
	engine := &labelEngine{}
	// phase ai run -- claude: the child is the harness.
	if err := newRuntime().Run(context.Background(), engine, []string{"/usr/local/bin/claude"}); err != nil {
		t.Fatal(err)
	}
	// phase ai run --harness: what the caller resolved.
	labelled := newRuntime()
	labelled.HarnessLabel = "opencode"
	if err := labelled.Run(context.Background(), engine, []string{"/opt/launcher"}); err != nil {
		t.Fatal(err)
	}
	// phase ai exec: the harness that invoked it.
	if err := newRuntime().Exec(context.Background(), engine, []string{"/usr/bin/true"}); err != nil {
		t.Fatal(err)
	}
	// The hook-managed proxy serves every harness on the machine.
	if err := newRuntime().ServeManaged(context.Background(), engine); err != nil {
		t.Fatal(err)
	}
	if want := []string{"claude-code", "opencode", "codex", ""}; !reflect.DeepEqual(engine.labels, want) {
		t.Fatalf("the engine was told %q, want %q", engine.labels, want)
	}
}
