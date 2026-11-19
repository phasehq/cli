package airuntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/proxy"
)

type sessionCapturingEngine struct {
	countingServeEngine
	session **ProxySession
}

func (engine sessionCapturingEngine) Serve(_ context.Context, session *ProxySession) error {
	*engine.session = session
	return nil
}

// identityConsole is a Console that opens sessions and says who a token is,
// on the routes the CLI asks. It counts what it is asked.
type identityConsole struct {
	server *httptest.Server
	// agent, user and serviceAccount are what the identity routes answer.
	agent, account string
	asked          atomic.Int32
	sessions       atomic.Int32
	// failing makes the identity routes answer 500.
	failing atomic.Bool
}

func newIdentityConsole(t *testing.T) *identityConsole {
	t.Helper()
	console := &identityConsole{
		agent:   `{"schemaVersion":1,"principalType":"agent","agent":{"id":"agent-9","name":"an Agent"},"workflow":{"id":"workflow-1","name":"a Workflow"},"organization":{"id":"org-1","name":"an organisation"}}`,
		account: `{"user_id":"account-1","account_id":"service-account-7","organisation":{"id":"org-1","name":"an organisation"},"wrapped_key_share":"not-read","apps":[{"id":"not-read"}]}`,
	}
	console.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := ""
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions/"):
			console.sessions.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "inventory-session", "sessionCredential": "inventory-session-capability",
				"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
				"configGeneration": 1, "configEnv": map[string]string{}, "connections": []any{},
			})
			return
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revoke/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "inventory-session", "revokedAt": time.Now().UTC()})
			return
		case r.Method == http.MethodGet && r.URL.Path == "/service/public/v1/agents/identity/" && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer Agent "):
			identity = console.agent
		case r.Method == http.MethodGet && r.URL.Path == "/service/secrets/tokens/" && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer Agent "):
			identity = console.account
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		console.asked.Add(1)
		if console.failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(identity))
	}))
	t.Cleanup(console.server.Close)
	return console
}

func testToken(prefix string) string {
	return prefix + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
}

// served opens one managed session of a runtime and returns what the engine
// was handed.
func served(t *testing.T, runtime *Runtime) *ProxySession {
	t.Helper()
	var session *ProxySession
	var calls atomic.Int32
	if err := runtime.ServeManaged(context.Background(), sessionCapturingEngine{countingServeEngine{calls: &calls}, &session}); err != nil {
		t.Fatal(err)
	}
	if session == nil {
		t.Fatal("no session reached the engine")
	}
	return session
}

// The proxy's inventory is kept where its CA is: the same directory and
// keystore, opened for the session's own tenant.
func TestSessionCarriesTheInventoryStoreBesideTheCA(t *testing.T) {
	console := newIdentityConsole(t)
	client, err := agentapi.NewClient(console.server.URL, testToken("pss_user:v1:"), console.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	keystore := &memoryPrivateKeyStore{values: map[string]string{}}
	directory := t.TempDir()
	runtime := &Runtime{Client: client, WorkflowID: "workflow-1", CAStore: proxy.CAStore{Directory: directory, Keyring: keystore}}
	session := served(t, runtime)
	if session.Inventory == nil || session.Inventory.Directory != directory || session.Inventory.Keyring != proxy.PrivateKeyStore(keystore) {
		t.Fatalf("the session's inventory store is not beside its CA: %+v", session)
	}
	if !session.Identity.Known() || session.Inventory.Tenant != session.Identity.Tenant {
		t.Fatalf("the session's store is not its own tenant's: %q and %q", session.Inventory.Tenant, session.Identity.Tenant)
	}
}

// Who a session is comes from the Console, for the token it was opened with,
// of every kind. Nothing is read from the login file for it.
func TestSessionIdentityIsWhatTheConsoleSaysTheTokenIs(t *testing.T) {
	// A login file that says something else entirely: it is never asked.
	previous := config.ConfigFilePath
	config.ConfigFilePath = filepath.Join(t.TempDir(), "config.json")
	t.Cleanup(func() { config.ConfigFilePath = previous })
	elsewhere := "org-of-the-login-file"
	saved, _ := json.Marshal(config.Config{DefaultUser: "file-account", PhaseUsers: []config.UserConfig{{Host: "https://file.test", ID: "file-account", OrganizationID: &elsewhere}}})
	if err := os.WriteFile(config.ConfigFilePath, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	console := newIdentityConsole(t)
	origin := strings.ToLower(console.server.URL)
	for name, c := range map[string]struct {
		token, workflow string
		login           string
	}{
		"a user's token":            {testToken("pss_user:v1:"), "workflow-1", origin + "\nuser\naccount-1"},
		"a service account's token": {testToken("pss_service:v2:"), "workflow-1", origin + "\nservice-account\nservice-account-7"},
		"an Agent's token":          {testToken("pss_agent:v1:"), "", origin + "\nagent\nagent-9"},
	} {
		// The host spelled as a login might spell it: one tenant all the same.
		for _, host := range []string{console.server.URL, strings.ToUpper(console.server.URL[:4]) + console.server.URL[4:] + "/", console.server.URL + "/service/public"} {
			client, err := agentapi.NewClient(host, c.token, console.server.Client())
			if err != nil {
				t.Fatalf("%s at %s: %v", name, host, err)
			}
			runtime := &Runtime{Client: client, WorkflowID: c.workflow, CAStore: proxy.CAStore{Directory: t.TempDir(), Keyring: &memoryPrivateKeyStore{values: map[string]string{}}}}
			session := served(t, runtime)
			if want := (proxy.InventoryIdentity{Tenant: origin + "\norganisation\norg-1", Login: c.login}); session.Identity != want || session.Inventory.Tenant != want.Tenant {
				t.Fatalf("%s at %s: the session is %q, %q", name, host, session.Identity.Tenant, session.Identity.Login)
			}
			if strings.Contains(session.Identity.Tenant+session.Identity.Login, "file") || strings.Contains(session.Identity.Tenant+session.Identity.Login, strings.Repeat("a", 64)) {
				t.Fatalf("%s: the identity holds something of the login file or the token", name)
			}
			// Every later session of the runtime is the same token's: the
			// Console is asked once, and a recycled session is the same one's.
			asked := console.asked.Load()
			if again := served(t, runtime); again.Identity != session.Identity || console.asked.Load() != asked {
				t.Fatalf("%s: a recycled session asked the Console again, or is another's", name)
			}
		}
	}
}

// When the Console does not say who the token is, the session has no
// identity and its store no tenant. Nothing is guessed.
func TestSessionWithNoWordFromTheConsoleHasNoIdentity(t *testing.T) {
	previous := config.ConfigFilePath
	config.ConfigFilePath = filepath.Join(t.TempDir(), "config.json")
	t.Cleanup(func() { config.ConfigFilePath = previous })
	organisation := "org-1"
	saved, _ := json.Marshal(config.Config{DefaultUser: "account-1", PhaseUsers: []config.UserConfig{{Host: "https://console.test", ID: "account-1", OrganizationID: &organisation}}})
	if err := os.WriteFile(config.ConfigFilePath, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	console := newIdentityConsole(t)
	answers := map[string]func(){
		"an error":           func() { console.failing.Store(true) },
		"no organisation":    func() { console.account = `{"user_id":"account-1","organisation":null}` },
		"an empty one":       func() { console.account = `{"user_id":"account-1","organisation":{"id":""}}` },
		"no account":         func() { console.account = `{"account_id":"a-service-account","organisation":{"id":"org-1"}}` },
		"an id it cannot be": func() { console.account = `{"user_id":"account-1\nagent\nother","organisation":{"id":"org-1"}}` },
		"not JSON":           func() { console.account = `<html>` },
	}
	for name, set := range answers {
		console.failing.Store(false)
		set()
		client, err := agentapi.NewClient(console.server.URL, testToken("pss_user:v1:"), console.server.Client())
		if err != nil {
			t.Fatal(err)
		}
		runtime := &Runtime{Client: client, WorkflowID: "workflow-1", CAStore: proxy.CAStore{Directory: t.TempDir(), Keyring: &memoryPrivateKeyStore{values: map[string]string{}}}}
		session := served(t, runtime)
		if session.Identity != (proxy.InventoryIdentity{}) || session.Inventory == nil || session.Inventory.Tenant != "" {
			t.Fatalf("%s: the session was given an identity: %q %q, store tenant %q", name, session.Identity.Tenant, session.Identity.Login, session.Inventory.Tenant)
		}
		inventory, loaded, err := session.Inventory.Open()
		if err != nil || len(loaded) != 0 || inventory.Status().Durable || inventory.Status().Reason != proxy.InventoryReasonNoTenant {
			t.Fatalf("%s: a store with no tenant: %v", name, err)
		}
		// It stays so for the runtime's life, whatever the Console says later.
		console.failing.Store(false)
		console.account = `{"user_id":"account-1","organisation":{"id":"org-1"}}`
		if again := served(t, runtime); again.Identity != (proxy.InventoryIdentity{}) {
			t.Fatalf("%s: a later session of the runtime changed identity", name)
		}
	}
}

// A start takes one look at the login: the host and the token are one
// account's, whatever the default account becomes while the keystore answers.
func TestRuntimeStartTakesOneLookAtTheLogin(t *testing.T) {
	previous := config.ConfigFilePath
	config.ConfigFilePath = filepath.Join(t.TempDir(), "config.json")
	aiPrevious := config.AIConfigPath
	config.AIConfigPath = filepath.Join(t.TempDir(), "ai.json")
	t.Cleanup(func() { config.ConfigFilePath, config.AIConfigPath = previous, aiPrevious })
	t.Setenv("PHASE_SERVICE_TOKEN", "")
	t.Setenv("PHASE_HOST", "")
	if err := config.SaveAIConfig(&config.AIConfig{Enabled: true, DefaultWorkflowID: "workflow-1"}); err != nil {
		t.Fatal(err)
	}
	looks := 0
	looked := activeLogin
	activeLogin = func() (keyring.Login, error) {
		looks++
		return keyring.Login{Token: testToken("pss_user:v1:"), Host: "https://one.test"}, nil
	}
	t.Cleanup(func() { activeLogin = looked })
	runtime, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if looks != 1 || runtime.Client.Host() != "https://one.test" {
		t.Fatalf("%d looks at the login, host %q", looks, runtime.Client.Host())
	}
}
