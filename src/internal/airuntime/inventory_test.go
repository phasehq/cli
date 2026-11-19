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

// identityConsole is a Console that opens sessions, and says in each whose it
// is: the two members a session payload carries. It counts what else it is asked.
type identityConsole struct {
	server *httptest.Server
	// identity is the session payload's members for a token of each kind, as
	// JSON after a comma, or "" for a Console that predates them.
	identity map[string]string
	sessions atomic.Int32
	others   atomic.Int32
}

// The ids are a Console's: the Agent's own, and for a user's token the
// organisation member's, which is what a login is saved under.
const (
	agentSessionIdentity = `,"organisation":{"id":"org-1"},"principal":{"type":"agent","id":"agent-9"}`
	userSessionIdentity  = `,"organisation":{"id":"org-1"},"principal":{"type":"user","id":"member-1"}`
)

func newIdentityConsole(t *testing.T) *identityConsole {
	t.Helper()
	console := &identityConsole{identity: map[string]string{"Agent": agentSessionIdentity, "User": userSessionIdentity}}
	console.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions/"):
			console.sessions.Add(1)
			kind, _, _ := strings.Cut(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), " ")
			_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"inventory-session","sessionCredential":"inventory-session-capability","expiresAt":"` +
				time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `","configGeneration":1,"configEnv":{},"connections":[]` + console.identity[kind] + `}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revoke/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "inventory-session", "revokedAt": time.Now().UTC()})
		default:
			console.others.Add(1)
			w.WriteHeader(http.StatusNotFound)
		}
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

// Who a session is comes from the session the Console opened, for a token of
// either kind that opens one. No other route is asked, and no file is read.
func TestSessionIdentityIsWhatItsSessionSays(t *testing.T) {
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
		"a user's token":   {testToken("pss_user:v1:"), "workflow-1", origin + "\nuser\nmember-1"},
		"an Agent's token": {testToken("pss_agent:v1:"), "", origin + "\nagent\nagent-9"},
	} {
		// The host spelled as a login might spell it: one tenant all the same.
		for _, host := range []string{console.server.URL, strings.ToUpper(console.server.URL[:4]) + console.server.URL[4:] + "/", console.server.URL + "/service/public"} {
			client, err := agentapi.NewClient(host, c.token, console.server.Client())
			if err != nil {
				t.Fatalf("%s at %s: %v", name, host, err)
			}
			runtime := &Runtime{Client: client, WorkflowID: c.workflow, CAStore: proxy.CAStore{Directory: t.TempDir(), Keyring: &memoryPrivateKeyStore{values: map[string]string{}}}}
			opened := console.sessions.Load()
			session := served(t, runtime)
			if want := (proxy.InventoryIdentity{Tenant: origin + "\norganisation\norg-1", Login: c.login}); session.Identity != want || session.Inventory.Tenant != want.Tenant {
				t.Fatalf("%s at %s: the session is %q, %q", name, host, session.Identity.Tenant, session.Identity.Login)
			}
			if strings.Contains(session.Identity.Tenant+session.Identity.Login, "file") || strings.Contains(session.Identity.Tenant+session.Identity.Login, strings.Repeat("a", 64)) {
				t.Fatalf("%s: the identity holds something of the login file or the token", name)
			}
			// A recycled session is the same one's.
			if again := served(t, runtime); again.Identity != session.Identity {
				t.Fatalf("%s: a recycled session is another's", name)
			}
			// A start costs the request that opens the session and no other.
			if console.sessions.Load() != opened+2 || console.others.Load() != 0 {
				t.Fatalf("%s: %d sessions opened and %d other requests", name, console.sessions.Load()-opened, console.others.Load())
			}
		}
	}
}

// A session that does not say whose it is, as an older Console's does not,
// has no identity and its store no tenant. Nothing is asked or guessed for it.
func TestSessionThatNamesNobodyHasNoIdentity(t *testing.T) {
	previous := config.ConfigFilePath
	config.ConfigFilePath = filepath.Join(t.TempDir(), "config.json")
	t.Cleanup(func() { config.ConfigFilePath = previous })
	organisation := "org-1"
	saved, _ := json.Marshal(config.Config{DefaultUser: "member-1", PhaseUsers: []config.UserConfig{{Host: "https://console.test", ID: "member-1", OrganizationID: &organisation}}})
	if err := os.WriteFile(config.ConfigFilePath, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	console := newIdentityConsole(t)
	serve := func(identity string) (*Runtime, *ProxySession) {
		t.Helper()
		console.identity["User"] = identity
		client, err := agentapi.NewClient(console.server.URL, testToken("pss_user:v1:"), console.server.Client())
		if err != nil {
			t.Fatal(err)
		}
		runtime := &Runtime{Client: client, WorkflowID: "workflow-1", CAStore: proxy.CAStore{Directory: t.TempDir(), Keyring: &memoryPrivateKeyStore{values: map[string]string{}}}}
		return runtime, served(t, runtime)
	}
	for name, identity := range map[string]string{
		"an older Console's":       ``,
		"no principal":             `,"organisation":{"id":"org-1"}`,
		"no organisation":          `,"principal":{"type":"user","id":"member-1"}`,
		"null members":             `,"organisation":null,"principal":null`,
		"an empty organisation":    `,"organisation":{"id":""},"principal":{"type":"user","id":"member-1"}`,
		"an empty principal":       `,"organisation":{"id":"org-1"},"principal":{"type":"user","id":""}`,
		"an id it cannot be":       `,"organisation":{"id":"org-1"},"principal":{"type":"user","id":"member-1\nagent\nother"}`,
		"a kind there is none of":  `,"organisation":{"id":"org-1"},"principal":{"type":"account","id":"member-1"}`,
		"another kind's principal": `,"organisation":{"id":"org-1"},"principal":{"type":"agent","id":"agent-9"}`,
		"a service account's":      `,"organisation":{"id":"org-1"},"principal":{"type":"service_account","id":"account-7"}`,
	} {
		runtime, session := serve(identity)
		if session.Identity != (proxy.InventoryIdentity{}) || session.Inventory == nil || session.Inventory.Tenant != "" {
			t.Fatalf("%s: the session was given an identity: %q %q, store tenant %q", name, session.Identity.Tenant, session.Identity.Login, session.Inventory.Tenant)
		}
		inventory, loaded, err := session.Inventory.Open()
		if err != nil || len(loaded) != 0 || inventory.Status().Durable || inventory.Status().Reason != proxy.InventoryReasonNoTenant {
			t.Fatalf("%s: a store with no tenant: %v", name, err)
		}
		// It stays so for the runtime's life, whatever a later session says:
		// its proxy was started with nothing to keep, and no other route is asked.
		console.identity["User"] = userSessionIdentity
		if again := served(t, runtime); again.Identity != (proxy.InventoryIdentity{}) {
			t.Fatalf("%s: a later session of the runtime changed identity", name)
		}
	}
	if console.others.Load() != 0 {
		t.Fatalf("the Console was asked %d other requests for a session that named nobody", console.others.Load())
	}
	// A runtime whose first session was named hands the engine what each later
	// one says, another's or nobody's, and the engine refuses what changed.
	runtime, first := serve(userSessionIdentity)
	console.identity["User"] = `,"organisation":{"id":"org-2"},"principal":{"type":"user","id":"member-1"}`
	other := served(t, runtime)
	console.identity["User"] = ``
	if nobody := served(t, runtime); !first.Identity.Known() || !other.Identity.Known() || other.Identity.SameTenant(first.Identity) || nobody.Identity.Known() {
		t.Fatalf("later sessions of a named runtime: %q then %q then %q", first.Identity.Tenant, other.Identity.Tenant, nobody.Identity.Tenant)
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
