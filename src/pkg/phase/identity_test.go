package phase

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
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	gokeyring "github.com/zalando/go-keyring"
)

// isolateLogins gives the test a login file and a keystore of its own, set
// before anything reads either, and no token or host in the environment.
func isolateLogins(t *testing.T, users ...config.UserConfig) {
	t.Helper()
	gokeyring.MockInit()
	isolateHarness(t, "", "")
	directory := t.TempDir()
	previousFile, previousDirectory := config.ConfigFilePath, config.PhaseSecretsDir
	config.PhaseSecretsDir, config.ConfigFilePath = directory, filepath.Join(directory, "config.json")
	t.Cleanup(func() {
		config.ConfigFilePath, config.PhaseSecretsDir = previousFile, previousDirectory
		rememberLogin(nil, "")
		ai.SetAgentLogin(false)
	})
	for _, name := range []string{"PHASE_SERVICE_TOKEN", "PHASE_HOST", "PHASE_OFFLINE"} {
		t.Setenv(name, "")
	}
	rememberLogin(nil, "")
	if len(users) > 0 {
		saved, err := json.Marshal(config.Config{DefaultUser: users[0].ID, PhaseUsers: users})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(config.ConfigFilePath, saved, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func serviceAccountToken() string {
	return strings.Replace(testToken("pss_service:"), "pss_service:v1:", "pss_service:v2:", 1)
}

// identityConsole says who a token is, on the route a login is saved from
// and on the Agent identity route, and counts what it was asked.
func identityConsole(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var asked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/service/secrets/tokens/":
			asked.Add(1)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"user_id":"console-user","account_id":"console-service-account","organisation":{"id":"console-org","name":"an organisation"},"apps":[]}`))
		case "/service/public/v1/agents/identity/":
			asked.Add(1)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"schemaVersion":1,"principalType":"agent","agent":{"id":"console-agent","name":"an Agent"},"workflow":{"id":"w","name":"a Workflow"},"organization":{"id":"console-org","name":"an organisation"}}`))
		default:
			_, _ = w.Write([]byte(`{"schemaVersion":1,"apps":[],"expired":[]}`))
		}
	}))
	t.Cleanup(server.Close)
	return server, &asked
}

// A command says it is the login its backend was built from. The default
// account changing afterwards, as phase users switch does, changes nothing.
func TestLoginIdentityIsTheSavedLoginTheBackendWasBuiltFrom(t *testing.T) {
	orgA, orgB := "org-a", "org-b"
	isolateLogins(t,
		config.UserConfig{Host: "https://A.Example.test/", ID: "account-a", OrganizationID: &orgA, Token: testToken("pss_user:")},
		config.UserConfig{Host: "https://b.example.test:8443", ID: "account-b", OrganizationID: &orgB, Token: serviceAccountToken()},
		config.UserConfig{Host: "https://a.example.test", ID: "account-c", Token: testToken("pss_user:")},
	)
	if got := LoginIdentity(context.Background()); got.Known() {
		t.Fatalf("a command with no backend says it is %q", got.Login)
	}
	if _, err := NewPhase(true, "", ""); err != nil {
		t.Fatal(err)
	}
	// phase users switch, after this command read its token.
	if err := config.SetDefaultUser("account-b"); err != nil {
		t.Fatal(err)
	}
	wantA := phaseproxy.NewInventoryIdentity("https://a.example.test", "org-a", phaseproxy.InventoryLoginUser, "account-a")
	if got := LoginIdentity(context.Background()); got != wantA || !got.Known() {
		t.Fatalf("after a switch the command says it is %q of %q", got.Login, got.Tenant)
	}
	// The next command is the other login's: a service account's, by its token.
	if _, err := NewPhase(true, "", ""); err != nil {
		t.Fatal(err)
	}
	wantB := phaseproxy.NewInventoryIdentity("https://b.example.test:8443", "org-b", phaseproxy.InventoryLoginServiceAccount, "account-b")
	if got := LoginIdentity(context.Background()); got != wantB || got.SameTenant(wantA) {
		t.Fatalf("the second command says it is %q of %q", got.Login, got.Tenant)
	}
	// A login that saved no organisation cannot tell, and one logged out
	// while its command ran has no record to tell from: neither is guessed.
	for _, account := range []string{"account-c", "account-a"} {
		if err := config.SetDefaultUser(account); err != nil {
			t.Fatal(err)
		}
		if _, err := NewPhase(true, "", ""); err != nil {
			t.Fatal(err)
		}
		if account == "account-a" {
			if err := config.RemoveUser(account); err != nil {
				t.Fatal(err)
			}
		}
		if got := LoginIdentity(context.Background()); got != (phaseproxy.InventoryIdentity{}) {
			t.Fatalf("%s: the command says it is %q of %q", account, got.Login, got.Tenant)
		}
	}
}

// A token from the environment has no saved login: the command asks the
// Console who it is, once, and is nobody when the Console does not say.
func TestLoginIdentityOfATokenFromTheEnvironmentIsTheConsolesWord(t *testing.T) {
	orgFile := "org-of-the-login-file"
	for name, c := range map[string]struct {
		token, kind, id string
	}{
		"a user's token":            {testToken("pss_user:"), phaseproxy.InventoryLoginUser, "console-user"},
		"a service account's token": {serviceAccountToken(), phaseproxy.InventoryLoginServiceAccount, "console-service-account"},
		"an Agent's token":          {testToken("pss_agent:"), phaseproxy.InventoryLoginAgent, "console-agent"},
	} {
		isolateLogins(t, config.UserConfig{Host: "https://file.test", ID: "file-account", OrganizationID: &orgFile, Token: testToken("pss_user:")})
		console, asked := identityConsole(t, http.StatusOK)
		t.Setenv("PHASE_SERVICE_TOKEN", c.token)
		t.Setenv("PHASE_HOST", console.URL)
		if _, err := NewBackend(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := phaseproxy.NewInventoryIdentity(console.URL, "console-org", c.kind, c.id)
		for range 2 {
			if got := LoginIdentity(context.Background()); got != want || !got.Known() || strings.Contains(got.Tenant+got.Login, "file") {
				t.Fatalf("%s: the command says it is %q of %q", name, got.Login, got.Tenant)
			}
		}
		if asked.Load() != 1 {
			t.Fatalf("%s: the Console was asked %d times", name, asked.Load())
		}
		// The Console does not say: nobody, and the login file is not asked.
		refusing, _ := identityConsole(t, http.StatusInternalServerError)
		t.Setenv("PHASE_HOST", refusing.URL)
		if _, err := NewBackend(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := LoginIdentity(context.Background()); got != (phaseproxy.InventoryIdentity{}) {
			t.Fatalf("%s: with no word from the Console the command says it is %q", name, got.Login)
		}
	}
	// A legacy service token is no kind of login the Console names.
	isolateLogins(t)
	console, _ := identityConsole(t, http.StatusOK)
	t.Setenv("PHASE_SERVICE_TOKEN", testToken("pss_service:"))
	t.Setenv("PHASE_HOST", console.URL)
	if _, err := NewBackend(); err != nil {
		t.Fatal(err)
	}
	if got := LoginIdentity(context.Background()); got.Known() {
		t.Fatalf("a legacy service token says it is %q", got.Login)
	}
}

// A saved Agent login says who it is from its own record, with no call.
func TestLoginIdentityOfASavedAgentLogin(t *testing.T) {
	organisation := "org-a"
	console, asked := identityConsole(t, http.StatusOK)
	isolateLogins(t, config.UserConfig{
		Host: console.URL, ID: "agent-local", PrincipalType: config.PrincipalAgent, PrincipalID: "agent-9", OrganizationID: &organisation, Token: testToken("pss_agent:"),
	})
	if _, err := NewBackend(); err != nil {
		t.Fatal(err)
	}
	want := phaseproxy.NewInventoryIdentity(console.URL, "org-a", phaseproxy.InventoryLoginAgent, "agent-9")
	if got := LoginIdentity(context.Background()); got != want || !got.Known() || asked.Load() != 0 {
		t.Fatalf("a saved Agent login says it is %q, after %d calls", got.Login, asked.Load())
	}
	// A record of one kind and a token of another names nobody.
	user := config.UserConfig{Host: "https://console.test", ID: "account-a", OrganizationID: &organisation}
	if got := SavedLoginIdentity(user.Host, phaseproxy.InventoryLoginAgent, user); got.Known() {
		t.Fatalf("a user's record with an Agent's token: %q", got.Login)
	}
	agent := config.UserConfig{Host: "https://console.test", ID: "agent-local", PrincipalType: config.PrincipalAgent, PrincipalID: "agent-9", OrganizationID: &organisation}
	if got := SavedLoginIdentity(agent.Host, phaseproxy.InventoryLoginUser, agent); got.Known() {
		t.Fatalf("an Agent's record with a user's token: %q", got.Login)
	}
}

// memoryKeystore stands in for the system keystore a proxy keeps its CA key in.
type memoryKeystore map[string]string

func (m memoryKeystore) Get(service, user string) (string, error) {
	value, ok := m[service+"/"+user]
	if !ok {
		return "", gokeyring.ErrNotFound
	}
	return value, nil
}

func (m memoryKeystore) Set(service, user, value string) error {
	m[service+"/"+user] = value
	return nil
}

// identityEngine keeps the identity of the session a runtime hands it.
type identityEngine struct{ served *phaseproxy.InventoryIdentity }

func (identityEngine) Ready() error { return nil }
func (identityEngine) Capabilities() airuntime.EngineCapabilities {
	return airuntime.EngineCapabilities{Protocols: []string{"http"}, InjectionActions: []string{"set_header"}}
}
func (e identityEngine) Serve(_ context.Context, session *airuntime.ProxySession) error {
	*e.served = session.Identity
	return nil
}
func (identityEngine) Run(context.Context, *airuntime.ProxySession, []string) error { return nil }

// One login is the same to a command and to the proxy of a session it opens,
// or the command would be a guest of its own proxy and nothing would be stored.
func TestACommandAndItsProxySayTheSameOfOneLogin(t *testing.T) {
	// The Console's ids: a user token's user_id, on the route a login is saved
	// from, is its organisation member's id, and so is its session's principal.
	const organisation, member, agent = "0b5e7c1a-1111-4222-8333-444455556666", "9f1c2d3e-aaaa-4bbb-8ccc-ddddeeeeffff", "5d2a9c47-0000-4abc-8def-123456789abc"
	// The Console is served at the origin's root and under a path as well.
	const under = "/deployed/here"
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		kind, _, _ := strings.Cut(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), " ")
		// Slashes are merged, as the web server in front of a Console does.
		r.URL.Path = strings.ReplaceAll(strings.TrimPrefix(r.URL.Path, under), "//", "/")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions/"):
			principal := `{"type":"user","id":"` + member + `"}`
			if kind == "Agent" {
				principal = `{"type":"agent","id":"` + agent + `"}`
			}
			_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"a-session","sessionCredential":"a-session-capability","expiresAt":"` +
				time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `","configGeneration":1,"configEnv":{},"connections":[],"organisation":{"id":"` + organisation + `"},"principal":` + principal + `}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revoke/"):
			_, _ = w.Write([]byte(`{"schemaVersion":1,"sessionUid":"a-session","revokedAt":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
		case r.URL.Path == "/service/secrets/tokens/":
			_, _ = w.Write([]byte(`{"user_id":"` + member + `","organisation":{"id":"` + organisation + `","name":"an organisation"},"apps":[]}`))
		case r.URL.Path == "/service/public/v1/agents/identity/":
			_, _ = w.Write([]byte(`{"schemaVersion":1,"principalType":"agent","agent":{"id":"` + agent + `","name":"an Agent"},"workflow":{"id":"w","name":"a Workflow"},"organization":{"id":"` + organisation + `","name":"an organisation"}}`))
		default:
			_, _ = w.Write([]byte(`{"schemaVersion":1,"apps":[],"expired":[]}`))
		}
	}))
	t.Cleanup(console.Close)
	org := organisation
	for name, c := range map[string]struct {
		token, workflow, kind, id string
		// saved is the login's record as phase auth writes it, nil for a
		// token from the environment.
		saved *config.UserConfig
	}{
		"a saved user login":                    {testToken("pss_user:"), "workflow-1", "user", member, &config.UserConfig{ID: member, OrganizationID: &org}},
		"a user's token from the environment":   {testToken("pss_user:"), "workflow-1", "user", member, nil},
		"a saved Agent login":                   {testToken("pss_agent:"), "", "agent", agent, &config.UserConfig{ID: "agent-local", PrincipalType: config.PrincipalAgent, PrincipalID: agent, OrganizationID: &org}},
		"an Agent's token from the environment": {testToken("pss_agent:"), "", "agent", agent, nil},
	} {
		// The host as a login has it: at the root, and under a path with and
		// without a slash after it. Each is one tenant to both, and the two
		// Consoles of the origin are never the same one.
		for host, served := range map[string]string{console.URL: console.URL, console.URL + under: console.URL + under, console.URL + under + "/": console.URL + under} {
			if c.saved != nil {
				saved := *c.saved
				saved.Host, saved.Token = host, c.token
				isolateLogins(t, saved)
			} else {
				isolateLogins(t)
				t.Setenv("PHASE_SERVICE_TOKEN", c.token)
				t.Setenv("PHASE_HOST", host)
			}
			if _, err := NewBackend(); err != nil {
				t.Fatalf("%s at %s: %v", name, host, err)
			}
			command := LoginIdentity(context.Background())
			client, err := agentapi.NewClient(host, c.token, console.Client())
			if err != nil {
				t.Fatalf("%s at %s: %v", name, host, err)
			}
			var proxy phaseproxy.InventoryIdentity
			runtime := &airuntime.Runtime{Client: client, WorkflowID: c.workflow, CAStore: phaseproxy.CAStore{Directory: t.TempDir(), Keyring: memoryKeystore{}}}
			if err := runtime.ServeManaged(context.Background(), identityEngine{&proxy}); err != nil {
				t.Fatalf("%s at %s: %v", name, host, err)
			}
			want := phaseproxy.InventoryIdentity{
				Tenant: served + "\norganisation\n" + organisation, Login: served + "\n" + c.kind + "\n" + c.id,
			}
			if command != want || proxy != want || !command.Is(proxy) {
				t.Fatalf("%s at %s: the command says %q of %q and its proxy %q of %q", name, host, command.Login, command.Tenant, proxy.Login, proxy.Tenant)
			}
			// What a logout would forget is the same login's, by the same rule.
			if c.saved != nil {
				saved := *c.saved
				saved.Host = host
				if logout := SavedLoginIdentity(host, c.kind, saved); logout != want {
					t.Fatalf("%s at %s: a logout would forget %q of %q", name, host, logout.Login, logout.Tenant)
				}
			}
		}
	}
}
