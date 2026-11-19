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

// The proxy's leak protection inventory is kept where its CA is: the same
// directory, the same keystore. A test's fakes, and a machine's own store,
// therefore cover both.
func TestSessionCarriesTheInventoryStoreBesideTheCA(t *testing.T) {
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "inventory-session", "sessionCredential": "inventory-session-capability",
				"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
				"configGeneration": 1, "configEnv": map[string]string{}, "connections": []any{},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revoke/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "inventory-session", "revokedAt": time.Now().UTC()})
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
	keystore := &memoryPrivateKeyStore{values: map[string]string{}}
	directory := t.TempDir()
	var session *ProxySession
	var calls atomic.Int32
	runtime := &Runtime{Client: client, WorkflowID: "workflow-1", CAStore: proxy.CAStore{Directory: directory, Keyring: keystore}, Tenant: "https://console.test\norganisation\norg-1", Principal: "https://console.test\naccount\naccount-1"}
	if err := runtime.ServeManaged(context.Background(), sessionCapturingEngine{countingServeEngine{calls: &calls}, &session}); err != nil {
		t.Fatal(err)
	}
	if session == nil || session.Inventory == nil || session.Inventory.Directory != directory || session.Inventory.Keyring != proxy.PrivateKeyStore(keystore) {
		t.Fatalf("the session's inventory store is not beside its CA: %+v", session)
	}
	if session.Principal != runtime.Principal || session.Inventory.Tenant != runtime.Tenant {
		t.Fatalf("the session does not carry the runtime's login: %q", session.Principal)
	}
}

// A saved login's tenant is its host and organisation, and its own id when
// it saved none. A token from the environment has neither: nothing is kept.
func TestSavedLoginNamesItsTenantAndPrincipal(t *testing.T) {
	previous := config.ConfigFilePath
	config.ConfigFilePath = filepath.Join(t.TempDir(), "config.json")
	t.Cleanup(func() { config.ConfigFilePath = previous })
	t.Setenv("PHASE_SERVICE_TOKEN", "")
	write := func(user config.UserConfig) {
		t.Helper()
		user.Token = "not-in-any-name"
		data, err := json.Marshal(config.Config{DefaultUser: user.ID, PhaseUsers: []config.UserConfig{user}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(config.ConfigFilePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if tenant, principal := savedLogin("https://console.test"); tenant != "" || principal != "" {
		t.Fatalf("no saved login: %q %q", tenant, principal)
	}
	organisation, blank := "org-1", " "
	const host = "https://console.test"
	for name, c := range map[string]struct {
		user              config.UserConfig
		tenant, principal string
	}{
		"a member":                      {config.UserConfig{ID: "account-1", OrganizationID: &organisation}, host + "\norganisation\norg-1", host + "\naccount\naccount-1"},
		"an Agent":                      {config.UserConfig{ID: "account-2", PrincipalType: config.PrincipalAgent, PrincipalID: "agent-9", OrganizationID: &organisation}, host + "\norganisation\norg-1", host + "\nagent\nagent-9"},
		"no organisation":               {config.UserConfig{ID: "account-3"}, host + "\naccount\naccount-3", host + "\naccount\naccount-3"},
		"a blank organisation":          {config.UserConfig{ID: "account-4", OrganizationID: &blank}, host + "\naccount\naccount-4", host + "\naccount\naccount-4"},
		"an Agent with no organisation": {config.UserConfig{ID: "account-5", PrincipalType: config.PrincipalAgent, PrincipalID: "agent-5"}, host + "\nagent\nagent-5", host + "\nagent\nagent-5"},
	} {
		write(c.user)
		tenant, principal := savedLogin("https://Console.test/")
		if tenant != c.tenant || principal != c.principal || strings.Contains(tenant+principal, "not-in-any-name") {
			t.Fatalf("%s: tenant %q, principal %q", name, tenant, principal)
		}
		if other, _ := savedLogin("https://other.test"); other == tenant {
			t.Fatalf("%s: another host is the same tenant", name)
		}
	}
	t.Setenv("PHASE_SERVICE_TOKEN", "a-token-from-the-environment")
	if tenant, principal := savedLogin(host); tenant != "" || principal != "" {
		t.Fatalf("a token from the environment named a saved login: %q %q", tenant, principal)
	}
}
