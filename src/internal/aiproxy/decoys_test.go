package aiproxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

func headerInjectionSession(t *testing.T, credential, decoy string) *airuntime.ProxySession {
	t.Helper()
	session := decodeTestSession(t, map[string]any{
		"schemaVersion": 1, "sessionUid": "session-decoys", "sessionCredential": credential,
		"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
		"configGeneration": 1, "configEnv": map[string]string{},
		"connections": []any{
			map[string]any{
				"grantId": "grant-api", "connectionId": "api", "credentialId": "api-cred", "serviceType": "example", "protocol": "http",
				"hosts":       []any{map[string]any{"match": "exact", "value": "api.example.test", "port": 443}},
				"injection":   map[string]any{"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}", "valueFrom": map[string]any{"source": "credential", "field": "token"}},
				"identifiers": map[string]string{}, "decoyMaterial": map[string]string{"token": decoy},
				"configEnv": map[string]string{}, "agentEnv": map[string]string{}, "environmentBindings": []any{},
				"secretMaterial": map[string]string{"token": "live-token"},
			},
		},
	})
	client, err := agentapi.NewClient("https://console.phase.dev", durableTestToken(), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	ca, _, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &airuntime.ProxySession{Config: session, Client: client, CA: ca}
}

func postgresSession(t *testing.T, credential, decoy string) *airuntime.ProxySession {
	t.Helper()
	session := decodeTestSession(t, map[string]any{
		"schemaVersion": 1, "sessionUid": "session-pg", "sessionCredential": credential,
		"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
		"configGeneration": 1, "configEnv": map[string]string{},
		"connections": []any{
			map[string]any{
				"grantId": "grant-pg", "connectionId": "pg", "credentialId": "pg-cred", "serviceType": "postgres", "protocol": "postgres",
				"hosts":       []any{map[string]any{"match": "exact", "value": "127.0.0.1", "port": 5432}},
				"injection":   map[string]any{"action": "pg_handshake", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}}},
				"identifiers": map[string]string{"username": "db_user"}, "decoyMaterial": map[string]string{"password": decoy},
				"configEnv": map[string]string{}, "agentEnv": map[string]string{"PGUSER": "db_user"},
				"environmentBindings": []any{map[string]any{"name": "PGUSER", "action": "set", "source": "identifier", "sourceField": "username", "sensitive": false, "systemManaged": true}},
				"secretMaterial":      map[string]string{"username": "db_user", "password": "live-db-password"},
			},
		},
	})
	client, err := agentapi.NewClient("https://console.phase.dev", durableTestToken(), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	ca, _, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &airuntime.ProxySession{Config: session, Client: client, CA: ca}
}

func TestDecoyHistoryRemembersGenerationsPerConnection(t *testing.T) {
	history := newDecoyHistory()
	first := headerInjectionSession(t, "backend-one", "decoy-one").Config.Connections[0]
	second := headerInjectionSession(t, "backend-two", "decoy-two").Config.Connections[0]
	history.remember([]agentapi.Connection{first})
	history.remember([]agentapi.Connection{first})
	views := history.previous(second)
	if len(views) != 1 || views[0].DecoyMaterial["token"] != "decoy-one" || views[0].ConnectionID != "api" {
		t.Fatalf("previous generations = %+v", views)
	}
	if live, _ := views[0].SecretMaterial.Get("token"); live != "live-token" {
		t.Fatal("historical view must keep the live secret material")
	}
	history.remember([]agentapi.Connection{second})
	if views := history.previous(second); len(views) != 1 || views[0].DecoyMaterial["token"] != "decoy-one" {
		t.Fatalf("current generation must be excluded from previous views: %+v", views)
	}
	if views := history.previous(first); len(views) != 1 || views[0].DecoyMaterial["token"] != "decoy-two" {
		t.Fatalf("history is symmetric per Connection: %+v", views)
	}
	other := second
	other.ConnectionID = "other"
	if views := history.previous(other); len(views) != 0 {
		t.Fatalf("history leaked across Connections: %+v", views)
	}
	if history.previous(agentapi.Connection{}) != nil {
		t.Fatal("empty Connection must have no history")
	}
	var nilHistory *decoyHistory
	nilHistory.remember([]agentapi.Connection{first})
	if nilHistory.previous(first) != nil {
		t.Fatal("nil history must be inert")
	}
}

func TestHTTPInjectionAcceptsPreviouslyIssuedDecoy(t *testing.T) {
	engine := New()
	previous := headerInjectionSession(t, "backend-one", "decoy-one")
	engine.decoyHistory().remember(previous.Config.Connections)
	current := headerInjectionSession(t, "backend-two", "decoy-two")
	state, err := newRuntimeStateWithCapability(current, "runtime-capability")
	if err != nil {
		t.Fatal(err)
	}
	state.decoys = engine.decoyHistory()
	state.decoys.remember(current.Config.Connections)
	connection := state.bindings[0].connection

	stale, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/me", nil)
	stale.Header.Set("Authorization", "Bearer decoy-one")
	result, err := applyHTTPInjectionWithHistory(stale, connection, state.previousDecoyViews(connection))
	if err != nil || result.Action != "set_header" || stale.Header.Get("Authorization") != "Bearer live-token" {
		t.Fatalf("stale decoy was not translated: result=%+v err=%v header=%q", result, err, stale.Header.Get("Authorization"))
	}
	fresh, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/me", nil)
	fresh.Header.Set("Authorization", "Bearer decoy-two")
	if _, err := applyHTTPInjectionWithHistory(fresh, connection, state.previousDecoyViews(connection)); err != nil || fresh.Header.Get("Authorization") != "Bearer live-token" {
		t.Fatalf("current decoy failed: %v", err)
	}
	unknown, _ := http.NewRequest(http.MethodGet, "https://api.example.test/v1/me", nil)
	unknown.Header.Set("Authorization", "Bearer never-issued")
	_, unknownErr := applyHTTPInjectionWithHistory(unknown, connection, state.previousDecoyViews(connection))
	if unknownErr == nil || unknown.Header.Get("Authorization") != "Bearer never-issued" {
		t.Fatalf("unknown decoy was accepted or the request was mutated: err=%v header=%q", unknownErr, unknown.Header.Get("Authorization"))
	}
	if !staleDecoyInjectionFailure(unknownErr) {
		t.Fatalf("swap miss must classify as a stale-decoy failure: %v", unknownErr)
	}
	if staleDecoyInjectionFailure(&phaseproxy.InjectionError{Code: phaseproxy.InjectionMissingMaterial}) {
		t.Fatal("missing material must not be retried against older generations")
	}
	if !staleDecoyInjectionFailure(&phaseproxy.InjectionError{Code: phaseproxy.InjectionFinalizerFailed, AWSSigV4Failure: phaseproxy.AWSSigV4AccessKeyMismatch}) {
		t.Fatal("SigV4 access-key mismatch must retry older generations")
	}
}

func TestProtocolBindingSelectionAcceptsPreviouslyIssuedDecoy(t *testing.T) {
	engine := New()
	previous := postgresSession(t, "backend-one", "decoy-one")
	engine.decoyHistory().remember(previous.Config.Connections)
	current := postgresSession(t, "backend-two", "decoy-two")
	state, err := newRuntimeStateWithCapability(current, "runtime-capability")
	if err != nil {
		t.Fatal(err)
	}
	state.decoys = engine.decoyHistory()
	state.decoys.remember(current.Config.Connections)
	for _, decoy := range []string{"decoy-one", "decoy-two"} {
		snapshot, err := state.selectProtocolBinding("postgres", "db_user", decoy, "")
		if err != nil {
			t.Fatalf("decoy %q was rejected: %v", decoy, err)
		}
		if live, _ := snapshot.binding.connection.SecretMaterial.Get("password"); live != "live-db-password" {
			t.Fatal("selection must resolve to the live binding")
		}
		snapshot.release()
	}
	if _, err := state.selectProtocolBinding("postgres", "db_user", "never-issued", ""); err == nil {
		t.Fatal("unknown decoy was accepted")
	}
	if _, err := state.selectProtocolBinding("postgres", "other_user", "decoy-one", ""); err == nil {
		t.Fatal("historical decoy must not match another username")
	}
}

func TestEngineKeepsCapabilityAndHistoryAcrossSessions(t *testing.T) {
	engine := New()
	first, err := engine.processRuntimeCapability("backend-one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.processRuntimeCapability("backend-two")
	if err != nil || second.Reveal() != first.Reveal() {
		t.Fatalf("relay capability must be stable across sessions: %v", err)
	}
	if engine.decoyHistory() != engine.decoyHistory() {
		t.Fatal("decoy history must be shared by every session of one Engine")
	}
	if (&Engine{}).decoyHistory() == nil {
		t.Fatal("zero Engine must create its history lazily")
	}
}
