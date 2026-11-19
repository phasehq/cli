package airuntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
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
	runtime := &Runtime{Client: client, WorkflowID: "workflow-1", CAStore: proxy.CAStore{Directory: directory, Keyring: keystore}}
	if err := runtime.ServeManaged(context.Background(), sessionCapturingEngine{countingServeEngine{calls: &calls}, &session}); err != nil {
		t.Fatal(err)
	}
	if session == nil || session.Inventory == nil || session.Inventory.Directory != directory || session.Inventory.Keyring != proxy.PrivateKeyStore(keystore) {
		t.Fatalf("the session's inventory store is not beside its CA: %+v", session)
	}
}
