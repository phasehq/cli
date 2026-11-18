package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/phasehq/cli/pkg/config"
	gokeyring "github.com/zalando/go-keyring"
)

// Purging all local data takes the Phase AI directory with it: the lifecycle
// log, audit events that were never delivered, and the CA key in the keystore.
func TestLogoutPurgeRemovesPhaseAIDataAndTheCAKey(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	gokeyring.MockInit()
	home := filepath.Dir(config.PhaseSecretsDir)
	aiDirectory := filepath.Join(home, "ai")
	originalDirectory := hookRuntimeDir
	hookRuntimeDir = func() (string, error) { return aiDirectory, nil }
	t.Cleanup(func() { hookRuntimeDir = originalDirectory })

	if err := config.AddUser(config.UserConfig{Host: console.server.URL, ID: "user-1"}); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(aiDirectory, "event-spool", "0123456789abcdef0123456789abcdef")
	if err := os.MkdirAll(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(spool, "event.json"), filepath.Join(aiDirectory, "runtime.log"), filepath.Join(aiDirectory, "ca.pem")} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := gokeyring.Set("phase-cli-ai-proxy-ca", "private-key-v1", "key"); err != nil {
		t.Fatal(err)
	}

	if _, stderr, err := runPhaseCommand(t, "", "users", "logout", "--purge"); err != nil {
		t.Fatalf("purge: %v %s", err, stderr)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("%s still exists after purge: %v", home, err)
	}
	if _, err := gokeyring.Get("phase-cli-ai-proxy-ca", "private-key-v1"); err != gokeyring.ErrNotFound {
		t.Fatalf("the CA key is still in the keystore: %v", err)
	}
}
