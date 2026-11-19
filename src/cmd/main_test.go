package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/pkg/ai"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	gokeyring "github.com/zalando/go-keyring"
)

// TestMain points the Phase AI directory and the CA keystore at throwaway
// fakes, so a test that forgets to isolate them can never read or sweep the
// real ~/.phase/ai, system keystore or trust store.
func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "phase-cmd-test-ai-")
	if err != nil {
		panic(err)
	}
	hookRuntimeDir = func() (string, error) { return directory, nil }
	// The same for phase up: no test may read the real engine's state, or speak to
	// the helper that holds this machine's routes.
	tunnelStateDirectory = func() (string, error) { return filepath.Join(directory, "tunnel"), nil }
	tunnelHelperSocket = filepath.Join(directory, "no-helper.sock")
	aiCAStore = phaseproxy.CAStore{Directory: directory, Keyring: fixedKeyring{err: gokeyring.ErrNotFound}}
	// The stale-skill notice reads the home directory's skill paths; only its
	// own tests, which set a temporary HOME, may run it.
	staleSkillCheck = func() []ai.StaleSkill { return nil }
	// A purge looks in the user's trust store for a Phase AI root.
	caTrustLeftover = func() string { return "" }
	// Leak protection registers with the proxy named in the environment; a
	// test that wants a session sets one of its own.
	leakguard.Environment = func(string) string { return "" }
	code := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(code)
}
