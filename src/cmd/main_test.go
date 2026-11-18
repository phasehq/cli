package cmd

import (
	"os"
	"testing"

	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/pkg/ai"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	gokeyring "github.com/zalando/go-keyring"
)

// TestMain points the Phase AI directory and the CA keystore at throwaway
// fakes, so a test that forgets to isolate them can never read or sweep the
// real ~/.phase/ai or system keystore.
func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "phase-cmd-test-ai-")
	if err != nil {
		panic(err)
	}
	hookRuntimeDir = func() (string, error) { return directory, nil }
	aiCAStore = phaseproxy.CAStore{Directory: directory, Keyring: fixedKeyring{err: gokeyring.ErrNotFound}}
	// The stale-skill notice reads the home directory's skill paths; only its
	// own tests, which set a temporary HOME, may run it.
	staleSkillCheck = func() []ai.StaleSkill { return nil }
	// Leak protection registers with the proxy named in the environment; a
	// test that wants a session sets one of its own.
	leakguard.Environment = func(string) string { return "" }
	code := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(code)
}
