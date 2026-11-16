package cmd

import (
	"os"
	"testing"

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
	claudeHookRuntimeDir = func() (string, error) { return directory, nil }
	aiCAStore = phaseproxy.CAStore{Directory: directory, Keyring: fixedKeyring{err: gokeyring.ErrNotFound}}
	code := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(code)
}
