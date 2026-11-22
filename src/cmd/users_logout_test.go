package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phasehq/cli/pkg/config"
	"github.com/spf13/cobra"
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

// purgeWithPhaseAIData runs logout --purge for a user whose machine may hold
// a Phase AI CA, and returns what the command printed.
func purgeWithPhaseAIData(t *testing.T, withCA bool) (stdout, stderr string) {
	t.Helper()
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	aiDirectory := filepath.Join(filepath.Dir(config.PhaseSecretsDir), "ai")
	originalDirectory := hookRuntimeDir
	hookRuntimeDir = func() (string, error) { return aiDirectory, nil }
	t.Cleanup(func() { hookRuntimeDir = originalDirectory })
	if err := config.AddUser(config.UserConfig{Host: console.server.URL, ID: "user-1"}); err != nil {
		t.Fatal(err)
	}
	if withCA {
		if err := os.MkdirAll(aiDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(aiDirectory, "ca.pem"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stdout, stderr, err := runPhaseCommand(t, "", "users", "logout", "--purge")
	if err != nil {
		t.Fatalf("purge: %v %s", err, stderr)
	}
	return stdout, stderr
}

// A purge from a shell that cannot reach the system keystore, over SSH say,
// cannot remove the CA key a desktop session stored there. It says so rather
// than reporting a clean purge. A machine that never made a Phase AI CA has
// no such key, and is told nothing.
func TestLogoutPurgeWarnsWhenTheKeystoreCouldNotBeReached(t *testing.T) {
	const warning = "The system keystore could not be reached, so a Phase AI CA key stored in it was not removed.\n"
	t.Cleanup(gokeyring.MockInit)
	gokeyring.MockInitWithError(errors.New("secret service unreachable"))
	if _, stderr := purgeWithPhaseAIData(t, true); !strings.Contains(stderr, warning) {
		t.Fatalf("an unreachable keystore went unreported: %q", stderr)
	}
	if _, stderr := purgeWithPhaseAIData(t, false); strings.Contains(stderr, "keystore") {
		t.Fatalf("a machine with no Phase AI CA was warned about its key: %q", stderr)
	}
	gokeyring.MockInit()
	if _, stderr := purgeWithPhaseAIData(t, true); strings.Contains(stderr, "keystore") {
		t.Fatalf("a keystore that answered was reported: %q", stderr)
	}
}

// The purge leaves the user's trust store alone. When a Phase AI root is in
// it, the output says so in one line with how to remove it; otherwise it
// says nothing of it.
func TestLogoutPurgeNamesAPhaseRootLeftInTheTrustStore(t *testing.T) {
	gokeyring.MockInit()
	const leftover = `The Phase AI root certificate stays in your keychain. To remove it, open Keychain Access and delete "Phase AI Proxy CA".`
	original := caTrustLeftover
	t.Cleanup(func() { caTrustLeftover = original })
	caTrustLeftover = func() string { return leftover }
	if stdout, _ := purgeWithPhaseAIData(t, true); !strings.HasSuffix(stdout, "Logged out and purged all local data.\n"+leftover+"\n") {
		t.Fatalf("the purge did not name the root it left trusted: %q", stdout)
	}
	caTrustLeftover = func() string { return "" }
	if stdout, _ := purgeWithPhaseAIData(t, true); strings.Contains(stdout, "root certificate") || !strings.HasSuffix(stdout, "Logged out and purged all local data.\n") {
		t.Fatalf("a purge with no root in the trust store: %q", stdout)
	}
}

// A saved account id is used as a path component; one that climbs out of the
// Phase directory must never make logout delete what it names.
func TestLogoutNeverDeletesOutsideThePhaseDirectory(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	gokeyring.MockInit()
	aiDirectory := filepath.Join(filepath.Dir(config.PhaseSecretsDir), "ai")
	originalDirectory := hookRuntimeDir
	hookRuntimeDir = func() (string, error) { return aiDirectory, nil }
	t.Cleanup(func() { hookRuntimeDir = originalDirectory })

	home := filepath.Dir(filepath.Dir(config.PhaseSecretsDir))
	victim := filepath.Join(home, "Documents")
	if err := os.MkdirAll(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, "notes.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := strings.Join([]string{"..", "..", "..", "Documents"}, string(filepath.Separator))
	if err := config.AddUser(config.UserConfig{Host: console.server.URL, ID: id}); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := runPhaseCommand(t, "", "users", "logout"); err != nil {
		t.Fatalf("logout: %v %s", err, stderr)
	}
	if _, err := os.Stat(filepath.Join(victim, "notes.txt")); err != nil {
		t.Fatalf("logout deleted a directory outside ~/.phase: %v", err)
	}
}

func TestOfflineCacheDirAcceptsOnlyPlainIDs(t *testing.T) {
	isolateAgentCommand(t, "https://console.phase.invalid")
	for _, id := range []string{"", ".", "..", "../x", `..\x`, "a/b", "/abs"} {
		if dir, ok := offlineCacheDir(id); ok {
			t.Errorf("id %q gave %s", id, dir)
		}
	}
	dir, ok := offlineCacheDir("0b5c0a6e-2f6b-4e3a-9a52-1c2d3e4f5a6b")
	if !ok || filepath.Dir(dir) != filepath.Join(config.PhaseSecretsDir, "offline") {
		t.Fatalf("a UUID id gave %q, %v", dir, ok)
	}
}

// The Phase AI proxy keeps the login it started with, so an ordinary logout
// and a switch to another user stop it, as a purge does.
func TestLogoutAndSwitchStopThePhaseAIProxy(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	gokeyring.MockInit()
	stops := 0
	original := stopHookRuntimeForLogin
	stopHookRuntimeForLogin = func(context.Context) error { stops++; return nil }
	t.Cleanup(func() { stopHookRuntimeForLogin = original })

	for _, id := range []string{"user-1", "user-2"} {
		if err := config.AddUser(config.UserConfig{Host: console.server.URL, ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := switchDefaultUser(&cobra.Command{}, config.UserConfig{Host: console.server.URL, ID: "user-1"}, "user-2"); err != nil {
		t.Fatal(err)
	}
	if stops != 1 {
		t.Fatalf("switching user stopped the proxy %d times, want 1", stops)
	}
	if err := switchDefaultUser(&cobra.Command{}, config.UserConfig{Host: console.server.URL, ID: "user-1"}, "user-1"); err != nil {
		t.Fatal(err)
	}
	if stops != 1 {
		t.Fatalf("choosing the current user stopped the proxy")
	}
	if _, stderr, err := runPhaseCommand(t, "", "users", "logout"); err != nil {
		t.Fatalf("logout: %v %s", err, stderr)
	}
	if stops != 2 {
		t.Fatalf("logout stopped the proxy %d times in all, want 2", stops)
	}
}
