package cmd

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/tunnel/control"
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

// phase up's engine keeps a session and its credentials in memory. Purging has to
// stop it as phase down would, not delete its state and leave it running.
func TestLogoutPurgeStopsThePhaseUpEngine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the engine is found with ps, and phase up doesn't run on Windows")
	}
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	gokeyring.MockInit()
	home := filepath.Dir(config.PhaseSecretsDir)
	directory := filepath.Join(home, "tunnel")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.AddUser(config.UserConfig{Host: console.server.URL, ID: "user-1"}); err != nil {
		t.Fatal(err)
	}

	// Something the pid file can point at that looks like the engine and stops when
	// asked, as the engine does.
	engineProcess := exec.Command("/bin/sh", "-c", `sleep 120 & child=$!; trap "kill $child; exit 0" TERM; wait`, "phase tunnel engine")
	if err := engineProcess.Start(); err != nil {
		t.Fatal(err)
	}
	pid := engineProcess.Process.Pid
	exited := make(chan struct{})
	go func() {
		_ = engineProcess.Wait()
		close(exited)
	}()
	t.Cleanup(func() { _ = engineProcess.Process.Kill() })
	if err := os.WriteFile(tunnelEnginePIDPath(directory), []byte(strconv.Itoa(pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "engine.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The engine is recognised by its command line, as ps shows it. phase up runs on
	// macOS only for now, and a ps elsewhere may not be able to say.
	if found, running := tunnelEnginePID(directory); !running || found != pid {
		if runtime.GOOS != "darwin" {
			t.Skip("ps here can't show a process's command line by its pid")
		}
		t.Fatalf("the stand-in engine (pid %d) wasn't recognised: %d, %v", pid, found, running)
	}

	// A helper that notes when it's asked to step aside, and whether the engine was
	// still there to carry traffic until then.
	socketDirectory, err := os.MkdirTemp("", "pu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDirectory) })
	listener, err := net.Listen("unix", filepath.Join(socketDirectory, "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	steppedAside := make(chan bool, 4)
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			conn := control.Wrap(raw)
			var request control.Request
			if err := conn.Receive(&request, 5*time.Second); err == nil && request.Op == control.OpDown {
				steppedAside <- processIsAlive(pid)
			}
			_ = conn.Send(control.Reply{})
			_ = raw.Close()
		}
	}()
	originalDirectory, originalSocket := tunnelStateDirectory, tunnelHelperSocket
	tunnelStateDirectory = func() (string, error) { return directory, nil }
	tunnelHelperSocket = filepath.Join(socketDirectory, "s")
	t.Cleanup(func() { tunnelStateDirectory, tunnelHelperSocket = originalDirectory, originalSocket })

	if _, stderr, err := runPhaseCommand(t, "", "users", "logout", "--purge"); err != nil || stderr != "" {
		t.Fatalf("purge: %v %s", err, stderr)
	}
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the engine is still running after a purge")
	}
	select {
	case engineWasRunning := <-steppedAside:
		if !engineWasRunning {
			t.Fatal("the engine was stopped before the helper stepped aside")
		}
	default:
		t.Fatal("the helper was never asked to step aside")
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("%s still exists after purge: %v", home, err)
	}
}

// With no engine running there's nothing to stop, and the helper isn't spoken to.
func TestLogoutPurgeLeavesTheHelperAloneWhenPhaseUpIsNotRunning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("phase up doesn't run on Windows")
	}
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	gokeyring.MockInit()
	home := filepath.Dir(config.PhaseSecretsDir)
	directory := filepath.Join(home, "tunnel")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.AddUser(config.UserConfig{Host: console.server.URL, ID: "user-1"}); err != nil {
		t.Fatal(err)
	}
	// A pid file left by an engine that has gone.
	if err := os.WriteFile(tunnelEnginePIDPath(directory), []byte("2147483646"), 0o600); err != nil {
		t.Fatal(err)
	}
	socketDirectory, err := os.MkdirTemp("", "pu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDirectory) })
	listener, err := net.Listen("unix", filepath.Join(socketDirectory, "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	asked := make(chan struct{}, 4)
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			asked <- struct{}{}
			_ = raw.Close()
		}
	}()
	originalDirectory, originalSocket := tunnelStateDirectory, tunnelHelperSocket
	tunnelStateDirectory = func() (string, error) { return directory, nil }
	tunnelHelperSocket = filepath.Join(socketDirectory, "s")
	t.Cleanup(func() { tunnelStateDirectory, tunnelHelperSocket = originalDirectory, originalSocket })

	if _, stderr, err := runPhaseCommand(t, "", "users", "logout", "--purge"); err != nil || stderr != "" {
		t.Fatalf("purge: %v %s", err, stderr)
	}
	select {
	case <-asked:
		t.Fatal("the helper was spoken to with no engine running")
	default:
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("%s still exists after purge: %v", home, err)
	}
}
