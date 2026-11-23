package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/internal/tunnel"
)

// registerAsACommandDoes registers a value with the engine's proxy the way a secrets
// command on this machine does when only phase up is running: it finds the proxy
// through the state the engine keeps, and sends keyed hashes.
func (e *running) registerAsACommandDoes(t *testing.T, id, value string) {
	t.Helper()
	state, err := ReadProxyState(e.directory)
	if err != nil {
		t.Fatalf("the engine's proxy state: %v", err)
	}
	// A command gives the proxy a second to answer. That is the command's own limit,
	// and a slow run of the tests may not keep to it: registering again is harmless.
	deadline := time.Now().Add(20 * time.Second)
	for {
		result, err := leakguard.Proxy{URL: state.ProxyURL, Source: "up"}.Register(context.Background(), []leakguard.Value{{Type: "secret", ID: id, Value: value}})
		if err == nil && result.Added == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("registering the value: %+v, %v", result, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// While its proxy serves a session, the engine keeps where the proxy listens and the
// capability its control API asks for, in a file that is its owner's alone. The
// status, which anyone may be shown, holds neither.
func TestTheEngineKeepsItsProxysStateWhileItServes(t *testing.T) {
	e := startEngine(t, nil)
	state, err := ReadProxyState(e.directory)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := url.Parse(state.ProxyURL)
	if err != nil || proxy.Scheme != "http" || proxy.Hostname() != "127.0.0.1" || proxy.User == nil {
		t.Fatalf("the proxy's address isn't one a command can use: %v", err)
	}
	capability, _ := proxy.User.Password()
	if state.Version != ProxyStateVersion || state.PID != os.Getpid() || state.Started.IsZero() || capability == "" {
		t.Fatalf("the state is incomplete: version %d, pid %d, started %v", state.Version, state.PID, state.Started)
	}
	info, err := os.Lstat(ProxyStatePath(e.directory))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("the state isn't a regular file: %v", err)
	}
	if goruntime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("the state can be read by others: %v", info.Mode().Perm())
	}
	e.registerAsACommandDoes(t, "deploy-key", "Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3Pd5Sg0Uf")

	// Nothing but the state holds the capability.
	e.status(t, func(status Status) bool { return status.Ready && status.HelperLinked })
	entries, err := os.ReadDir(e.directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == filepath.Base(ProxyStatePath(e.directory)) {
			continue
		}
		content, err := os.ReadFile(filepath.Join(e.directory, entry.Name()))
		if err == nil && strings.Contains(string(content), capability) {
			t.Fatalf("%s holds the proxy's capability", entry.Name())
		}
	}

	// It goes with the engine.
	e.stop()
	if _, err := os.Lstat(ProxyStatePath(e.directory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the proxy's state outlived the engine: %v", err)
	}
}

func TestProxyStateIsReadWithCare(t *testing.T) {
	good := ProxyState{Version: ProxyStateVersion, PID: os.Getpid(), Started: time.Now().UTC(), ProxyURL: "http://phase:capability@127.0.0.1:9553"}
	write := func(t *testing.T, state any, mode os.FileMode) string {
		t.Helper()
		directory := t.TempDir()
		payload, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ProxyStatePath(directory), payload, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(ProxyStatePath(directory), mode); err != nil {
			t.Fatal(err)
		}
		return directory
	}
	if state, err := ReadProxyState(write(t, good, 0o600)); err != nil || state.ProxyURL != good.ProxyURL || state.PID != good.PID {
		t.Fatalf("a good state wasn't read: %+v, %v", state, err)
	}
	if _, err := ReadProxyState(t.TempDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no state: %v", err)
	}
	later, noURL, noPID := good, good, good
	later.Version, noURL.ProxyURL, noPID.PID = ProxyStateVersion+1, "", 0
	for name, directory := range map[string]string{
		"a later version":    write(t, later, 0o600),
		"no proxy address":   write(t, noURL, 0o600),
		"no process":         write(t, noPID, 0o600),
		"not a state at all": write(t, "http://phase:capability@127.0.0.1:9553", 0o600),
	} {
		if state, err := ReadProxyState(directory); err == nil {
			t.Errorf("%s was read as %+v", name, state)
		}
	}
	if goruntime.GOOS == "windows" {
		return
	}
	for name, mode := range map[string]os.FileMode{"readable by the group": 0o640, "readable by anyone": 0o604, "writable by anyone": 0o602} {
		if state, err := ReadProxyState(write(t, good, mode)); err == nil {
			t.Errorf("a state %s was read as %+v", name, state)
		}
	}
	// A link is not followed, wherever it leads.
	elsewhere := write(t, good, 0o600)
	directory := t.TempDir()
	if err := os.Symlink(ProxyStatePath(elsewhere), ProxyStatePath(directory)); err != nil {
		t.Fatal(err)
	}
	if state, err := ReadProxyState(directory); err == nil {
		t.Fatalf("a link was followed to %+v", state)
	}
}

// A state left by an engine that was killed names no proxy of the next engine's, and
// is gone before that engine has one.
func TestAnEngineStartsWithoutAnotherEnginesProxyState(t *testing.T) {
	directory := t.TempDir()
	stale := ProxyState{Version: ProxyStateVersion, PID: 1 << 30, Started: time.Now().UTC(), ProxyURL: "http://phase:stale@127.0.0.1:9"}
	payload, _ := json.Marshal(stale)
	if err := os.WriteFile(ProxyStatePath(directory), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// It stops at once, having opened no session.
	err := Run(ctx, Config{
		Runtime: fakeRuntime{session: testSession(t)}, SocketPath: filepath.Join(directory, "no-helper"), StateDirectory: directory,
		ProxyAddress: "127.0.0.1:1", PostgresAddress: "127.0.0.1:2", WireGuardPort: freePort(t, "udp"),
		Upstream: &tunnel.Upstream{Servers: []string{"127.0.0.1"}, OnlyOverrides: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(ProxyStatePath(directory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the other engine's state is still there: %v", err)
	}
}

// A second engine can't take the port a running engine listens on, and stops. It
// leaves the running engine's proxy state as it was: without it, no command on this
// machine could register a secret value with the proxy that reads for the tunnel.
func TestASecondEngineLeavesTheRunningEnginesProxyStateAlone(t *testing.T) {
	directory := t.TempDir()
	running := ProxyState{Version: ProxyStateVersion, PID: os.Getpid(), Started: time.Now().UTC(), ProxyURL: "http://phase:running@127.0.0.1:9553"}
	payload, _ := json.Marshal(running)
	if err := os.WriteFile(ProxyStatePath(directory), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	// The running engine's port.
	held, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = Run(ctx, Config{
		Runtime: fakeRuntime{session: testSession(t)}, SocketPath: filepath.Join(directory, "no-helper"), StateDirectory: directory,
		ProxyAddress: "127.0.0.1:1", PostgresAddress: "127.0.0.1:2", WireGuardPort: held.LocalAddr().(*net.UDPAddr).Port,
		Upstream: &tunnel.Upstream{Servers: []string{"127.0.0.1"}, OnlyOverrides: true},
	})
	if err == nil || !strings.Contains(err.Error(), "listen for the helper") {
		t.Fatalf("a second engine on the same port returned %v", err)
	}
	state, err := ReadProxyState(directory)
	if err != nil || state.ProxyURL != running.ProxyURL || state.PID != running.PID {
		t.Fatalf("the running engine's proxy state after a second engine tried to start: %+v, %v", state, err)
	}
}
