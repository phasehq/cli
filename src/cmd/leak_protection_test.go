package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
	"github.com/phasehq/cli/pkg/phase"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
)

// downSession makes the process look like it runs inside a Phase AI session
// whose proxy is not listening.
func downSession(t *testing.T) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	environment := map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": "http://phase:capability@" + address}
	previous := leakguard.Environment
	leakguard.Environment = func(key string) string { return environment[key] }
	t.Cleanup(func() { leakguard.Environment = previous })
}

func captureLeakWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buffer bytes.Buffer
	previous := leakWarnings
	leakWarnings = &buffer
	t.Cleanup(func() { leakWarnings = previous })
	return &buffer
}

var leakTestSecrets = []sdk.SecretResult{
	{Key: "STRIPE_KEY", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS", Type: "secret", Path: "/"},
	{Key: "LOG_LEVEL", Value: "debug", Type: "config", Path: "/"},
}

func TestAgentLoginRefusesWhenLeakProtectionIsDown(t *testing.T) {
	downSession(t)
	warnings := captureLeakWarnings(t)
	err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets)
	if !errors.Is(err, errLeakProtectionUnreachable) {
		t.Fatalf("an Agent login carried on without leak protection: %v", err)
	}
	if !strings.Contains(err.Error(), "phase ai status") || strings.Contains(err.Error(), "sk_live") || strings.Count(err.Error(), "\n") != 0 {
		t.Fatalf("the refusal is not one clear line: %q", err.Error())
	}
	if warnings.Len() != 0 {
		t.Fatal("an Agent refusal also printed a warning")
	}
}

func TestOtherLoginsWarnOnceAndCarryOn(t *testing.T) {
	downSession(t)
	warnings := captureLeakWarnings(t)
	if err := protectValues(context.Background(), false, []leakguard.Value{{Type: "secret", ID: "STRIPE_KEY", Value: leakTestSecrets[0].Value}}); err != nil {
		t.Fatalf("a personal login was refused: %v", err)
	}
	if got := warnings.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, "phase ai status") || strings.Contains(got, "sk_live") {
		t.Fatalf("warning: %q", got)
	}
}

func TestNothingIsRegisteredOutsideASessionOrForConfig(t *testing.T) {
	calls := 0
	previous := leakRegister
	leakRegister = func(context.Context, leakguard.Proxy, []leakguard.Value) (leakguard.Result, error) {
		calls++
		return leakguard.Result{}, errors.New("unreachable")
	}
	t.Cleanup(func() { leakRegister = previous })
	previousEnvironment := leakguard.Environment
	leakguard.Environment = func(string) string { return "" }
	t.Cleanup(func() { leakguard.Environment = previousEnvironment })
	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets); err != nil || calls != 0 {
		t.Fatalf("outside a session: %v, %d calls", err, calls)
	}
	downSession(t)
	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets[1:]); err != nil || calls != 0 {
		t.Fatalf("config values were registered: %v, %d calls", err, calls)
	}
	var registered []leakguard.Value
	leakRegister = func(_ context.Context, _ leakguard.Proxy, values []leakguard.Value) (leakguard.Result, error) {
		registered = values
		return leakguard.Result{Added: len(values)}, nil
	}
	dynamic := sdk.SecretResult{Key: "DB_PASSWORD", Value: "Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3", IsDynamic: true}
	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, append(leakTestSecrets, dynamic)); err != nil {
		t.Fatal(err)
	}
	if len(registered) != 2 || registered[0].Type != "secret" || registered[0].ID != "STRIPE_KEY" || registered[1].Type != "dynamic" {
		t.Fatalf("registered: %+v", registered)
	}
	// This backend knows no Phase id for them, so each is registered under its
	// key name and says so.
	if !registered[0].KeyName || !registered[1].KeyName {
		t.Fatalf("a key name was registered as an id of the Console's: %+v", registered)
	}
}

func TestLeaseCredentialsAreFoundInADynamicSecretsResponse(t *testing.T) {
	payload := []byte(`[{"id":"ds-1","name":"db","lease":{"id":"lease-123","credentials":[{"key":"DB_USER","value":"phase_user_8f2k"},{"key":"DB_PASSWORD","value":"Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3"}]}},{"id":"ds-2","lease":null}]`)
	var values []leakguard.Value
	var root any
	_ = json.Unmarshal(payload, &root)
	collectLeaseCredentials(root, &values, 0)
	if len(values) != 2 || values[0].Type != "dynamic" || values[0].ID != "lease-123" || values[1].Value != "Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3" {
		t.Fatalf("lease credentials: %+v", values)
	}
	// A lease's id is the Console's own, not a key name.
	if values[0].KeyName || values[1].KeyName {
		t.Fatalf("a lease id was registered as a key name: %+v", values)
	}
}

func TestStatusLineSummarisesLeakProtection(t *testing.T) {
	line := leakProtectionSummary(remoteapi.LeakProtectionStatus{
		Mode: "censor", SecretsKnown: 12, Unprotected: 1,
		InspectedHosts: []string{"api.anthropic.com"}, UnreadHosts: []string{"*.cursor.sh", "cursor.sh"},
	})
	want := "censor (secrets in model traffic are replaced with placeholders); 12 secrets known, 1 too short or plain to protect; not inspected: *.cursor.sh, cursor.sh"
	if line != want {
		t.Fatalf("status line:\n%s\n%s", line, want)
	}
	if line := leakProtectionSummary(remoteapi.LeakProtectionStatus{Mode: "off", SecretsKnown: 1}); line != "off (model traffic is not inspected); 1 secret known" {
		t.Fatalf("off: %s", line)
	}
}

// A full inventory says so, for an Agent and for anyone else, and never
// claims the proxy could not be reached.
func TestAFullInventoryHasItsOwnMessage(t *testing.T) {
	downSession(t)
	previous := leakRegister
	leakRegister = func(context.Context, leakguard.Proxy, []leakguard.Value) (leakguard.Result, error) {
		return leakguard.Result{}, leakguard.ErrInventoryFull
	}
	t.Cleanup(func() { leakRegister = previous })
	values := []leakguard.Value{{Type: "secret", ID: "STRIPE_KEY", Value: leakTestSecrets[0].Value}}
	warnings := captureLeakWarnings(t)
	err := protectValues(context.Background(), true, values)
	if !errors.Is(err, errLeakInventoryFull) || !strings.Contains(err.Error(), "full") || strings.Contains(err.Error(), "reach") ||
		!strings.Contains(err.Error(), "Restarting the Phase AI proxy") {
		t.Fatalf("Agent: %v", err)
	}
	if err := protectValues(context.Background(), false, values); err != nil {
		t.Fatal(err)
	}
	if got := warnings.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, "full") || strings.Contains(got, "reach") {
		t.Fatalf("warning: %q", got)
	}
}

// An Agent login handing out values outside a session is told once, on the
// warning stream, that nothing is protected, and is not refused.
func TestAgentLoginOutsideASessionIsToldOnce(t *testing.T) {
	previousEnvironment := leakguard.Environment
	leakguard.Environment = func(string) string { return "" }
	t.Cleanup(func() { leakguard.Environment = previousEnvironment })
	inactiveNotice = sync.Once{}
	t.Cleanup(func() { inactiveNotice = sync.Once{} })
	warnings := captureLeakWarnings(t)
	for i := 0; i < 3; i++ {
		if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets); err != nil {
			t.Fatalf("an Agent login outside a session was refused: %v", err)
		}
	}
	if got := warnings.String(); got != leakProtectionInactiveMsg+"\n" || strings.Contains(got, "sk_live") {
		t.Fatalf("notice: %q", got)
	}
	// Only config values: nothing is handed out that needs protecting.
	inactiveNotice = sync.Once{}
	warnings.Reset()
	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets[1:]); err != nil || warnings.Len() != 0 {
		t.Fatalf("config only: %v %q", err, warnings.String())
	}
}

// leakControlProxy answers the two routes a registration uses, as the Phase
// proxy does for whoever holds its capability.
type leakControlProxy struct {
	mu       sync.Mutex
	keyCalls int
	posts    int
	ids      []string
	kinds    []string
	full     bool
}

const leakTestCapability = "runtime-capability"

// newLeakControlProxy returns the fake and its address with the capability,
// as a runtime writes it into its state.
func newLeakControlProxy(t *testing.T) (*leakControlProxy, string) {
	t.Helper()
	key, err := censor.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	fake := &leakControlProxy{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("phase:"+leakTestCapability)) || r.URL.Host != "phase.invalid" {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/inventory/key":
			fake.keyCalls++
			_ = json.NewEncoder(w).Encode(remoteapi.InventoryKeyResponse{SchemaVersion: 1, Key: base64.StdEncoding.EncodeToString(key.Bytes()), Format: censor.EntriesVersion})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/inventory":
			fake.posts++
			if fake.full {
				w.WriteHeader(http.StatusInsufficientStorage)
				_, _ = w.Write([]byte(`{"error":{"code":"leak_inventory_full","message":"full"}}`))
				return
			}
			var request remoteapi.InventoryRequest
			if json.NewDecoder(r.Body).Decode(&request) != nil || len(request.IDKinds) != len(request.Entries) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			for index, raw := range request.Entries {
				entry, err := censor.ParseEntries(raw)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				fake.ids = append(fake.ids, entry.Type+":"+entry.ID)
				fake.kinds = append(fake.kinds, request.IDKinds[index])
			}
			_ = json.NewEncoder(w).Encode(remoteapi.InventoryResponse{SchemaVersion: 1, Added: len(request.Entries)})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return fake, strings.Replace(server.URL, "http://", "http://phase:"+leakTestCapability+"@", 1)
}

func (f *leakControlProxy) registered() (posts int, ids, kinds []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.posts, append([]string(nil), f.ids...), append([]string(nil), f.kinds...)
}

// hookProxyState writes the state a hook-managed proxy publishes: where it
// listens, and the process that runs it.
func hookProxyState(t *testing.T, directory, proxyURL string, pid int) {
	t.Helper()
	state := hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: "generation-leak", RuntimeFingerprint: "fingerprint",
		PID: pid, StartedAt: time.Now().UTC(), ProxyURL: proxyURL,
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
}

// noSession leaves the process with no Phase AI session in its environment,
// as in a shell that does not load one, and a login that is not an Agent's.
func noSession(t *testing.T) {
	t.Helper()
	previous := leakguard.Environment
	leakguard.Environment = func(string) string { return "" }
	t.Cleanup(func() { leakguard.Environment = previous })
	t.Setenv("PHASE_SERVICE_TOKEN", "pss_service:v2:not-an-agent")
	inactiveNotice, runtimeWarning = sync.Once{}, sync.Once{}
	t.Cleanup(func() { inactiveNotice, runtimeWarning = sync.Once{}, sync.Once{} })
}

// closedAddress is a loopback address nothing listens on.
func closedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

// A command in a shell that carries no proxy variables still registers what
// it hands out, with the proxy the harness hooks keep running: it finds that
// proxy through the runtime state, as phase ai status does.
func TestValuesAreRegisteredWithTheHookProxyWithoutProxyVariables(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	noSession(t)
	fake, proxyURL := newLeakControlProxy(t)
	hookProxyState(t, directory, proxyURL, os.Getpid())
	warnings := captureLeakWarnings(t)

	found, ok := leakguard.Locate()
	if !ok || found.InSession() || found.Source != leakRuntimeSource || found.URL != proxyURL {
		t.Fatalf("the hook proxy was not found: %+v %v", found, ok)
	}
	// A login that is not an Agent's: the id is the secret's key name.
	if err := protectSecrets(context.Background(), nil, leakTestSecrets); err != nil {
		t.Fatal(err)
	}
	// An Agent login registers there as well.
	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets); err != nil {
		t.Fatal(err)
	}
	// So does a lease, under the lease's own id.
	lease := []byte(`[{"id":"ds-1","lease":{"id":"lease-123","credentials":[{"key":"DB_PASSWORD","value":"Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3"}]}}]`)
	if err := protectLeaseCredentials(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	posts, ids, kinds := fake.registered()
	if posts != 3 || !reflect.DeepEqual(ids, []string{"secret:STRIPE_KEY", "secret:STRIPE_KEY", "dynamic:lease-123"}) ||
		!reflect.DeepEqual(kinds, []string{remoteapi.InventoryIDKeyName, remoteapi.InventoryIDKeyName, remoteapi.InventoryIDPhase}) {
		t.Fatalf("%d registrations of %v as %v", posts, ids, kinds)
	}
	if fake.keyCalls != 1 {
		t.Fatalf("the key was fetched %d times in one process", fake.keyCalls)
	}
	if warnings.Len() != 0 {
		t.Fatalf("a registration that worked warned: %q", warnings.String())
	}
}

// With no proxy running, a command that hands out values pays one check of
// one file: nothing is read, and nothing is called.
func TestWithNoProxyRunningACommandPaysOneFileCheck(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	noSession(t)
	statePath := filepath.Join(directory, hookRuntimeStateFile)
	checks := 0
	previousStat := leakRuntimeStat
	leakRuntimeStat = func(path string) (os.FileInfo, error) {
		checks++
		if path != statePath {
			t.Errorf("%s was looked at", path)
		}
		return previousStat(path)
	}
	t.Cleanup(func() { leakRuntimeStat = previousStat })
	calls := 0
	previousRegister := leakRegister
	leakRegister = func(ctx context.Context, proxy leakguard.Proxy, values []leakguard.Value) (leakguard.Result, error) {
		calls++
		return previousRegister(ctx, proxy, values)
	}
	t.Cleanup(func() { leakRegister = previousRegister })
	warnings := captureLeakWarnings(t)

	const commands = 200
	started := time.Now()
	for i := 0; i < commands; i++ {
		if err := protectSecrets(context.Background(), nil, leakTestSecrets); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(started); checks != commands || calls != 0 || elapsed > 2*time.Second {
		t.Fatalf("%d commands made %d file checks and %d registrations in %v", commands, checks, calls, elapsed)
	}
	if _, ok := leakguard.Locate(); ok {
		t.Fatal("a proxy was found where none runs")
	}

	// State left behind by a proxy that is gone names an address. Nothing is
	// sent there: the process that wrote it is not alive.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var connections atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			_ = conn.Close()
		}
	}()
	const deadPID = 1 << 30
	hookProxyState(t, directory, "http://phase:"+leakTestCapability+"@"+listener.Addr().String(), deadPID)
	for _, backend := range []phase.SecretsBackend{nil, &phase.AgentBackend{}} {
		if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
			t.Fatal(err)
		}
	}
	// Nor is state used that this version does not read, or that is not a
	// runtime's own file.
	if err := writeOwnerOnlyJSON(statePath, map[string]any{"version": hookRuntimeStateVersion + 1, "generation": "g", "pid": os.Getpid(), "proxyUrl": "http://phase:" + leakTestCapability + "@" + listener.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	if err := protectSecrets(context.Background(), nil, leakTestSecrets); err != nil {
		t.Fatal(err)
	}
	hookProxyState(t, directory, "http://phase:"+leakTestCapability+"@"+listener.Addr().String(), os.Getpid())
	if runtime.GOOS != "windows" {
		if err := os.Chmod(statePath, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := protectSecrets(context.Background(), nil, leakTestSecrets); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if calls != 0 || connections.Load() != 0 {
		t.Fatalf("%d registrations and %d connections to a proxy that is not running", calls, connections.Load())
	}
	// An Agent login with no proxy anywhere is told once, as before; nobody
	// else is told anything.
	if got := warnings.String(); got != leakProtectionInactiveMsg+"\n" {
		t.Fatalf("warnings: %q", got)
	}
}

// A registration with the hook proxy that fails warns once and never refuses
// the command, whoever is logged in: the command may have nothing to do with
// an AI tool, and refusing it would break every shell on the machine.
func TestAFailedRegistrationWithTheHookProxyWarnsOnceAndCarriesOn(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	noSession(t)
	// The process that wrote the state is alive and its proxy does not answer.
	hookProxyState(t, directory, "http://phase:"+leakTestCapability+"@"+closedAddress(t), os.Getpid())
	warnings := captureLeakWarnings(t)
	started := time.Now()
	for i := 0; i < 2; i++ {
		for name, backend := range map[string]phase.SecretsBackend{"another login": nil, "an Agent login": &phase.AgentBackend{}} {
			if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
				t.Fatalf("%s was refused: %v", name, err)
			}
		}
	}
	if err := protectValues(context.Background(), true, []leakguard.Value{{Type: "dynamic", ID: "lease-1", Value: leakTestSecrets[0].Value}}); err != nil {
		t.Fatalf("an Agent's lease was refused: %v", err)
	}
	if got := warnings.String(); got != leakProtectionWarning+"\n" || strings.Contains(got, "sk_live") {
		t.Fatalf("five failed registrations warned %q", got)
	}
	if elapsed := time.Since(started); elapsed > 5*leakguard.Timeout {
		t.Fatalf("five failed registrations took %v", elapsed)
	}

	// A proxy that answers and is full says that, once, and refuses nobody.
	fake, proxyURL := newLeakControlProxy(t)
	fake.full = true
	hookProxyState(t, directory, proxyURL, os.Getpid())
	runtimeWarning = sync.Once{}
	warnings.Reset()
	for _, backend := range []phase.SecretsBackend{&phase.AgentBackend{}, nil, &phase.AgentBackend{}} {
		if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
			t.Fatalf("a full inventory refused a command outside a session: %v", err)
		}
	}
	if got := warnings.String(); got != leakInventoryFullWarning+"\n" {
		t.Fatalf("a full inventory warned %q", got)
	}
	if posts, _, _ := fake.registered(); posts != 3 {
		t.Fatalf("%d registrations reached the proxy", posts)
	}
}

// The session's own proxy comes first. Inside a session nothing else is
// looked for, and what a failure means there is unchanged: an Agent login is
// refused even while another proxy runs on the machine.
func TestTheSessionsProxyComesBeforeTheHookProxy(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	noSession(t)
	hook, hookURL := newLeakControlProxy(t)
	hookProxyState(t, directory, hookURL, os.Getpid())
	session, sessionURL := newLeakControlProxy(t)
	environment := map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": sessionURL}
	leakguard.Environment = func(key string) string { return environment[key] }
	checks := 0
	previousStat := leakRuntimeStat
	leakRuntimeStat = func(path string) (os.FileInfo, error) { checks++; return previousStat(path) }
	t.Cleanup(func() { leakRuntimeStat = previousStat })
	warnings := captureLeakWarnings(t)

	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets); err != nil {
		t.Fatal(err)
	}
	if err := protectSecrets(context.Background(), nil, leakTestSecrets); err != nil {
		t.Fatal(err)
	}
	if posts, _, _ := session.registered(); posts != 2 {
		t.Fatalf("%d registrations reached the session's proxy", posts)
	}
	if posts, _, _ := hook.registered(); posts != 0 || checks != 0 {
		t.Fatalf("inside a session the hook proxy got %d registrations after %d looks at its state", posts, checks)
	}

	// The session's proxy stops answering.
	environment["HTTPS_PROXY"] = "http://phase:" + leakTestCapability + "@" + closedAddress(t)
	err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets)
	if !errors.Is(err, errLeakProtectionUnreachable) {
		t.Fatalf("an Agent login inside a session carried on without leak protection: %v", err)
	}
	if err := protectSecrets(context.Background(), nil, leakTestSecrets); err != nil {
		t.Fatalf("another login inside a session was refused: %v", err)
	}
	if got := warnings.String(); got != leakProtectionWarning+"\n" {
		t.Fatalf("warnings: %q", got)
	}
	if posts, _, _ := hook.registered(); posts != 0 {
		t.Fatal("a session whose proxy is down registered with another proxy")
	}
}
