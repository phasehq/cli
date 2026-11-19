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
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/phase"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
	gokeyring "github.com/zalando/go-keyring"
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

// A session that kept its marker and lost its proxy variables is treated as
// a session whose leak protection is down: an Agent login is refused and any
// other login is warned, where a shell outside a session is told nothing.
func TestASessionWithoutItsProxyVariablesIsNotTakenForNoSession(t *testing.T) {
	previousEnvironment := leakguard.Environment
	leakguard.Environment = func(key string) string {
		if key == "PHASE_AI_ENABLED" {
			return "1"
		}
		return ""
	}
	t.Cleanup(func() { leakguard.Environment = previousEnvironment })
	previousStat := leakRuntimeStat
	leakRuntimeStat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { leakRuntimeStat = previousStat })
	warnings := captureLeakWarnings(t)
	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets); !errors.Is(err, errLeakProtectionUnreachable) {
		t.Fatalf("an Agent login was handed values in a session with no leak protection: %v", err)
	}
	if warnings.Len() != 0 {
		t.Fatalf("an Agent refusal also printed a warning: %q", warnings.String())
	}
	if err := protectValues(context.Background(), false, []leakguard.Value{{Type: "secret", ID: "STRIPE_KEY", Value: leakTestSecrets[0].Value}}); err != nil {
		t.Fatalf("a personal login was refused: %v", err)
	}
	if got := warnings.String(); got != leakProtectionWarning+"\n" {
		t.Fatalf("warning: %q", got)
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

// A value too short to protect is still handed out, to an Agent login too,
// and the command says how many such values there were and nothing else of
// them.
func TestValuesThatCouldNotBeProtectedAreCountedInAWarning(t *testing.T) {
	const short = "Pa55w0rd!x"
	previous := leakRegister
	t.Cleanup(func() { leakRegister = previous })
	session := leakguard.Proxy{URL: "http://phase:capability@127.0.0.1:1", Source: leakguard.SourceSession}
	for _, c := range []struct {
		unprotected int
		want        string
	}{
		{0, ""},
		{1, "Phase: 1 value from this command is too short or plain to protect, so it is not removed from model traffic.\n"},
		{3, "Phase: 3 values from this command are too short or plain to protect, so they are not removed from model traffic.\n"},
	} {
		for _, agent := range []bool{true, false} {
			warnings := captureLeakWarnings(t)
			leakRegister = func(_ context.Context, _ leakguard.Proxy, values []leakguard.Value) (leakguard.Result, error) {
				return leakguard.Result{Added: len(values) - c.unprotected, Unprotected: c.unprotected}, nil
			}
			values := []leakguard.Value{
				{Type: "secret", ID: "DB_PASSWORD", Value: short}, {Type: "secret", ID: "ADMIN_PIN", Value: "4821"},
				{Type: "secret", ID: "DEPLOY_KEY", Value: "k9"}, {Type: "secret", ID: "STRIPE_KEY", Value: leakTestSecrets[0].Value},
			}
			if err := protectValuesWith(context.Background(), []leakguard.Proxy{session}, agent, values); err != nil {
				t.Fatalf("agent=%t: %d unprotected values refused the command: %v", agent, c.unprotected, err)
			}
			got := warnings.String()
			if got != c.want {
				t.Fatalf("agent=%t: %d unprotected values warned %q, want %q", agent, c.unprotected, got, c.want)
			}
			// Every proxy is sent the same values, so two that took them say it once.
			again := captureLeakWarnings(t)
			machine := leakguard.Proxy{URL: "http://phase:capability@127.0.0.1:2", Source: leakRuntimeSource}
			if err := protectValuesWith(context.Background(), []leakguard.Proxy{session, machine}, agent, values); err != nil || again.String() != c.want {
				t.Fatalf("agent=%t: with two proxies, %d unprotected values warned %q, want %q (%v)", agent, c.unprotected, again.String(), c.want, err)
			}
			for _, value := range values {
				if strings.Contains(got, value.Value) || strings.Contains(got, value.ID) {
					t.Fatalf("the warning names a value or its key: %q", got)
				}
			}
		}
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
	// A host that would be read, and is not being read now, is listed with
	// why; a host the table never reads has no reason to give.
	line = leakProtectionSummary(remoteapi.LeakProtectionStatus{
		Mode: "censor", SecretsKnown: 2, InspectedHosts: []string{"api.openai.com"},
		UnreadHosts:   []string{"*.cursor.sh", "api.anthropic.com", "cursor.sh", "opencode.ai"},
		UnreadReasons: map[string][]string{"opencode.ai": {"hello_resumption", "upstream_handshake_failed"}, "api.anthropic.com": {"tls_refused"}},
	})
	want = "censor (secrets in model traffic are replaced with placeholders); 2 secrets known; not inspected: *.cursor.sh, api.anthropic.com (tls_refused), cursor.sh, opencode.ai (hello_resumption, upstream_handshake_failed)"
	if line != want {
		t.Fatalf("status line:\n%s\n%s", line, want)
	}
}

// The status line counts the pattern rules that are not applied and names
// none: the ids are in the status JSON for whoever needs them. phase ai status
// prints the line as the proxy's status says it.
func TestStatusLineCountsSkippedRulesAndNamesNone(t *testing.T) {
	status := remoteapi.LeakProtectionStatus{
		Mode: "censor", SecretsKnown: 3, Unprotected: 1, RulesSkipped: 2, SkippedRules: []string{"later-format", "phase-user-token"},
		InspectedHosts: []string{"api.anthropic.com"}, UnreadHosts: []string{"cursor.sh"},
	}
	want := "censor (secrets in model traffic are replaced with placeholders); 3 secrets known, 1 too short or plain to protect; 2 pattern rules skipped; not inspected: cursor.sh"
	if line := leakProtectionSummary(status); line != want || strings.Contains(line, "later-format") || strings.Contains(line, "phase-user-token") {
		t.Fatalf("status line:\n%s\n%s", line, want)
	}
	status.RulesSkipped, status.Unprotected, status.UnreadHosts = 1, 0, nil
	if line := leakProtectionSummary(status); line != "censor (secrets in model traffic are replaced with placeholders); 3 secrets known; 1 pattern rule skipped" {
		t.Fatalf("one rule: %s", line)
	}

	// The whole command, against a proxy whose status says so. It reads the
	// setup and the login, so both point at files of the test's own.
	directory := withHookRuntimeDirectory(t)
	withAICAKeystore(t, gokeyring.ErrNotFound)
	originalAIConfig, originalConfig := config.AIConfigPath, config.ConfigFilePath
	config.AIConfigPath = filepath.Join(t.TempDir(), "ai.json")
	config.ConfigFilePath = filepath.Join(t.TempDir(), "config.json")
	t.Cleanup(func() { config.AIConfigPath, config.ConfigFilePath = originalAIConfig, originalConfig })
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "http://phase.invalid/v1/status" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"schemaVersion":1,"kind":"phase.ai.status","safeToPrint":true,"connections":[],` +
			`"leakProtection":{"mode":"censor","secretsKnown":3,"unprotected":0,"inspectedHosts":["api.anthropic.com"],"unreadHosts":[],` +
			`"rulesSkipped":2,"skippedRules":["later-format","phase-user-token"]}}`))
	}))
	t.Cleanup(proxy.Close)
	hookProxyState(t, directory, strings.Replace(proxy.URL, "http://", "http://phase:"+leakTestCapability+"@", 1), os.Getpid())
	rendered := renderAIStatus(context.Background())
	if !strings.Contains(rendered, "Leaks:       censor (secrets in model traffic are replaced with placeholders); 3 secrets known; 2 pattern rules skipped\n") ||
		strings.Contains(rendered, "later-format") {
		t.Fatalf("phase ai status:\n%s", rendered)
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
	requests int
	keyCalls int
	posts    int
	ids      []string
	kinds    []string
	full     bool
	// keyStatus and keyBody make the key request fail: with a status, or
	// with a body that is not the answer. stall holds every request back.
	keyStatus int
	keyBody   string
	stall     time.Duration
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
		fake.requests++
		stall := fake.stall
		fake.mu.Unlock()
		if stall > 0 {
			time.Sleep(stall)
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/inventory/key":
			fake.keyCalls++
			if fake.keyStatus != 0 {
				w.WriteHeader(fake.keyStatus)
				return
			}
			if fake.keyBody != "" {
				_, _ = w.Write([]byte(fake.keyBody))
				return
			}
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
	inactiveNotice, proxyWarning = sync.Once{}, oncePerSource{}
	t.Cleanup(func() { inactiveNotice, proxyWarning = sync.Once{}, oncePerSource{} })
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

	found := leakguard.Locate()
	if len(found) != 1 || found[0].InSession() || found[0].Source != leakRuntimeSource || found[0].URL != proxyURL {
		t.Fatalf("the hook proxy was not found: %+v", found)
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

// With no proxy running, a command that hands out values pays two file
// checks: of the runtime state, and of the runtime lock, which is how a daemon
// that is starting or recycling is told from none. Nothing is read, nothing
// is called and nothing is waited for.
func TestWithNoProxyRunningACommandPaysTwoFileChecks(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	noSession(t)
	statePath := filepath.Join(directory, hookRuntimeStateFile)
	lockPath := filepath.Join(directory, hookRuntimeLockFile)
	checks, checked := 0, map[string]int{}
	previousStat := leakRuntimeStat
	leakRuntimeStat = func(path string) (os.FileInfo, error) {
		checks++
		checked[path]++
		if path != statePath && path != lockPath {
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
	if elapsed := time.Since(started); checks != 2*commands || checked[statePath] != commands || checked[lockPath] != commands || calls != 0 || elapsed > 2*time.Second {
		t.Fatalf("%d commands made %d file checks (%v) and %d registrations in %v", commands, checks, checked, calls, elapsed)
	}
	if found := leakguard.Locate(); len(found) != 0 {
		t.Fatalf("a proxy was found where none runs: %+v", found)
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

// Runtime state that names an address nothing listens at is stale: its proxy
// is gone, or its process id went to another program. That is no proxy
// running, exactly as with no state at all: a human login hears nothing, and
// an Agent login is told once that nothing is protected. A warning there
// would be printed by every secrets command in every shell on the machine.
func TestStaleRuntimeStateIsNoProxyRunning(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	noSession(t)
	// The process that wrote the state looks alive, and nothing listens.
	stale := "http://phase:" + leakTestCapability + "@" + closedAddress(t)
	hookProxyState(t, directory, stale, os.Getpid())
	warnings := captureLeakWarnings(t)
	if found := leakguard.Locate(); len(found) != 1 || found[0].URL != stale {
		t.Fatalf("the state was not read: %+v", found)
	}
	started := time.Now()
	for i := 0; i < 3; i++ {
		if err := protectSecrets(context.Background(), nil, leakTestSecrets); err != nil {
			t.Fatalf("a human login was refused: %v", err)
		}
	}
	if warnings.Len() != 0 {
		t.Fatalf("a human login was warned about a proxy that is not running: %q", warnings.String())
	}
	for i := 0; i < 2; i++ {
		if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets); err != nil {
			t.Fatalf("an Agent login was refused: %v", err)
		}
	}
	if err := protectValues(context.Background(), true, []leakguard.Value{{Type: "dynamic", ID: "lease-1", Value: leakTestSecrets[0].Value}}); err != nil {
		t.Fatalf("an Agent's lease was refused: %v", err)
	}
	// Each of the six pays one dial and no more: at once where the system
	// refuses at once, the dial timeout where it is slow to, as Windows can
	// be. Half a second a command leaves room for that and is still no whole
	// timeout.
	if elapsed := time.Since(started); elapsed > 3*leakguard.Timeout {
		t.Fatalf("six commands with nothing listening took %v", elapsed)
	}
	withStale := warnings.String()

	// With no state file at all the same commands say the same.
	if err := os.Remove(filepath.Join(directory, hookRuntimeStateFile)); err != nil {
		t.Fatal(err)
	}
	inactiveNotice = sync.Once{}
	warnings.Reset()
	if err := protectSecrets(context.Background(), nil, leakTestSecrets); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets); err != nil {
			t.Fatal(err)
		}
	}
	if withStale != warnings.String() || withStale != leakProtectionInactiveMsg+"\n" {
		t.Fatalf("with stale state: %q\nwith no state:    %q", withStale, warnings.String())
	}

	// Inside a session nothing listening is still a failure: the session's
	// own proxy is meant to be there.
	environment := map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": stale}
	leakguard.Environment = func(key string) string { return environment[key] }
	warnings.Reset()
	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets); !errors.Is(err, errLeakProtectionUnreachable) {
		t.Fatalf("an Agent login inside a session whose proxy is gone carried on: %v", err)
	}
	if err := protectSecrets(context.Background(), nil, leakTestSecrets); err != nil || warnings.String() != leakProtectionWarning+"\n" {
		t.Fatalf("another login inside a session whose proxy is gone: %v %q", err, warnings.String())
	}
}

// Any other failure of the proxy found through the runtime state warns once
// and never refuses the command, whoever is logged in: the proxy runs and
// did not take the values, and the command may have nothing to do with an AI
// tool.
func TestAFailedRegistrationWithTheHookProxyWarnsOnceAndCarriesOn(t *testing.T) {
	for name, c := range map[string]struct {
		fail     func(*leakControlProxy)
		warning  string
		commands int
	}{
		"an HTTP error":                {func(f *leakControlProxy) { f.keyStatus = http.StatusInternalServerError }, leakProtectionWarning, 4},
		"a capability it refuses":      {func(f *leakControlProxy) { f.keyStatus = http.StatusProxyAuthRequired }, leakProtectionWarning, 4},
		"an answer that is not JSON":   {func(f *leakControlProxy) { f.keyBody = "<html>not the proxy</html>" }, leakProtectionWarning, 4},
		"an answer of another version": {func(f *leakControlProxy) { f.keyBody = `{"schemaVersion":9,"key":"AAAA","format":1}` }, leakProtectionWarning, 4},
		"a key that is no key":         {func(f *leakControlProxy) { f.keyBody = `{"schemaVersion":1,"key":"AAAA","format":1}` }, leakProtectionWarning, 4},
		// One command only: each waits out the whole timeout.
		"no answer in time": {func(f *leakControlProxy) { f.stall = leakguard.Timeout + 300*time.Millisecond }, leakProtectionWarning, 1},
		"a full inventory":  {func(f *leakControlProxy) { f.full = true }, leakInventoryFullWarning, 4},
	} {
		t.Run(name, func(t *testing.T) {
			directory := withHookRuntimeDirectory(t)
			noSession(t)
			fake, proxyURL := newLeakControlProxy(t)
			c.fail(fake)
			hookProxyState(t, directory, proxyURL, os.Getpid())
			warnings := captureLeakWarnings(t)
			backends := []phase.SecretsBackend{nil, &phase.AgentBackend{}, nil, &phase.AgentBackend{}}
			for _, backend := range backends[:c.commands] {
				if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
					t.Fatalf("a command outside a session was refused: %v", err)
				}
			}
			if got := warnings.String(); got != c.warning+"\n" || strings.Contains(got, "sk_live") {
				t.Fatalf("%d failed registrations warned %q", c.commands, got)
			}
			fake.mu.Lock()
			reached := fake.requests
			fake.mu.Unlock()
			if reached == 0 {
				t.Fatal("the proxy was never asked: the test shows nothing")
			}
			// The warning is said once; every command still tries to register.
			if posts, _, _ := fake.registered(); c.warning == leakInventoryFullWarning && posts != c.commands {
				t.Fatalf("%d of %d registrations reached the proxy", posts, c.commands)
			}
		})
	}
}

// Inside a session the session's own proxy comes first and decides for the
// command, as before. The proxy the harness hooks keep running is registered
// with as well: it reads the model traffic of the harnesses whose shells do
// not load the Phase environment, and a value handed out inside a session
// reaches those too. Before, only the session's proxy was told, and the other
// one never learnt the value.
func TestInsideASessionEveryProxyIsRegisteredWithAndTheSessionsDecides(t *testing.T) {
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
	registrations := func(fake *leakControlProxy) int {
		posts, _, _ := fake.registered()
		return posts
	}
	// said returns what the commands since the last look printed, and lets
	// the next failure of each proxy be told again.
	said := func() string {
		got := warnings.String()
		warnings.Reset()
		proxyWarning = oncePerSource{}
		return got
	}
	agent, human := phase.SecretsBackend(&phase.AgentBackend{}), phase.SecretsBackend(nil)

	found := leakguard.Locate()
	if len(found) != 2 || !found[0].InSession() || found[1].InSession() || found[1].Source != leakRuntimeSource || found[1].URL != hookURL {
		t.Fatalf("inside a session with the hook proxy running: %+v", found)
	}
	// Both are told, under the same placeholder, at the cost of one look at
	// the hook proxy's state.
	checks = 0
	for _, backend := range []phase.SecretsBackend{agent, human} {
		if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
			t.Fatal(err)
		}
	}
	_, sessionIDs, _ := session.registered()
	_, hookIDs, _ := hook.registered()
	if want := []string{"secret:STRIPE_KEY", "secret:STRIPE_KEY"}; !reflect.DeepEqual(sessionIDs, want) || !reflect.DeepEqual(hookIDs, want) {
		t.Fatalf("the session's proxy was told of %v and the hook proxy of %v", sessionIDs, hookIDs)
	}
	if got := said(); got != "" || checks != 2 {
		t.Fatalf("two registrations that worked said %q after %d looks at the hook proxy's state", got, checks)
	}

	// The hook proxy fails. That is one line, once, which names it, and
	// refuses nobody: the session's proxy took the values.
	hook.mu.Lock()
	hook.full = true
	hook.mu.Unlock()
	for _, backend := range []phase.SecretsBackend{agent, human, agent} {
		if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
			t.Fatalf("a failure of the hook proxy refused a command inside a session: %v", err)
		}
	}
	if got := said(); got != leakHookProxyFullWarning+"\n" || !strings.Contains(got, "hook-managed") || strings.Contains(got, "sk_live") {
		t.Fatalf("three commands with the hook proxy's inventory full said %q", got)
	}
	broken, brokenURL := newLeakControlProxy(t)
	broken.keyStatus = http.StatusInternalServerError
	hookProxyState(t, directory, brokenURL, os.Getpid())
	for _, backend := range []phase.SecretsBackend{agent, human} {
		if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
			t.Fatalf("a failure of the hook proxy refused a command inside a session: %v", err)
		}
	}
	if got := said(); got != leakHookProxyWarning+"\n" || !strings.Contains(got, "hook-managed") {
		t.Fatalf("two commands with the hook proxy failing said %q", got)
	}
	// Its state names an address nothing listens at: no proxy runs there,
	// and nothing is said.
	hookProxyState(t, directory, "http://phase:"+leakTestCapability+"@"+closedAddress(t), os.Getpid())
	for _, backend := range []phase.SecretsBackend{agent, human} {
		if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
			t.Fatal(err)
		}
	}
	if got := said(); got != "" || registrations(session) != 9 {
		t.Fatalf("stale state of the hook proxy, inside a session: %q, and %d registrations with the session's proxy", got, registrations(session))
	}

	// The session's proxy stops answering. An Agent login is refused, as
	// before, and before any other proxy is spoken to.
	hook.mu.Lock()
	hook.full = false
	hook.mu.Unlock()
	hookProxyState(t, directory, hookURL, os.Getpid())
	environment["HTTPS_PROXY"] = "http://phase:" + leakTestCapability + "@" + closedAddress(t)
	told := registrations(hook)
	err := protectSecrets(context.Background(), agent, leakTestSecrets)
	if !errors.Is(err, errLeakProtectionUnreachable) {
		t.Fatalf("an Agent login inside a session carried on without leak protection: %v", err)
	}
	if got := said(); got != "" || registrations(hook) != told {
		t.Fatalf("a refused command said %q and made %d registrations with the hook proxy", got, registrations(hook)-told)
	}
	// Any other login is warned, as before, and carries on. What it hands
	// out is still registered with the hook proxy.
	if err := protectSecrets(context.Background(), human, leakTestSecrets); err != nil {
		t.Fatalf("another login inside a session was refused: %v", err)
	}
	if got := said(); got != leakProtectionWarning+"\n" || registrations(hook) != told+1 {
		t.Fatalf("another login with the session's proxy down said %q and made %d registrations with the hook proxy", got, registrations(hook)-told)
	}
	// Both fail: the session's line as ever, and the hook proxy's own.
	hook.mu.Lock()
	hook.full = true
	hook.mu.Unlock()
	if err := protectSecrets(context.Background(), human, leakTestSecrets); err != nil {
		t.Fatal(err)
	}
	if got := said(); got != leakProtectionWarning+"\n"+leakHookProxyFullWarning+"\n" {
		t.Fatalf("another login with both proxies failing said %q", got)
	}
}

// In a shell that loads the environment of the proxy the harness hooks keep
// running, that proxy is the session's own, and the runtime state names the
// same one. It is one proxy: it is registered with once, and what a failure
// means is what it means for a session's proxy.
func TestTheHookProxyAsTheSessionsOwnIsRegisteredWithOnce(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	noSession(t)
	hook, hookURL := newLeakControlProxy(t)
	hookProxyState(t, directory, hookURL, os.Getpid())
	environment := map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": hookURL}
	leakguard.Environment = func(key string) string { return environment[key] }
	warnings := captureLeakWarnings(t)

	if found := leakguard.Locate(); len(found) != 1 || !found[0].InSession() || found[0].URL != hookURL {
		t.Fatalf("a session whose proxy the runtime state names too: %+v", found)
	}
	for _, backend := range []phase.SecretsBackend{&phase.AgentBackend{}, nil} {
		if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
			t.Fatal(err)
		}
	}
	if posts, _, _ := hook.registered(); posts != 2 || warnings.Len() != 0 {
		t.Fatalf("two commands made %d registrations and said %q", posts, warnings.String())
	}
	hook.mu.Lock()
	hook.full = true
	hook.mu.Unlock()
	if err := protectSecrets(context.Background(), &phase.AgentBackend{}, leakTestSecrets); !errors.Is(err, errLeakInventoryFull) {
		t.Fatalf("an Agent login inside the session carried on: %v", err)
	}
	if err := protectSecrets(context.Background(), nil, leakTestSecrets); err != nil {
		t.Fatalf("another login inside the session was refused: %v", err)
	}
	// One line, in the session's words: the proxy is not also spoken of as
	// another one.
	if got := warnings.String(); got != leakInventoryFullWarning+"\n" {
		t.Fatalf("the commands said %q", got)
	}
	if posts, _, _ := hook.registered(); posts != 4 {
		t.Fatalf("four commands made %d registrations", posts)
	}
}

// leakTestProxy is what the source this file adds finds: nothing, unless a
// test sets it. It stands in for one more proxy that runs on the machine,
// without the files a real source reads.
var leakTestProxy string

const leakTestSource = "test"

func init() {
	leakguard.AddSource(leakguard.Source{Name: leakTestSource, Find: func() (string, bool) { return leakTestProxy, leakTestProxy != "" }})
}

// Outside a session every proxy found is tried, whatever became of the ones
// before it. One that nothing listens at is no proxy, and is passed over in
// silence. One that failed is named, since another may have taken the
// values. Only when none of them runs is there no proxy.
func TestOutsideASessionEveryProxyFoundIsTried(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	noSession(t)
	hook, hookURL := newLeakControlProxy(t)
	other, otherURL := newLeakControlProxy(t)
	t.Cleanup(func() { leakTestProxy = "" })
	warnings := captureLeakWarnings(t)
	registrations := func(fake *leakControlProxy) int {
		posts, _, _ := fake.registered()
		return posts
	}
	said := func() string {
		got := warnings.String()
		warnings.Reset()
		inactiveNotice, proxyWarning = sync.Once{}, oncePerSource{}
		return got
	}
	stale := func() string { return "http://phase:" + leakTestCapability + "@" + closedAddress(t) }
	run := func() {
		t.Helper()
		for _, backend := range []phase.SecretsBackend{nil, &phase.AgentBackend{}} {
			if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
				t.Fatalf("a command outside a session was refused: %v", err)
			}
		}
	}

	// Both run: both are told.
	hookProxyState(t, directory, hookURL, os.Getpid())
	leakTestProxy = otherURL
	if found := leakguard.Locate(); len(found) != 2 || found[0].Source != leakRuntimeSource || found[1].Source != leakTestSource || found[0].InSession() || found[1].InSession() {
		t.Fatalf("the proxies found: %+v", found)
	}
	run()
	if got := said(); got != "" || registrations(hook) != 2 || registrations(other) != 2 {
		t.Fatalf("with both running: %q, %d and %d registrations", got, registrations(hook), registrations(other))
	}
	// The first one's state is stale. Before, the command stopped there, and
	// the proxy that runs was never told.
	hookProxyState(t, directory, stale(), os.Getpid())
	run()
	if got := said(); got != "" || registrations(other) != 4 {
		t.Fatalf("with the first proxy gone: %q, %d registrations with the one that runs", got, registrations(other))
	}
	// The first one fails. It is named, and the other is told all the same.
	hook.mu.Lock()
	hook.full = true
	hook.mu.Unlock()
	hookProxyState(t, directory, hookURL, os.Getpid())
	run()
	if got := said(); got != leakHookProxyFullWarning+"\n" || registrations(other) != 6 {
		t.Fatalf("with the first proxy's inventory full: %q, %d registrations with the other", got, registrations(other))
	}
	// A source this file knows no words for speaks in the general ones.
	hook.mu.Lock()
	hook.full = false
	hook.mu.Unlock()
	other.mu.Lock()
	other.full = true
	other.mu.Unlock()
	run()
	if got := said(); got != leakInventoryFullWarning+"\n" || registrations(hook) != 6 {
		t.Fatalf("with the other proxy's inventory full: %q, %d registrations with the hook proxy", got, registrations(hook))
	}
	hook.mu.Lock()
	hook.full = true
	hook.mu.Unlock()
	// The later one is gone and the first fails: still named, since it is one
	// of the proxies the command found.
	leakTestProxy = stale()
	run()
	if got := said(); got != leakHookProxyFullWarning+"\n" {
		t.Fatalf("with the first proxy's inventory full and the other gone: %q", got)
	}
	// None of them runs: no proxy, as with none found. An Agent login is told
	// once, and nobody else anything.
	hookProxyState(t, directory, stale(), os.Getpid())
	run()
	run()
	if got := said(); got != leakProtectionInactiveMsg+"\n" {
		t.Fatalf("with neither proxy running: %q", got)
	}
	// A proxy found on its own speaks as before, in the general words.
	leakTestProxy = ""
	hookProxyState(t, directory, hookURL, os.Getpid())
	run()
	if got := said(); got != leakInventoryFullWarning+"\n" {
		t.Fatalf("with the hook proxy on its own, its inventory full: %q", got)
	}
}

// hookDaemonLock writes the lock a hook daemon holds: the process that runs
// it, when it started, and when it last withdrew its state to recycle its
// session.
func hookDaemonLock(t *testing.T, directory string, pid int, created, recycling time.Time) {
	t.Helper()
	lock := hookRuntimeLock{Version: hookRuntimeStateVersion, Generation: "generation-leak", PID: pid, CreatedAt: created.UTC()}
	if !recycling.IsZero() {
		lock.RecyclingAt = recycling.UTC()
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), lock); err != nil {
		t.Fatal(err)
	}
}

// publishHookProxyStateLater writes the state a daemon publishes when its
// session is ready, after a moment: the daemon coming back from a recycle.
func publishHookProxyStateLater(t *testing.T, directory, proxyURL string, after time.Duration) {
	t.Helper()
	published := make(chan error, 1)
	go func() {
		time.Sleep(after)
		published <- writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), hookRuntimeState{
			Version: hookRuntimeStateVersion, Generation: "generation-leak", RuntimeFingerprint: "fingerprint",
			PID: os.Getpid(), StartedAt: time.Now().UTC(), ProxyURL: proxyURL,
		})
	}()
	t.Cleanup(func() {
		if err := <-published; err != nil {
			t.Error(err)
		}
	})
}

// While the hook daemon recycles its session there is no proxy to register
// with for some seconds: its listener is closed, and then its state is gone.
// A value handed out then is registered once the daemon is back. Before, the
// gap was taken for no proxy running: the value went out, and the daemon,
// which comes back with its inventory, never learnt it.
func TestValuesHandedOutWhileTheDaemonRecyclesAreRegistered(t *testing.T) {
	for name, c := range map[string]struct {
		// stale leaves the daemon's state where it was, naming an address
		// nothing listens at any more: the first seconds of a recycle.
		stale bool
		// created is how long ago the daemon started, and recycling how long
		// ago it last said it withdrew its state (negative: never).
		created, recycling time.Duration
	}{
		// In the order a recycle goes through them.
		"its listener is closed and nothing says so yet":  {true, time.Hour, -1},
		"it says it is recycling, its state still there":  {true, time.Hour, 0},
		"its state is withdrawn":                          {false, time.Hour, 0},
		"it recycled before and is at it again":           {true, time.Hour, time.Hour},
		"it is starting":                                  {false, time.Second, -1},
		"it is starting, an earlier daemon's state there": {true, time.Second, -1},
	} {
		for login, backend := range map[string]phase.SecretsBackend{"an Agent login": &phase.AgentBackend{}, "another login": nil} {
			t.Run(name+", "+login, func(t *testing.T) {
				directory := withHookRuntimeDirectory(t)
				noSession(t)
				fake, proxyURL := newLeakControlProxy(t)
				warnings := captureLeakWarnings(t)
				var recycling time.Time
				if c.recycling >= 0 {
					recycling = time.Now().Add(-c.recycling)
				}
				hookDaemonLock(t, directory, os.Getpid(), time.Now().Add(-c.created), recycling)
				if c.stale {
					hookProxyState(t, directory, "http://phase:"+leakTestCapability+"@"+closedAddress(t), os.Getpid())
				}
				publishHookProxyStateLater(t, directory, proxyURL, 150*time.Millisecond)

				started := time.Now()
				if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
					t.Fatalf("the command was refused: %v", err)
				}
				elapsed := time.Since(started)
				posts, ids, _ := fake.registered()
				if posts != 1 || !reflect.DeepEqual(ids, []string{"secret:STRIPE_KEY"}) {
					t.Fatalf("%d registrations of %v reached the daemon once it was back", posts, ids)
				}
				if warnings.Len() != 0 {
					t.Fatalf("a registration that worked said %q", warnings.String())
				}
				if elapsed < 100*time.Millisecond || elapsed > leakguard.Timeout+500*time.Millisecond {
					t.Fatalf("the command waited %v for a daemon that was back after 150ms", elapsed)
				}
			})
		}
	}
}

// A daemon that is not back in time is a proxy that could not be reached: the
// command says so once and carries on, as for any other failed registration
// with the hook proxy. It is never taken for no proxy running.
func TestADaemonThatDoesNotComeBackInTimeIsUnreachable(t *testing.T) {
	for name, stale := range map[string]bool{"its state is withdrawn": false, "its listener is closed and nothing says so yet": true} {
		t.Run(name, func(t *testing.T) {
			directory := withHookRuntimeDirectory(t)
			noSession(t)
			warnings := captureLeakWarnings(t)
			if stale {
				// The daemon started an hour ago and still owns the state it
				// published; nothing listens where the state points.
				hookDaemonLock(t, directory, os.Getpid(), time.Now().Add(-time.Hour), time.Time{})
				hookProxyState(t, directory, "http://phase:"+leakTestCapability+"@"+closedAddress(t), os.Getpid())
			} else {
				hookDaemonLock(t, directory, os.Getpid(), time.Now().Add(-time.Hour), time.Now())
			}
			if found := leakguard.Locate(); len(found) != 1 || found[0].InSession() || found[0].Source != leakRuntimeSource {
				t.Fatalf("a daemon that is recycling was not found: %+v", found)
			}
			for _, backend := range []phase.SecretsBackend{&phase.AgentBackend{}, nil} {
				started := time.Now()
				if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
					t.Fatalf("a command outside a session was refused: %v", err)
				}
				if elapsed := time.Since(started); elapsed < leakguard.Timeout*8/10 || elapsed > 3*leakguard.Timeout {
					t.Fatalf("the command waited %v for the daemon, not about %v", elapsed, leakguard.Timeout)
				}
			}
			// One line for the process, and it is not the one for no proxy.
			if got := warnings.String(); got != leakProtectionWarning+"\n" || strings.Contains(got, "sk_live") {
				t.Fatalf("the commands said %q", got)
			}
			// Only config values: there is nothing to register, so nothing is
			// waited for.
			started := time.Now()
			if err := protectSecrets(context.Background(), nil, leakTestSecrets[1:]); err != nil || time.Since(started) > leakguard.Timeout/2 {
				t.Fatalf("a command with nothing to protect: %v after %v", err, time.Since(started))
			}
		})
	}
}

// A lock that does not say a daemon is on its way costs no wait: its process
// is gone, or it has claimed to start or recycle for longer than either takes
// and published no state, or the state there is not its own.
//
// Where live state points at an address nothing listens at, each command
// still pays one dial. That is over at once on most systems and after the dial
// timeout, a fraction of a second, where the system is slow to refuse, as
// Windows can be. A wait for the daemon would be a whole second a command, so
// those commands are allowed half of that each, which tells the two apart
// without counting on a quick refusal. The others dial nothing and are held
// to costing next to nothing.
func TestALockThatSaysNothingIsOnItsWayCostsNoWait(t *testing.T) {
	const deadPID = 1 << 30
	type leftState struct {
		pid        int
		generation string
	}
	for name, c := range map[string]struct {
		pid       int
		created   time.Duration
		recycling time.Duration
		state     *leftState
	}{
		"its process is gone":                           {deadPID, time.Second, time.Second, nil},
		"its process is gone and its state was left":    {deadPID, time.Second, time.Second, &leftState{deadPID, "generation-leak"}},
		"it started long ago and has no state":          {os.Getpid(), time.Hour, -1, nil},
		"it recycled long ago and has no state":         {os.Getpid(), time.Hour, 3 * hookStartTimeout, nil},
		"it has no process yet":                         {0, time.Second, -1, nil},
		"the state is another daemon's, long gone":      {os.Getpid(), time.Hour, -1, &leftState{os.Getpid(), "another-generation"}},
		"the state names another process than the lock": {os.Getpid(), time.Hour, -1, &leftState{os.Getppid(), "generation-leak"}},
	} {
		t.Run(name, func(t *testing.T) {
			directory := withHookRuntimeDirectory(t)
			noSession(t)
			warnings := captureLeakWarnings(t)
			var recycling time.Time
			if c.recycling >= 0 {
				recycling = time.Now().Add(-c.recycling)
			}
			hookDaemonLock(t, directory, c.pid, time.Now().Add(-c.created), recycling)
			if c.state != nil {
				// Nothing listens where the state points.
				state := hookRuntimeState{
					Version: hookRuntimeStateVersion, Generation: c.state.generation, RuntimeFingerprint: "fingerprint",
					PID: c.state.pid, StartedAt: time.Now().UTC(), ProxyURL: "http://phase:" + leakTestCapability + "@" + closedAddress(t),
				}
				if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), state); err != nil {
					t.Fatal(err)
				}
			}
			const commands = 10
			started := time.Now()
			for i := 0; i < commands/2; i++ {
				for _, backend := range []phase.SecretsBackend{nil, &phase.AgentBackend{}} {
					if err := protectSecrets(context.Background(), backend, leakTestSecrets); err != nil {
						t.Fatal(err)
					}
				}
			}
			allowed := leakguard.Timeout / 2
			if c.state != nil && c.state.pid != deadPID {
				allowed = commands * leakguard.Timeout / 2
			}
			if elapsed := time.Since(started); elapsed > allowed {
				t.Fatalf("%d commands took %v, over %v: they waited for a daemon that is not coming", commands, elapsed, allowed)
			}
			// No proxy runs: an Agent login is told once, nobody else anything.
			if got := warnings.String(); got != leakProtectionInactiveMsg+"\n" {
				t.Fatalf("the commands said %q", got)
			}
		})
	}
}
