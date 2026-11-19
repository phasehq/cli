package aiproxy

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gokeyring "github.com/zalando/go-keyring"

	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// testKeystore stands in for the system keystore, as the CA store's tests'
// memory keyring does: nothing here reaches the real one.
type testKeystore struct {
	mu     sync.Mutex
	values map[string]string
	// absent makes it a machine with no keystore.
	absent bool
}

func (k *testKeystore) Get(service, user string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.absent {
		return "", errors.New("org.freedesktop.secrets was not provided by any service")
	}
	value, ok := k.values[service+"/"+user]
	if !ok {
		return "", gokeyring.ErrNotFound
	}
	return value, nil
}

func (k *testKeystore) Set(service, user, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.absent {
		return errors.New("org.freedesktop.secrets was not provided by any service")
	}
	k.values[service+"/"+user] = value
	return nil
}

func newTestInventoryStore(t *testing.T) *phaseproxy.InventoryStore {
	t.Helper()
	return &phaseproxy.InventoryStore{Directory: filepath.Join(t.TempDir(), "ai"), Keyring: &testKeystore{values: map[string]string{}}}
}

// newStoredLeakRig is a proxy that starts with what the store holds.
func newStoredLeakRig(t *testing.T, store *phaseproxy.InventoryStore) *leakRig {
	t.Helper()
	rig := newLeakRig(t, leakModeCensor)
	guard, err := newStoredLeakGuard(leakModeCensor, store)
	if err != nil {
		t.Fatal(err)
	}
	rig.guard, rig.proxy.leak, rig.proxy.control.leak = guard, guard, guard
	return rig
}

func rawStatus(t *testing.T, rig *leakRig) (*remoteapi.LeakProtectionStatus, string) {
	t.Helper()
	recorder := controlCall(rig.proxy, http.MethodGet, "/v1/status", "", nil)
	var status remoteapi.StatusResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &status) != nil || status.LeakProtection == nil || status.LeakProtection.Inventory == nil {
		t.Fatalf("status: %d %s", recorder.Code, recorder.Body.String())
	}
	return status.LeakProtection, recorder.Body.String()
}

// A value registered with one proxy is replaced by a proxy started after it
// that nothing was registered with: the hook-managed proxy after its idle
// exit, an upgrade or a reboot, with a conversation whose history holds the
// value.
func TestLeakInventoryOutlivesTheProxy(t *testing.T) {
	store := newTestInventoryStore(t)
	first := newStoredLeakRig(t, store)
	if status, _ := rawStatus(t, first); status.Inventory.Storage != remoteapi.LeakInventoryStored || status.Inventory.Loaded != 0 || status.SecretsKnown != 0 {
		t.Fatalf("a first start: %+v", status.Inventory)
	}
	environment := map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": first.proxyURL.String()}
	previous := leakguard.Environment
	leakguard.Environment = func(key string) string { return environment[key] }
	defer func() { leakguard.Environment = previous }()
	result, err := leakguard.Register(context.Background(), []leakguard.Value{
		{Type: "secret", ID: "secret-id-1", Value: leakSecretOne},
		{Type: "secret", ID: "DATABASE_URL", Value: leakSecretTwo, KeyName: true},
		{Type: "secret", ID: "secret-id-3", Value: "short"},
	})
	if err != nil || result.Added != 2 || result.Unprotected != 1 {
		t.Fatalf("registration: %+v %v", result, err)
	}
	first.proxy.CloseHijacked()

	second := newStoredLeakRig(t, store)
	status, body := rawStatus(t, second)
	if status.SecretsKnown != 2 || status.Unprotected != 0 || *status.Inventory != (remoteapi.LeakInventoryStatus{Storage: remoteapi.LeakInventoryStored, Loaded: 2}) {
		t.Fatalf("the second proxy: %+v %+v", status, status.Inventory)
	}
	if !strings.Contains(body, `"inventory":{"storage":"stored","loaded":2,"notLoaded":0,"unmatchedScheme":0,"unmatchedKey":0}`) {
		t.Fatalf("status: %s", body)
	}
	for _, private := range []string{"secret-id-1", "DATABASE_URL", leakSecretOne, hex.EncodeToString(second.guard.key.Bytes())} {
		if strings.Contains(body, private) {
			t.Fatalf("status names %q", private)
		}
	}
	if !bytes.Equal(first.guard.key.Bytes(), second.guard.key.Bytes()) {
		t.Fatal("the second proxy hashes with another key")
	}
	// The resumed conversation: the value itself, and its hex.
	content := leakSecretOne + " and " + leakSecretTwo + " and " + hex.EncodeToString([]byte(leakSecretOne))
	postMessages(t, second.client(second.phaseRoots), "https://api.anthropic.com/v1/messages", anthropicBody(content), "")
	received := second.lastReceived()
	if bytes.Contains(received.body, []byte(leakSecretOne)) || bytes.Contains(received.body, []byte("Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3")) || bytes.Contains(received.body, []byte(hex.EncodeToString([]byte(leakSecretOne)))) {
		t.Fatalf("a stored value reached the provider: %s", received.body)
	}
	if bytes.Count(received.body, []byte("ph:secret:secret-id-1")) != 2 || !bytes.Contains(received.body, []byte("ph:secret:DATABASE_URL")) {
		t.Fatalf("the stored values were not replaced: %s", received.body)
	}
	// What was known of an id is stored with it: a key name stays out of events.
	if got := second.guard.eventPlaceholders([]string{"ph:secret:DATABASE_URL", "ph:secret:secret-id-1"}); len(got) != 2 || got[0] != "ph:secret" || got[1] != "ph:secret:secret-id-1" {
		t.Fatalf("event placeholders: %v", got)
	}
	// The value is registered again with the second proxy: nothing doubles.
	environment["HTTPS_PROXY"] = second.proxyURL.String()
	if result, err := leakguard.Register(context.Background(), []leakguard.Value{{Type: "secret", ID: "secret-id-1", Value: leakSecretOne}}); err != nil || result.Added != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	third := newStoredLeakRig(t, store)
	if status, _ := rawStatus(t, third); status.SecretsKnown != 2 || status.Inventory.Loaded != 2 {
		t.Fatalf("the third proxy: %+v", status.Inventory)
	}
}

// Scheme 1 entries from an older client are matched while the proxy runs and
// never stored (they carry whole rolling hashes), and replace nothing.
func TestLeakInventoryMatchesSchemeOneEntriesFromMemoryOnly(t *testing.T) {
	store := newTestInventoryStore(t)
	first, err := newStoredLeakGuard(leakModeCensor, store)
	if err != nil {
		t.Fatal(err)
	}
	old, err := censor.IndexValueScheme(first.key, 1, "secret", "one", leakSecretOne)
	if err != nil {
		t.Fatal(err)
	}
	current, err := censor.IndexValue(first.key, "secret", "two", leakSecretTwo)
	if err != nil {
		t.Fatal(err)
	}
	if added, _, err := first.add([]*censor.Entries{old, current}, []bool{false, false}); err != nil || added != 2 {
		t.Fatalf("%d %v", added, err)
	}
	if out, _ := first.index.Redact([]byte(leakSecretOne + " " + leakSecretTwo)); string(out) != "ph:secret:one ph:secret:two" {
		t.Fatalf("%q", out)
	}
	second, err := newStoredLeakGuard(leakModeCensor, store)
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := second.index.Redact([]byte(leakSecretTwo)); string(out) != "ph:secret:two" || second.loaded != 1 {
		t.Fatalf("%q, %d loaded", out, second.loaded)
	}
	// Another value under the id the older client used: both stay matched.
	other := "Hd6Fs1Gp0YaJw3Rk8Tn5Vb2Xq7Zc4Lm9"
	again, err := censor.IndexValue(first.key, "secret", "one", other)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.add([]*censor.Entries{again}, []bool{false}); err != nil {
		t.Fatal(err)
	}
	if out, _ := first.index.Redact([]byte(leakSecretOne + " " + other)); string(out) != "ph:secret:one ph:secret:one" {
		t.Fatalf("a value sharing an id across schemes was dropped: %q", out)
	}
	inventory, loaded, err := store.Open()
	if err != nil || len(loaded) != 2 || inventory.Status().OtherScheme != 0 {
		t.Fatalf("%d loaded, %v", len(loaded), err)
	}
	for _, stored := range loaded {
		if stored.Entries.Version != censor.EntriesVersion {
			t.Fatalf("%s is stored under scheme %d", stored.Entries.ID, stored.Entries.Version)
		}
	}
}

// When the store holds more than the index has room for, the values
// registered most recently are the ones loaded, and status counts the rest.
func TestLeakInventoryLoadsTheNewestIntoAFullIndex(t *testing.T) {
	store := newTestInventoryStore(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	store.Now = func() time.Time { return now }
	first, err := newStoredLeakGuard(leakModeCensor, store)
	if err != nil {
		t.Fatal(err)
	}
	values := []string{
		"mQ4zT7wK2nB9xR5cV8pL1dH6", "Yg3Js6Uf9Ia2Oe5Pw8Ld1Kc4", "tN7bX2vM5qZ8rW3kG6hC9jF1",
		"E4sA7dU1iO8pY5lT2gR9fK6h", "zC3vB6nM9xL2kJ5hG8fD1sQ4",
	}
	for i, value := range values {
		registerLeakValues(t, first, map[string]string{fmt.Sprintf("value-%d", i): value})
		now = now.Add(time.Hour)
	}
	leakIndexMaxSecrets = 3
	t.Cleanup(func() { leakIndexMaxSecrets = 0 })
	rig := newStoredLeakRig(t, store)
	status, body := rawStatus(t, rig)
	if status.SecretsKnown != 3 || status.Inventory.Loaded != 3 || status.Inventory.NotLoaded != 2 || !strings.Contains(body, `"notLoaded":2`) {
		t.Fatalf("%+v: %s", status.Inventory, body)
	}
	out, _ := rig.guard.index.Redact([]byte(strings.Join(values, " ")))
	if want := values[0] + " " + values[1] + " ph:secret:value-2 ph:secret:value-3 ph:secret:value-4"; string(out) != want {
		t.Fatalf("the newest values were not the ones loaded: %s", out)
	}
	// What was left out is still in the store, for an index with room.
	leakIndexMaxSecrets = 0
	if all, err := newStoredLeakGuard(leakModeCensor, store); err != nil || all.loaded != 5 || all.notLoaded != 0 {
		t.Fatalf("%v", err)
	}
}

// On a machine with no keystore nothing is stored and nothing changed: the
// inventory is in memory, a second proxy knows nothing, and status says why.
func TestLeakInventoryWithoutAKeystoreIsMemoryOnly(t *testing.T) {
	store := &phaseproxy.InventoryStore{Directory: filepath.Join(t.TempDir(), "ai"), Keyring: &testKeystore{absent: true}}
	first := newStoredLeakRig(t, store)
	registerLeakValues(t, first.guard, map[string]string{"one": leakSecretOne})
	status, body := rawStatus(t, first)
	if status.SecretsKnown != 1 || *status.Inventory != (remoteapi.LeakInventoryStatus{Storage: remoteapi.LeakInventoryMemory, Reason: phaseproxy.InventoryReasonNoKeystore}) {
		t.Fatalf("%+v", status.Inventory)
	}
	if !strings.Contains(body, `"inventory":{"storage":"memory","reason":"no_keystore","loaded":0,"notLoaded":0,"unmatchedScheme":0,"unmatchedKey":0}`) {
		t.Fatalf("status: %s", body)
	}
	postMessages(t, first.client(first.phaseRoots), "https://api.anthropic.com/v1/messages", anthropicBody(leakSecretOne), "")
	if received := first.lastReceived(); !bytes.Contains(received.body, []byte("ph:secret:one")) {
		t.Fatalf("the value was not replaced: %s", received.body)
	}
	if _, err := os.Lstat(store.Directory); !os.IsNotExist(err) {
		t.Fatalf("something was written without a keystore: %v", err)
	}
	second := newStoredLeakRig(t, store)
	if status, _ := rawStatus(t, second); status.SecretsKnown != 0 || status.Inventory.Loaded != 0 {
		t.Fatalf("%+v", status)
	}
	if bytes.Equal(first.guard.key.Bytes(), second.guard.key.Bytes()) {
		t.Fatal("two memory inventories share a key")
	}
	// A proxy that was given no store says that.
	plain := newLeakRig(t, leakModeCensor)
	if status, _ := rawStatus(t, plain); *status.Inventory != (remoteapi.LeakInventoryStatus{Storage: remoteapi.LeakInventoryMemory, Reason: phaseproxy.InventoryReasonNotConfigured}) {
		t.Fatalf("%+v", status.Inventory)
	}
}

// Status counts what the store holds that this proxy cannot match: entries
// under a replaced key, and a file a newer version wrote.
func TestLeakInventoryStatusCountsWhatIsNotMatched(t *testing.T) {
	store := newTestInventoryStore(t)
	first := newStoredLeakRig(t, store)
	registerLeakValues(t, first.guard, map[string]string{"one": leakSecretOne, "two": leakSecretTwo})
	if err := store.ReplaceKey(); err != nil {
		t.Fatal(err)
	}
	second := newStoredLeakRig(t, store)
	status, body := rawStatus(t, second)
	if status.SecretsKnown != 0 || *status.Inventory != (remoteapi.LeakInventoryStatus{Storage: remoteapi.LeakInventoryStored, UnmatchedKey: 2}) {
		t.Fatalf("%+v", status.Inventory)
	}
	if !strings.Contains(body, `"unmatchedKey":2`) {
		t.Fatalf("status: %s", body)
	}
	postMessages(t, second.client(second.phaseRoots), "https://api.anthropic.com/v1/messages", anthropicBody("a "+leakSecretTwo+" b"), "")
	if received := second.lastReceived(); bytes.Contains(received.body, []byte("ph:secret:two")) {
		t.Fatalf("entries of a replaced key were matched: %s", received.body)
	}
	// The first proxy goes on with what it holds, and stops storing.
	registerLeakValues(t, first.guard, map[string]string{"three": "Jw3Rk8Tn5Vb2Xq7Zc4Lm9Hd6Fs1Gp0Ya"})
	if status, _ := rawStatus(t, first); status.SecretsKnown != 3 || status.Inventory.Storage != remoteapi.LeakInventoryMemory || status.Inventory.Reason != phaseproxy.InventoryReasonKeyReplaced {
		t.Fatalf("%+v %+v", status, status.Inventory)
	}

	// A file from a newer version of Phase.
	registerLeakValues(t, second.guard, map[string]string{"one": leakSecretOne})
	path := filepath.Join(store.Directory, "leak-inventory.bin")
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file[11] = phaseproxy.InventoryStoreFormat + 1
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatal(err)
	}
	third := newStoredLeakRig(t, store)
	registerLeakValues(t, third.guard, map[string]string{"two": leakSecretTwo})
	if status, _ := rawStatus(t, third); status.SecretsKnown != 1 || *status.Inventory != (remoteapi.LeakInventoryStatus{Storage: remoteapi.LeakInventoryMemory, Reason: phaseproxy.InventoryReasonNewerFormat}) {
		t.Fatalf("%+v %+v", status, status.Inventory)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, file) {
		t.Fatal("the newer file was changed")
	}
}

// The engine opens the store with the first session, and a capture layer's
// question about hosts before that does not leave it with an inventory that
// stores nothing.
func TestEngineOpensTheInventoryStoreOnce(t *testing.T) {
	t.Setenv(LeakProtectionEnvironmentKey, "")
	store := newTestInventoryStore(t)
	engine := &Engine{}
	if !engine.ShouldRead("claude", "api.anthropic.com") || len(engine.ReadHosts("claude")) == 0 {
		t.Fatal("the host table was not answered before a session")
	}
	guard, err := engine.leakGuard(store)
	if err != nil {
		t.Fatal(err)
	}
	if status := guard.status().Inventory; status.Storage != remoteapi.LeakInventoryStored {
		t.Fatalf("%+v", status)
	}
	registerLeakValues(t, guard, map[string]string{"one": leakSecretOne})
	// A recycled session, and one that names no store, get the same guard.
	for _, next := range []*phaseproxy.InventoryStore{store, nil} {
		if again, err := engine.leakGuard(next); err != nil || again != guard {
			t.Fatalf("the engine made another guard: %v", err)
		}
	}
	if !engine.ShouldRead("claude", "api.anthropic.com") {
		t.Fatal("ShouldRead")
	}
	// Another process of the same user.
	other, err := (&Engine{}).leakGuard(store)
	if err != nil || other.status().SecretsKnown != 1 || other.status().Inventory.Loaded != 1 {
		t.Fatalf("%v", err)
	}
	// With no store the engine keeps the inventory in memory.
	plain, err := (&Engine{}).leakGuard(nil)
	if err != nil || plain.status().Inventory.Reason != phaseproxy.InventoryReasonNotConfigured {
		t.Fatalf("%v", err)
	}
}
