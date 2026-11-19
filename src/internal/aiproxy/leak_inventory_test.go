package aiproxy

import (
	"bytes"
	"context"
	"encoding/base64"
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
	return &phaseproxy.InventoryStore{Directory: filepath.Join(t.TempDir(), "ai"), Keyring: &testKeystore{values: map[string]string{}}, Tenant: leakTestTenant}
}

// leakTestTenant is the host and organisation the tests' proxies act for.
const leakTestTenant = "https://console.test\norganisation\ntest-organisation"

// leakTestLogin is the login the tests' proxies act as unless they say.
const leakTestLogin = "https://console.test\naccount\ntest-account"

// newStoredLeakRig is a proxy that starts with what the store holds.
func newStoredLeakRig(t *testing.T, store *phaseproxy.InventoryStore) *leakRig {
	t.Helper()
	return newStoredLeakRigAs(t, store, leakTestLogin)
}

// newStoredLeakRigAs is newStoredLeakRig for a proxy acting as login.
func newStoredLeakRigAs(t *testing.T, store *phaseproxy.InventoryStore, login string) *leakRig {
	t.Helper()
	rig := newLeakRig(t, leakModeCensor)
	guard, err := newStoredLeakGuard(leakModeCensor, store, login)
	if err != nil {
		t.Fatal(err)
	}
	rig.guard, rig.proxy.leak, rig.proxy.control.leak = guard, guard, guard
	return rig
}

// guardKeyBytes is both parts of the key a guard hands its clients.
func guardKeyBytes(guard *leakGuard) []byte {
	return append(guard.key.LookupBytes(), guard.key.ConfirmBytes()...)
}

// answeredKey rebuilds the key a client makes of the key route's answer.
func answeredKey(t testing.TB, answer remoteapi.InventoryKeyResponse) *censor.Key {
	t.Helper()
	lookup, _ := base64.StdEncoding.DecodeString(answer.Key)
	confirm, _ := base64.StdEncoding.DecodeString(answer.ConfirmKey)
	key, err := censor.KeyFromBytes(lookup, confirm)
	if err != nil {
		t.Fatalf("the answered key does not rebuild: %v", err)
	}
	return key
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
	for _, private := range []string{"secret-id-1", "DATABASE_URL", leakSecretOne, hex.EncodeToString(second.guard.key.LookupBytes()), hex.EncodeToString(second.guard.key.ConfirmBytes())} {
		if strings.Contains(body, private) {
			t.Fatalf("status names %q", private)
		}
	}
	if !bytes.Equal(guardKeyBytes(first.guard), guardKeyBytes(second.guard)) {
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
	first, err := newStoredLeakGuard(leakModeCensor, store, leakTestLogin)
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
	second, err := newStoredLeakGuard(leakModeCensor, store, leakTestLogin)
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
	first, err := newStoredLeakGuard(leakModeCensor, store, leakTestLogin)
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
	if all, err := newStoredLeakGuard(leakModeCensor, store, leakTestLogin); err != nil || all.loaded != 5 || all.notLoaded != 0 {
		t.Fatalf("%v", err)
	}
}

// On a machine with no keystore nothing is stored and nothing changed: the
// inventory is in memory, a second proxy knows nothing, and status says why.
func TestLeakInventoryWithoutAKeystoreIsMemoryOnly(t *testing.T) {
	store := &phaseproxy.InventoryStore{Directory: filepath.Join(t.TempDir(), "ai"), Keyring: &testKeystore{absent: true}, Tenant: leakTestTenant}
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
	if bytes.Equal(guardKeyBytes(first.guard), guardKeyBytes(second.guard)) {
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
	guard, err := engine.leakGuard(store, leakTestLogin)
	if err != nil {
		t.Fatal(err)
	}
	if status := guard.status().Inventory; status.Storage != remoteapi.LeakInventoryStored {
		t.Fatalf("%+v", status)
	}
	registerLeakValues(t, guard, map[string]string{"one": leakSecretOne})
	// A recycled session, and one that names no store, get the same guard.
	for _, next := range []*phaseproxy.InventoryStore{store, nil} {
		if again, err := engine.leakGuard(next, leakTestLogin); err != nil || again != guard {
			t.Fatalf("the engine made another guard: %v", err)
		}
	}
	if !engine.ShouldRead("claude", "api.anthropic.com") {
		t.Fatal("ShouldRead")
	}
	// Another process of the same user.
	other, err := (&Engine{}).leakGuard(store, leakTestLogin)
	if err != nil || other.status().SecretsKnown != 1 || other.status().Inventory.Loaded != 1 {
		t.Fatalf("%v", err)
	}
	// With no store the engine keeps the inventory in memory.
	plain, err := (&Engine{}).leakGuard(nil, leakTestLogin)
	if err != nil || plain.status().Inventory.Reason != phaseproxy.InventoryReasonNotConfigured {
		t.Fatalf("%v", err)
	}
}

const (
	leakLoginA = "https://console.test\naccount\naccount-a"
	leakLoginB = "https://console.test\nagent\nagent-b"
)

// keyAnswer is the key route's answer of a proxy, parsed and as it was sent.
func keyAnswer(t *testing.T, rig *leakRig) (remoteapi.InventoryKeyResponse, []byte) {
	t.Helper()
	recorder := controlCall(rig.proxy, http.MethodGet, "/v1/inventory/key", "", nil)
	var answer remoteapi.InventoryKeyResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &answer) != nil {
		t.Fatalf("key: %d", recorder.Code)
	}
	return answer, recorder.Body.Bytes()
}

// phaseIDs says every id of a registration is one the Console issued.
func phaseIDs(n int) []string {
	kinds := make([]string, n)
	for i := range kinds {
		kinds[i] = remoteapi.InventoryIDPhase
	}
	return kinds
}

// A proxy started again replaces what its own login registered, by id, and
// what another login of its organisation did, by type alone: never that id.
func TestRestartedProxyReplacesItsTenantsValues(t *testing.T) {
	store := newTestInventoryStore(t)
	const shared, idOfB = "Hd6Fs1Gp0YaJw3Rk8Tn5Vb2Xq7Zc4Lm9", "9f1c2d3e-id-only-b-may-see"
	asA := newStoredLeakRigAs(t, store, leakLoginA)
	if answer := registerThroughControl(t, asA.proxy, []leakguard.Value{
		{Type: "secret", ID: "from-a", Value: leakSecretOne}, {Type: "secret", ID: "shared-a", Value: shared},
	}, phaseIDs(2)); answer == nil || answer.Added != 2 {
		t.Fatalf("A's registration: %+v", answer)
	}
	asB := newStoredLeakRigAs(t, store, leakLoginB)
	if answer := registerThroughControl(t, asB.proxy, []leakguard.Value{
		{Type: "secret", ID: idOfB, Value: leakSecretTwo}, {Type: "secret", ID: "shared-b", Value: shared},
	}, phaseIDs(2)); answer == nil || answer.Added != 2 {
		t.Fatalf("B's registration: %+v", answer)
	}
	asA.proxy.CloseHijacked()
	asB.proxy.CloseHijacked()

	restarted := newStoredLeakRigAs(t, store, leakLoginA)
	status, statusBody := rawStatus(t, restarted)
	if status.SecretsKnown != 4 || status.Inventory.Loaded != 4 || status.Inventory.Damaged != 0 || status.Inventory.OtherTenants != 0 {
		t.Fatalf("the restarted proxy: %+v %+v", status, status.Inventory)
	}
	content := leakSecretOne + " and " + leakSecretTwo + " and " + shared + " and " + hex.EncodeToString([]byte(leakSecretTwo))
	postMessages(t, restarted.client(restarted.phaseRoots), "https://api.anthropic.com/v1/messages", anthropicBody(content), "")
	received := restarted.lastReceived()
	for name, value := range map[string]string{"A's": leakSecretOne, "B's": "Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3", "the shared": shared, "the hex of B's": hex.EncodeToString([]byte(leakSecretTwo))} {
		if bytes.Contains(received.body, []byte(value)) {
			t.Fatalf("%s value reached the provider: %s", name, received.body)
		}
	}
	// A's own ids are written, the shared value under A's; B's value is
	// ph:secret and nothing more.
	if !bytes.Contains(received.body, []byte("ph:secret:from-a and ph:secret and ph:secret:shared-a and ph:secret\"")) {
		t.Fatalf("what the provider received: %s", received.body)
	}
	events := restarted.distinctLeakEvents(t, 1)
	detail := events[0].Detail
	if sortedList(detail["placeholders"]) != "ph:secret,ph:secret:from-a,ph:secret:shared-a" || detail["inventoryHits"] != float64(4) {
		t.Fatalf("event detail: %+v", detail)
	}
	shipped, _ := json.Marshal(events)
	for name, text := range map[string][]byte{"the request": received.body, "the event": shipped, "status": []byte(statusBody)} {
		for _, id := range []string{idOfB, "shared-b"} {
			if bytes.Contains(text, []byte(id)) {
				t.Fatalf("%s names %q, an id of another login", name, id)
			}
		}
	}
	// And a proxy acting as B writes its own ids and withholds A's.
	other := newStoredLeakRigAs(t, store, leakLoginB)
	if out, _ := other.guard.index.Redact([]byte(leakSecretOne + " " + shared + " " + leakSecretTwo)); string(out) != "ph:secret ph:secret:shared-b ph:secret:"+idOfB {
		t.Fatalf("B's proxy: %q", out)
	}
}

// otherTenantStore is the same directory and keystore, for another tenant.
func otherTenantStore(store *phaseproxy.InventoryStore, tenant string) *phaseproxy.InventoryStore {
	other := *store
	other.Tenant = tenant
	return &other
}

// A session of one organisation never matches, loads or names what another's
// registered: the value goes through as it is, and only records are counted.
func TestAnotherTenantsValuesAreNeverMatched(t *testing.T) {
	storeB := newTestInventoryStore(t)
	storeA := otherTenantStore(storeB, "https://console.test\norganisation\nanother-organisation")
	const idOfB = "7a2b-id-of-tenant-b"
	asB := newStoredLeakRigAs(t, storeB, leakLoginB)
	if answer := registerThroughControl(t, asB.proxy, []leakguard.Value{{Type: "sealed", ID: idOfB, Value: leakSecretTwo}}, phaseIDs(1)); answer == nil || answer.Added != 1 {
		t.Fatalf("B's registration: %+v", answer)
	}
	asB.proxy.CloseHijacked()

	// The same login string in another tenant is another login altogether.
	asA := newStoredLeakRigAs(t, storeA, leakLoginB)
	status, statusBody := rawStatus(t, asA)
	if status.SecretsKnown != 0 || status.Inventory.Storage != remoteapi.LeakInventoryStored || status.Inventory.Loaded != 0 ||
		status.Inventory.OtherTenants != 1 || status.Inventory.Damaged != 0 || status.Inventory.UnmatchedKey != 0 {
		t.Fatalf("A's proxy: %+v %+v", status, status.Inventory)
	}
	if strings.Contains(statusBody, idOfB) || strings.Contains(statusBody, "sealed") {
		t.Fatalf("status says something of another tenant's record: %s", statusBody)
	}
	answerA, _ := keyAnswer(t, asA)
	answerB, _ := keyAnswer(t, asB)
	if answerA.Key == answerB.Key || answerA.ConfirmKey == answerB.ConfirmKey {
		t.Fatal("two tenants were handed a key in common")
	}
	content := "the value is " + leakSecretTwo + " and " + hex.EncodeToString([]byte(leakSecretTwo))
	body := anthropicBody(content)
	postMessages(t, asA.client(asA.phaseRoots), "https://api.anthropic.com/v1/messages", body, "")
	if received := asA.lastReceived(); !bytes.Equal(received.body, []byte(body)) {
		t.Fatalf("a request holding another tenant's value was changed: %s", received.body)
	}
	if events := asA.leakEventsNow(); len(events) != 0 {
		t.Fatalf("A's proxy reported on another tenant's value: %+v", events)
	}
	// A registers the same value itself: its own record, its own id, and
	// B's record is still there, unopened, for B's next proxy.
	if answer := registerThroughControl(t, asA.proxy, []leakguard.Value{{Type: "secret", ID: "from-a", Value: leakSecretTwo}}, phaseIDs(1)); answer == nil || answer.Added != 1 {
		t.Fatalf("A's registration: %+v", answer)
	}
	if out, _ := asA.guard.index.Redact([]byte(leakSecretTwo)); string(out) != "ph:secret:from-a" {
		t.Fatalf("A's own registration: %q", out)
	}
	asA.proxy.CloseHijacked()
	again := newStoredLeakRigAs(t, storeB, leakLoginB)
	if status, _ := rawStatus(t, again); status.SecretsKnown != 1 || status.Inventory.Loaded != 1 || status.Inventory.OtherTenants != 1 {
		t.Fatalf("B's next proxy: %+v %+v", status, status.Inventory)
	}
	if out, _ := again.guard.index.Redact([]byte(leakSecretTwo)); string(out) != "ph:sealed:"+idOfB {
		t.Fatalf("B's next proxy: %q", out)
	}
	// A login that names no tenant keeps nothing and loads nothing.
	nobody := newStoredLeakRigAs(t, otherTenantStore(storeB, ""), leakLoginB)
	if status, _ := rawStatus(t, nobody); status.SecretsKnown != 0 || status.Inventory.Storage != remoteapi.LeakInventoryMemory || status.Inventory.Reason != phaseproxy.InventoryReasonNoTenant {
		t.Fatalf("a login with no tenant: %+v %+v", status, status.Inventory)
	}
}

// The key route hands out the lookup key and the proxy's own principal's
// confirming key: never the master, never another login's confirming key.
func TestKeyAnswerHoldsOnlyItsOwnPrincipalsKeys(t *testing.T) {
	store := newTestInventoryStore(t)
	asB := newStoredLeakRigAs(t, store, leakLoginB)
	if answer := registerThroughControl(t, asB.proxy, []leakguard.Value{{Type: "secret", ID: "from-b", Value: leakSecretTwo}}, nil); answer == nil || answer.Added != 1 {
		t.Fatalf("B's registration: %+v", answer)
	}
	// A's proxy holds B's confirming key, to match B's record with.
	asA := newStoredLeakRigAs(t, store, leakLoginA)
	if out, _ := asA.guard.index.Redact([]byte(leakSecretTwo)); string(out) != "ph:secret" {
		t.Fatalf("A's proxy does not match B's value by type alone: %q", out)
	}
	answer, sent := keyAnswer(t, asA)
	answerB, _ := keyAnswer(t, asB)
	var fields map[string]json.RawMessage
	if json.Unmarshal(sent, &fields) != nil || len(fields) != 4 || fields["schemaVersion"] == nil || fields["key"] == nil || fields["confirmKey"] == nil || fields["format"] == nil {
		t.Fatalf("the answer's fields: %s", sent)
	}
	if answer.Format != censor.EntriesVersion || answer.Key != answerB.Key || answer.ConfirmKey == answerB.ConfirmKey || answer.ConfirmKey == answer.Key {
		t.Fatal("the answers do not share a lookup key and differ by confirming key")
	}
	if answer.Key != base64.StdEncoding.EncodeToString(asA.guard.key.LookupBytes()) || answer.ConfirmKey != base64.StdEncoding.EncodeToString(asA.guard.key.ConfirmBytes()) {
		t.Fatal("the answer is not the proxy's own principal's key")
	}
	stored, err := store.Keyring.Get("phase-cli-ai-leak-inventory", "key-v1")
	if err != nil {
		t.Fatal(err)
	}
	master, err := base64.StdEncoding.DecodeString(stored[strings.LastIndexByte(stored, ':')+1:])
	if err != nil || len(master) != censor.KeySize {
		t.Fatalf("the keystore holds no master: %v", err)
	}
	// The bytes sent, and the bytes they decode to, hold neither secret in
	// any spelling, whole or by half.
	decoded := append([]byte{}, sent...)
	for _, field := range []string{answer.Key, answer.ConfirmKey} {
		raw, err := base64.StdEncoding.DecodeString(field)
		if err != nil || len(raw) != censor.KeySize {
			t.Fatalf("a key in the answer is not %d bytes: %v", censor.KeySize, err)
		}
		decoded = append(append(decoded, 0), raw...)
	}
	for name, secret := range map[string][]byte{"the master": master, "B's confirming key": asB.guard.key.ConfirmBytes()} {
		for _, part := range [][]byte{secret, secret[:16], secret[16:]} {
			spellings := [][]byte{part, []byte(hex.EncodeToString(part)), []byte(base64.StdEncoding.EncodeToString(part)), []byte(base64.RawURLEncoding.EncodeToString(part))}
			for _, spelling := range spellings {
				if bytes.Contains(decoded, spelling) {
					t.Fatalf("the key answer holds %s", name)
				}
			}
		}
	}
	// A client of A, with what it was handed, indexes B's value to hashes
	// that are not the ones B's record holds: the registration adds a record.
	before := asA.guard.index.Stats()
	if answer := registerThroughControl(t, asA.proxy, []leakguard.Value{{Type: "secret", ID: "from-b", Value: leakSecretTwo}}, nil); answer == nil || answer.Added != 1 {
		t.Fatalf("A's registration: %+v", answer)
	}
	if after := asA.guard.index.Stats(); after.Forms != 2*before.Forms {
		t.Fatalf("A's entries for B's value were B's own: %+v then %+v", before, after)
	}
}
