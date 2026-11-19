package aiproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
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

// leakTestIdentity is who the tests' proxies are unless they say: a user of
// the tests' organisation, as the Console would name the session.
var leakTestIdentity = phaseproxy.NewInventoryIdentity("https://console.test", "test-organisation", phaseproxy.InventoryLoginUser, "test-account")

// leakTestTenant is the host and organisation the tests' proxies act for.
var leakTestTenant = leakTestIdentity.Tenant

// newStoredLeakRig is a proxy that starts with what the store holds.
func newStoredLeakRig(t *testing.T, store *phaseproxy.InventoryStore) *leakRig {
	t.Helper()
	return newStoredLeakRigAs(t, store, leakTestIdentity)
}

// newStoredLeakRigAs is newStoredLeakRig for a proxy whose session is identity's.
func newStoredLeakRigAs(t *testing.T, store *phaseproxy.InventoryStore, identity phaseproxy.InventoryIdentity) *leakRig {
	t.Helper()
	rig := newLeakRig(t, leakModeCensor)
	guard, err := newStoredLeakGuard(leakModeCensor, store, identity)
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
	result, err := registerAsCommand(leakTestIdentity, []leakguard.Value{
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
	if result, err := registerAsCommand(leakTestIdentity, []leakguard.Value{{Type: "secret", ID: "secret-id-1", Value: leakSecretOne}}); err != nil || result.Added != 1 {
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
	first, err := newStoredLeakGuard(leakModeCensor, store, leakTestIdentity)
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
	second, err := newStoredLeakGuard(leakModeCensor, store, leakTestIdentity)
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

// A start loads a share of the index, each login's most recent values first.
// Status counts the rest, and they stay in the store.
func TestLeakInventoryLoadsTheNewestIntoAShareOfTheIndex(t *testing.T) {
	store := newTestInventoryStore(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	store.Now = func() time.Time { return now }
	first, err := newStoredLeakGuard(leakModeCensor, store, leakTestIdentity)
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
	// An index of eight loads four at most, and two for one login.
	leakIndexMaxSecrets = 8
	t.Cleanup(func() { leakIndexMaxSecrets = 0 })
	rig := newStoredLeakRig(t, store)
	status, body := rawStatus(t, rig)
	if status.SecretsKnown != 2 || status.Inventory.Loaded != 2 || status.Inventory.NotLoaded != 3 || !strings.Contains(body, `"notLoaded":3`) {
		t.Fatalf("%+v: %s", status.Inventory, body)
	}
	out, _ := rig.guard.index.Redact([]byte(strings.Join(values, " ")))
	if want := strings.Join(values[:3], " ") + " ph:secret:value-3 ph:secret:value-4"; string(out) != want {
		t.Fatalf("the newest values were not the ones loaded: %s", out)
	}
	// What was left out is still in the store, for an index with room.
	leakIndexMaxSecrets = 0
	if all, err := newStoredLeakGuard(leakModeCensor, store, leakTestIdentity); err != nil || all.loaded != 5 || all.notLoaded != 0 {
		t.Fatalf("%v", err)
	}
	// Three logins with two values each: the session's own are loaded first,
	// and the rest fill what is left of half the index, newest first.
	shared := newTestInventoryStore(t)
	now = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	shared.Now = func() time.Time { return now }
	third := phaseproxy.NewInventoryIdentity("https://console.test", "test-organisation", phaseproxy.InventoryLoginServiceAccount, "account-c")
	// Each login stores through its own proxy: no other writes for it.
	writers := map[phaseproxy.InventoryIdentity]*leakRig{}
	for i, who := range []phaseproxy.InventoryIdentity{leakLoginA, leakLoginB, third, leakLoginA, leakLoginB, third} {
		if writers[who] == nil {
			writers[who] = newStoredLeakRigAs(t, shared, who)
		}
		if a := registerThroughControl(t, writers[who].proxy, []leakguard.Value{{Type: "secret", ID: fmt.Sprintf("v-%d", i), Value: values[i%len(values)] + fmt.Sprint(i)}}, phaseIDs(1)); a == nil || a.Added != 1 {
			t.Fatalf("registration %d", i)
		}
		now = now.Add(time.Hour)
	}
	leakIndexMaxSecrets = 8
	next := newStoredLeakRigAs(t, shared, leakLoginA)
	if status, _ := rawStatus(t, next); status.Inventory.Loaded != 4 || status.Inventory.NotLoaded != 2 {
		t.Fatalf("three logins' values into half an index of eight: %+v", status.Inventory)
	}
	found, _ := next.guard.index.Redact([]byte(values[0] + "0 " + values[3] + "3 " + values[1] + "1 " + values[4] + "4 " + values[0] + "5"))
	if want := "ph:secret:v-0 ph:secret:v-3 " + values[1] + "1 ph:secret ph:secret"; string(found) != want {
		t.Fatalf("the session's own values first, then the newest: %s", found)
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
	guard, err := engine.leakGuard(store, leakTestIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if status := guard.status().Inventory; status.Storage != remoteapi.LeakInventoryStored {
		t.Fatalf("%+v", status)
	}
	registerLeakValues(t, guard, map[string]string{"one": leakSecretOne})
	// A recycled session, and one that names no store, get the same guard.
	for _, next := range []*phaseproxy.InventoryStore{store, nil} {
		if again, err := engine.leakGuard(next, leakTestIdentity); err != nil || again != guard {
			t.Fatalf("the engine made another guard: %v", err)
		}
	}
	if !engine.ShouldRead("claude", "api.anthropic.com") {
		t.Fatal("ShouldRead")
	}
	// Another process of the same user.
	other, err := (&Engine{}).leakGuard(store, leakTestIdentity)
	if err != nil || other.status().SecretsKnown != 1 || other.status().Inventory.Loaded != 1 {
		t.Fatalf("%v", err)
	}
	// With no store the engine keeps the inventory in memory.
	plain, err := (&Engine{}).leakGuard(nil, leakTestIdentity)
	if err != nil || plain.status().Inventory.Reason != phaseproxy.InventoryReasonNotConfigured {
		t.Fatalf("%v", err)
	}
}

// An engine's guard is one tenant's and one login's. A session of another
// organisation or login, or of none the Console named, is refused.
func TestEngineRefusesASessionOfAnotherIdentity(t *testing.T) {
	t.Setenv(LeakProtectionEnvironmentKey, "")
	store := newTestInventoryStore(t)
	engine := &Engine{}
	first, err := engine.leakGuard(store, leakLoginA)
	if err != nil {
		t.Fatal(err)
	}
	registerLeakValues(t, first, map[string]string{"id-of-a": leakSecretOne})
	for name, next := range map[string]phaseproxy.InventoryIdentity{
		"another organisation":       otherTenantA,
		"another login of its own":   leakLoginB,
		"none the Console named":     {},
		"one that is not well made":  {Tenant: leakLoginA.Tenant, Login: "https://console.test\naccount\naccount-a"},
		"its tenant, spelled anyhow": {Tenant: "HTTPS://console.test\norganisation\ntest-organisation", Login: leakLoginA.Login},
	} {
		guard, err := engine.leakGuard(store, next)
		if !errors.Is(err, errLeakIdentityChanged) || guard != nil {
			t.Fatalf("a session of %s was given a guard: %v", name, err)
		}
	}
	// The first session's own, again, is served; and a session with no
	// identity first keeps every later one that has one out as well.
	if again, err := engine.leakGuard(store, leakLoginA); err != nil || again != first {
		t.Fatalf("the engine's own session: %v", err)
	}
	nameless := &Engine{}
	if guard, err := nameless.leakGuard(store, phaseproxy.InventoryIdentity{}); err != nil || guard.identity.Known() || guard.status().Inventory.Reason != phaseproxy.InventoryReasonNoTenant {
		t.Fatalf("a session the Console did not name: %v", err)
	}
	if _, err := nameless.leakGuard(store, leakLoginA); !errors.Is(err, errLeakIdentityChanged) {
		t.Fatalf("a named session after a nameless one: %v", err)
	}
	// A whole session is refused the same way, before anything is served.
	session := headerInjectionSession(t, "a-live-credential-value-0001", "a-decoy-credential-value-0001")
	session.Identity = otherTenantA
	if err := engine.Serve(context.Background(), session); !errors.Is(err, errLeakIdentityChanged) {
		t.Fatalf("a session of another organisation was served: %v", err)
	}
}

// Two logins of the tests' organisation: a person's and an Agent's.
var (
	leakLoginA = phaseproxy.NewInventoryIdentity("https://console.test", "test-organisation", phaseproxy.InventoryLoginUser, "account-a")
	leakLoginB = phaseproxy.NewInventoryIdentity("https://console.test", "test-organisation", phaseproxy.InventoryLoginAgent, "agent-b")
)

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

// Logins of another organisation on the same host, and of the same
// organisation id on another host.
var (
	otherTenantA    = phaseproxy.NewInventoryIdentity("https://console.test", "another-organisation", phaseproxy.InventoryLoginUser, "account-a")
	otherTenantB    = phaseproxy.NewInventoryIdentity("https://console.test", "another-organisation", phaseproxy.InventoryLoginAgent, "agent-b")
	otherHostTenant = phaseproxy.NewInventoryIdentity("https://phase.other.test", "test-organisation", phaseproxy.InventoryLoginUser, "account-a")
)

// storedRecords is how many records the store's file holds, whosever they are.
func storedRecords(t *testing.T, store *phaseproxy.InventoryStore) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(store.Directory, "leak-inventory.bin"))
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	// A header of 20 bytes, then each record after its own length.
	records := 0
	for rest := data[20:]; len(rest) >= 4; records++ {
		rest = rest[4+int(binary.BigEndian.Uint32(rest)):]
	}
	return records
}

// A session of one organisation never matches, loads or names what another's
// registered: the value goes through as it is, and only records are counted.
func TestAnotherTenantsValuesAreNeverMatched(t *testing.T) {
	store := newTestInventoryStore(t)
	const idOfB = "7a2b-id-of-tenant-b"
	asB := newStoredLeakRigAs(t, store, leakLoginB)
	if answer := registerThroughControl(t, asB.proxy, []leakguard.Value{{Type: "sealed", ID: idOfB, Value: leakSecretTwo}}, phaseIDs(1)); answer == nil || answer.Added != 1 {
		t.Fatalf("B's registration: %+v", answer)
	}
	asB.proxy.CloseHijacked()

	for name, identity := range map[string]phaseproxy.InventoryIdentity{"another organisation": otherTenantB, "another host": otherHostTenant} {
		asA := newStoredLeakRigAs(t, store, identity)
		status, statusBody := rawStatus(t, asA)
		if status.SecretsKnown != 0 || status.Inventory.Storage != remoteapi.LeakInventoryStored || status.Inventory.Loaded != 0 ||
			status.Inventory.OtherTenants < 1 || status.Inventory.Damaged != 0 || status.Inventory.UnmatchedKey != 0 {
			t.Fatalf("%s: %+v %+v", name, status, status.Inventory)
		}
		if strings.Contains(statusBody, idOfB) || strings.Contains(statusBody, "sealed") {
			t.Fatalf("%s: status says something of another tenant's record: %s", name, statusBody)
		}
		ownA, ownB := statedKey(t, asA.proxy, identity), statedKey(t, asB.proxy, leakLoginB)
		if ownA.Key == ownB.Key || ownA.ConfirmKey == ownB.ConfirmKey {
			t.Fatalf("%s: two tenants were handed a key in common", name)
		}
		content := "the value is " + leakSecretTwo + " and " + hex.EncodeToString([]byte(leakSecretTwo))
		body := anthropicBody(content)
		postMessages(t, asA.client(asA.phaseRoots), "https://api.anthropic.com/v1/messages", body, "")
		if received := asA.lastReceived(); !bytes.Equal(received.body, []byte(body)) {
			t.Fatalf("%s: a request holding another tenant's value was changed: %s", name, received.body)
		}
		if events := asA.leakEventsNow(); len(events) != 0 {
			t.Fatalf("%s: reported on another tenant's value: %+v", name, events)
		}
		// It registers the same value itself: its own record, its own id,
		// and B's record is still there, unopened, for B's next proxy.
		if answer := registerThroughControl(t, asA.proxy, []leakguard.Value{{Type: "secret", ID: "from-a", Value: leakSecretTwo}}, phaseIDs(1)); answer == nil || answer.Added != 1 {
			t.Fatalf("%s: its own registration: %+v", name, answer)
		}
		if out, _ := asA.guard.index.Redact([]byte(leakSecretTwo)); string(out) != "ph:secret:from-a" {
			t.Fatalf("%s: its own registration: %q", name, out)
		}
		asA.proxy.CloseHijacked()
	}
	again := newStoredLeakRigAs(t, store, leakLoginB)
	if status, _ := rawStatus(t, again); status.SecretsKnown != 1 || status.Inventory.Loaded != 1 || status.Inventory.OtherTenants != 2 {
		t.Fatalf("B's next proxy: %+v %+v", status, status.Inventory)
	}
	if out, _ := again.guard.index.Redact([]byte(leakSecretTwo)); string(out) != "ph:sealed:"+idOfB {
		t.Fatalf("B's next proxy: %q", out)
	}
	// The tenant a store was made with is not the one opened: the session's is.
	mislabelled := *store
	mislabelled.Tenant = leakLoginB.Tenant
	if rig := newStoredLeakRigAs(t, &mislabelled, otherTenantB); rig.guard.status().SecretsKnown != 1 || rig.guard.status().Inventory.Loaded != 1 {
		t.Fatalf("a store labelled with another tenant loaded it: %+v", rig.guard.status().Inventory)
	} else if out, _ := rig.guard.index.Redact([]byte(leakSecretTwo)); string(out) != "ph:secret:from-a" {
		t.Fatalf("a store labelled with another tenant: %q", out)
	}
}

// A command that is not of the proxy's own login registers with A's running
// proxy. Nothing of it reaches a store, traffic, events or status but ph:<type>.
func TestACommandOfAnotherLoginNeverReachesTheProxysStore(t *testing.T) {
	const idOfB, keyOfB = "0b5e7c1a-secret-id-of-org-b", "ORG_B_DATABASE_URL"
	second := "Hd6Fs1Gp0YaJw3Rk8Tn5Vb2Xq7Zc4Lm9"
	for name, stated := range map[string]phaseproxy.InventoryIdentity{
		"another organisation":                      otherTenantB,
		"another login of the proxy's organisation": leakLoginB,
		"the proxy's account as another kind":       phaseproxy.NewInventoryIdentity("https://console.test", "test-organisation", phaseproxy.InventoryLoginAgent, "account-a"),
		"the same organisation id on another host":  otherHostTenant,
		"none it could state":                       {},
		"a tenant and no login":                     {Tenant: leakLoginA.Tenant},
		"the proxy's tenant, misspelt":              {Tenant: "https://CONSOLE.test\norganisation\ntest-organisation", Login: "https://CONSOLE.test\nuser\naccount-a"},
		"a login of another host":                   {Tenant: leakLoginA.Tenant, Login: otherHostTenant.Login},
	} {
		t.Run(name, func(t *testing.T) {
			store := newTestInventoryStore(t)
			daemon := newStoredLeakRigAs(t, store, leakLoginA)
			environment := map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": daemon.proxyURL.String()}
			previous := leakguard.Environment
			leakguard.Environment = func(key string) string { return environment[key] }
			defer func() { leakguard.Environment = previous }()
			before, _ := rawStatus(t, daemon)
			result, err := registerAsCommand(stated, []leakguard.Value{
				{Type: "secret", ID: idOfB, Value: leakSecretTwo}, {Type: "secret", ID: keyOfB, KeyName: true, Value: second},
				{Type: "secret", ID: "too-short-of-b", Value: "short"},
			})
			if err != nil || result.Added != 2 || result.Unprotected != 1 {
				t.Fatalf("the registration: %+v %v", result, err)
			}
			// While the proxy lives the values are replaced, with no id.
			content := "x " + leakSecretTwo + " y " + second + " z " + hex.EncodeToString([]byte(leakSecretTwo))
			postMessages(t, daemon.client(daemon.phaseRoots), "https://api.anthropic.com/v1/messages", anthropicBody(content), "")
			received := daemon.lastReceived()
			if !bytes.Contains(received.body, []byte("x ph:secret y ph:secret z ph:secret\"")) {
				t.Fatalf("what the provider received: %s", received.body)
			}
			events := daemon.distinctLeakEvents(t, 1)
			if detail := events[0].Detail; detail["placeholders"] != "ph:secret" || detail["placeholderCount"] != float64(2) || detail["inventoryHits"] != float64(3) {
				t.Fatalf("the event: %+v", detail)
			}
			status, statusBody := rawStatus(t, daemon)
			if status.SecretsKnown != before.SecretsKnown || status.Unprotected != before.Unprotected || status.Inventory.Unstored != 2 || status.Inventory.Loaded != 0 {
				t.Fatalf("status counts another account's values as the session's: %+v %+v", status, status.Inventory)
			}
			shipped, _ := json.Marshal(events)
			for where, text := range map[string][]byte{"the request": received.body, "the events": append(shipped, daemon.shippedPayloads()...), "status": []byte(statusBody)} {
				for _, id := range []string{idOfB, keyOfB, "too-short-of-b"} {
					if bytes.Contains(text, []byte(id)) {
						t.Fatalf("%s names %q, an id of another account", where, id)
					}
				}
			}
			// Nothing was written for anyone: not for A, not for B.
			if records := storedRecords(t, store); records != 0 {
				t.Fatalf("%d records were stored for a command of another account", records)
			}
			daemon.proxy.CloseHijacked()

			// A's next proxy knows nothing of it: the store holds nothing to
			// load, name, count or report, and the value passes as it came.
			next := newStoredLeakRigAs(t, store, leakLoginA)
			status, statusBody = rawStatus(t, next)
			if status.SecretsKnown != 0 || status.Inventory.Loaded != 0 || status.Inventory.OtherTenants != 0 || status.Inventory.Unstored != 0 || status.Inventory.NotLoaded != 0 {
				t.Fatalf("A's next proxy: %+v %+v", status, status.Inventory)
			}
			body := anthropicBody(content)
			postMessages(t, next.client(next.phaseRoots), "https://api.anthropic.com/v1/messages", body, "")
			if got := next.lastReceived(); !bytes.Equal(got.body, []byte(body)) {
				t.Fatalf("A's next proxy changed a request for a value it was never to keep: %s", got.body)
			}
			if events := next.leakEventsNow(); len(events) != 0 || strings.Contains(statusBody, idOfB) {
				t.Fatalf("A's next proxy reported on it: %+v", events)
			}
			// And B's own next proxy starts with nothing A's proxy wrote.
			if stated.Known() {
				ofB := newStoredLeakRigAs(t, store, stated)
				if status, _ := rawStatus(t, ofB); status.SecretsKnown != 0 || status.Inventory.Loaded != 0 || status.Inventory.OtherTenants != 0 {
					t.Fatalf("B's next proxy: %+v %+v", status, status.Inventory)
				}
			}
		})
	}
}

// The login changes with the daemon alive, within one organisation. What the
// command registers is a guest's: replaced while the daemon runs, stored nowhere.
func TestALoginChangeWithTheDaemonAliveIsAGuestOfTheDaemon(t *testing.T) {
	store := newTestInventoryStore(t)
	const idOfB = "9f1c2d3e-id-only-b-may-see"
	daemon := newStoredLeakRigAs(t, store, leakLoginA)
	environment := map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": daemon.proxyURL.String()}
	previous := leakguard.Environment
	leakguard.Environment = func(key string) string { return environment[key] }
	defer func() { leakguard.Environment = previous }()
	// Before the switch the command is the daemon's own login.
	if result, err := registerAsCommand(leakLoginA, []leakguard.Value{{Type: "secret", ID: "from-a", Value: leakSecretOne}}); err != nil || result.Added != 1 {
		t.Fatalf("A's registration: %+v %v", result, err)
	}
	// After it, the same proxy is found by a command of login B.
	if result, err := registerAsCommand(leakLoginB, []leakguard.Value{{Type: "secret", ID: idOfB, Value: leakSecretTwo}}); err != nil || result.Added != 1 {
		t.Fatalf("B's registration: %+v %v", result, err)
	}
	check := func(rig *leakRig, want string) {
		t.Helper()
		postMessages(t, rig.client(rig.phaseRoots), "https://api.anthropic.com/v1/messages", anthropicBody(leakSecretOne+" and "+leakSecretTwo), "")
		received := rig.lastReceived()
		if !bytes.Contains(received.body, []byte(want+"\"")) {
			t.Fatalf("what the provider received: %s", received.body)
		}
	}
	check(daemon, "ph:secret:from-a and ph:secret")
	status, statusBody := rawStatus(t, daemon)
	shipped, _ := json.Marshal(daemon.distinctLeakEvents(t, 1))
	if status.SecretsKnown != 1 || status.Inventory.Unstored != 1 || bytes.Contains(shipped, []byte(idOfB)) || strings.Contains(statusBody, idOfB) || bytes.Contains(daemon.lastReceived().body, []byte(idOfB)) {
		t.Fatalf("the running proxy: %+v %s", status, shipped)
	}
	// A's daemon wrote its own login's record and none into B's partition.
	if records := storedRecords(t, store); records != 1 {
		t.Fatalf("%d records stored", records)
	}
	daemon.proxy.CloseHijacked()
	// So it lasted as long as the daemon: A's next proxy passes B's value on,
	// and B's own proxy starts with A's value, withheld, and nothing of B's.
	check(newStoredLeakRigAs(t, store, leakLoginA), "ph:secret:from-a and "+leakSecretTwo)
	asB := newStoredLeakRigAs(t, store, leakLoginB)
	if status, _ := rawStatus(t, asB); status.SecretsKnown != 1 || status.Inventory.Loaded != 1 {
		t.Fatalf("B's own proxy: %+v", status.Inventory)
	}
	check(asB, "ph:secret and "+leakSecretTwo)
	// B registers through its own proxy: stored, and named to B alone.
	if answer := registerThroughControl(t, asB.proxy, []leakguard.Value{{Type: "secret", ID: idOfB, Value: leakSecretTwo}}, phaseIDs(1)); answer == nil || answer.Added != 1 || storedRecords(t, store) != 2 {
		t.Fatalf("B's registration with its own proxy: %+v", answer)
	}
	check(asB, "ph:secret and ph:secret:"+idOfB)
	asB.proxy.CloseHijacked()
	// A proxy of A that starts now loads B's stored value and withholds its id.
	restarted := newStoredLeakRigAs(t, store, leakLoginA)
	check(restarted, "ph:secret:from-a and ph:secret")
	if status, body := rawStatus(t, restarted); status.SecretsKnown != 2 || status.Inventory.Loaded != 2 || strings.Contains(body, idOfB) || bytes.Contains(restarted.lastReceived().body, []byte(idOfB)) {
		t.Fatalf("A's proxy after B stored its own: %+v", status.Inventory)
	}
	// Another organisation's proxy loads neither.
	if status, _ := rawStatus(t, newStoredLeakRigAs(t, store, otherTenantA)); status.SecretsKnown != 0 || status.Inventory.OtherTenants != 2 {
		t.Fatalf("another organisation's proxy: %+v", status.Inventory)
	}
}

// A proxy whose session the Console did not name has no tenant and no login:
// it stores nothing, and is to every command what a proxy was before a store.
func TestAProxyWithNoIdentityKeepsNothingAndProtectsAsBefore(t *testing.T) {
	store := newTestInventoryStore(t)
	rig := newStoredLeakRigAs(t, store, phaseproxy.InventoryIdentity{})
	// One key, whatever a command states.
	keys := statedKey(t, rig.proxy, phaseproxy.InventoryIdentity{})
	for _, stated := range []phaseproxy.InventoryIdentity{leakLoginA, otherTenantA, {Tenant: leakLoginA.Tenant}} {
		if statedKey(t, rig.proxy, stated) != keys {
			t.Fatal("a proxy with no identity hands commands different keys")
		}
	}
	if keys.Key != base64.StdEncoding.EncodeToString(rig.guard.key.LookupBytes()) || keys.ConfirmKey != base64.StdEncoding.EncodeToString(rig.guard.key.ConfirmBytes()) {
		t.Fatal("the key it hands out is not its one process key")
	}
	for i, stated := range []phaseproxy.InventoryIdentity{leakLoginA, {}, otherTenantA} {
		values := []leakguard.Value{{Type: "secret", ID: "an-id", Value: leakSecretOne}, {Type: "secret", ID: fmt.Sprintf("id-%d", i), Value: fmt.Sprintf("Zm%dXn8Cb7Va6Sd5Fg4Hj3Kl2Qw1", i)}}
		if answer := registerThroughControlAs(t, rig.proxy, stated, values, phaseIDs(2)); answer == nil || answer.Added != 2 {
			t.Fatalf("registration: %+v", answer)
		}
	}
	status, _ := rawStatus(t, rig)
	if status.SecretsKnown != 4 || status.Inventory.Storage != remoteapi.LeakInventoryMemory || status.Inventory.Reason != phaseproxy.InventoryReasonNoTenant || status.Inventory.Unstored != 0 {
		t.Fatalf("%+v %+v", status, status.Inventory)
	}
	// Ids are written and fragments matched, as they were.
	if out, _ := rig.guard.index.Redact([]byte("a " + leakSecretOne + " b " + leakSecretOne[:30] + " c Zm2Xn8Cb7Va6Sd5Fg4Hj3Kl2Qw1")); string(out) != "a ph:secret:an-id b ph:secret:an-id c ph:secret:id-2" {
		t.Fatalf("%q", out)
	}
	if _, err := os.Lstat(store.Directory); !os.IsNotExist(err) {
		t.Fatalf("a proxy with no identity wrote to the store: %v", err)
	}
}

// The key route hands a command of the session's own login that login's
// stored keys, and any other command keys of this process alone.
func TestKeyAnswerFollowsTheStatedIdentity(t *testing.T) {
	store := newTestInventoryStore(t)
	asA, asB := newStoredLeakRigAs(t, store, leakLoginA), newStoredLeakRigAs(t, store, leakLoginB)
	own, ownB := statedKey(t, asA.proxy, leakLoginA), statedKey(t, asB.proxy, leakLoginB)
	sent, _ := json.Marshal(own)
	var fields map[string]json.RawMessage
	if json.Unmarshal(sent, &fields) != nil || len(fields) != 5 || fields["schemaVersion"] == nil || fields["key"] == nil || fields["confirmKey"] == nil || fields["format"] == nil || fields["keyId"] == nil {
		t.Fatalf("the answer's fields: %s", sent)
	}
	if own.Format != censor.EntriesVersion || own.Key != ownB.Key || own.ConfirmKey == ownB.ConfirmKey || own.ConfirmKey == own.Key || own.KeyID == ownB.KeyID {
		t.Fatal("two logins of a tenant do not share a lookup key and differ by confirming key")
	}
	if own.Key != base64.StdEncoding.EncodeToString(asA.guard.key.LookupBytes()) || own.ConfirmKey != base64.StdEncoding.EncodeToString(asA.guard.key.ConfirmBytes()) {
		t.Fatal("the answer to the session's own login is not its principal's key")
	}
	// A command of login B at A's proxy gets nothing B's own proxy hands B.
	if asked := statedKey(t, asA.proxy, leakLoginB); asked.Key == ownB.Key || asked.ConfirmKey == ownB.ConfirmKey || asked.KeyID == ownB.KeyID || asked.Key == own.Key {
		t.Fatal("a command that states another login of the tenant was handed a key of the tenant's")
	}
	stored, err := store.Keyring.Get("phase-cli-ai-leak-inventory", "key-v1")
	if err != nil {
		t.Fatal(err)
	}
	master, err := base64.StdEncoding.DecodeString(stored[strings.LastIndexByte(stored, ':')+1:])
	if err != nil || len(master) != censor.KeySize {
		t.Fatalf("the keystore holds no master: %v", err)
	}
	// What the other tenant's own proxy would hold: its lookup and confirming keys.
	theirs := newStoredLeakRigAs(t, store, otherTenantA)
	secrets := map[string][]byte{
		"the master": master, "the tenant's lookup key": asA.guard.key.LookupBytes(), "A's confirming key": asA.guard.key.ConfirmBytes(),
		"B's confirming key": asB.guard.key.ConfirmBytes(), "the other tenant's lookup key": theirs.guard.key.LookupBytes(),
		"the other tenant's confirming key": theirs.guard.key.ConfirmBytes(),
	}
	holds := func(answer remoteapi.InventoryKeyResponse, names ...string) string {
		for _, name := range names {
			if keyAnswerHolds(t, answer, secrets[name]) {
				return name
			}
		}
		return ""
	}
	if held := holds(own, "the master", "B's confirming key", "the other tenant's lookup key", "the other tenant's confirming key"); held != "" {
		t.Fatalf("the answer to the session's own login holds %s", held)
	}
	every := []string{"the master", "the tenant's lookup key", "A's confirming key", "B's confirming key", "the other tenant's lookup key", "the other tenant's confirming key"}
	guests := map[string]remoteapi.InventoryKeyResponse{}
	for name, stated := range map[string]phaseproxy.InventoryIdentity{
		"another organisation": otherTenantA, "another host": otherHostTenant, "nobody": {}, "a tenant alone": {Tenant: leakLoginA.Tenant},
		"another login of the tenant": leakLoginB,
	} {
		answer := statedKey(t, asA.proxy, stated)
		if held := holds(answer, every...); held != "" {
			t.Fatalf("a command of %s was handed %s", name, held)
		}
		// A guest gets the same keys each time it asks, whatever it states.
		if again := statedKey(t, asA.proxy, stated); again != answer {
			t.Fatalf("a command of %s asking twice was handed other keys", name)
		}
		guests[name] = answer
	}
	// A GET states nothing, and is nobody's: the keys of every command that
	// states nothing, or nothing that is an identity.
	recorder := controlCall(asA.proxy, http.MethodGet, "/v1/inventory/key", "", nil)
	var plain remoteapi.InventoryKeyResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &plain) != nil || holds(plain, every...) != "" {
		t.Fatalf("a key request that states nothing: %d", recorder.Code)
	}
	if plain != guests["nobody"] || plain != guests["a tenant alone"] {
		t.Fatal("commands that state no identity are not one guest")
	}
	// Guests share this process's lookup key and nothing else, and none of
	// it outlives the process: the next proxy hands out other keys.
	confirming := map[string]string{plain.ConfirmKey: "a GET"}
	for _, name := range []string{"another organisation", "another host", "another login of the tenant"} {
		guest := guests[name]
		if other, twice := confirming[guest.ConfirmKey]; twice || guest.Key != plain.Key || guest.KeyID == plain.KeyID {
			t.Fatalf("a command of %s and %s do not differ by confirming key alone", name, other)
		}
		confirming[guest.ConfirmKey] = name
	}
	next := newStoredLeakRigAs(t, store, leakLoginA)
	if again := statedKey(t, next.proxy, otherTenantA); again.Key == guests["another organisation"].Key || again.ConfirmKey == guests["another organisation"].ConfirmKey {
		t.Fatal("a guest's key outlived the proxy that made it")
	}
	if again := statedKey(t, next.proxy, leakLoginA); again != own {
		t.Fatal("the session's own key changed with the proxy")
	}
	// A client of A, with what it was handed, indexes B's value to hashes
	// that are not the ones B's record holds: the registration adds a record.
	if answer := registerThroughControl(t, asB.proxy, []leakguard.Value{{Type: "secret", ID: "from-b", Value: leakSecretTwo}}, nil); answer == nil || answer.Added != 1 {
		t.Fatalf("B's registration: %+v", answer)
	}
	loaded := newStoredLeakRigAs(t, store, leakLoginA)
	before := loaded.guard.index.Stats()
	if answer := registerThroughControl(t, loaded.proxy, []leakguard.Value{{Type: "secret", ID: "from-b", Value: leakSecretTwo}}, nil); answer == nil || answer.Added != 1 {
		t.Fatalf("A's registration: %+v", answer)
	}
	if after := loaded.guard.index.Stats(); after.Forms != 2*before.Forms {
		t.Fatalf("A's entries for B's value were B's own: %+v then %+v", before, after)
	}
}

// Status counts a value once for each login that registered it: a dummy
// under a guessed key name moves the count the same, right or wrong.
func TestStatusNeverConfirmsAnotherLoginsID(t *testing.T) {
	store := newTestInventoryStore(t)
	asB := newStoredLeakRigAs(t, store, leakLoginB)
	if a := registerThroughControl(t, asB.proxy, []leakguard.Value{{Type: "secret", ID: "PROD_DATABASE_URL", Value: leakSecretTwo}}, []string{remoteapi.InventoryIDKeyName}); a == nil || a.Added != 1 {
		t.Fatal("B's registration")
	}
	asB.proxy.CloseHijacked()
	asA := newStoredLeakRigAs(t, store, leakLoginA)
	known := func() int { s, _ := rawStatus(t, asA); return s.SecretsKnown }
	guess := func(stated phaseproxy.InventoryIdentity, id, value string) int {
		t.Helper()
		before := known()
		if a := registerThroughControlAs(t, asA.proxy, stated, []leakguard.Value{{Type: "secret", ID: id, Value: value}}, []string{remoteapi.InventoryIDKeyName}); a == nil || a.Added != 1 {
			t.Fatalf("the dummy registration of %s", id)
		}
		return known() - before
	}
	wrong := guess(leakLoginA, "STRIPE_SECRET_KEY", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0x")
	right := guess(leakLoginA, "PROD_DATABASE_URL", "Zx9Cv8Bn7Mq6Ws5Ed4Rf3Tg2Yh1Uj0Ik")
	if wrong != 1 || right != 1 {
		t.Fatalf("the count moved by %d for a wrong guess and %d for the right one", wrong, right)
	}
	// A command of another account moves the session's count not at all, and
	// what it does move counts registrations, whatever they held.
	unstored := func() int { s, _ := rawStatus(t, asA); return s.Inventory.Unstored }
	for _, id := range []string{"NOBODYS_KEY", "PROD_DATABASE_URL", "PROD_DATABASE_URL"} {
		before := unstored()
		if moved := guess(otherTenantA, id, "Qw7Er8Ty9Ui0Op1As2Df3Gh4Jk5Lz6Xc"); moved != 0 || unstored()-before != 1 {
			t.Fatalf("a guest's registration of %s moved the counts by %d and %d", id, moved, unstored()-before)
		}
	}
}

// Every value of another login found is reported once, though each is
// written ph:<type>: two values are two events, the same again is none.
func TestEachWithheldValueIsReportedOnce(t *testing.T) {
	store := newTestInventoryStore(t)
	const second = "Hd6Fs1Gp0YaJw3Rk8Tn5Vb2Xq7Zc4Lm9"
	asB := newStoredLeakRigAs(t, store, leakLoginB)
	if a := registerThroughControl(t, asB.proxy, []leakguard.Value{
		{Type: "secret", ID: "b-one", Value: leakSecretOne}, {Type: "secret", ID: "b-two", Value: second},
	}, phaseIDs(2)); a == nil || a.Added != 2 {
		t.Fatal("B's registration")
	}
	asB.proxy.CloseHijacked()
	asA := newStoredLeakRigAs(t, store, leakLoginA)
	// A guest's value is withheld the same way, and is a third.
	if a := registerThroughControlAs(t, asA.proxy, otherTenantA, []leakguard.Value{{Type: "secret", ID: "guest-one", Value: leakSecretThree}}, phaseIDs(1)); a == nil || a.Added != 1 {
		t.Fatal("the guest's registration")
	}
	send := func(content string) {
		postMessages(t, asA.client(asA.phaseRoots), "https://api.anthropic.com/v1/messages", anthropicBody(content), "")
		if received := asA.lastReceived(); !bytes.Contains(received.body, []byte("ph:secret")) || bytes.Contains(received.body, []byte("ph:secret:")) {
			t.Fatalf("what the provider received: %s", received.body)
		}
	}
	send("first " + leakSecretOne)
	asA.distinctLeakEvents(t, 1)
	send("another " + second)
	events := asA.distinctLeakEvents(t, 2)
	send("a guest's " + leakSecretThree)
	events = asA.distinctLeakEvents(t, 3)
	// The conversation so far, sent again with every model request: nothing new.
	send("first " + leakSecretOne + " another " + second + " a guest's " + leakSecretThree)
	time.Sleep(50 * time.Millisecond)
	if again := asA.leakEventsNow(); len(again) != 3 {
		t.Fatalf("%d events after the same three values were sent again", len(again))
	}
	shipped, _ := json.Marshal(events)
	for _, event := range events {
		if event.Detail["placeholders"] != "ph:secret" || event.Detail["placeholderCount"] != float64(1) {
			t.Fatalf("an event of a withheld value: %+v", event.Detail)
		}
	}
	for _, id := range []string{"b-one", "b-two", "guest-one"} {
		if bytes.Contains(shipped, []byte(id)) {
			t.Fatalf("an event names %q", id)
		}
	}
	// One request with all three counts three values under one placeholder.
	fresh := newStoredLeakRigAs(t, store, leakLoginA)
	postMessages(t, fresh.client(fresh.phaseRoots), "https://api.anthropic.com/v1/messages", anthropicBody(leakSecretOne+" "+second+" "+leakSecretOne), "")
	if detail := fresh.distinctLeakEvents(t, 1)[0].Detail; detail["placeholders"] != "ph:secret" || detail["placeholderCount"] != float64(2) || detail["replacedCount"] != float64(2) || detail["inventoryHits"] != float64(3) {
		t.Fatalf("one request with two withheld values: %+v", detail)
	}
}

// A value another login or account registered is replaced where it stands
// whole and nowhere else: the proxy confirms no guessed piece of it.
func TestWithheldValuesAreNotConfirmedPieceByPiece(t *testing.T) {
	store := newTestInventoryStore(t)
	asB := newStoredLeakRigAs(t, store, leakLoginB)
	if a := registerThroughControl(t, asB.proxy, []leakguard.Value{{Type: "secret", ID: "of-b", Value: leakSecretTwo}}, phaseIDs(1)); a == nil || a.Added != 1 {
		t.Fatal("B's registration")
	}
	asB.proxy.CloseHijacked()
	asA := newStoredLeakRigAs(t, store, leakLoginA)
	if a := registerThroughControl(t, asA.proxy, []leakguard.Value{{Type: "secret", ID: "of-a", Value: leakSecretOne}}, phaseIDs(1)); a == nil || a.Added != 1 {
		t.Fatal("A's registration")
	}
	if a := registerThroughControlAs(t, asA.proxy, otherTenantA, []leakguard.Value{{Type: "secret", ID: "of-guest", Value: leakSecretThree}}, phaseIDs(1)); a == nil || a.Added != 1 {
		t.Fatal("the guest's registration")
	}
	password := "Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3"
	for name, piece := range map[string]string{
		"the first half of B's":    leakSecretTwo[:len(leakSecretTwo)/2],
		"B's, its password short":  leakSecretTwo[:36],
		"B's password and no more": password[:len(password)-1],
		"a chunk of B's password":  password[:14],
		"most of a guest's":        leakSecretThree[2:],
		"the hex of half of B's":   hex.EncodeToString([]byte(leakSecretTwo[:30])),
	} {
		body := anthropicBody("is it " + piece + " then")
		postMessages(t, asA.client(asA.phaseRoots), "https://api.anthropic.com/v1/messages", body, "")
		if received := asA.lastReceived(); !bytes.Equal(received.body, []byte(body)) {
			t.Fatalf("%s was confirmed: %s", name, received.body)
		}
	}
	if events := asA.leakEventsNow(); len(events) != 0 {
		t.Fatalf("a piece of a withheld value was reported: %+v", events)
	}
	// The session's own value is still found by a piece of it, and a
	// withheld one whole, in any of its forms, and by its URL's password.
	postMessages(t, asA.client(asA.phaseRoots), "https://api.anthropic.com/v1/messages",
		anthropicBody("a "+leakSecretOne[:30]+" b "+leakSecretTwo+" c "+hex.EncodeToString([]byte(leakSecretThree))+" d "+password+" e"), "")
	if received := asA.lastReceived(); !bytes.Contains(received.body, []byte("a ph:secret:of-a b ph:secret c ph:secret d ph:secret e")) {
		t.Fatalf("what the provider received: %s", received.body)
	}
}

// A login registers up to its share and is told when it is full. Another
// login, and the same login after a restart, still has room.
func TestAFullInventoryIsOneLoginsAndDoesNotOutliveARestart(t *testing.T) {
	store := newTestInventoryStore(t)
	leakIndexMaxSecrets = 8
	t.Cleanup(func() { leakIndexMaxSecrets = 0 })
	values := []string{
		"mQ4zT7wK2nB9xR5cV8pL1dH6", "Yg3Js6Uf9Ia2Oe5Pw8Ld1Kc4", "tN7bX2vM5qZ8rW3kG6hC9jF1", "E4sA7dU1iO8pY5lT2gR9fK6h",
		"zC3vB6nM9xL2kJ5hG8fD1sQ4", "Kd8Fj2Ls9Qa4Wz7Xe1Cr5Vt6", "Pb3Ny7Mu1Hi9Og5Lk2Jf8Dz4", "Rw6Tq0Ye4Ui8Oa2Sd7Fg1Hj3",
	}
	register := func(rig *leakRig, stated phaseproxy.InventoryIdentity, id, value string) int {
		t.Helper()
		keyAnswer := statedKey(t, rig.proxy, stated)
		entry, err := censor.IndexValue(answeredKey(t, keyAnswer), "secret", id, value)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := entry.Marshal()
		body, _ := json.Marshal(remoteapi.InventoryRequest{SchemaVersion: 1, Entries: []json.RawMessage{encoded}, Tenant: stated.Tenant, Login: stated.Login, KeyID: keyAnswer.KeyID})
		recorder := controlCall(rig.proxy, http.MethodPost, "/v1/inventory", "application/json", body)
		if recorder.Code != http.StatusOK && errorCode(recorder) != "leak_inventory_full" {
			t.Fatalf("registering %s: %d %s", id, recorder.Code, recorder.Body.String())
		}
		return recorder.Code
	}
	first := newStoredLeakRigAs(t, store, leakLoginA)
	// One login's share of an index of eight is four.
	for i := 0; i < 4; i++ {
		if code := register(first, leakLoginA, fmt.Sprintf("a-%d", i), values[i]); code != http.StatusOK {
			t.Fatalf("value %d of login A: HTTP %d", i, code)
		}
	}
	if code := register(first, leakLoginA, "a-4", values[4]); code != http.StatusInsufficientStorage {
		t.Fatalf("login A past its share: HTTP %d", code)
	}
	// Another login of the tenant, and a command of another account, are
	// not shut out by it: each is a guest, with the guests' share to fill.
	if code := register(first, leakLoginB, "b-0", values[5]); code != http.StatusOK {
		t.Fatalf("login B after login A filled its share: HTTP %d", code)
	}
	if code := register(first, otherTenantA, "guest-0", values[6]); code != http.StatusOK {
		t.Fatalf("a guest after login A filled its share: HTTP %d", code)
	}
	first.proxy.CloseHijacked()
	// A proxy that starts again loads a share of what is stored and has room:
	// the review found every later registration refused until records expired.
	for restart := 1; restart <= 3; restart++ {
		next := newStoredLeakRigAs(t, store, leakLoginA)
		status, _ := rawStatus(t, next)
		if status.Inventory.Loaded > 4 || status.Inventory.Loaded == 0 || status.Inventory.Loaded+status.Inventory.NotLoaded != 3+restart {
			t.Fatalf("restart %d loaded %d and left out %d", restart, status.Inventory.Loaded, status.Inventory.NotLoaded)
		}
		fresh := fmt.Sprintf("Zm%dXn8Cb7Va6Sd5Fg4Hj3Kl2Qw1", restart)
		if code := register(next, leakLoginA, fmt.Sprintf("new-%d", restart), fresh); code != http.StatusOK {
			t.Fatalf("restart %d: registering a new value: HTTP %d", restart, code)
		}
		if out, _ := next.guard.index.Redact([]byte(fresh)); string(out) != fmt.Sprintf("ph:secret:new-%d", restart) {
			t.Fatalf("restart %d: the new value is not replaced: %q", restart, out)
		}
		next.proxy.CloseHijacked()
	}
}

// One tenant's client, posting as much as the control API takes, leaves
// another tenant's stored record where it was, and its own within its bound.
func TestAClientsVolumeNeverEvictsAnotherTenantsRecords(t *testing.T) {
	store := newTestInventoryStore(t)
	asB := newStoredLeakRigAs(t, store, otherTenantB)
	if a := registerThroughControl(t, asB.proxy, []leakguard.Value{{Type: "secret", ID: "b-id", Value: leakSecretTwo}}, phaseIDs(1)); a == nil || a.Added != 1 {
		t.Fatal("B's registration")
	}
	asB.proxy.CloseHijacked()
	asA := newStoredLeakRigAs(t, store, leakLoginA)
	keyAnswer := statedKey(t, asA.proxy, leakLoginA)
	// One-chunk entries under one id: the cheapest record there is.
	for post := 0; post < 3; post++ {
		request := remoteapi.InventoryRequest{SchemaVersion: 1, Tenant: leakLoginA.Tenant, Login: leakLoginA.Login, KeyID: keyAnswer.KeyID}
		for i := 0; i < maxInventoryEntries; i++ {
			chunk := make([]byte, 3+16)
			if _, err := rand.Read(chunk); err != nil {
				t.Fatal(err)
			}
			entry := &censor.Entries{Version: 2, Type: "secret", ID: "x", Forms: []censor.Form{{Form: "raw", Length: 12, Lookups: chunk[:3], MACs: chunk[3:], Weak: []byte{0}}}}
			encoded, err := entry.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			request.Entries = append(request.Entries, encoded)
		}
		body, _ := json.Marshal(request)
		if recorder := controlCall(asA.proxy, http.MethodPost, "/v1/inventory", "application/json", body); recorder.Code != http.StatusOK {
			t.Fatalf("post %d: HTTP %d %s", post, recorder.Code, recorder.Body.String())
		}
	}
	asA.proxy.CloseHijacked()
	if records := storedRecords(t, store); records != 4096+1 {
		t.Fatalf("the file holds %d records: one login's bound is 4096, beside B's one", records)
	}
	nextB := newStoredLeakRigAs(t, store, otherTenantB)
	status, _ := rawStatus(t, nextB)
	if out, _ := nextB.guard.index.Redact([]byte("x " + leakSecretTwo)); status.Inventory.Loaded != 1 || status.Inventory.OtherTenants != 4096 || string(out) != "x ph:secret:b-id" {
		t.Fatalf("tenant B after tenant A's volume: %+v, %q", status.Inventory, out)
	}
}

// sendWithValueInURL posts a model request that holds a value in its URL and
// in its body, and answers with the status the client got.
func sendWithValueInURL(t *testing.T, rig *leakRig, value string) int {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages?m="+value, bytes.NewReader(anthropicBody("the value is "+value)))
	request.Header.Set("Content-Type", "application/json")
	return doRequest(t, rig.client(rig.phaseRoots), request)
}

// A value in a URL stops the request at the proxy it was registered with. A
// proxy that knows it only from the store replaces and reports it, and never blocks.
func TestAStoredValueInAURLIsReportedAndNeverBlocks(t *testing.T) {
	store := newTestInventoryStore(t)
	const marker = "Mm4Kk7Rr2Ss9Tt1Uu6Vv3Ww8"
	values := []leakguard.Value{{Type: "secret", ID: "marker-id", Value: marker}}
	first := newStoredLeakRigAs(t, store, leakLoginA)
	if answer := registerThroughControl(t, first.proxy, values, phaseIDs(1)); answer == nil || answer.Added != 1 {
		t.Fatalf("registration: %+v", answer)
	}
	if status := sendWithValueInURL(t, first, marker); status != http.StatusForbidden || first.receivedCount() != 0 {
		t.Fatalf("the proxy the value was registered with: HTTP %d", status)
	}
	first.proxy.CloseHijacked()
	for name, c := range map[string]struct {
		identity phaseproxy.InventoryIdentity
		written  string
	}{"the same login, restarted": {leakLoginA, "ph:secret:marker-id"}, "another login of the tenant": {leakLoginB, "ph:secret"}} {
		rig := newStoredLeakRigAs(t, store, c.identity)
		if status := sendWithValueInURL(t, rig, marker); status != http.StatusOK {
			t.Fatalf("%s: a stored value in the URL stopped the request: HTTP %d", name, status)
		}
		// Replaced where it can be, and reported where it cannot.
		received := rig.lastReceived()
		if received.rawQuery != "m="+marker || !bytes.Contains(received.body, []byte("the value is "+c.written+"\"")) {
			t.Fatalf("%s: what the provider received: %s %s", name, received.rawQuery, received.body)
		}
		event := rig.distinctLeakEvents(t, 1)[0]
		if event.ProxyDecision != "allow" || event.Outcome != outcomeCensored || event.Detail["where"] != "body,url" || event.Detail["placeholders"] != c.written {
			t.Fatalf("%s: the event: %+v", name, event)
		}
		// A body that cannot be rewritten is no reason either.
		request, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(append([]byte{0xff, 0x00}, marker...)))
		if status := doRequest(t, rig.client(rig.phaseRoots), request); status != http.StatusOK {
			t.Fatalf("%s: a stored value in a binary body stopped the request: HTTP %d", name, status)
		}
		rig.proxy.CloseHijacked()
	}
	// Registered again, it is the running proxy's own, and stops a request again.
	again := newStoredLeakRigAs(t, store, leakLoginA)
	if status := sendWithValueInURL(t, again, marker); status != http.StatusOK {
		t.Fatalf("before it is registered again: HTTP %d", status)
	}
	if answer := registerThroughControl(t, again.proxy, values, phaseIDs(1)); answer == nil || answer.Added != 1 {
		t.Fatalf("registration: %+v", answer)
	}
	if status := sendWithValueInURL(t, again, marker); status != http.StatusForbidden {
		t.Fatalf("after it is registered again: HTTP %d", status)
	}
}

// A value that is a host or a path of a model host's own requests is not
// indexed: held, it would stop every request there. It counts as unprotected.
func TestAValueThatIsAModelHostOrPathIsNotIndexed(t *testing.T) {
	store := newTestInventoryStore(t)
	rig := newStoredLeakRigAs(t, store, leakLoginA)
	public := []leakguard.Value{
		{Type: "secret", ID: "API_PATH", Value: "/v1/messages"}, {Type: "secret", ID: "API_HOST", Value: "api.anthropic.com"},
		{Type: "secret", ID: "RESPONSES_PATH", Value: codexSocketPath},
	}
	for name, stated := range map[string]phaseproxy.InventoryIdentity{"the session's own login": leakLoginA, "a guest": otherTenantA, "a command that states nothing": {}} {
		if answer := registerThroughControlAs(t, rig.proxy, stated, public, phaseIDs(3)); answer == nil || answer.Added != 0 || answer.Unprotected != 3 {
			t.Fatalf("%s registering a model host's own host and paths: %+v", name, answer)
		}
	}
	status, _ := rawStatus(t, rig)
	if status.SecretsKnown != 0 || status.Unprotected != 3 || rig.guard.index.Stats().Guests != 0 || storedRecords(t, store) != 0 {
		t.Fatalf("%+v, %+v", status, rig.guard.index.Stats())
	}
	// A longer path that begins as one is taken, and its beginning is no match.
	longer := []leakguard.Value{{Type: "secret", ID: "COUNT_PATH", Value: "/v1/messages/count_tokens?beta=true"}}
	if answer := registerThroughControl(t, rig.proxy, longer, phaseIDs(1)); answer == nil || answer.Added != 1 {
		t.Fatalf("a longer path: %+v", answer)
	}
	body := anthropicBody("hello")
	for _, target := range []string{"https://api.anthropic.com/v1/messages", "https://api.anthropic.com/v1/messages?beta=true", "https://api.openai.com/v1/responses"} {
		request, _ := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if code := doRequest(t, rig.client(rig.phaseRoots), request); code != http.StatusOK || !bytes.Equal(rig.lastReceived().body, body) {
			t.Fatalf("%s: HTTP %d", target, code)
		}
	}
	if events := rig.leakEventsNow(); len(events) != 0 {
		t.Fatalf("a model host's own requests were reported: %+v", events)
	}
	// The value itself, whole, is still what it was registered as.
	request, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages/count_tokens?beta=true", bytes.NewReader(body))
	if code := doRequest(t, rig.client(rig.phaseRoots), request); code != http.StatusForbidden {
		t.Fatalf("the longer path, whole, in a URL: HTTP %d", code)
	}
	// What an earlier proxy stored of such a value is not loaded either.
	rig.proxy.CloseHijacked()
	next := newStoredLeakRigAs(t, store, leakLoginA)
	request, _ = http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if code := doRequest(t, next.client(next.phaseRoots), request); code != http.StatusOK || next.guard.status().SecretsKnown != 1 {
		t.Fatalf("the next proxy: HTTP %d, %+v", code, next.guard.status())
	}
}

// A client of the proxy's own login fills a lookup value with forged forms and
// registers a guess of a chunk of another login's value last: held, right or wrong.
func TestAFilledLookupValueConfirmsNoChunkOfAnotherLoginsValue(t *testing.T) {
	store := newTestInventoryStore(t)
	const valueOfB = "Zk3Qw9Lm2Xr7Tb5Nc8Vd1Hy6Gs4Fp0Ju7Ke2Ma9"
	asB := newStoredLeakRigAs(t, store, leakLoginB)
	if answer := registerThroughControl(t, asB.proxy, []leakguard.Value{{Type: "secret", ID: "id-of-b", Value: valueOfB}}, phaseIDs(1)); answer == nil || answer.Added != 1 {
		t.Fatalf("B: %+v", answer)
	}
	asB.proxy.CloseHijacked()
	asA := newStoredLeakRigAs(t, store, leakLoginA)
	if status, _ := rawStatus(t, asA); status.Inventory.Loaded != 1 {
		t.Fatalf("A did not load B's value: %+v", status.Inventory)
	}
	keyAnswer := statedKey(t, asA.proxy, leakLoginA)
	for name, guess := range map[string]string{
		"first": valueOfB[:12], "second": valueOfB[12:24], "third": valueOfB[24:36], "wrong": "Aa1Bb2Cc3Dd4", "misaligned": valueOfB[1:13], "one-off": valueOfB[:11] + "-",
	} {
		filler, probe := forgedProbe(t, answeredKey(t, keyAnswer), "secret", name, guess)
		if recorder := postInventory(t, asA.proxy, leakLoginA, keyAnswer.KeyID, filler, probe); recorder.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d %s", name, recorder.Code, errorCode(recorder))
		}
		if out, _ := asA.guard.index.Redact([]byte("x " + guess + " y")); string(out) != "x ph:secret:probe-"+name+" y" {
			t.Errorf("the guess %q was not held: whether it is says whether it is a chunk of B's value: %q", name, out)
		}
		// Seen from outside: the client's own probe in a URL stops the request,
		// whichever chunk it guessed.
		request, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages?q="+guess, bytes.NewReader(anthropicBody("hello")))
		request.Header.Set("Content-Type", "application/json")
		if code := doRequest(t, asA.client(asA.phaseRoots), request); code != http.StatusForbidden {
			t.Errorf("the guess %q in a URL: HTTP %d", name, code)
		}
	}
	// B's value is still found whole, through the crowd, and names no id.
	if out, _ := asA.guard.index.Redact([]byte("a " + valueOfB + " b")); string(out) != "a ph:secret b" {
		t.Fatalf("B's value: %q", out)
	}
}
