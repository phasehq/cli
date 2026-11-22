package proxy

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/pkg/censor"
)

const inventoryTestAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func inventoryTestValue(t testing.TB, alphabet string, n int) string {
	t.Helper()
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(raw)
}

// lockedKeyring is the CA store tests' memory keyring, safe for the
// goroutines that stand in for separate proxy processes.
type lockedKeyring struct {
	mu sync.Mutex
	memoryKeyring
}

func (k *lockedKeyring) Get(service, user string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.memoryKeyring.Get(service, user)
}

func (k *lockedKeyring) Set(service, user, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.memoryKeyring.Set(service, user, value)
}

func init() {
	inventoryKeySettle, inventoryKeyCheckEvery = 5*time.Millisecond, 0
}

func newInventoryTestStore(t testing.TB) InventoryStore {
	t.Helper()
	return InventoryStore{Directory: t.TempDir(), Keyring: &lockedKeyring{memoryKeyring: memoryKeyring{values: map[string]string{}}}, Tenant: inventoryTestTenant}
}

func openInventory(t testing.TB, store InventoryStore) (*Inventory, []StoredEntries) {
	t.Helper()
	inv, loaded, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	return inv, loaded
}

// inventoryTestTenant is the tenant the tests' stores are opened for.
const inventoryTestTenant = "https://console.test\norganisation\ntest-organisation"

// inventoryTestLogin is the login most tests register as.
const inventoryTestLogin = "https://console.test\naccount\ntest-account"

// testPrincipal is the principal of the tests' login in an inventory.
func testPrincipal(t testing.TB, inv *Inventory) InventoryPrincipal {
	t.Helper()
	return principalOf(t, inv, inventoryTestLogin)
}

func principalOf(t testing.TB, inv *Inventory, login string) InventoryPrincipal {
	t.Helper()
	principal, err := inv.Principal(login)
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

// inventoryKeyBytes is both parts of the key the tests' login is handed.
func inventoryKeyBytes(t testing.TB, inv *Inventory) []byte {
	t.Helper()
	key := testPrincipal(t, inv).Key()
	return append(key.LookupBytes(), key.ConfirmBytes()...)
}

func inventoryEntries(t testing.TB, inv *Inventory, scheme int, id, value string) *censor.Entries {
	t.Helper()
	entries, err := censor.IndexValueScheme(testPrincipal(t, inv).Key(), scheme, "secret", id, value)
	if err != nil || !entries.Protected() {
		t.Fatalf("index %s: %v", id, err)
	}
	return entries
}

// finds reports whether an index of the loaded entries, each under its own
// principal's key, replaces value.
func finds(t testing.TB, inv *Inventory, loaded []StoredEntries, value string) bool {
	t.Helper()
	index, err := censor.NewIndex(testPrincipal(t, inv).Key(), censor.IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, stored := range loaded {
		if err := index.AddKeyed(stored.Principal.Key(), stored.Entries); err != nil {
			t.Fatalf("a loaded entry was refused by the index: %v", err)
		}
	}
	out, _ := index.Redact([]byte("the value is " + value + " here"))
	return !strings.Contains(string(out), value)
}

func inventoryFilePath(store InventoryStore) string {
	return filepath.Join(store.Directory, inventoryFileName)
}

// inventoryFileRecords is how many records the file holds, whosever they
// are: what its lengths show to anyone who can read it, and no status says.
func inventoryFileRecords(t testing.TB, store InventoryStore) int {
	t.Helper()
	data, err := os.ReadFile(inventoryFilePath(store))
	if err != nil {
		t.Fatal(err)
	}
	records := 0
	for rest := data[inventoryHeaderSize:]; len(rest) >= 4; records++ {
		rest = rest[4+int(binary.BigEndian.Uint32(rest)):]
	}
	return records
}

// A value registered with one proxy is known to the next one, which reads
// the same key from the keystore and the entries from the file.
func TestInventorySurvivesARestart(t *testing.T) {
	store := newInventoryTestStore(t)
	first, loaded := openInventory(t, store)
	if status := first.Status(); !status.Durable || status.Reason != "" || len(loaded) != 0 || status.Loaded != 0 {
		t.Fatalf("a first start: %+v, %d loaded", status, len(loaded))
	}
	value, named := inventoryTestValue(t, inventoryTestAlphabet, 40), inventoryTestValue(t, inventoryTestAlphabet, 40)
	first.Add([]StoredEntries{
		{Principal: testPrincipal(t, first), Entries: inventoryEntries(t, first, censor.EntriesVersion, "one", value)},
		{Principal: testPrincipal(t, first), Entries: inventoryEntries(t, first, censor.EntriesVersion, "DATABASE_PASSWORD", named), KeyNamed: true},
	})
	// A value too short to protect has nothing to store.
	short, err := censor.IndexValue(testPrincipal(t, first).Key(), "secret", "short", "abc")
	if err != nil {
		t.Fatal(err)
	}
	first.Add([]StoredEntries{{Entries: short}})

	second, loaded := openInventory(t, store)
	if !bytes.Equal(inventoryKeyBytes(t, first), inventoryKeyBytes(t, second)) {
		t.Fatal("the second proxy has another key")
	}
	if status := second.Status(); !status.Durable || status.Loaded != 2 || len(loaded) != 2 || status.OtherKey || status.Damaged+status.OtherScheme+status.Expired != 0 {
		t.Fatalf("%+v, %d loaded", status, len(loaded))
	}
	if !finds(t, second, loaded, value) || !finds(t, second, loaded, named) {
		t.Fatal("a stored value is not found after a restart")
	}
	keyNamed := map[string]bool{}
	for _, stored := range loaded {
		keyNamed[stored.Entries.ID] = stored.KeyNamed
	}
	if keyNamed["one"] || !keyNamed["DATABASE_PASSWORD"] {
		t.Fatalf("what is known of the ids was not kept: %v", keyNamed)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(inventoryFilePath(store))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("the file is not owner-only: %v %v", info, err)
		}
	}
	// Registering the same values again writes nothing.
	before, _ := os.Stat(inventoryFilePath(store))
	second.Add(loaded)
	after, _ := os.Stat(inventoryFilePath(store))
	if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		t.Fatal("a repeated registration rewrote the file")
	}
}

// Without a keystore nothing is stored: no key, no file, not even the
// directory, and the inventory works from memory as it always did.
func TestInventoryWithoutAKeystoreIsMemoryOnly(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "ai")
	store := InventoryStore{Directory: directory, Keyring: unusableKeyring{}, Tenant: inventoryTestTenant}
	inv, loaded := openInventory(t, store)
	if status := inv.Status(); status.Durable || status.Reason != InventoryReasonNoKeystore || len(loaded) != 0 {
		t.Fatalf("%+v", status)
	}
	value := inventoryTestValue(t, inventoryTestAlphabet, 40)
	entries := inventoryEntries(t, inv, censor.EntriesVersion, "one", value)
	inv.Add([]StoredEntries{{Principal: testPrincipal(t, inv), Entries: entries}})
	if !finds(t, inv, []StoredEntries{{Principal: testPrincipal(t, inv), Entries: entries}}, value) {
		t.Fatal("the memory inventory's key does not index")
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("the directory was made without a keystore: %v", err)
	}
	again, _ := openInventory(t, store)
	if bytes.Equal(inventoryKeyBytes(t, inv), inventoryKeyBytes(t, again)) {
		t.Fatal("two memory inventories share a key")
	}
	if err := store.ReplaceKey(); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	// A keystore that reads and cannot be written is no keystore either.
	readOnly := InventoryStore{Directory: filepath.Join(t.TempDir(), "ai"), Keyring: &memoryKeyring{values: map[string]string{}, setError: os.ErrPermission}, Tenant: inventoryTestTenant}
	inv, _ = openInventory(t, readOnly)
	if status := inv.Status(); status.Durable || status.Reason != InventoryReasonNoKeystore {
		t.Fatalf("%+v", status)
	}
	if _, err := os.Lstat(inventoryFilePath(readOnly)); !os.IsNotExist(err) {
		t.Fatalf("a file was written with no key stored: %v", err)
	}
}

// Several proxies of one user register at once: every entry of every one of
// them is in the file afterwards, and the file is whole.
func TestInventoryConcurrentWriters(t *testing.T) {
	store := newInventoryTestStore(t)
	const proxies, batches, perBatch = 4, 6, 5
	values := make([][]string, proxies)
	var wait sync.WaitGroup
	start := make(chan struct{})
	// The key exists: proxies that make the first key together are another
	// test's (TestInventoryFirstStartsTogether).
	openInventory(t, store)
	for p := 0; p < proxies; p++ {
		for i := 0; i < batches*perBatch; i++ {
			values[p] = append(values[p], inventoryTestValue(t, inventoryTestAlphabet, 32))
		}
		wait.Add(1)
		go func(p int) {
			defer wait.Done()
			<-start
			// Each opens for itself, as a process would.
			inv, _, err := store.Open()
			if err != nil {
				t.Error(err)
				return
			}
			for b := 0; b < batches; b++ {
				var batch []StoredEntries
				for i := 0; i < perBatch; i++ {
					at := b*perBatch + i
					entries, err := censor.IndexValue(testPrincipal(t, inv).Key(), "secret", fmt.Sprintf("p%d-%d", p, at), values[p][at])
					if err != nil {
						t.Error(err)
						return
					}
					batch = append(batch, StoredEntries{Principal: testPrincipal(t, inv), Entries: entries})
				}
				inv.Add(batch)
			}
			if status := inv.Status(); !status.Durable {
				t.Errorf("proxy %d stopped storing: %+v", p, status)
			}
		}(p)
	}
	close(start)
	wait.Wait()
	inv, loaded := openInventory(t, store)
	if status := inv.Status(); len(loaded) != proxies*batches*perBatch || status.Damaged != 0 || status.OtherKey {
		t.Fatalf("%d entries loaded of %d: %+v", len(loaded), proxies*batches*perBatch, status)
	}
	for p := range values {
		for _, value := range values[p] {
			if !finds(t, inv, loaded, value) {
				t.Fatal("a value registered beside other writers was lost")
			}
		}
	}
	entries, err := os.ReadDir(store.Directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), inventoryTempPrefix) {
			t.Fatalf("a temporary file was left: %s", entry.Name())
		}
	}
}

// An entry not registered again for InventoryEntryLifetime is dropped when
// the store is opened, and one registered again within it lives on.
func TestInventoryEntriesExpire(t *testing.T) {
	store := newInventoryTestStore(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	store.Now = func() time.Time { return now }
	inv, _ := openInventory(t, store)
	stale, kept := inventoryTestValue(t, inventoryTestAlphabet, 40), inventoryTestValue(t, inventoryTestAlphabet, 40)
	staleEntries := inventoryEntries(t, inv, censor.EntriesVersion, "stale", stale)
	keptEntries := inventoryEntries(t, inv, censor.EntriesVersion, "kept", kept)
	principal := testPrincipal(t, inv)
	inv.Add([]StoredEntries{{Principal: principal, Entries: staleEntries}, {Principal: principal, Entries: keptEntries}})

	now = now.Add(20 * 24 * time.Hour)
	inv.Add([]StoredEntries{{Principal: principal, Entries: keptEntries}})

	now = now.Add(InventoryEntryLifetime - 20*24*time.Hour + time.Hour)
	reopened, loaded := openInventory(t, store)
	if status := reopened.Status(); status.Expired != 1 || status.Loaded != 1 || len(loaded) != 1 || loaded[0].Entries.ID != "kept" {
		t.Fatalf("%+v", status)
	}
	if finds(t, reopened, loaded, stale) || !finds(t, reopened, loaded, kept) {
		t.Fatal("expiry kept the wrong entry")
	}
	// The expired entry left the file when the store was opened.
	if again, loaded := openInventory(t, store); again.Status().Expired != 0 || len(loaded) != 1 {
		t.Fatalf("%+v", again.Status())
	}
	now = now.Add(InventoryEntryLifetime + time.Hour)
	_, loaded = openInventory(t, store)
	info, err := os.Stat(inventoryFilePath(store))
	if len(loaded) != 0 || err != nil || info.Size() != int64(inventoryHeaderSize) {
		t.Fatalf("%d loaded, %v, %v", len(loaded), info, err)
	}
	// A record from a clock far ahead of this one would never expire: it is
	// not taken.
	now = now.Add(-10 * InventoryEntryLifetime)
	if reopened, loaded := openInventory(t, store); len(loaded) != 0 || reopened.Status().Expired != 0 {
		t.Fatalf("%+v", reopened.Status())
	}
}

// A file of a newer store format is left exactly as it is, and the proxy
// runs from memory and says why.
func TestInventoryLeavesANewerStoreFormatAlone(t *testing.T) {
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	value := inventoryTestValue(t, inventoryTestAlphabet, 40)
	inv.Add([]StoredEntries{{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, censor.EntriesVersion, "one", value)}})
	newer, err := os.ReadFile(inventoryFilePath(store))
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(newer[len(inventoryMagic):], InventoryStoreFormat+1)
	newer = append(newer, "whatever a later format keeps here"...)
	if err := os.WriteFile(inventoryFilePath(store), newer, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, loaded := openInventory(t, store)
	if status := reopened.Status(); status.Durable || status.Reason != InventoryReasonNewerFormat || len(loaded) != 0 {
		t.Fatalf("%+v", status)
	}
	if !bytes.Equal(inventoryKeyBytes(t, reopened), inventoryKeyBytes(t, inv)) {
		t.Fatal("the key was replaced")
	}
	other := inventoryTestValue(t, inventoryTestAlphabet, 40)
	reopened.Add([]StoredEntries{{Principal: testPrincipal(t, reopened), Entries: inventoryEntries(t, reopened, censor.EntriesVersion, "two", other)}})
	// The proxy that was running when the newer file appeared leaves it too.
	inv.Add([]StoredEntries{{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, censor.EntriesVersion, "three", other)}})
	if status := inv.Status(); status.Durable || status.Reason != InventoryReasonNewerFormat {
		t.Fatalf("%+v", status)
	}
	if after, err := os.ReadFile(inventoryFilePath(store)); err != nil || !bytes.Equal(after, newer) {
		t.Fatalf("the newer file was changed: %v", err)
	}
}

// foreignSchemeRecord stores a record under a matching scheme this build
// does not know, as a newer or an older build would have.
func foreignSchemeRecord(t *testing.T, inv *Inventory, scheme uint32, id string, now time.Time) []byte {
	t.Helper()
	principal := testPrincipal(t, inv)
	wire := []byte(`{"v":` + fmt.Sprint(scheme) + `,"type":"secret","id":"` + id + `","shape":"of another scheme"}`)
	body := append(append([]byte{0}, principal.id[:]...), wire...)
	record, err := inv.sealBody(inventoryRecord{
		scheme: scheme, registered: now.Unix(), tenant: inv.tenant,
		login: inv.loginTag(principal.id), content: inv.tag("content", principal.id[:], wire),
	}, body)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockCAFile(filepath.Join(inv.directory, inventoryLockName))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := inv.write(append(inv.read().records, record)); err != nil {
		t.Fatal(err)
	}
	return record.raw
}

// Entries in a scheme the build does not match stay in the file, counted, for
// the build that does. Nothing registered under their ids replaces them.
func TestInventoryKeepsEachEntrysScheme(t *testing.T) {
	store := newInventoryTestStore(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	store.Now = func() time.Time { return now }
	inv, _ := openInventory(t, store)
	current := inventoryTestValue(t, inventoryTestAlphabet, 40)
	inv.Add([]StoredEntries{{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, censor.EntriesVersion, "current", current)}})
	records := map[string][]byte{
		"a later scheme's":                    foreignSchemeRecord(t, inv, 99, "later", now),
		"a retired scheme's":                  foreignSchemeRecord(t, inv, 0, "retired", now),
		"a retired scheme's, under a used id": foreignSchemeRecord(t, inv, 0, "DATABASE_URL", now),
		"a later scheme's, under a used id":   foreignSchemeRecord(t, inv, 99, "DATABASE_URL", now),
	}
	reopened, loaded := openInventory(t, store)
	if status := reopened.Status(); !status.Durable || status.OtherScheme != 4 || status.Loaded != 1 || status.Damaged != 0 {
		t.Fatalf("%+v", status)
	}
	// The CLI registers a value under an id other schemes' records hold.
	value := inventoryTestValue(t, inventoryTestAlphabet, 40)
	reopened.Add([]StoredEntries{{Principal: testPrincipal(t, reopened), Entries: inventoryEntries(t, reopened, censor.EntriesVersion, "DATABASE_URL", value)}})
	file, err := os.ReadFile(inventoryFilePath(store))
	if err != nil {
		t.Fatal(err)
	}
	for name, record := range records {
		if !bytes.Contains(file, record) {
			t.Errorf("%s record did not stay in the file as it was", name)
		}
	}
	final, loaded := openInventory(t, store)
	if status := final.Status(); status.OtherScheme != 4 || status.Loaded != 2 {
		t.Fatalf("%+v", status)
	}
	if !finds(t, final, loaded, value) || !finds(t, final, loaded, current) {
		t.Fatal("a value was lost")
	}
	// What no build registers again goes with its age, whatever its scheme.
	now = now.Add(InventoryEntryLifetime + time.Hour)
	if expired, _ := openInventory(t, store); expired.Status().Expired != 6 || expired.Status().OtherScheme != 0 {
		t.Fatalf("%+v", expired.Status())
	}
}

// Two values under one placeholder (a key name is shared across apps) are
// both stored, and each is stored again once it has gone from the file.
func TestInventoryKeepsEveryValueOfAPlaceholder(t *testing.T) {
	store := newInventoryTestStore(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	store.Now = func() time.Time { return now }
	inv, _ := openInventory(t, store)
	staging, production := inventoryTestValue(t, inventoryTestAlphabet, 40), inventoryTestValue(t, inventoryTestAlphabet, 40)
	inv.Add([]StoredEntries{{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, censor.EntriesVersion, "DATABASE_URL", staging)}})
	inv.Add([]StoredEntries{{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, censor.EntriesVersion, "DATABASE_URL", production)}})
	reopened, loaded := openInventory(t, store)
	if len(loaded) != 2 || !finds(t, reopened, loaded, staging) || !finds(t, reopened, loaded, production) {
		t.Fatalf("%d loaded: a value sharing a placeholder was dropped", len(loaded))
	}
	// A value whose record is gone is not remembered as stored.
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	inv.Add([]StoredEntries{{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, censor.EntriesVersion, "DATABASE_URL", staging)}})
	if _, loaded := openInventory(t, store); len(loaded) != 1 {
		t.Fatalf("%d loaded after the value was stored again", len(loaded))
	}
}

// Entries of scheme 1 carry whole rolling hashes, which the key undoes: they
// are matched from memory and never written to the file.
func TestInventoryNeverStoresWholeRollingHashes(t *testing.T) {
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	older, current := inventoryTestValue(t, inventoryTestAlphabet, 40), inventoryTestValue(t, inventoryTestAlphabet, 40)
	inv.Add([]StoredEntries{{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, 1, "older", older)}})
	if info, err := os.Stat(inventoryFilePath(store)); err != nil || info.Size() != int64(inventoryHeaderSize) {
		t.Fatalf("scheme 1 entries were written: %v %v", info, err)
	}
	inv.Add([]StoredEntries{
		{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, 1, "older", older)},
		{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, censor.EntriesVersion, "current", current)},
	})
	reopened, loaded := openInventory(t, store)
	if status := reopened.Status(); len(loaded) != 1 || loaded[0].Entries.Version != censor.EntriesVersion || !status.Durable || status.Damaged != 0 {
		t.Fatalf("%d loaded, %+v", len(loaded), status)
	}
	for _, stored := range loaded {
		for _, form := range stored.Entries.Forms {
			if len(form.Rolls) != 0 {
				t.Fatal("a stored form holds whole rolling hashes")
			}
		}
	}
}

// Entries made under another key are not matched and are counted; the next
// write drops them. A proxy that was running when the key was replaced keeps
// what it has in memory and stops writing.
func TestInventoryUnderAnotherKey(t *testing.T) {
	store := newInventoryTestStore(t)
	running, _ := openInventory(t, store)
	value := inventoryTestValue(t, inventoryTestAlphabet, 40)
	running.Add([]StoredEntries{
		{Principal: testPrincipal(t, running), Entries: inventoryEntries(t, running, censor.EntriesVersion, "one", value)},
		{Principal: testPrincipal(t, running), Entries: inventoryEntries(t, running, censor.EntriesVersion, "two", inventoryTestValue(t, inventoryTestAlphabet, 40))},
	})
	if err := store.ReplaceKey(); err != nil {
		t.Fatal(err)
	}
	fresh, loaded := openInventory(t, store)
	if bytes.Equal(inventoryKeyBytes(t, fresh), inventoryKeyBytes(t, running)) || fresh.keyID == running.keyID {
		t.Fatal("the key was not replaced")
	}
	if status := fresh.Status(); !status.Durable || !status.OtherKey || status.Loaded != 0 || len(loaded) != 0 {
		t.Fatalf("%+v", status)
	}
	if info, err := os.Stat(inventoryFilePath(store)); err != nil || info.Size() != int64(inventoryHeaderSize) {
		t.Fatalf("the other key's entries were not dropped: %v %v", info, err)
	}
	// Entries hashed under the old key match nothing under the new one.
	stale := []StoredEntries{{Principal: testPrincipal(t, fresh), Entries: inventoryEntries(t, running, censor.EntriesVersion, "one", value)}}
	if finds(t, fresh, stale, value) {
		t.Fatal("entries of another key matched")
	}
	fresh.Add([]StoredEntries{{Principal: testPrincipal(t, fresh), Entries: inventoryEntries(t, fresh, censor.EntriesVersion, "new", value)}})
	before, _ := os.ReadFile(inventoryFilePath(store))
	running.Add([]StoredEntries{{Principal: testPrincipal(t, running), Entries: inventoryEntries(t, running, censor.EntriesVersion, "late", inventoryTestValue(t, inventoryTestAlphabet, 40))}})
	if status := running.Status(); status.Durable || status.Reason != InventoryReasonKeyReplaced {
		t.Fatalf("%+v", status)
	}
	if after, _ := os.ReadFile(inventoryFilePath(store)); !bytes.Equal(before, after) {
		t.Fatal("a proxy holding a replaced key wrote to the store")
	}
}

// Remove takes the file and everything written beside it.
func TestInventoryRemove(t *testing.T) {
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	inv.Add([]StoredEntries{{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, censor.EntriesVersion, "one", inventoryTestValue(t, inventoryTestAlphabet, 40))}})
	if err := os.WriteFile(filepath.Join(store.Directory, inventoryTempPrefix+"123"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Directory, "ca.pem"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	// The lock files stay, for the processes that lock them (see
	// TestInventoryRemoveLeavesTheLock).
	entries, err := os.ReadDir(store.Directory)
	if err != nil || len(entries) != 3 || entries[0].Name() != "ca.pem" || entries[1].Name() != inventoryLockName || entries[2].Name() != inventoryQueueName {
		t.Fatalf("%v %v", entries, err)
	}
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := (InventoryStore{Directory: filepath.Join(store.Directory, "missing"), Keyring: store.Keyring}).Remove(); err != nil {
		t.Fatal(err)
	}
}

// Whatever is done to the file, opening the store neither fails nor panics,
// hands over only entries that were stored and that the index accepts, and
// leaves a store that works: a value registered afterwards is there at the
// next start.
func TestInventoryDamagedFiles(t *testing.T) {
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	values := map[string]string{}
	var batch []StoredEntries
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("value-%d", i)
		values[id] = inventoryTestValue(t, inventoryTestAlphabet, 24+7*i)
		batch = append(batch, StoredEntries{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, censor.EntriesVersion, id, values[id]), KeyNamed: i%3 == 0})
	}
	inv.Add(batch)
	good, err := os.ReadFile(inventoryFilePath(store))
	if err != nil {
		t.Fatal(err)
	}
	stored := map[string]string{}
	for _, entry := range batch {
		wire, _ := entry.Entries.Marshal()
		stored[entry.Entries.ID] = string(wire)
	}

	random := mathrand.New(mathrand.NewSource(1))
	mutations := map[string][]byte{
		"empty":            {},
		"header only":      good[:inventoryHeaderSize],
		"half a header":    good[:inventoryHeaderSize/2],
		"another magic":    append([]byte("NOTPHASE"), good[8:]...),
		"format zero":      append(append([]byte(inventoryMagic), 0, 0, 0, 0), good[12:]...),
		"garbage appended": append(append([]byte{}, good...), bytes.Repeat([]byte{0xff}, 4096)...),
		"zeros appended":   append(append([]byte{}, good...), make([]byte, 4096)...),
		"all zeros":        make([]byte, len(good)),
		"all ones":         bytes.Repeat([]byte{0xff}, len(good)),
		"doubled":          append(append([]byte{}, good...), good[inventoryHeaderSize:]...),
		"text":             []byte(strings.Repeat("this is not an inventory\n", 100)),
	}
	for cut := inventoryHeaderSize; cut < len(good); cut += 1 + len(good)/97 {
		mutations[fmt.Sprintf("truncated at %d", cut)] = good[:cut]
	}
	for i := 0; i < 300; i++ {
		mutated := append([]byte{}, good...)
		at := random.Intn(len(mutated))
		mutated[at] ^= byte(1 << random.Intn(8))
		mutations[fmt.Sprintf("bit flipped at %d (%d)", at, i)] = mutated
	}
	// Every bit of the header: the magic, the store format and the key's id.
	for at := 0; at < inventoryHeaderSize; at++ {
		for bit := 0; bit < 8; bit++ {
			mutated := append([]byte{}, good...)
			mutated[at] ^= 1 << bit
			mutations[fmt.Sprintf("header byte %d, bit %d", at, bit)] = mutated
		}
	}
	// Every length field set to something it is not.
	for at := inventoryHeaderSize; at < len(good); {
		length := int(binary.BigEndian.Uint32(good[at:]))
		for _, wrong := range []uint32{0, 1, uint32(length - 1), uint32(length + 1), 1 << 31, 0xffffffff} {
			mutated := append([]byte{}, good...)
			binary.BigEndian.PutUint32(mutated[at:], wrong)
			mutations[fmt.Sprintf("length at %d set to %d", at, wrong)] = mutated
		}
		at += 4 + length
	}

	// emptied says the file is a whole one that holds no entries, and
	// unreadable that it is no inventory this build can open at all.
	unreadable := map[string]bool{
		"empty": true, "half a header": true, "another magic": true, "format zero": true,
		"all zeros": true, "all ones": true, "text": true, "oversized": true,
	}
	check := func(name string, emptied bool) {
		t.Helper()
		before, _ := os.ReadFile(inventoryFilePath(store))
		reopened, loaded, err := store.Open()
		if err != nil || reopened == nil {
			t.Fatalf("%s: the store did not open: %v", name, err)
		}
		status := reopened.Status()
		if status.Reason == InventoryReasonNewerFormat || status.Reason == InventoryReasonUnreadable {
			// A later format's file, or no inventory at all: left exactly as
			// it is by the start and by a registration.
			reopened.Add([]StoredEntries{{Principal: testPrincipal(t, reopened), Entries: inventoryEntries(t, reopened, censor.EntriesVersion, "after", inventoryTestValue(t, inventoryTestAlphabet, 40))}})
			after, _ := os.ReadFile(inventoryFilePath(store))
			if status.Durable || len(loaded) != 0 || (!bytes.Equal(before, after) && name != "oversized") {
				t.Fatalf("%s: %+v", name, status)
			}
			if info, err := os.Stat(inventoryFilePath(store)); err != nil || info.Size() != int64(len(before)) && name != "oversized" {
				t.Fatalf("%s: the file was written: %v", name, err)
			}
			return
		}
		if unreadable[name] || strings.HasPrefix(name, "header byte 0,") {
			t.Fatalf("%s: a file that is no inventory was taken for one: %+v", name, status)
		}
		if !status.Durable || status.Loaded != len(loaded) || len(loaded) > len(batch) {
			t.Fatalf("%s: %+v, %d loaded", name, status, len(loaded))
		}
		for _, entry := range loaded {
			wire, err := entry.Entries.Marshal()
			if err != nil || stored[entry.Entries.ID] != string(wire) {
				t.Fatalf("%s: an entry that was never stored was loaded", name)
			}
			if !finds(t, reopened, []StoredEntries{entry}, values[entry.Entries.ID]) {
				t.Fatalf("%s: a loaded entry does not match its value", name)
			}
		}
		if len(loaded) < len(batch) && status.Damaged == 0 && !status.OtherKey && !emptied {
			t.Fatalf("%s: %d entries are missing and none is counted as damaged: %+v", name, len(batch)-len(loaded), status)
		}
		// The store works afterwards.
		value := inventoryTestValue(t, inventoryTestAlphabet, 40)
		reopened.Add([]StoredEntries{{Principal: testPrincipal(t, reopened), Entries: inventoryEntries(t, reopened, censor.EntriesVersion, "after", value)}})
		after, loaded := openInventory(t, store)
		if status := after.Status(); !status.Durable || status.Damaged != 0 || !finds(t, after, loaded, value) {
			t.Fatalf("%s: the store did not recover: %+v", name, status)
		}
	}
	for name, content := range mutations {
		if err := os.WriteFile(inventoryFilePath(store), content, 0o600); err != nil {
			t.Fatal(err)
		}
		check(name, len(content) == inventoryHeaderSize)
	}

	// Files that are not read at all.
	replace := func(make func(path string)) {
		t.Helper()
		_ = os.RemoveAll(inventoryFilePath(store))
		make(inventoryFilePath(store))
	}
	replace(func(path string) {
		// Larger than the store may grow: sparse, so it costs nothing here.
		if err := os.WriteFile(path, good, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path, maxInventoryFileBytes+1); err != nil {
			t.Fatal(err)
		}
	})
	check("oversized", false)
	if info, err := os.Stat(inventoryFilePath(store)); err != nil || info.Size() != maxInventoryFileBytes+1 {
		t.Fatalf("the oversized file was written: %v", err)
	}
	if runtime.GOOS != "windows" {
		outside := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.WriteFile(outside, good, 0o600); err != nil {
			t.Fatal(err)
		}
		replace(func(path string) {
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
		})
		// What stands in the file's place and is not an owner-only file of
		// this user is neither read nor replaced.
		reopened, loaded := openInventory(t, store)
		if status := reopened.Status(); len(loaded) != 0 || status.Durable || status.Reason != InventoryReasonUnreadable {
			t.Fatalf("a symlink was followed: %+v", status)
		}
		if after, err := os.ReadFile(outside); err != nil || !bytes.Equal(after, good) {
			t.Fatal("the symlink's target was written")
		}
		if info, err := os.Lstat(inventoryFilePath(store)); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("the symlink was replaced: %v", err)
		}
		replace(func(path string) {
			if err := os.WriteFile(path, good, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		})
		reopened, loaded = openInventory(t, store)
		if status := reopened.Status(); len(loaded) != 0 || status.Durable || status.Reason != InventoryReasonUnreadable {
			t.Fatalf("a file others can read was trusted: %+v", status)
		}
		if after, err := os.ReadFile(inventoryFilePath(store)); err != nil || !bytes.Equal(after, good) {
			t.Fatal("a file others can read was written over")
		}
		replace(func(path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		})
		// A directory in the file's place: the proxy runs from memory and
		// says so.
		reopened, loaded = openInventory(t, store)
		if status := reopened.Status(); len(loaded) != 0 || status.Durable || status.Reason != InventoryReasonUnreadable {
			t.Fatalf("%+v", status)
		}
	}
}

// A damaged header id, a damaged length or a damaged head costs the record it
// is in and no other: every record whose head still opens under the key is
// kept, whosever it is, and the file is whole again afterwards.
func TestInventoryKeepsIntactRecordsPastDamage(t *testing.T) {
	// Four records of one tenant, then one of another.
	build := func(t *testing.T) (own, other InventoryStore, good []byte, starts []int) {
		own = newInventoryTestStore(t)
		other = own
		other.Tenant = "https://console.test\norganisation\nanother-organisation"
		inv, _ := openInventory(t, own)
		var batch []StoredEntries
		for i := 0; i < 4; i++ {
			batch = append(batch, oneEntry(t, inv, fmt.Sprintf("own-%d", i))...)
		}
		inv.Add(batch)
		theirs, _ := openInventory(t, other)
		theirs.Add(oneEntry(t, theirs, "theirs"))
		good = mustRead(t, inventoryFilePath(own))
		for at := inventoryHeaderSize; at < len(good); at += 4 + int(binary.BigEndian.Uint32(good[at:])) {
			starts = append(starts, at)
		}
		if len(starts) != 5 {
			t.Fatalf("%d records in the file", len(starts))
		}
		return own, other, good, starts
	}
	for name, c := range map[string]struct {
		damage      func(file []byte, starts []int) []byte
		own, theirs int
		// whole says the damage was to no record: the file is as it was after.
		whole bool
	}{
		"a bit of the header's key id":        {func(file []byte, _ []int) []byte { file[len(inventoryMagic)+4] ^= 1; return file }, 4, 1, true},
		"the last bit of the header's key id": {func(file []byte, _ []int) []byte { file[inventoryHeaderSize-1] ^= 0x80; return file }, 4, 1, true},
		"a first length of zero": {func(file []byte, starts []int) []byte {
			binary.BigEndian.PutUint32(file[starts[0]:], 0)
			return file
		}, 3, 1, false},
		"a first length past the file": {func(file []byte, starts []int) []byte {
			binary.BigEndian.PutUint32(file[starts[0]:], 0xffffffff)
			return file
		}, 3, 1, false},
		"a length of zero in the middle": {func(file []byte, starts []int) []byte {
			binary.BigEndian.PutUint32(file[starts[2]:], 0)
			return file
		}, 3, 1, false},
		"another tenant's length of zero": {func(file []byte, starts []int) []byte {
			binary.BigEndian.PutUint32(file[starts[4]:], 0)
			return file
		}, 4, 0, false},
		"a bit of a head": {func(file []byte, starts []int) []byte { file[starts[1]+4+inventoryNonceSize+3] ^= 4; return file }, 3, 1, false},
		"bytes that are no record between two": {func(file []byte, starts []int) []byte {
			return append(append(append([]byte{}, file[:starts[2]]...), bytes.Repeat([]byte{0, 0, 1, 7}, 60)...), file[starts[2]:]...)
		}, 4, 1, true},
	} {
		t.Run(name, func(t *testing.T) {
			own, other, good, starts := build(t)
			if err := os.WriteFile(inventoryFilePath(own), c.damage(append([]byte{}, good...), starts), 0o600); err != nil {
				t.Fatal(err)
			}
			inv, loaded := openInventory(t, own)
			if status := inv.Status(); !status.Durable || status.OtherKey || status.Damaged != 1 || len(loaded) != c.own {
				t.Fatalf("the tenant's proxy loaded %d of its records, want %d: %+v", len(loaded), c.own, status)
			}
			after := mustRead(t, inventoryFilePath(own))
			if c.whole && !bytes.Equal(after, good) {
				t.Fatalf("the file is %d bytes after damage to no record, and was %d", len(after), len(good))
			}
			if records := inventoryFileRecords(t, own); records != c.own+c.theirs {
				t.Fatalf("%d records are left in the file, want %d", records, c.own+c.theirs)
			}
			// The other tenant's proxy, and the next of this one: the same
			// records, and nothing damaged any more.
			for which, want := range map[*InventoryStore]int{&own: c.own, &other: c.theirs} {
				next, loaded := openInventory(t, *which)
				if status := next.Status(); !status.Durable || status.Damaged != 0 || len(loaded) != want {
					t.Fatalf("a later proxy of %q loaded %d records, want %d: %+v", which.Tenant, len(loaded), want, status)
				}
			}
		})
	}
}

// boundedRecord is a record of a size, a time, a tenant and a login, for the
// bounds alone: nothing opens it.
func boundedRecord(tenant, login byte, registered int64, size int) inventoryRecord {
	return inventoryRecord{registered: registered, tenant: [inventoryTagSize]byte{tenant}, login: [inventoryTagSize]byte{login}, raw: make([]byte, size)}
}

// Past a bound, the login that is writing loses its own oldest records and
// no other login or tenant loses any.
func TestInventoryBoundsDropOnlyTheWritersOwnOldest(t *testing.T) {
	previous := inventoryBounds
	t.Cleanup(func() { inventoryBounds = previous })
	inventoryBounds.file, inventoryBounds.tenant, inventoryBounds.login = storeBound{100, 1 << 20}, storeBound{12, 600}, storeBound{8, 400}
	inv := &Inventory{tenant: [inventoryTagSize]byte{1}}
	const mine, colleague, other = 1, 2, 9
	count := func(records []inventoryRecord, tenant, login byte) (n int, oldest int64) {
		oldest = -1
		for at, record := range records {
			if at > 0 && records[at-1].registered > record.registered {
				t.Fatal("not oldest first")
			}
			if record.tenant[0] == tenant && record.login[0] == login {
				if n++; oldest < 0 {
					oldest = record.registered
				}
			}
		}
		return n, oldest
	}
	writing := map[[inventoryTagSize]byte]bool{{mine}: true}
	var records []inventoryRecord
	for i := 0; i < 6; i++ {
		records = append(records, boundedRecord(1, colleague, int64(i), 50), boundedRecord(2, other, int64(i), 1<<16))
	}
	// A login's own bound: twenty writes leave its newest eight.
	for i := 0; i < 20; i++ {
		records = append(records, boundedRecord(1, mine, int64(100+i), 10))
	}
	kept := inv.bound(append([]inventoryRecord{}, records...), writing)
	if n, oldest := count(kept, 1, mine); n != 6 || oldest != 114 {
		// The tenant's bound of twelve leaves six beside the colleague's six.
		t.Fatalf("the writing login keeps %d from %d", n, oldest)
	}
	for name, who := range map[string][2]byte{"another login of the tenant": {1, colleague}, "another tenant": {2, other}} {
		if n, oldest := count(kept, who[0], who[1]); n != 6 || oldest != 0 {
			t.Fatalf("%s lost records to the writer: %d left, from %d", name, n, oldest)
		}
	}
	// By bytes: records of 150 bytes fit a login's 400 twice.
	inventoryBounds.tenant = storeBound{100, 1 << 20}
	large := append([]inventoryRecord{}, records[:12]...)
	for i := 0; i < 5; i++ {
		large = append(large, boundedRecord(1, mine, int64(200+i), 150))
	}
	if n, oldest := count(inv.bound(large, writing), 1, mine); n != 2 || oldest != 203 {
		t.Fatalf("by bytes the writing login keeps %d from %d", n, oldest)
	}
	// A file others have filled: the writer stores what room is left, which
	// may be nothing, and still no one else loses a record.
	inventoryBounds.file = storeBound{14, 1 << 30}
	kept = inv.bound(append([]inventoryRecord{}, records...), writing)
	if n, _ := count(kept, 1, mine); n != 2 || len(kept) != 14 {
		t.Fatalf("a full file: the writer keeps %d of %d", n, len(kept))
	}
	inventoryBounds.file = storeBound{12, 1 << 30}
	kept = inv.bound(append([]inventoryRecord{}, records...), writing)
	if n, _ := count(kept, 1, mine); n != 0 || len(kept) != 12 {
		t.Fatalf("a file with no room: the writer keeps %d of %d", n, len(kept))
	}
	// A tenant stores for so many logins: one more gets no room.
	inventoryBounds = previous
	inventoryBounds.tenantLogins = 2
	crowd := []inventoryRecord{boundedRecord(1, 2, 1, 10), boundedRecord(1, 3, 2, 10), boundedRecord(1, mine, 3, 10)}
	if kept := inv.bound(crowd, writing); len(kept) != 2 || kept[0].login[0] != 2 || kept[1].login[0] != 3 {
		t.Fatalf("a login past the tenant's count was stored: %d records", len(kept))
	}
}

// What a bound drops of the writer's own records is counted: status said
// "stored" of a login whose tenant others had filled, and that stored nothing.
func TestInventoryStatusCountsWhatABoundDropped(t *testing.T) {
	previous := inventoryBounds
	t.Cleanup(func() { inventoryBounds = previous })
	inventoryBounds.login, inventoryBounds.tenant = storeBound{4, 8 << 20}, storeBound{8, 16 << 20}
	store := newInventoryTestStore(t)
	register := func(login string, values int) *Inventory {
		t.Helper()
		inv, _ := openInventory(t, store)
		principal := principalOf(t, inv, login)
		for i := 0; i < values; i++ {
			entries, err := censor.IndexValue(principal.Key(), "secret", fmt.Sprintf("v%d", i), inventoryTestValue(t, inventoryTestAlphabet, 40))
			if err != nil {
				t.Fatal(err)
			}
			inv.Add([]StoredEntries{{Principal: principal, Entries: entries}})
		}
		return inv
	}
	held := func(login string) (mine int) {
		t.Helper()
		inv, loaded := openInventory(t, store)
		for _, stored := range loaded {
			if stored.Principal.Is(principalOf(t, inv, login)) {
				mine++
			}
		}
		return mine
	}
	// A login past its own bound loses its oldest: six registered, four kept.
	first := register("https://console.test\nagent\na", 6)
	if status := first.Status(); !status.Durable || status.Dropped != 2 || held("https://console.test\nagent\na") != 4 {
		t.Fatalf("a login past its own bound: %+v", status)
	}
	if status := register("https://console.test\nagent\nb", 4).Status(); !status.Durable || status.Dropped != 0 {
		t.Fatalf("a login within its bound: %+v", status)
	}
	// The tenant is full of the other two: the late login stores nothing.
	late := register("https://console.test\nuser\nthe-developer", 3)
	if status := late.Status(); !status.Durable || status.Dropped != 3 || held("https://console.test\nuser\nthe-developer") != 0 {
		t.Fatalf("a login whose tenant is full: %+v", status)
	}
	if held("https://console.test\nagent\na") != 4 || held("https://console.test\nagent\nb") != 4 {
		t.Fatal("another login lost records to the late one")
	}
}

// Through the store itself: one tenant's volume, in large values or in many
// small ones, leaves another tenant's record where it was.
func TestOneTenantsVolumeNeverEvictsAnothers(t *testing.T) {
	previous := inventoryBounds
	t.Cleanup(func() { inventoryBounds = previous })
	storeB := newInventoryTestStore(t)
	storeA := storeB
	storeA.Tenant = "https://console.test\norganisation\nanother-organisation"
	invB, _ := openInventory(t, storeB)
	ofB := principalOf(t, invB, inventoryLoginB)
	valueB := inventoryTestValue(t, inventoryTestAlphabet, 40)
	entriesB, err := censor.IndexValue(ofB.Key(), "secret", "of-b", valueB)
	if err != nil {
		t.Fatal(err)
	}
	invB.Add([]StoredEntries{{Entries: entriesB, Principal: ofB}})
	one, err := os.Stat(inventoryFilePath(storeB))
	if err != nil {
		t.Fatal(err)
	}
	// The file has room for B's record and eleven like it; a tenant for eight.
	record := int(one.Size()) - inventoryHeaderSize
	inventoryBounds.file = storeBound{1000, inventoryHeaderSize + 12*record + record/2}
	inventoryBounds.tenant, inventoryBounds.login = storeBound{8, 1 << 30}, storeBound{6, 1 << 30}

	invA, _ := openInventory(t, storeA)
	ofA, alsoA := principalOf(t, invA, inventoryLoginA), principalOf(t, invA, inventoryLoginB)
	var last string
	for i := 0; i < 40; i++ {
		who := ofA
		if i%2 == 1 {
			who = alsoA
		}
		last = inventoryTestValue(t, inventoryTestAlphabet, 40)
		entries, err := censor.IndexValue(who.Key(), "secret", fmt.Sprintf("a-%d", i), last)
		if err != nil {
			t.Fatal(err)
		}
		invA.Add([]StoredEntries{{Entries: entries, Principal: who}})
	}
	nextA, loadedA := openInventory(t, storeA)
	if len(loadedA) != 8 || inventoryFileRecords(t, storeA) != 9 || !finds(t, nextA, loadedA, last) {
		t.Fatalf("tenant A after its own volume: %d loaded, %d records in the file", len(loadedA), inventoryFileRecords(t, storeA))
	}
	nextB, loadedB := openInventory(t, storeB)
	if len(loadedB) != 1 || inventoryFileRecords(t, storeB) != 9 || !finds(t, nextB, loadedB, valueB) {
		t.Fatalf("tenant B after tenant A's volume: %d loaded, %d records in the file", len(loadedB), inventoryFileRecords(t, storeB))
	}
	// And B, writing past its own bounds, drops none of A's.
	for i := 0; i < 20; i++ {
		entries, _ := censor.IndexValue(ofB.Key(), "secret", fmt.Sprintf("b-%d", i), inventoryTestValue(t, inventoryTestAlphabet, 40))
		nextB.Add([]StoredEntries{{Entries: entries, Principal: principalOf(t, nextB, inventoryLoginB)}})
	}
	if _, again := openInventory(t, storeA); len(again) != 8 {
		t.Fatalf("tenant B's volume dropped tenant A's records: %d left", len(again))
	}
	if info, err := os.Stat(inventoryFilePath(storeB)); err != nil || int(info.Size()) > inventoryBounds.file.bytes {
		t.Fatalf("the file passed its bound: %v", err)
	}
}

// The file shows in the clear how many records it holds and how long each
// is: no tag says which are one tenant's, login's or placeholder's.
func TestInventoryFileShowsNoTenantLoginOrPlaceholder(t *testing.T) {
	store := newInventoryTestStore(t)
	other := store
	other.Tenant = "https://console.test\norganisation\nanother-organisation"
	inv, _ := openInventory(t, store)
	a, b := principalOf(t, inv, inventoryLoginA), principalOf(t, inv, inventoryLoginB)
	for _, who := range []InventoryPrincipal{a, b, a} {
		entries, _ := censor.IndexValue(who.Key(), "secret", "DATABASE_URL", inventoryTestValue(t, inventoryTestAlphabet, 40))
		inv.Add([]StoredEntries{{Entries: entries, Principal: who, KeyNamed: true}})
	}
	elsewhere, _ := openInventory(t, other)
	entries, _ := censor.IndexValue(principalOf(t, elsewhere, inventoryLoginA).Key(), "secret", "DATABASE_URL", inventoryTestValue(t, inventoryTestAlphabet, 40))
	elsewhere.Add([]StoredEntries{{Entries: entries, Principal: principalOf(t, elsewhere, inventoryLoginA), KeyNamed: true}})

	data, err := os.ReadFile(inventoryFilePath(store))
	if err != nil {
		t.Fatal(err)
	}
	// Every 16 bytes of the file after its header, at any offset: none repeats.
	seen := map[[inventoryTagSize]byte]int{}
	for at := inventoryHeaderSize; at+inventoryTagSize <= len(data); at++ {
		window := [inventoryTagSize]byte(data[at : at+inventoryTagSize])
		if first, twice := seen[window]; twice {
			t.Fatalf("16 bytes at %d repeat those at %d: a tag in the clear", at, first)
		}
		seen[window] = at
	}
	unlock, err := lockInventory(inv.directory, inventoryLockWait)
	if err != nil {
		t.Fatal(err)
	}
	file := inv.read()
	unlock()
	logins, tenants := map[[inventoryTagSize]byte]int{}, map[[inventoryTagSize]byte]int{}
	for _, record := range file.records {
		logins[record.login]++
		tenants[record.tenant]++
		for name, tag := range map[string][inventoryTagSize]byte{"tenant": record.tenant, "login": record.login, "content": record.content} {
			if bytes.Contains(data, tag[:]) {
				t.Fatalf("a record's %s tag is in the clear", name)
			}
		}
	}
	// Opened with the file key, the heads group by tenant and by login: the
	// same key name under two logins is two logins' records, not one owner's.
	if len(file.records) != 4 || len(tenants) != 2 || len(logins) != 3 || logins[inv.loginTag(a.id)] != 2 || logins[inv.loginTag(b.id)] != 1 {
		t.Fatalf("%d records, %d tenants, logins %v", len(file.records), len(tenants), logins)
	}
	// A head changed in the file is one record lost, and the rest still load.
	data[inventoryHeaderSize+4+inventoryNonceSize+2] ^= 1
	if err := os.WriteFile(inventoryFilePath(store), data, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, loaded := openInventory(t, store)
	if status := reopened.Status(); len(loaded) != 2 || status.Damaged != 1 || inventoryFileRecords(t, store) != 3 {
		t.Fatalf("after a damaged head: %d loaded, %+v", len(loaded), status)
	}
}

// Logging out removes what one login stored, or all its tenant stored, and
// nothing of anyone else's; it makes no key and no file.
func TestForgetRemovesALoginsOrATenantsRecords(t *testing.T) {
	store := newInventoryTestStore(t)
	other := store
	other.Tenant = "https://console.test\norganisation\nanother-organisation"
	if everyone, err := store.Forget([]string{inventoryLoginA}, true); err != nil || everyone {
		t.Fatal(everyone, err)
	}
	if _, err := store.Keyring.Get(inventoryKeyringService, inventoryKeyringUser); err == nil {
		t.Fatal("forgetting made a key")
	}
	if _, err := os.Stat(inventoryFilePath(store)); !os.IsNotExist(err) {
		t.Fatalf("forgetting made a file: %v", err)
	}
	values := map[string]string{}
	add := func(s InventoryStore, login, id string) {
		inv, _ := openInventory(t, s)
		who := principalOf(t, inv, login)
		values[id] = inventoryTestValue(t, inventoryTestAlphabet, 40)
		entries, _ := censor.IndexValue(who.Key(), "secret", id, values[id])
		inv.Add([]StoredEntries{{Entries: entries, Principal: who}})
	}
	add(store, inventoryLoginA, "a-one")
	add(store, inventoryLoginA, "a-two")
	add(store, inventoryLoginB, "b-one")
	add(other, inventoryLoginA, "elsewhere")
	held := func(s InventoryStore) (ids []string) {
		inv, loaded := openInventory(t, s)
		for _, stored := range loaded {
			if !finds(t, inv, []StoredEntries{stored}, values[stored.Entries.ID]) {
				t.Fatalf("%s no longer matches", stored.Entries.ID)
			}
			ids = append(ids, stored.Entries.ID)
		}
		sort.Strings(ids)
		return ids
	}
	if everyone, err := store.Forget([]string{inventoryLoginA, "", "a login that stored nothing"}, false); err != nil || everyone {
		t.Fatal(everyone, err)
	}
	if got := held(store); fmt.Sprint(got) != "[b-one]" {
		t.Fatalf("after one login is forgotten its tenant holds %v", got)
	}
	if got := held(other); fmt.Sprint(got) != "[elsewhere]" {
		t.Fatalf("another tenant's records after a logout: %v", got)
	}
	if everyone, err := store.Forget(nil, true); err != nil || everyone {
		t.Fatal(everyone, err)
	}
	if got := held(store); len(got) != 0 {
		t.Fatalf("after its tenant is forgotten: %v", got)
	}
	if got := held(other); fmt.Sprint(got) != "[elsewhere]" {
		t.Fatalf("another tenant's records after a tenant's logout: %v", got)
	}
	// A store with no tenant, and a machine with no keystore, have nothing.
	none := store
	none.Tenant = ""
	if everyone, err := none.Forget([]string{inventoryLoginA}, true); err != nil || everyone {
		t.Fatal(everyone, err)
	}
}

// troubledKeyring is a keystore that can stop answering at all, as the
// desktop's does to a shell with no session bus, or refuse the inventory key.
type troubledKeyring struct {
	*lockedKeyring
	silent, refusing atomic.Bool
}

func (k *troubledKeyring) Get(service, user string) (string, error) {
	if k.silent.Load() {
		return "", errors.New("org.freedesktop.secrets was not provided by any service")
	}
	if k.refusing.Load() && service == inventoryKeyringService {
		return "", errors.New("user interaction is not allowed")
	}
	return k.lockedKeyring.Get(service, user)
}

func (k *troubledKeyring) Set(service, user, value string) error {
	if k.silent.Load() {
		return errors.New("org.freedesktop.secrets was not provided by any service")
	}
	return k.lockedKeyring.Set(service, user, value)
}

// troubledStore is a store with a login's record, another login's of its
// tenant and another tenant's, and the key they were stored under.
func troubledStore(t *testing.T) (store InventoryStore, keyring *troubledKeyring, tenants []InventoryStore, key string) {
	t.Helper()
	store = newInventoryTestStore(t)
	keyring = &troubledKeyring{lockedKeyring: store.Keyring.(*lockedKeyring)}
	store.Keyring = keyring
	other := store
	other.Tenant = "https://console.test\norganisation\nanother-organisation"
	for id, who := range map[string]struct {
		store InventoryStore
		login string
	}{"a-one": {store, inventoryLoginA}, "b-one": {store, inventoryLoginB}, "elsewhere": {other, inventoryLoginA}} {
		inv, _ := openInventory(t, who.store)
		principal := principalOf(t, inv, who.login)
		entries, err := censor.IndexValue(principal.Key(), "secret", id, inventoryTestValue(t, inventoryTestAlphabet, 40))
		if err != nil {
			t.Fatal(err)
		}
		inv.Add([]StoredEntries{{Entries: entries, Principal: principal}})
	}
	key, err := keyring.lockedKeyring.Get(inventoryKeyringService, inventoryKeyringUser)
	if err != nil || inventoryFileRecords(t, store) != 3 {
		t.Fatalf("the store was not made: %v", err)
	}
	return store, keyring, []InventoryStore{store, other}, key
}

// A logout removes the login's stored values whatever the keystore says. With
// no key that opens the file nothing tells whose a record is, so all of it
// goes and Forget says so: what a logout reported removed never loads again.
func TestForgetDoesNotDependOnTheKeystore(t *testing.T) {
	cases := map[string]func(t *testing.T, store InventoryStore, keyring *troubledKeyring){
		"a keystore that does not answer": func(_ *testing.T, _ InventoryStore, keyring *troubledKeyring) { keyring.silent.Store(true) },
		"a keystore that refuses the key": func(_ *testing.T, _ InventoryStore, keyring *troubledKeyring) { keyring.refusing.Store(true) },
		"a keystore that holds no key": func(_ *testing.T, _ InventoryStore, keyring *troubledKeyring) {
			keyring.mu.Lock()
			defer keyring.mu.Unlock()
			delete(keyring.values, inventoryKeyringService+"/"+inventoryKeyringUser)
		},
		"a key this build cannot read": func(t *testing.T, _ InventoryStore, keyring *troubledKeyring) {
			if err := keyring.Set(inventoryKeyringService, inventoryKeyringUser, "v2:0011223344556677:AAAA"); err != nil {
				t.Fatal(err)
			}
		},
		"a file under another key": func(t *testing.T, store InventoryStore, _ *troubledKeyring) {
			if err := store.ReplaceKey(); err != nil {
				t.Fatal(err)
			}
		},
		"a file of a newer format": func(t *testing.T, store InventoryStore, _ *troubledKeyring) {
			file := mustRead(t, inventoryFilePath(store))
			file[len(inventoryMagic)+3] = InventoryStoreFormat + 1
			if err := os.WriteFile(inventoryFilePath(store), file, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	if runtime.GOOS != "windows" {
		cases["a file others can read"] = func(t *testing.T, store InventoryStore, _ *troubledKeyring) {
			if err := os.Chmod(inventoryFilePath(store), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, trouble := range cases {
		t.Run(name, func(t *testing.T) {
			store, keyring, tenants, key := troubledStore(t)
			trouble(t, store, keyring)
			everyone, err := store.Forget([]string{inventoryLoginA}, false)
			if err != nil || !everyone {
				t.Fatalf("a logout answered %v, %v: it is to remove every login's and say so", everyone, err)
			}
			if _, err := os.Lstat(inventoryFilePath(store)); !os.IsNotExist(err) {
				t.Fatalf("the file is still there after the logout: %v", err)
			}
			// The keystore is back, with the key the records were stored under.
			keyring.silent.Store(false)
			keyring.refusing.Store(false)
			if err := keyring.Set(inventoryKeyringService, inventoryKeyringUser, key); err != nil {
				t.Fatal(err)
			}
			for _, tenant := range tenants {
				if _, loaded := openInventory(t, tenant); len(loaded) != 0 {
					t.Fatalf("%d records load again after a logout that reported them removed", len(loaded))
				}
			}
		})
	}
	// With the key, and a file it opens, only the login's own records go.
	store, _, tenants, _ := troubledStore(t)
	if everyone, err := store.Forget([]string{inventoryLoginA}, false); err != nil || everyone {
		t.Fatalf("a logout with the key answered %v, %v", everyone, err)
	}
	for at, want := range []string{"b-one", "elsewhere"} {
		if _, loaded := openInventory(t, tenants[at]); len(loaded) != 1 || loaded[0].Entries.ID != want {
			t.Fatalf("after a logout with the key a tenant holds %d records, want %s alone", len(loaded), want)
		}
	}
}

// A logout says what it could not remove: with or without the key, a store
// it cannot write is an error, and nothing it left is reported gone.
func TestForgetSaysWhatItCouldNotRemove(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory that refuses its owner's writes")
	}
	for name, silent := range map[string]bool{"with the key": false, "with a keystore that does not answer": true} {
		t.Run(name, func(t *testing.T) {
			store, keyring, _, _ := troubledStore(t)
			keyring.silent.Store(silent)
			if err := os.Chmod(store.Directory, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(store.Directory, 0o700) })
			everyone, err := store.Forget([]string{inventoryLoginA}, false)
			if err == nil || everyone {
				t.Fatalf("a logout that could remove nothing answered %v, %v", everyone, err)
			}
			if err := os.Chmod(store.Directory, 0o700); err != nil {
				t.Fatal(err)
			}
			keyring.silent.Store(false)
			if _, loaded := openInventory(t, store); len(loaded) != 2 {
				t.Fatalf("%d of the tenant's records are left after a logout that failed", len(loaded))
			}
		})
	}
}

// Nothing the store writes holds a piece of a value, a digest of one that is
// not keyed, a placeholder's id, or the key: the file is opaque without the
// keystore, and the key is nowhere but the keystore.
func TestInventoryFileHoldsNoPlaintext(t *testing.T) {
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	values := map[string]string{
		"STRIPE_LIVE_KEY":   "sk" + "_live_" + inventoryTestValue(t, inventoryTestAlphabet, 60),
		"HEX_KEY":           inventoryTestValue(t, "0123456789abcdef", 64),
		"DATABASE_URL":      "postgres://orders_app:" + inventoryTestValue(t, inventoryTestAlphabet, 24) + "@orders-db.internal.example.com:5432/orders",
		"SYMBOLS":           inventoryTestValue(t, inventoryTestAlphabet+"!@#$%^&*", 28),
		"SERVICE_ACCOUNT":   `{"type":"service_account","private_key_id":"` + inventoryTestValue(t, "0123456789abcdef", 40) + `","client_secret":"` + inventoryTestValue(t, inventoryTestAlphabet, 36) + `"}`,
		"SHORT_HEX_API_KEY": inventoryTestValue(t, "0123456789abcdef", 20),
	}
	var batch []StoredEntries
	for id, value := range values {
		batch = append(batch, StoredEntries{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, censor.EntriesVersion, id, value), KeyNamed: true})
	}
	inv.Add(batch)

	var written []byte
	files, err := os.ReadDir(store.Directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(store.Directory, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		written = append(written, content...)
		written = append(written, 0)
	}
	if len(written) < 4096 {
		t.Fatalf("only %d bytes were written", len(written))
	}
	holds := func(what string, piece []byte) {
		t.Helper()
		for _, form := range [][]byte{piece, []byte(hex.EncodeToString(piece)), []byte(base64.StdEncoding.EncodeToString(piece)), []byte(base64.RawURLEncoding.EncodeToString(piece))} {
			if len(form) >= 8 && bytes.Contains(written, form[:len(form)-len(form)%4]) {
				t.Fatalf("the store's files hold %s", what)
			}
		}
	}
	digests := func(data []byte) [][]byte {
		s256, s1, m5 := sha256.Sum256(data), sha1.Sum(data), md5.Sum(data)
		return [][]byte{s256[:], s256[:16], s1[:], m5[:]}
	}
	for id, value := range values {
		for at := 0; at+8 <= len(value); at++ {
			if bytes.Contains(written, []byte(value[at:at+8])) {
				t.Fatalf("the store's files hold 8 bytes of %s, at offset %d", id, at)
			}
		}
		holds("a placeholder's id", []byte(id))
		for _, digest := range digests([]byte(value)) {
			holds("an unkeyed digest of "+id, digest)
		}
		// Unkeyed digests of the chunks an entry's hashes are made over.
		for _, form := range []string{value, hex.EncodeToString([]byte(value)), base64.StdEncoding.EncodeToString([]byte(value))} {
			for _, size := range []int{12, 24} {
				for at := 0; at+size <= len(form); at += size {
					for _, digest := range digests([]byte(form[at : at+size])) {
						holds("an unkeyed digest of a chunk of "+id, digest)
					}
				}
			}
		}
	}
	handed := testPrincipal(t, inv).Key()
	holds("the lookup key", handed.LookupBytes())
	holds("half of the lookup key", handed.LookupBytes()[:16])
	holds("the confirming key", handed.ConfirmBytes())
	holds("half of the confirming key", handed.ConfirmBytes()[:16])
	holds("the placeholder type and id as the entries name them", []byte(`"type":"secret"`))

	// The keyed hashes themselves are sealed as well: no chunk hash of the
	// entries is in the file as it is on the wire.
	for _, entry := range batch {
		for _, form := range entry.Entries.Forms {
			for at := 0; at+16 <= len(form.MACs); at += 16 {
				if bytes.Contains(written, form.MACs[at:at+16]) {
					t.Fatal("the file holds a chunk hash outside its seal")
				}
			}
		}
	}
	// And the master is in the keystore, where the next proxy finds it. It
	// is neither key a client is handed.
	stored, err := store.Keyring.Get(inventoryKeyringService, inventoryKeyringUser)
	if err != nil || len(strings.Split(stored, ":")) != 3 {
		t.Fatalf("the master is not in the keystore: %v", err)
	}
	for name, part := range map[string][]byte{"lookup": handed.LookupBytes(), "confirming": handed.ConfirmBytes()} {
		if strings.Contains(stored, base64.StdEncoding.EncodeToString(part)) {
			t.Fatalf("the keystore holds the %s key as it is handed out", name)
		}
	}
	if again, loaded := openInventory(t, store); len(loaded) != len(batch) || again.Status().Damaged != 0 {
		t.Fatalf("%+v", again.Status())
	}
}
