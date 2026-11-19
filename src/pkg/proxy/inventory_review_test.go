package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gokeyring "github.com/zalando/go-keyring"

	"github.com/phasehq/cli/pkg/censor"
)

// hookKeyring is a keystore whose inventory key can fail to read, and that
// calls before on every use of that key, holding no lock of its own.
type hookKeyring struct {
	*lockedKeyring
	failGet atomic.Pointer[error]
	before  func(operation string)
}

func (k *hookKeyring) hook(service, operation string) {
	if service == inventoryKeyringService && k.before != nil {
		k.before(operation)
	}
}

func (k *hookKeyring) Get(service, user string) (string, error) {
	k.hook(service, "get")
	if err := k.failGet.Load(); err != nil && service == inventoryKeyringService {
		return "", *err
	}
	return k.lockedKeyring.Get(service, user)
}

func (k *hookKeyring) Set(service, user, value string) error {
	k.hook(service, "set")
	return k.lockedKeyring.Set(service, user, value)
}

// deletingHookKeyring can delete as well, as the system keystores can.
type deletingHookKeyring struct{ *hookKeyring }

func (k deletingHookKeyring) Delete(service, user string) error {
	k.hook(service, "delete")
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.values[service+"/"+user]; !ok {
		return gokeyring.ErrNotFound
	}
	delete(k.values, service+"/"+user)
	return nil
}

func newHookedInventoryStore(t testing.TB) (InventoryStore, *hookKeyring) {
	t.Helper()
	store := newInventoryTestStore(t)
	hooked := &hookKeyring{lockedKeyring: store.Keyring.(*lockedKeyring)}
	store.Keyring = deletingHookKeyring{hooked}
	return store, hooked
}

func storedInventoryKey(t testing.TB, store InventoryStore) string {
	t.Helper()
	keyring := store.Keyring.(deletingHookKeyring).lockedKeyring
	value, err := keyring.Get(inventoryKeyringService, inventoryKeyringUser)
	if err != nil && !errors.Is(err, gokeyring.ErrNotFound) {
		t.Fatal(err)
	}
	return value
}

func oneEntry(t testing.TB, inv *Inventory, id string) []StoredEntries {
	t.Helper()
	return []StoredEntries{{Principal: testPrincipal(t, inv), Entries: inventoryEntries(t, inv, censor.EntriesVersion, id, inventoryTestValue(t, inventoryTestAlphabet, 40))}}
}

// A keystore read that fails for any reason but "there is none" (a locked
// keychain, a refused prompt) leaves key and file alone: memory only.
func TestInventoryKeystoreReadFailureKeepsTheKey(t *testing.T) {
	store, keyring := newHookedInventoryStore(t)
	first, _ := openInventory(t, store)
	first.Add(oneEntry(t, first, "one"))
	key, file := storedInventoryKey(t, store), mustRead(t, inventoryFilePath(store))

	failure := errors.New("keychain interaction not allowed")
	keyring.failGet.Store(&failure)
	during, loaded := openInventory(t, store)
	if status := during.Status(); status.Durable || status.Reason != InventoryReasonKeyUnreadable || len(loaded) != 0 {
		t.Fatalf("%+v, %d loaded", status, len(loaded))
	}
	during.Add(oneEntry(t, during, "two"))
	if storedInventoryKey(t, store) != key || !bytes.Equal(mustRead(t, inventoryFilePath(store)), file) {
		t.Fatal("a keystore that could not be read had its key or the file replaced")
	}
	// A proxy that was storing keeps on, whatever its status question got.
	first.Add(oneEntry(t, first, "three"))
	if status := first.Status(); !status.Durable {
		t.Fatalf("a keystore that did not answer stopped a running proxy storing: %+v", status)
	}

	keyring.failGet.Store(nil)
	after, loaded := openInventory(t, store)
	if status := after.Status(); !status.Durable || len(loaded) != 2 || !bytes.Equal(inventoryKeyBytes(t, after), inventoryKeyBytes(t, first)) {
		t.Fatalf("%+v, %d loaded", status, len(loaded))
	}
}

// A key this build cannot parse may be a later build's: it is left alone.
func TestInventoryUnparsableKeyIsLeftAlone(t *testing.T) {
	store, _ := newHookedInventoryStore(t)
	first, _ := openInventory(t, store)
	first.Add(oneEntry(t, first, "one"))
	file := mustRead(t, inventoryFilePath(store))
	for _, value := range []string{"v2:0011223344556677:AAAA", "v1:nothex:AAAA", ""} {
		if err := store.Keyring.Set(inventoryKeyringService, inventoryKeyringUser, value); err != nil {
			t.Fatal(err)
		}
		inv, loaded := openInventory(t, store)
		if status := inv.Status(); status.Durable || status.Reason != InventoryReasonKeyUnreadable || len(loaded) != 0 {
			t.Fatalf("%q: %+v", value, status)
		}
		inv.Add(oneEntry(t, inv, "two"))
		if storedInventoryKey(t, store) != value || !bytes.Equal(mustRead(t, inventoryFilePath(store)), file) {
			t.Fatalf("%q: the key or the file was replaced", value)
		}
	}
}

func mustRead(t testing.TB, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// A file of a newer format that also fails the permission check is not
// written over: nothing that exists and was not read is.
func TestInventoryNewerFormatWithLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not checked on Windows")
	}
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	inv.Add(oneEntry(t, inv, "one"))
	path := inventoryFilePath(store)
	newer := mustRead(t, path)
	binary.BigEndian.PutUint32(newer[len(inventoryMagic):], InventoryStoreFormat+1)
	if err := os.WriteFile(path, newer, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	reopened, loaded := openInventory(t, store)
	if status := reopened.Status(); status.Durable || status.Reason != InventoryReasonUnreadable || len(loaded) != 0 {
		t.Fatalf("%+v", status)
	}
	reopened.Add(oneEntry(t, reopened, "two"))
	inv.Add(oneEntry(t, inv, "three"))
	if status := inv.Status(); status.Durable || status.Reason != InventoryReasonUnreadable {
		t.Fatalf("the proxy that was running: %+v", status)
	}
	if !bytes.Equal(mustRead(t, path), newer) {
		t.Fatal("a newer file that failed the permission check was written over")
	}
}

// Remove leaves the lock file: unlinked while held, a process waiting on it
// and a process arriving after would each hold "the" lock at once.
func TestInventoryRemoveLeavesTheLock(t *testing.T) {
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	inv.Add(oneEntry(t, inv, "one"))
	lockPath := filepath.Join(store.Directory, inventoryLockName)
	before, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, remove := range []func() error{store.Remove, store.Purge} {
		if err := remove(); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(lockPath)
		if err != nil || !os.SameFile(before, after) {
			t.Fatalf("the lock file was removed or replaced: %v", err)
		}
	}
}

// Remove racing writers: every write and every removal is whole, and the
// store works afterwards.
func TestInventoryRemoveRacingWriters(t *testing.T) {
	store := newInventoryTestStore(t)
	openInventory(t, store)
	var wait sync.WaitGroup
	stop := make(chan struct{})
	var inside atomic.Int32
	for w := 0; w < 3; w++ {
		wait.Add(1)
		go func(w int) {
			defer wait.Done()
			inv, _, err := store.Open()
			if err != nil {
				t.Error(err)
				return
			}
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				inv.Add(oneEntry(t, inv, fmt.Sprintf("w%d-%d", w, i)))
				// The lock is one lock for everyone, whatever was removed.
				if unlock, err := lockInventory(store.Directory); err == nil {
					if inside.Add(1) != 1 {
						t.Error("two processes held the store's lock at once")
					}
					inside.Add(-1)
					unlock()
				}
			}
		}(w)
	}
	for i := 0; i < 40; i++ {
		if err := store.Remove(); err != nil {
			t.Error(err)
		}
	}
	close(stop)
	wait.Wait()
	inv, _ := openInventory(t, store)
	if status := inv.Status(); !status.Durable || status.Damaged != 0 || status.OtherKey != 0 {
		t.Fatalf("%+v", status)
	}
	inv.Add(oneEntry(t, inv, "after"))
	if again, loaded := openInventory(t, store); len(loaded) == 0 || again.Status().Damaged != 0 {
		t.Fatalf("%+v", again.Status())
	}
	entries, _ := os.ReadDir(store.Directory)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), inventoryTempPrefix) {
			t.Fatalf("a temporary file was left: %s", entry.Name())
		}
	}
}

// Purge deletes the key before the file: in the other order, a proxy that
// registered between the two left its entries behind the purge.
func TestInventoryPurgeDeletesTheKeyFirst(t *testing.T) {
	store, keyring := newHookedInventoryStore(t)
	running, _ := openInventory(t, store)
	running.Add(oneEntry(t, running, "one"))
	keyring.before = func(operation string) {
		if operation == "delete" {
			keyring.before = nil
			running.Add(oneEntry(t, running, "registered-during-the-purge"))
		}
	}
	if err := store.Purge(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(inventoryFilePath(store)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entries registered during a purge outlived it: %v", err)
	}
	if storedInventoryKey(t, store) != "" {
		t.Fatal("the key outlived the purge")
	}
	// The running proxy says at once that its key is gone, and stores nothing.
	if status := running.Status(); status.Durable || status.Reason != InventoryReasonKeyReplaced {
		t.Fatalf("%+v", status)
	}
	running.Add(oneEntry(t, running, "after"))
	if _, err := os.Stat(inventoryFilePath(store)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a proxy whose key was purged wrote the store again: %v", err)
	}
}

// Purge racing proxies that register: when both are done there is no key and
// no file, whoever came first.
func TestInventoryPurgeRacingRegistration(t *testing.T) {
	for round := 0; round < 20; round++ {
		store, _ := newHookedInventoryStore(t)
		running, _ := openInventory(t, store)
		running.Add(oneEntry(t, running, "one"))
		if round%2 == 1 {
			// The file alone is gone first, as phase ai disable leaves it
			// when it is run twice.
			if err := store.Remove(); err != nil {
				t.Fatal(err)
			}
		}
		var wait sync.WaitGroup
		wait.Add(1)
		go func() {
			defer wait.Done()
			for i := 0; i < 30; i++ {
				running.Add(oneEntry(t, running, fmt.Sprintf("v%d", i)))
			}
		}()
		if err := store.Purge(); err != nil {
			t.Fatal(err)
		}
		wait.Wait()
		if _, err := os.Stat(inventoryFilePath(store)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("round %d: a file outlived the purge: %v", round, err)
		}
		if storedInventoryKey(t, store) != "" {
			t.Fatalf("round %d: the key outlived the purge", round)
		}
	}
}

// A keystore that cannot delete has the key replaced, and the file still goes.
func TestInventoryPurgeWhenDeleteIsRefused(t *testing.T) {
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	inv.Add(oneEntry(t, inv, "one"))
	if err := store.Purge(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(inventoryFilePath(store)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%v", err)
	}
	if again, loaded := openInventory(t, store); bytes.Equal(inventoryKeyBytes(t, again), inventoryKeyBytes(t, inv)) || len(loaded) != 0 {
		t.Fatal("the key was not replaced")
	}
}

// The store's lock has a deadline: past it a starting proxy runs from memory
// and says so, a running one stops storing, and a removal fails.
func TestInventoryLockHasADeadline(t *testing.T) {
	previous := inventoryLockWait
	inventoryLockWait = 60 * time.Millisecond
	t.Cleanup(func() { inventoryLockWait = previous })
	store := newInventoryTestStore(t)
	running, _ := openInventory(t, store)
	running.Add(oneEntry(t, running, "one"))
	file := mustRead(t, inventoryFilePath(store))

	unlock, err := lockCAFile(filepath.Join(store.Directory, inventoryLockName))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	starting, loaded := openInventory(t, store)
	if status := starting.Status(); status.Durable || status.Reason != InventoryReasonBusy || len(loaded) != 0 {
		t.Fatalf("%+v", status)
	}
	if !bytes.Equal(inventoryKeyBytes(t, starting), inventoryKeyBytes(t, running)) {
		t.Fatal("a proxy that could not take the lock has another key")
	}
	running.Add(oneEntry(t, running, "two"))
	if status := running.Status(); status.Durable || status.Reason != InventoryReasonBusy {
		t.Fatalf("%+v", status)
	}
	if err := store.Remove(); !errors.Is(err, errInventoryBusy) {
		t.Fatalf("%v", err)
	}
	if waited := time.Since(started); waited > 3*time.Second {
		t.Fatalf("waited %v on a held lock", waited)
	}
	unlock()
	if !bytes.Equal(mustRead(t, inventoryFilePath(store)), file) {
		t.Fatal("the file was written without the lock")
	}
	if again, loaded := openInventory(t, store); !again.Status().Durable || len(loaded) != 1 {
		t.Fatalf("%+v", again.Status())
	}
}

// No keystore call is made with the store's lock held: a keystore may wait on
// a person, and every other proxy would wait with it.
func TestInventoryAsksTheKeystoreWithNoLockHeld(t *testing.T) {
	store, keyring := newHookedInventoryStore(t)
	lockPath := filepath.Join(store.Directory, inventoryLockName)
	var calls, held atomic.Int32
	keyring.before = func(operation string) {
		calls.Add(1)
		unlock, busy, err := tryLockFile(lockPath)
		if err != nil {
			t.Error(err)
			return
		}
		if busy {
			held.Add(1)
			return
		}
		unlock()
	}
	steps := map[string]func(){}
	inv, _ := openInventory(t, store)
	check := func(step string) {
		t.Helper()
		if calls.Swap(0) == 0 {
			t.Fatalf("%s: the keystore was not asked", step)
		}
		if held.Swap(0) != 0 {
			t.Fatalf("%s: the keystore was asked with the store's lock held", step)
		}
	}
	check("a first start")
	steps["a registration after the file went"] = func() {
		if err := store.Remove(); err != nil {
			t.Fatal(err)
		}
		inv.Add(oneEntry(t, inv, "one"))
	}
	steps["a status question"] = func() { inv.Status() }
	steps["a later start"] = func() { openInventory(t, store) }
	steps["a start over another key's file"] = func() {
		if err := store.ReplaceKey(); err != nil {
			t.Fatal(err)
		}
		openInventory(t, store)
	}
	steps["a purge"] = func() {
		if err := store.Purge(); err != nil {
			t.Fatal(err)
		}
	}
	for _, step := range []string{"a registration after the file went", "a status question", "a later start", "a start over another key's file", "a purge"} {
		steps[step]()
		check(step)
	}
}

// A running proxy whose key was replaced says so the next time it is asked,
// not at its next write.
func TestInventoryStatusSeesAReplacedKey(t *testing.T) {
	store := newInventoryTestStore(t)
	running, _ := openInventory(t, store)
	running.Add(oneEntry(t, running, "one"))
	if status := running.Status(); !status.Durable {
		t.Fatalf("%+v", status)
	}
	if err := store.ReplaceKey(); err != nil {
		t.Fatal(err)
	}
	if status := running.Status(); status.Durable || status.Reason != InventoryReasonKeyReplaced {
		t.Fatalf("%+v", status)
	}
	file := mustRead(t, inventoryFilePath(store))
	running.Add(oneEntry(t, running, "two"))
	if !bytes.Equal(mustRead(t, inventoryFilePath(store)), file) {
		t.Fatal("a proxy holding a replaced key wrote to the store")
	}
}

// Proxies that make the first key together end with one key: each that
// stores holds the key the keystore kept, and none writes under another.
func TestInventoryFirstStartsTogether(t *testing.T) {
	for round := 0; round < 10; round++ {
		store, _ := newHookedInventoryStore(t)
		const proxies = 6
		opened := make([]*Inventory, proxies)
		var wait sync.WaitGroup
		for p := range opened {
			wait.Add(1)
			go func(p int) {
				defer wait.Done()
				inv, _, err := store.Open()
				if err != nil {
					t.Error(err)
					return
				}
				inv.Add(oneEntry(t, inv, fmt.Sprintf("p%d", p)))
				opened[p] = inv
			}(p)
		}
		wait.Wait()
		kept := storedInventoryKey(t, store)
		storing := 0
		for p, inv := range opened {
			if inv == nil {
				t.Fatal("a proxy did not open")
			}
			status := inv.Status()
			holdsKept := strings.Contains(kept, fmt.Sprintf("%x", inv.keyID[:]))
			switch {
			case status.Durable && !holdsKept:
				t.Fatalf("round %d: proxy %d stores under a key the keystore does not hold", round, p)
			case status.Durable:
				storing++
			case status.Reason != InventoryReasonKeyReplaced:
				t.Fatalf("round %d: proxy %d: %+v", round, p, status)
			}
		}
		final, loaded := openInventory(t, store)
		if status := final.Status(); !status.Durable || status.OtherKey != 0 || status.Damaged != 0 || len(loaded) != storing {
			t.Fatalf("round %d: %d loaded of %d stored: %+v", round, len(loaded), storing, status)
		}
	}
}
