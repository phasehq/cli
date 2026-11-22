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

// Remove leaves the lock files: unlinked while held, a process waiting on one
// and a process arriving after would each hold "the" lock at once.
func TestInventoryRemoveLeavesTheLock(t *testing.T) {
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	inv.Add(oneEntry(t, inv, "one"))
	for _, name := range []string{inventoryLockName, inventoryQueueName} {
		lockPath := filepath.Join(store.Directory, name)
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
				t.Fatalf("%s was removed or replaced: %v", name, err)
			}
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
				if unlock, err := lockInventory(store.Directory, inventoryLockWait); err == nil {
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
	if status := inv.Status(); !status.Durable || status.Damaged != 0 || status.OtherKey {
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

// A disable removes the key without reading it first. A keychain that
// refuses the read still loses the key, one that cannot delete has it
// replaced, and one that will do neither is an error and never a silent
// success: either way the entries are gone.
func TestInventoryPurgeDoesNotNeedToReadTheKey(t *testing.T) {
	refused := errors.New("user interaction is not allowed")
	gone := func(t *testing.T, store InventoryStore) {
		t.Helper()
		if _, err := os.Stat(inventoryFilePath(store)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the entries outlived the disable: %v", err)
		}
	}
	t.Run("a keystore that deletes", func(t *testing.T) {
		store, hooked := newHookedInventoryStore(t)
		inv, _ := openInventory(t, store)
		inv.Add(oneEntry(t, inv, "one"))
		hooked.failGet.Store(&refused)
		if err := store.Purge(); err != nil {
			t.Fatal(err)
		}
		hooked.failGet.Store(nil)
		gone(t, store)
		if storedInventoryKey(t, store) != "" {
			t.Fatal("the key outlived a disable whose read of it was refused")
		}
		if again, loaded := openInventory(t, store); bytes.Equal(inventoryKeyBytes(t, again), inventoryKeyBytes(t, inv)) || len(loaded) != 0 {
			t.Fatal("a proxy enabled again hands out the keys the disable was to remove")
		}
	})
	t.Run("a keystore that cannot delete", func(t *testing.T) {
		store, keyring, _, key := troubledStore(t)
		keyring.refusing.Store(true)
		if err := store.Purge(); err != nil {
			t.Fatal(err)
		}
		gone(t, store)
		if after, err := keyring.lockedKeyring.Get(inventoryKeyringService, inventoryKeyringUser); err != nil || after == key {
			t.Fatalf("the key was not replaced after a refused read: %v", err)
		}
	})
	t.Run("a keystore that does neither", func(t *testing.T) {
		store, keyring, _, key := troubledStore(t)
		keyring.silent.Store(true)
		err := store.Purge()
		if err == nil || !strings.Contains(err.Error(), "remove the leak protection inventory key") {
			t.Fatalf("a disable that left the key behind answered %v", err)
		}
		gone(t, store)
		if after, _ := keyring.lockedKeyring.Get(inventoryKeyringService, inventoryKeyringUser); after != key {
			t.Fatal("the keystore was written while it did not answer")
		}
		// With no file left, a keystore that does not answer is a machine
		// with none: there is nothing to remove and nothing to say.
		if err := store.Purge(); err != nil {
			t.Fatalf("a disable with no keystore and nothing stored: %v", err)
		}
	})
}

// A purge of all local data removes the inventory key as it removes the CA
// key beside it: a keystore that does not answer may still hold it, and that
// is reported; one that answers and holds no key is not.
func TestDeleteStoredInventoryKeyReportsAKeystoreItCouldNotReach(t *testing.T) {
	t.Cleanup(gokeyring.MockInit)
	gokeyring.MockInitWithError(errors.New("secret service unreachable"))
	if err := DeleteStoredInventoryKey(); !errors.Is(err, ErrKeystoreUnreachable) {
		t.Fatalf("an unreachable keystore was reported as %v", err)
	}
	gokeyring.MockInit()
	if err := DeleteStoredInventoryKey(); err != nil {
		t.Fatalf("a keystore with no inventory key: %v", err)
	}
	if err := gokeyring.Set(inventoryKeyringService, inventoryKeyringUser, "key"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteStoredInventoryKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := gokeyring.Get(inventoryKeyringService, inventoryKeyringUser); !errors.Is(err, gokeyring.ErrNotFound) {
		t.Fatalf("the inventory key is still in the keystore: %v", err)
	}
}

// shortLockWaits makes the store's waits short enough for a test to sit out.
func shortLockWaits(t *testing.T, proxy, removal time.Duration) {
	t.Helper()
	wait, remove := inventoryLockWait, inventoryRemoveWait
	inventoryLockWait, inventoryRemoveWait = proxy, removal
	t.Cleanup(func() { inventoryLockWait, inventoryRemoveWait = wait, remove })
}

// The store's lock has a deadline: past it a starting proxy runs from memory
// and says so, a running one does not store, and a removal fails. None of it
// is for life: the next registration stores again.
func TestInventoryLockHasADeadline(t *testing.T) {
	shortLockWaits(t, 60*time.Millisecond, 200*time.Millisecond)
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
	// A removal waits longer than a proxy does, and says what it left behind.
	began := time.Now()
	err = store.Remove()
	if !errors.Is(err, errInventoryBusy) || !strings.Contains(err.Error(), "was not removed") || time.Since(began) < inventoryRemoveWait {
		t.Fatalf("a removal from a store in use: %v after %v", err, time.Since(began))
	}
	own := store
	own.Tenant = inventoryTestTenant
	if everyone, err := own.Forget([]string{inventoryTestLogin}, false); everyone || !errors.Is(err, errInventoryBusy) || !strings.Contains(err.Error(), "was not removed") {
		t.Fatalf("a logout from a store in use: %v", err)
	}
	if waited := time.Since(started); waited > 3*time.Second {
		t.Fatalf("waited %v on a held lock", waited)
	}
	unlock()
	if !bytes.Equal(mustRead(t, inventoryFilePath(store)), file) {
		t.Fatal("the file was written without the lock")
	}
	// The lock is free again: each proxy stores what is registered next, and
	// the one whose registration found the store in use stores it then.
	two := oneEntry(t, running, "two-again")
	running.Add(two)
	starting.Add(oneEntry(t, starting, "three"))
	for name, inv := range map[string]*Inventory{"the running proxy": running, "the one that started meanwhile": starting} {
		if status := inv.Status(); !status.Durable || status.Reason != "" {
			t.Fatalf("%s after the lock was free again: %+v", name, status)
		}
	}
	if again, loaded := openInventory(t, store); !again.Status().Durable || len(loaded) != 3 {
		t.Fatalf("%+v, %d loaded", again.Status(), len(loaded))
	}
}

// eventually waits for something a write behind an answer brings about.
func eventually(t *testing.T, what string, done func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !done(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("it never came about: %s", what)
		}
	}
}

// A registration's answer waits a bounded time for the store. A store in use
// for longer is written behind the answer; one in use past the lock's own
// deadline is reported, and the next registration stores; and writes do not
// pile up behind a store that stays in use.
func TestInventoryAddWithinDoesNotHoldItsCallerForTheStore(t *testing.T) {
	shortLockWaits(t, 2*time.Second, 5*time.Second)
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	lockPath := filepath.Join(store.Directory, inventoryLockName)
	const wait = 30 * time.Millisecond

	unlock, err := lockCAFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	inv.AddWithin(oneEntry(t, inv, "written-behind"), wait)
	if waited := time.Since(began); waited >= inventoryLockWait/2 {
		t.Fatalf("a registration waited %v on a store in use, with %v to answer in", waited, wait)
	}
	if records := inventoryFileRecords(t, store); records != 0 {
		t.Fatalf("%d records were written without the lock", records)
	}
	unlock()
	eventually(t, "the write behind the answer", func() bool { return inventoryFileRecords(t, store) == 1 })
	eventually(t, "the store's place given back", func() bool { return len(inv.behind) == 0 })
	if status := inv.Status(); !status.Durable {
		t.Fatalf("after the write behind the answer: %+v", status)
	}

	// A store in use past the lock's deadline: the value is in memory only,
	// status says so, and the next registration stores.
	inventoryLockWait = 60 * time.Millisecond
	if unlock, err = lockCAFile(lockPath); err != nil {
		t.Fatal(err)
	}
	inv.AddWithin(oneEntry(t, inv, "not-stored"), wait)
	eventually(t, "a store in use reported", func() bool { return inv.Status().Reason == InventoryReasonBusy })
	// Writes already waiting are not joined by more: each one past the bound
	// returns at once, and none of them is left running.
	inventoryLockWait = 2 * time.Second
	began = time.Now()
	for i := 0; i < 3*inventoryWritesBehind; i++ {
		inv.AddWithin(oneEntry(t, inv, fmt.Sprintf("piled-%d", i)), time.Millisecond)
		if waiting := len(inv.behind); waiting > inventoryWritesBehind {
			t.Fatalf("%d writes wait on the store", waiting)
		}
	}
	if waited := time.Since(began); waited >= inventoryLockWait/2 {
		t.Fatalf("registrations past the bound waited %v", waited)
	}
	if status := inv.Status(); status.Durable || status.Reason != InventoryReasonBusy {
		t.Fatalf("with writes waiting past the bound: %+v", status)
	}
	unlock()
	eventually(t, "every waiting write done", func() bool { return len(inv.behind) == 0 })
	inv.AddWithin(oneEntry(t, inv, "stored-again"), time.Minute)
	if status := inv.Status(); !status.Durable || status.Reason != "" {
		t.Fatalf("after the store was free again: %+v", status)
	}
	// Whatever was written behind is whole, and the last one is there.
	if again, loaded := openInventory(t, store); again.Status().Damaged != 0 || len(loaded) < 2 || len(loaded) > 2+inventoryWritesBehind {
		t.Fatalf("%d loaded, %+v", len(loaded), again.Status())
	}
	// An inventory that stores nothing has nothing to wait for.
	memory, err := MemoryInventory()
	if err != nil {
		t.Fatal(err)
	}
	memory.AddWithin(oneEntry(t, memory, "memory"), time.Minute)
	if len(memory.behind) != 0 {
		t.Fatal("a memory inventory queued a write")
	}
}

// A removal that finds the store in use for a while still removes it.
func TestInventoryRemovalWaitsForAStoreInUse(t *testing.T) {
	shortLockWaits(t, 30*time.Millisecond, 10*time.Second)
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	inv.Add(oneEntry(t, inv, "one"))
	for name, remove := range map[string]func() error{
		"a logout": func() error {
			own := store
			own.Tenant = inventoryTestTenant
			_, err := own.Forget([]string{inventoryTestLogin}, false)
			return err
		},
		"a disable": store.Remove,
	} {
		unlock, err := lockCAFile(filepath.Join(store.Directory, inventoryLockName))
		if err != nil {
			t.Fatal(err)
		}
		// Held for longer than a proxy waits.
		time.AfterFunc(5*inventoryLockWait, unlock)
		if err := remove(); err != nil {
			t.Fatalf("%s while the store was in use: %v", name, err)
		}
	}
	if _, err := os.Stat(inventoryFilePath(store)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the file is still there: %v", err)
	}
}

// A writer that lets the lock go and comes straight back for it, as a proxy
// that registers again and again does, does not overtake a process that waits.
func TestInventoryLockGoesToTheOneThatWaited(t *testing.T) {
	directory := t.TempDir()
	unlock, err := lockInventory(directory, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	had := make(chan error, 1)
	go func() {
		waited, err := lockInventory(directory, 10*time.Second)
		had <- err
		if err == nil {
			waited()
		}
	}()
	// The other process is waiting once it holds the queue's lock.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		leave, busy, err := tryLockFile(filepath.Join(directory, inventoryQueueName))
		if err != nil || time.Now().After(deadline) {
			t.Fatalf("no process came to wait: %v", err)
		}
		if busy {
			break
		}
		leave()
	}
	unlock()
	again, err := lockInventory(directory, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer again()
	select {
	case err := <-had:
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("the writer that came back had the lock again before the process that waited for it")
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
		if status := final.Status(); !status.Durable || status.OtherKey || status.Damaged != 0 || len(loaded) != storing {
			t.Fatalf("round %d: %d loaded of %d stored: %+v", round, len(loaded), storing, status)
		}
	}
}

// A keystore that stops answering (locked, or waiting for approval) never
// makes Status late: it says what it last knew, and the answer lands later.
func TestInventoryStatusDoesNotWaitForAStalledKeystore(t *testing.T) {
	store, keyring := newHookedInventoryStore(t)
	running, _ := openInventory(t, store)
	running.Add(oneEntry(t, running, "one"))
	if err := store.ReplaceKey(); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	keyring.before = func(operation string) {
		if operation == "get" {
			<-release
		}
	}
	started := time.Now()
	status := running.Status()
	if waited := time.Since(started); waited > inventoryKeyCheckWait+time.Second || !status.Durable {
		t.Fatalf("a stalled keystore: Status took %v and said %+v", waited, status)
	}
	// Asked again while the question is still out: no wait at all.
	started = time.Now()
	if running.Status(); time.Since(started) > inventoryKeyCheckWait/2 {
		t.Fatalf("a second Status waited %v for the same question", time.Since(started))
	}
	close(release)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if status := running.Status(); !status.Durable && status.Reason == InventoryReasonKeyReplaced {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the keystore's late answer was never reported")
		}
	}
}

// A registration acknowledged while another process held the store is still
// written when the proxy stops, as long as Finish is given the time.
func TestInventoryFinishWaitsForWritesLeftRunning(t *testing.T) {
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	unlock, err := lockInventory(inv.directory, inventoryLockWait)
	if err != nil {
		t.Fatal(err)
	}
	inv.AddWithin(oneEntry(t, inv, "acknowledged"), 20*time.Millisecond)
	if inv.Finish(20 * time.Millisecond) {
		unlock()
		t.Fatal("Finish said a write blocked on the store's lock had ended")
	}
	time.AfterFunc(200*time.Millisecond, unlock)
	if !inv.Finish(InventoryFinishWait) {
		t.Fatal("Finish gave up on a write that could end")
	}
	if _, loaded := openInventory(t, store); len(loaded) != 1 {
		t.Fatalf("the next proxy found %d of the 1 acknowledged entries", len(loaded))
	}
	// Finish gives back every place it took: writes go on queuing after it.
	if len(inv.behind) != 0 {
		t.Fatalf("Finish left %d places taken", len(inv.behind))
	}
}
