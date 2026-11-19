package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
	"github.com/phasehq/cli/pkg/config"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	gokeyring "github.com/zalando/go-keyring"
)

const (
	inventoryTestKeyService = "phase-cli-ai-leak-inventory"
	inventoryTestKeyUser    = "key-v1"
	inventoryTestFile       = "leak-inventory.bin"
)

// memoryKeystore is a keystore that holds what it is given.
type memoryKeystore struct {
	mu     sync.Mutex
	values map[string]string
}

func (k *memoryKeystore) Get(service, user string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	value, ok := k.values[service+"/"+user]
	if !ok {
		return "", gokeyring.ErrNotFound
	}
	return value, nil
}

func (k *memoryKeystore) Set(service, user, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.values[service+"/"+user] = value
	return nil
}

// deletingKeystore can also delete, as the system keystore can.
type deletingKeystore struct{ memoryKeystore }

func (k *deletingKeystore) Delete(service, user string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.values, service+"/"+user)
	return nil
}

// inventoryTestTenant is the tenant the tests' proxy would act for.
const inventoryTestTenant = "https://console.test\norganisation\ntest-organisation"

// storeAValue opens the inventory as a proxy does and registers one value.
func storeAValue(t *testing.T, store phaseproxy.InventoryStore) {
	t.Helper()
	store.Tenant = inventoryTestTenant
	inventory, _, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	principal, err := inventory.Principal("https://console.test\naccount\ntest-account")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := censor.IndexValue(principal.Key(), "secret", "one", "Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3Jw3Rk8Tn5Vb2")
	if err != nil {
		t.Fatal(err)
	}
	inventory.Add([]phaseproxy.StoredEntries{{Entries: entries, Principal: principal}})
	if status := inventory.Status(); !status.Durable {
		t.Fatalf("the inventory is not stored: %+v", status)
	}
	if info, err := os.Stat(filepath.Join(store.Directory, inventoryTestFile)); err != nil || info.Size() < 100 {
		t.Fatalf("no inventory file: %v", err)
	}
}

// Purging all local data removes the leak protection inventory with the CA
// key: its key from the keystore, and its entries with ~/.phase.
func TestLogoutPurgeRemovesTheLeakInventory(t *testing.T) {
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
	// The mocked keystore stands in for the system one, so this is the store
	// a proxy would open.
	storeAValue(t, phaseproxy.InventoryStore{Directory: aiDirectory})
	if _, err := gokeyring.Get(inventoryTestKeyService, inventoryTestKeyUser); err != nil {
		t.Fatalf("the inventory key is not in the keystore: %v", err)
	}

	if _, stderr, err := runPhaseCommand(t, "", "users", "logout", "--purge"); err != nil {
		t.Fatalf("purge: %v %s", err, stderr)
	}
	if _, err := os.Stat(filepath.Join(aiDirectory, inventoryTestFile)); !os.IsNotExist(err) {
		t.Fatalf("the inventory file is still there after purge: %v", err)
	}
	if _, err := gokeyring.Get(inventoryTestKeyService, inventoryTestKeyUser); err != gokeyring.ErrNotFound {
		t.Fatalf("the inventory key is still in the keystore: %v", err)
	}
}

// phase ai disable removes the file and the key (replaced where it cannot be
// deleted). The lock file stays: removed, two proxies could each hold it.
func TestAIDisableRemovesTheLeakInventory(t *testing.T) {
	for name, keystore := range map[string]phaseproxy.PrivateKeyStore{
		"a keystore that deletes":       &deletingKeystore{memoryKeystore{values: map[string]string{}}},
		"a keystore that cannot delete": &memoryKeystore{values: map[string]string{}},
	} {
		t.Run(name, func(t *testing.T) {
			isolateAISetup(t)
			directory, err := hookRuntimeDir()
			if err != nil {
				t.Fatal(err)
			}
			original := aiCAStore
			aiCAStore = phaseproxy.CAStore{Directory: directory, Keyring: keystore}
			t.Cleanup(func() { aiCAStore = original })
			storeAValue(t, aiInventoryStore())
			before, err := keystore.Get(inventoryTestKeyService, inventoryTestKeyUser)
			if err != nil {
				t.Fatal(err)
			}

			if err := runAIDisableForTest(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(directory, inventoryTestFile)); !os.IsNotExist(err) {
				t.Fatalf("%s is still there after disable: %v", inventoryTestFile, err)
			}
			for _, lock := range []string{"leak-inventory.lock", "leak-inventory.queue"} {
				if _, err := os.Lstat(filepath.Join(directory, lock)); err != nil {
					t.Fatalf("%s was removed by disable: %v", lock, err)
				}
			}
			after, err := keystore.Get(inventoryTestKeyService, inventoryTestKeyUser)
			if _, deletes := keystore.(*deletingKeystore); deletes {
				if err != gokeyring.ErrNotFound {
					t.Fatalf("the inventory key is still in the keystore: %v", err)
				}
			} else if err != nil || after == before {
				t.Fatalf("the inventory key was neither deleted nor replaced: %v", err)
			}
			// The next proxy starts with nothing.
			next := aiInventoryStore()
			next.Tenant = inventoryTestTenant
			inventory, loaded, err := next.Open()
			if err != nil || len(loaded) != 0 || inventory.Status().OtherKey {
				t.Fatalf("%d loaded, %v", len(loaded), err)
			}
			// Disabling again, with nothing left, is not an error.
			if err := runAIDisableForTest(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLeakProtectionSummarySaysHowTheInventoryIsKept(t *testing.T) {
	const prefix = "censor (secrets in model traffic are replaced with placeholders); 3 secrets known"
	for name, c := range map[string]struct {
		inventory remoteapi.LeakInventoryStatus
		want      string
	}{
		"stored": {
			remoteapi.LeakInventoryStatus{Storage: "stored", Loaded: 3},
			"; inventory kept across restarts (3 loaded at start)",
		},
		"stored, with entries it cannot match": {
			remoteapi.LeakInventoryStatus{Storage: "stored", Loaded: 1, UnmatchedScheme: 2, UnmatchedKey: true, Damaged: 1},
			"; inventory kept across restarts (1 loaded at start), 2 stored by another version of Phase and not matched until read again, what was stored under a replaced key dropped, 1 unreadable and dropped",
		},
		"no keystore": {
			remoteapi.LeakInventoryStatus{Storage: "memory", Reason: "no_keystore"},
			"; inventory kept in memory only (no system keystore): a restarted proxy knows a value once a command reads it again",
		},
		"a newer file": {
			remoteapi.LeakInventoryStatus{Storage: "memory", Reason: "newer_store_format"},
			"; inventory kept in memory only (the stored inventory was written by a newer version of Phase and is left as it is)",
		},
		"a replaced key": {
			remoteapi.LeakInventoryStatus{Storage: "memory", Reason: "key_replaced"},
			"; inventory kept in memory only (its key was replaced while the proxy ran; the next proxy start stores again)",
		},
		"an unwritable file": {
			remoteapi.LeakInventoryStatus{Storage: "memory", Reason: "store_unusable"},
			"; inventory kept in memory only (the inventory file could not be written)",
		},
		"a keystore that did not give the key": {
			remoteapi.LeakInventoryStatus{Storage: "memory", Reason: "key_unreadable"},
			"; inventory kept in memory only (the system keystore did not give its key; the key and the stored inventory are left as they are)",
		},
		"a file that could not be read": {
			remoteapi.LeakInventoryStatus{Storage: "memory", Reason: "store_unreadable"},
			"; inventory kept in memory only (the inventory file could not be read and is left as it is; phase ai disable removes it)",
		},
		"a held lock": {
			remoteapi.LeakInventoryStatus{Storage: "memory", Reason: "store_busy"},
			"; inventory kept in memory only (another process held the inventory file; the next registration tries again)",
		},
		"more stored than a start loads": {
			remoteapi.LeakInventoryStatus{Storage: "stored", Loaded: 5000, NotLoaded: 12},
			"; inventory kept across restarts (5000 loaded at start), 12 registered longer ago left out to keep room",
		},
		"more registered than the store keeps for a login": {
			remoteapi.LeakInventoryStatus{Storage: "stored", Loaded: 2500, Dropped: 7},
			"; inventory kept across restarts (2500 loaded at start), 7 not stored to keep the store within its bounds",
		},
		"commands of another account": {
			remoteapi.LeakInventoryStatus{Storage: "stored", Loaded: 2, Unstored: 3},
			"; inventory kept across restarts (2 loaded at start), 3 registrations from commands of another login, or of none they could state, protected until this proxy exits",
		},
		"a session the Console did not name": {
			remoteapi.LeakInventoryStatus{Storage: "memory", Reason: "no_tenant"},
			"; inventory kept in memory only (the Console did not say which organisation and login this session is)",
		},
		"no store": {
			remoteapi.LeakInventoryStatus{Storage: "memory", Reason: "not_configured"},
			"; inventory kept in memory only (no store)",
		},
	} {
		inventory := c.inventory
		if line := leakProtectionSummary(remoteapi.LeakProtectionStatus{Mode: "censor", SecretsKnown: 3, Inventory: &inventory}); line != prefix+c.want {
			t.Errorf("%s: %q", name, line)
		}
	}
	// A proxy of an earlier version reports no inventory, and the line is as it was.
	if line := leakProtectionSummary(remoteapi.LeakProtectionStatus{Mode: "censor", SecretsKnown: 3}); line != prefix {
		t.Errorf("%q", line)
	}
}

// storeFor registers one value as a proxy of a tenant would for a login.
func storeFor(t *testing.T, store phaseproxy.InventoryStore, identity phaseproxy.InventoryIdentity, id string) {
	t.Helper()
	store.Tenant = identity.Tenant
	inventory, _, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	principal, err := inventory.Principal(identity.Login)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := censor.IndexValue(principal.Key(), "secret", id, "Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3Jw3Rk8Tn5Vb2"+id)
	if err != nil {
		t.Fatal(err)
	}
	inventory.Add([]phaseproxy.StoredEntries{{Entries: entries, Principal: principal}})
}

// storedIDs are the ids a tenant's next proxy would load.
func storedIDs(t *testing.T, store phaseproxy.InventoryStore, tenant string) []string {
	t.Helper()
	store.Tenant = tenant
	_, loaded, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, stored := range loaded {
		ids = append(ids, stored.Entries.ID)
	}
	sort.Strings(ids)
	return ids
}

// A logout removes what the inventory stored for that login, and for its
// organisation once no saved login of it is left. Others' records and the key stay.
func TestLogoutRemovesTheLoginsStoredValues(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	t.Setenv("PHASE_SERVICE_TOKEN", "")
	t.Setenv("PHASE_HOST", "")
	gokeyring.MockInit()
	keystore := &memoryKeystore{values: map[string]string{}}
	original := aiCAStore
	aiCAStore = phaseproxy.CAStore{Directory: filepath.Join(t.TempDir(), "ai"), Keyring: keystore}
	t.Cleanup(func() { aiCAStore = original })

	const host = "https://console.test"
	orgOne, orgTwo := "org-one", "org-two"
	users := []config.UserConfig{
		{Host: host, ID: "account-a", OrganizationID: &orgOne},
		{Host: host + "/", ID: "agent-local", PrincipalType: config.PrincipalAgent, PrincipalID: "agent-9", OrganizationID: &orgOne},
		{Host: host, ID: "account-c", OrganizationID: &orgTwo},
	}
	for _, user := range users {
		if err := config.AddUser(user); err != nil {
			t.Fatal(err)
		}
	}
	userA := phaseproxy.NewInventoryIdentity(host, orgOne, phaseproxy.InventoryLoginUser, "account-a")
	agent := phaseproxy.NewInventoryIdentity(host, orgOne, phaseproxy.InventoryLoginAgent, "agent-9")
	userC := phaseproxy.NewInventoryIdentity(host, orgTwo, phaseproxy.InventoryLoginUser, "account-c")
	// A service account another machine's login stored for in organisation one.
	visitor := phaseproxy.NewInventoryIdentity(host, orgOne, phaseproxy.InventoryLoginServiceAccount, "a-service-account")
	for id, identity := range map[string]phaseproxy.InventoryIdentity{"of-a": userA, "of-agent": agent, "of-c": userC, "of-visitor": visitor} {
		storeFor(t, aiInventoryStore(), identity, id)
	}
	key, err := keystore.Get(inventoryTestKeyService, inventoryTestKeyUser)
	if err != nil {
		t.Fatal(err)
	}
	logout := func(account string) {
		t.Helper()
		if err := config.SetDefaultUser(account); err != nil {
			t.Fatal(err)
		}
		if _, stderr, err := runPhaseCommand(t, "", "users", "logout"); err != nil || strings.Contains(stderr, "leak protection") {
			t.Fatalf("logout of %s: %v %s", account, err, stderr)
		}
	}
	held := func() string {
		t.Helper()
		return fmt.Sprint(storedIDs(t, aiInventoryStore(), userA.Tenant), storedIDs(t, aiInventoryStore(), userC.Tenant))
	}
	// One login of organisation one logs out: its own records go.
	logout("account-a")
	if got := held(); got != "[of-agent of-visitor] [of-c]" {
		t.Fatalf("after one login of an organisation logged out: %s", got)
	}
	// The last saved login of organisation one: everything of it goes.
	logout("agent-local")
	if got := held(); got != "[] [of-c]" {
		t.Fatalf("after an organisation's last login logged out: %s", got)
	}
	if after, err := keystore.Get(inventoryTestKeyService, inventoryTestKeyUser); err != nil || after != key {
		t.Fatalf("a logout replaced or removed the inventory key: %v", err)
	}
	logout("account-c")
	if got := held(); got != "[] []" {
		t.Fatalf("after every login logged out: %s", got)
	}
}

// A logout with nothing stored makes no key and no file.
func TestLogoutWithNoInventoryWritesNothing(t *testing.T) {
	console := newFakeAgentConsole(t)
	isolateAgentCommand(t, console.server.URL)
	t.Setenv("PHASE_SERVICE_TOKEN", "")
	gokeyring.MockInit()
	keystore := &memoryKeystore{values: map[string]string{}}
	original := aiCAStore
	aiCAStore = phaseproxy.CAStore{Directory: filepath.Join(t.TempDir(), "ai"), Keyring: keystore}
	t.Cleanup(func() { aiCAStore = original })
	organisation := "org-one"
	if err := config.AddUser(config.UserConfig{Host: "https://console.test", ID: "account-a", OrganizationID: &organisation}); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := runPhaseCommand(t, "", "users", "logout"); err != nil || strings.Contains(stderr, "leak protection") {
		t.Fatalf("logout: %v %s", err, stderr)
	}
	if _, err := keystore.Get(inventoryTestKeyService, inventoryTestKeyUser); err != gokeyring.ErrNotFound {
		t.Fatalf("a logout made an inventory key: %v", err)
	}
	if _, err := os.Lstat(aiCAStore.Directory); !os.IsNotExist(err) {
		t.Fatalf("a logout wrote to the Phase AI directory: %v", err)
	}
}
