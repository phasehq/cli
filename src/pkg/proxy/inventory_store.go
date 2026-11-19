package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	gokeyring "github.com/zalando/go-keyring"

	"github.com/phasehq/cli/pkg/censor"
)

// The leak protection inventory: one master key in the system keystore and one
// owner-only file of sealed records (see internal/aiproxy/CONTROL_API.md).
//
// Store format 1, integers big-endian. A head is sealed under the file key and
// a body under its tenant's key, each bound to what precedes it:
//
//	magic "PHLKINV1" | format uint32 | key id [8], then for each record
//	length uint32 | nonce [12] | sealed head | nonce [12] | sealed body
//	head: scheme uint32 | registered int64 | tenant, login, content tag [16] each
//	body: flag byte (1: the id is a key name) | principal id [16] | entries
const (
	// InventoryStoreFormat is the store format this build writes.
	InventoryStoreFormat = 1
	// InventoryEntryLifetime is how long an entry is kept after it was last
	// registered. Every command that decrypts a value registers it again.
	InventoryEntryLifetime = 30 * 24 * time.Hour

	inventoryKeyringService = "phase-cli-ai-leak-inventory"
	inventoryKeyringUser    = "key-v1"
	inventoryFileName       = "leak-inventory.bin"
	inventoryLockName       = "leak-inventory.lock"
	inventoryTempPrefix     = ".phase-inventory-"
	inventoryMagic          = "PHLKINV1"
	inventoryKeyIDSize      = 8
	inventoryHeaderSize     = len(inventoryMagic) + 4 + inventoryKeyIDSize
	inventoryTagSize        = 16
	inventoryNonceSize      = 12
	// inventoryBodyFixed is a sealed body before its entries: the flag byte
	// and the principal's id.
	inventoryBodyFixed = 1 + inventoryTagSize

	inventoryTenantLabel  = "phase-leak-inventory-tenant-v1"
	inventoryLookupLabel  = "phase-leak-inventory-lookup-v1"
	inventoryConfirmLabel = "phase-leak-inventory-confirm-v1"
	inventorySealLabel    = "phase-leak-inventory-seal-v1"
	inventoryTagLabel     = "phase-leak-inventory-tag-v1"
	inventoryFileLabel    = "phase-leak-inventory-file-v1"
	// inventoryHeadSize is a record's head before it is sealed, and
	// inventorySealOverhead what AES-GCM adds to what it seals.
	inventoryHeadSize     = 4 + 8 + 3*inventoryTagSize
	inventorySealOverhead = 16
	// inventoryRecordFixed is a record after its length and before its body.
	inventoryRecordFixed = inventoryNonceSize + inventoryHeadSize + inventorySealOverhead + inventoryNonceSize

	// inventoryRefreshAfter is how stale a stored entry's time may get before
	// a registration of the same value writes the file again. Registrations
	// repeat with every command, and most of them change nothing.
	inventoryRefreshAfter = 24 * time.Hour
	// inventoryClockSlack is how far ahead of this machine's clock a record's
	// time may be before the record is taken for damaged.
	inventoryClockSlack = 24 * time.Hour

	// maxInventoryFileBytes and maxInventoryRecords bound what is read.
	maxInventoryFileBytes = 64 << 20
	maxInventoryRecords   = 1 << 16
	// maxInventoryRecordBytes bounds one record: a registration is at most
	// 4 MiB on the wire.
	maxInventoryRecordBytes = 8 << 20
)

// storeBound is a number of records and their bytes.
type storeBound struct{ records, bytes int }

// inventoryBounds bound what is stored in all, for a tenant and for a login.
// Past one, the login that is writing loses its own oldest, and no one else any.
var inventoryBounds = struct {
	file, tenant, login storeBound
	tenantLogins        int
}{
	file:         storeBound{maxInventoryRecords, maxInventoryFileBytes},
	tenant:       storeBound{8192, 16 << 20},
	login:        storeBound{4096, 8 << 20},
	tenantLogins: 64,
}

// Tests shorten these.
var (
	// inventoryLockWait is how long a process waits for the store's lock
	// before it runs from memory: a writer holds it for one small file.
	inventoryLockWait = 2 * time.Second
	// inventoryKeySettle is how long the first start of all waits before it
	// reads back the key it made, in case another process made one too.
	inventoryKeySettle = 250 * time.Millisecond
	// inventoryKeyCheckEvery is how often, at most, Status asks the keystore
	// whether the key is still this process's.
	inventoryKeyCheckEvery = time.Second
)

// Why an inventory is kept in memory only.
const (
	// InventoryReasonNoKeystore: no system keystore to hold the key.
	InventoryReasonNoKeystore = "no_keystore"
	// InventoryReasonNewerFormat: the file was written by a newer version of
	// Phase and is left as it is.
	InventoryReasonNewerFormat = "newer_store_format"
	// InventoryReasonKeyReplaced: the key in the keystore is no longer the
	// one this process started with.
	InventoryReasonKeyReplaced = "key_replaced"
	// InventoryReasonUnusable: the directory or the file could not be
	// written.
	InventoryReasonUnusable = "store_unusable"
	// InventoryReasonKeyUnreadable: the keystore holds a key, or may hold
	// one, that could not be read (locked, refused, or not this build's).
	InventoryReasonKeyUnreadable = "key_unreadable"
	// InventoryReasonUnreadable: the file exists and could not be opened or
	// understood, and is left as it is.
	InventoryReasonUnreadable = "store_unreadable"
	// InventoryReasonBusy: another process held the store's lock too long.
	InventoryReasonBusy = "store_busy"
	// InventoryReasonNotConfigured: the proxy was started without a store.
	InventoryReasonNotConfigured = "not_configured"
	// InventoryReasonNoTenant: the Console did not say which organisation
	// and login the session is, so there is no one to keep the inventory for.
	InventoryReasonNoTenant = "no_tenant"
)

// NoKeystoreInventoryNotice is what status says of the inventory on a machine
// with no system keystore.
const NoKeystoreInventoryNotice = "kept in memory only (no system keystore): a restarted proxy knows a value once a command reads it again"

// InventoryStore is where the leak protection inventory is kept: the key in
// the keystore, the entries in Directory. The zero value is the user's own
// store, beside the CA.
type InventoryStore struct {
	Directory string
	Keyring   PrivateKeyStore
	// Tenant names whose inventory this is: an InventoryIdentity's Tenant.
	// Empty shares with nobody: memory only, nothing stored.
	Tenant string
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// StoredEntries is one registered value: its entries, whether its id is a
// secret's key name, and the principal whose confirming key made them.
type StoredEntries struct {
	Entries   *censor.Entries
	KeyNamed  bool
	Principal InventoryPrincipal
}

// InventoryPrincipal is one login's place in an inventory: an opaque id and
// the key its entries are indexed and confirmed with.
type InventoryPrincipal struct {
	id  [inventoryTagSize]byte
	key *censor.Key
}

// ID is the principal's opaque id: something to tell principals apart by.
func (p InventoryPrincipal) ID() [16]byte { return p.id }

// Key is the lookup key with this principal's confirming key: what a client
// of the principal is handed, and what the index confirms its entries with.
func (p InventoryPrincipal) Key() *censor.Key { return p.key }

// Is reports whether two principals are the same login of the same tenant.
func (p InventoryPrincipal) Is(other InventoryPrincipal) bool {
	return p.key != nil && p.id == other.id
}

// InventoryStatus is what an opened inventory says of itself: counts only.
type InventoryStatus struct {
	// Durable reports that registered values are written to the store.
	// Reason says why not.
	Durable bool
	Reason  string
	// Loaded counts the stored entries handed over when the store was opened.
	Loaded int
	// OtherScheme counts stored entries in a matching scheme this build does
	// not match: kept, and in need of registering again.
	OtherScheme int
	// OtherKey counts stored entries made under another key: never matched,
	// and dropped when the file is next written.
	OtherKey int
	// OtherTenant counts stored records of other tenants: never opened,
	// never matched, and kept as they are.
	OtherTenant int
	// Damaged counts stored entries that could not be read or validated.
	Damaged int
	// Expired counts stored entries dropped for their age when the store was
	// opened.
	Expired int
}

// Inventory is an opened store: the keys derived from the master, and the
// file being added to. Each proxy process opens one. It keeps no master.
type Inventory struct {
	store     InventoryStore
	directory string
	// lookup is the lookup key alone, and confirmRoot what every principal's
	// confirming key is expanded from.
	lookup      *censor.Key
	confirmRoot []byte
	keyID       [inventoryKeyIDSize]byte
	// tenant is the tag this tenant's records carry in the file.
	tenant [inventoryTagSize]byte
	seal   cipher.AEAD
	// file seals every record's head: derived from the master, not a tenant.
	file   cipher.AEAD
	tagKey [32]byte
	// principals are the keys already expanded, by principal id.
	principalMu sync.Mutex
	principals  map[[inventoryTagSize]byte]*censor.Key

	// adding lets one Add at a time through. mu guards what follows it and
	// is never held across the keystore or the store's lock.
	adding     sync.Mutex
	mu         sync.Mutex
	status     InventoryStatus
	keyChecked time.Time
	// known is when each entry this process has seen stored was registered,
	// by content tag, so a repeated registration costs no file access.
	known map[[inventoryTagSize]byte]int64
	// seen is the file known was read from. Another file in its place, or
	// none, means known says nothing of what is stored now.
	seen os.FileInfo
}

type inventoryRecord struct {
	scheme     uint32
	registered int64
	// tenant is whose record it is. Another tenant's is never opened.
	tenant [inventoryTagSize]byte
	// login is which of the tenant's logins registered it.
	login   [inventoryTagSize]byte
	content [inventoryTagSize]byte
	// head is the record's head as it was before it was sealed.
	head []byte
	// raw is the whole record as it is in the file, its length included.
	raw []byte
}

func (s InventoryStore) keyring() PrivateKeyStore {
	if s.Keyring == nil {
		return OSKeyring{}
	}
	return s.Keyring
}

func (s InventoryStore) directory() (string, error) {
	if s.Directory != "" {
		return filepath.Clean(s.Directory), nil
	}
	return DefaultCADirectory()
}

func (s InventoryStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// KeystoreAvailable reports whether the system keystore answers at all,
// without reading the inventory key.
func (s InventoryStore) KeystoreAvailable() bool {
	return CAStore{Keyring: s.Keyring}.KeystoreAvailable()
}

// memoryInventory is an inventory that stores nothing: today's behaviour
// before there was a store, with a master that goes with the process.
func memoryInventory(reason string) (*Inventory, error) {
	master := make([]byte, censor.KeySize)
	if _, err := rand.Read(master); err != nil {
		return nil, err
	}
	defer clear(master)
	// The master is this process's alone, so whatever names the tenant will do.
	inv, err := newInventory(InventoryStore{}, "", [inventoryKeyIDSize]byte{}, master, "memory")
	if err != nil {
		return nil, err
	}
	inv.status.Reason = reason
	return inv, nil
}

// MemoryInventory is the inventory of a proxy started without a store.
func MemoryInventory() (*Inventory, error) {
	return memoryInventory(InventoryReasonNotConfigured)
}

// Principal is a login's place in the inventory, the same from every proxy
// while the master lasts: a proxy makes its own session's, and no client's.
func (inv *Inventory) Principal(login string) (InventoryPrincipal, error) {
	var id [inventoryTagSize]byte
	if login == "" {
		// An empty login gets one this process alone holds.
		if _, err := rand.Read(id[:]); err != nil {
			return InventoryPrincipal{}, err
		}
	} else {
		id = inv.tag("principal", []byte(login))
	}
	return inv.principal(id)
}

// principal expands the confirming key of a principal id. Only the id goes
// in, so a stored record's principal is rebuilt without knowing its login.
func (inv *Inventory) principal(id [inventoryTagSize]byte) (InventoryPrincipal, error) {
	inv.principalMu.Lock()
	defer inv.principalMu.Unlock()
	if key, ok := inv.principals[id]; ok {
		return InventoryPrincipal{id: id, key: key}, nil
	}
	confirm, err := hkdf.Expand(sha256.New, inv.confirmRoot, inventoryConfirmLabel+":"+hex.EncodeToString(id[:]), censor.KeySize)
	if err != nil {
		return InventoryPrincipal{}, err
	}
	defer clear(confirm)
	key, err := inv.lookup.WithConfirm(confirm)
	if err != nil {
		return InventoryPrincipal{}, err
	}
	inv.principals[id] = key
	return InventoryPrincipal{id: id, key: key}, nil
}

// Status reports how the inventory is kept and what opening it found. It asks
// the keystore, at most once a second, whether the key is still this one.
func (inv *Inventory) Status() InventoryStatus {
	inv.mu.Lock()
	status := inv.status
	due := status.Durable && time.Since(inv.keyChecked) >= inventoryKeyCheckEvery
	if due {
		inv.keyChecked = time.Now()
	}
	inv.mu.Unlock()
	if due {
		if current, err := inv.keyCurrent(); err == nil && !current {
			inv.demote(InventoryReasonKeyReplaced)
			status.Durable, status.Reason = false, InventoryReasonKeyReplaced
		}
	}
	return status
}

// demote stops the inventory writing to the store, for the life of the
// process, and records why.
func (inv *Inventory) demote(reason string) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if inv.status.Durable || inv.status.Reason == "" {
		inv.status.Durable, inv.status.Reason = false, reason
	}
}

// keyCurrent asks the keystore whether it still names this process's key. An
// error is a keystore that did not answer, which says nothing either way.
func (inv *Inventory) keyCurrent() (bool, error) {
	id, raw, err := inv.store.storedKey()
	clear(raw)
	if errors.Is(err, errNoInventoryKey) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return id == inv.keyID, nil
}

// Open loads the inventory, making the key on first use, and returns what
// the file held that this build can match, oldest registration first. It
// fails only when no key can be made at all. Whatever is wrong with the
// keystore, the directory or the file leaves an inventory that works from
// memory, or with what could be read, and says so in its status.
func (s InventoryStore) Open() (*Inventory, []StoredEntries, error) {
	// A login that names no tenant shares with nobody: nothing is derived
	// from the user's master for it, and nothing is stored.
	if s.Tenant == "" {
		inv, err := memoryInventory(InventoryReasonNoTenant)
		return inv, nil, err
	}
	// A machine with no keystore keeps nothing: no key on disk, no file.
	if !s.KeystoreAvailable() {
		inv, err := memoryInventory(InventoryReasonNoKeystore)
		return inv, nil, err
	}
	directory, err := s.directory()
	if err != nil {
		inv, err := memoryInventory(InventoryReasonUnusable)
		return inv, nil, err
	}
	if os.MkdirAll(directory, 0o700) != nil || os.Chmod(directory, 0o700) != nil {
		inv, err := memoryInventory(InventoryReasonUnusable)
		return inv, nil, err
	}
	// Asked with no lock held: a keystore may wait on a person. A key is made
	// only on "there is none"; any other answer may hide a key in use.
	id, raw, err := s.storedKey()
	switch {
	case errors.Is(err, errNoInventoryKey):
		if _, raw, err = s.newKey(); err != nil {
			inv, err := memoryInventory(InventoryReasonNoKeystore)
			return inv, nil, err
		}
		clear(raw)
		// Proxies that start together may each make a key, and no lock is
		// held to stop them: each takes the one the keystore settles on.
		time.Sleep(inventoryKeySettle)
		if id, raw, err = s.storedKey(); err != nil {
			inv, err := memoryInventory(InventoryReasonKeyUnreadable)
			return inv, nil, err
		}
	case err != nil:
		inv, err := memoryInventory(InventoryReasonKeyUnreadable)
		return inv, nil, err
	}
	inv, err := newInventory(s, directory, id, raw, s.Tenant)
	clear(raw)
	if err != nil {
		inv, err := memoryInventory(InventoryReasonKeyUnreadable)
		return inv, nil, err
	}
	loaded, reason := inv.load(false)
	if reason == inventoryForeign {
		// The file is under another key, as when two first starts each made
		// one: only the proxy whose key the keystore kept may replace it.
		current, err := inv.keyCurrent()
		switch {
		case err != nil:
			reason = InventoryReasonKeyUnreadable
		case !current:
			reason = InventoryReasonKeyReplaced
		default:
			loaded, reason = inv.load(true)
		}
	}
	inv.status.Durable, inv.status.Reason = reason == "", reason
	return inv, loaded, nil
}

// inventoryForeign is load's and store's answer for a file that is missing
// or under another key, when they were not told the keystore was asked.
const inventoryForeign = "foreign"

// load reads the file under the store's lock, drops what cannot be used and
// returns the rest. It answers with why nothing may be stored, or "".
func (inv *Inventory) load(keyConfirmed bool) (loaded []StoredEntries, reason string) {
	unlock, err := lockInventory(inv.directory)
	if err != nil {
		return nil, lockFailure(err)
	}
	defer unlock()
	file := inv.read()
	switch {
	case file.newer:
		return nil, InventoryReasonNewerFormat
	case file.unreadable:
		return nil, InventoryReasonUnreadable
	case file.foreign && !keyConfirmed:
		return nil, inventoryForeign
	}
	sweepInventoryTemporaries(inv.directory)
	now := inv.store.now()
	var kept []inventoryRecord
	inv.status.Damaged, inv.status.OtherKey = file.damaged, file.otherKey
	for _, record := range file.records {
		// Another tenant's record is carried over unopened, while it lasts.
		if record.tenant != inv.tenant {
			if now.Unix()-record.registered <= int64(InventoryEntryLifetime/time.Second) {
				inv.status.OtherTenant++
				kept = append(kept, record)
			}
			continue
		}
		switch stored, verdict := inv.open(record, now); verdict {
		case recordExpired:
			inv.status.Expired++
		case recordDamaged:
			inv.status.Damaged++
		case recordOtherScheme:
			inv.status.OtherScheme++
			kept = append(kept, record)
		default:
			loaded = append(loaded, stored)
			kept = append(kept, record)
			inv.known[record.content] = record.registered
		}
	}
	inv.status.Loaded = len(loaded)
	// What was dropped goes from the file now, and a first start leaves the
	// file a later write expects to find.
	if !file.present || len(kept) != len(file.records) || file.damaged > 0 || file.otherKey > 0 {
		if err := inv.write(kept); err != nil {
			return loaded, InventoryReasonUnusable
		}
	}
	inv.seen, _ = os.Stat(inv.path())
	return loaded, ""
}

// errInventoryBusy is a lock another process held past inventoryLockWait.
var errInventoryBusy = errors.New("the leak protection inventory is in use by another process")

// lockInventory takes the store's lock within inventoryLockWait. The lock
// file is never removed, and no keystore call is made while it is held.
func lockInventory(directory string) (func(), error) {
	path := filepath.Join(directory, inventoryLockName)
	for deadline := time.Now().Add(inventoryLockWait); ; time.Sleep(2 * time.Millisecond) {
		unlock, busy, err := tryLockFile(path)
		if err != nil {
			return nil, err
		}
		if !busy {
			return unlock, nil
		}
		if time.Now().After(deadline) {
			return nil, errInventoryBusy
		}
	}
}

func lockFailure(err error) string {
	if errors.Is(err, errInventoryBusy) {
		return InventoryReasonBusy
	}
	return InventoryReasonUnusable
}

// newInventory derives one tenant's keys from the master, each under its
// own label. Neither the master nor anything of another tenant is kept.
func newInventory(s InventoryStore, directory string, id [inventoryKeyIDSize]byte, master []byte, tenant string) (*Inventory, error) {
	if len(master) != censor.KeySize || tenant == "" {
		return nil, errors.New("the inventory master key or tenant is not valid")
	}
	// The file key seals record heads, whosever the record is.
	fileKey, err := hkdf.Key(sha256.New, master, nil, inventoryFileLabel, censor.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(fileKey)
	fileSeal, err := newInventorySeal(fileKey)
	if err != nil {
		return nil, err
	}
	// The tenant's tag is keyed, so the file names no host or organisation,
	// and the tenant's root is derived from the master under the tag.
	tagging, err := hkdf.Key(sha256.New, master, nil, inventoryTenantLabel+"-tag", censor.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(tagging)
	named := hmac.New(sha256.New, tagging)
	named.Write([]byte(tenant))
	var tag [inventoryTagSize]byte
	copy(tag[:], named.Sum(nil))
	root, err := hkdf.Key(sha256.New, master, nil, inventoryTenantLabel+":"+hex.EncodeToString(tag[:]), censor.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(root)
	derived := make(map[string][]byte, 4)
	for _, label := range []string{inventoryLookupLabel, inventoryConfirmLabel, inventorySealLabel, inventoryTagLabel} {
		key, err := hkdf.Expand(sha256.New, root, label, censor.KeySize)
		if err != nil {
			return nil, err
		}
		derived[label] = key
	}
	lookup, err := censor.LookupKeyFromBytes(derived[inventoryLookupLabel])
	if err != nil {
		return nil, err
	}
	seal, err := newInventorySeal(derived[inventorySealLabel])
	if err != nil {
		return nil, err
	}
	inv := &Inventory{
		store: s, directory: directory, lookup: lookup, confirmRoot: derived[inventoryConfirmLabel], keyID: id, tenant: tag, seal: seal, file: fileSeal,
		principals: map[[inventoryTagSize]byte]*censor.Key{},
		known:      map[[inventoryTagSize]byte]int64{},
	}
	copy(inv.tagKey[:], derived[inventoryTagLabel])
	clear(derived[inventoryLookupLabel])
	clear(derived[inventorySealLabel])
	clear(derived[inventoryTagLabel])
	return inv, nil
}

func newInventorySeal(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// errNoInventoryKey is the keystore saying it holds no inventory key: the
// one answer after which a key is made.
var errNoInventoryKey = errors.New("no leak protection inventory key is stored")

// storedKey reads the master and its id from the keystore.
func (s InventoryStore) storedKey() (id [inventoryKeyIDSize]byte, raw []byte, err error) {
	value, err := s.keyring().Get(inventoryKeyringService, inventoryKeyringUser)
	if errors.Is(err, gokeyring.ErrNotFound) {
		return id, nil, errNoInventoryKey
	}
	if err != nil {
		return id, nil, err
	}
	parts := strings.Split(value, ":")
	if len(parts) != 3 || parts[0] != "v1" {
		return id, nil, errors.New("the stored inventory key is not valid")
	}
	decodedID, err := hex.DecodeString(parts[1])
	if err != nil || len(decodedID) != inventoryKeyIDSize {
		return id, nil, errors.New("the stored inventory key is not valid")
	}
	raw, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != censor.KeySize {
		return id, nil, errors.New("the stored inventory key is not valid")
	}
	copy(id[:], decodedID)
	return id, raw, nil
}

// newKey makes a master with a new id and stores it.
func (s InventoryStore) newKey() (id [inventoryKeyIDSize]byte, raw []byte, err error) {
	raw = make([]byte, censor.KeySize)
	if _, err := rand.Read(raw); err != nil {
		return id, nil, err
	}
	if _, err := rand.Read(id[:]); err != nil {
		return id, nil, err
	}
	value := "v1:" + hex.EncodeToString(id[:]) + ":" + base64.StdEncoding.EncodeToString(raw)
	if err := s.keyring().Set(inventoryKeyringService, inventoryKeyringUser, value); err != nil {
		return id, nil, err
	}
	return id, raw, nil
}

// ReplaceKey puts a new master, with a new id, in the keystore. Entries stored
// under the one before it are never matched again: the next proxy to start
// counts them and drops them. A proxy still running keeps what it holds in
// memory and stops writing to the store. Purge uses it where a key cannot be
// deleted; nothing else does, and there is no command for it.
func (s InventoryStore) ReplaceKey() error {
	if !s.KeystoreAvailable() {
		return nil
	}
	_, raw, err := s.newKey()
	clear(raw)
	return err
}

// Remove deletes the stored entries and what was written beside them, and
// leaves the key. A missing file or directory is not an error. The lock file
// stays: a process waiting on it would otherwise hold a lock no one else sees.
func (s InventoryStore) Remove() error {
	directory, err := s.directory()
	if err != nil {
		return err
	}
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() {
		return nil
	}
	unlock, err := lockInventory(directory)
	if err != nil {
		return fmt.Errorf("lock leak protection inventory: %w", err)
	}
	defer unlock()
	sweepInventoryTemporaries(directory)
	if err := os.Remove(filepath.Join(directory, inventoryFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Forget removes what is stored for logins of the store's tenant, or for the
// whole tenant, as a logout does. It makes no key or file and touches no other.
func (s InventoryStore) Forget(logins []string, wholeTenant bool) error {
	if s.Tenant == "" {
		return nil
	}
	directory, err := s.directory()
	if err != nil {
		return err
	}
	// With no file there is nothing to remove, and the keystore is not asked.
	if _, err := os.Lstat(filepath.Join(directory, inventoryFileName)); err != nil || !s.KeystoreAvailable() {
		return nil
	}
	id, raw, err := s.storedKey()
	if errors.Is(err, errNoInventoryKey) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the leak protection inventory key: %w", err)
	}
	inv, err := newInventory(s, directory, id, raw, s.Tenant)
	clear(raw)
	if err != nil {
		return err
	}
	gone := map[[inventoryTagSize]byte]bool{}
	for _, login := range logins {
		if login != "" {
			gone[inv.loginTag(inv.tag("principal", []byte(login)))] = true
		}
	}
	unlock, err := lockInventory(directory)
	if err != nil {
		return fmt.Errorf("lock leak protection inventory: %w", err)
	}
	defer unlock()
	file := inv.read()
	if !file.present {
		// No file, or one this key cannot read: nothing of this tenant's to remove.
		return nil
	}
	kept := file.records[:0:0]
	for _, record := range file.records {
		if record.tenant != inv.tenant || !(wholeTenant || gone[record.login]) {
			kept = append(kept, record)
		}
	}
	if len(kept) == len(file.records) {
		return nil
	}
	return inv.write(kept)
}

// DeleteStoredInventoryKey removes the inventory key from the system
// keystore, as DeleteStoredCAKey removes the CA key: for a purge of all local
// data, and when Phase AI is disabled. A missing key or keystore is not an
// error.
func DeleteStoredInventoryKey() error {
	err := gokeyring.Delete(inventoryKeyringService, inventoryKeyringUser)
	if err == nil || errors.Is(err, gokeyring.ErrNotFound) {
		return nil
	}
	if !(CAStore{}).KeystoreAvailable() {
		return nil
	}
	return err
}

// Purge removes the stored inventory: the key from the keystore, then the
// entries. It is what phase ai disable does. A key the keystore cannot
// delete is replaced, so that nothing stored under it is matched again.
//
// The key goes first: a proxy registering meanwhile writes before the file
// is removed, or finds the file gone and its key with it, and writes nothing.
func (s InventoryStore) Purge() error {
	return errors.Join(s.deleteKey(), s.Remove())
}

func (s InventoryStore) deleteKey() error {
	_, err := s.keyring().Get(inventoryKeyringService, inventoryKeyringUser)
	if err != nil {
		// No key, or no keystore to hold one.
		return nil
	}
	if deleter, ok := s.keyring().(interface {
		Delete(service, user string) error
	}); ok {
		if err := deleter.Delete(inventoryKeyringService, inventoryKeyringUser); err == nil || errors.Is(err, gokeyring.ErrNotFound) {
			return nil
		}
	}
	// A key that cannot be deleted is replaced: what is stored under it is
	// then another key's, to every proxy.
	_, raw, err := s.newKey()
	clear(raw)
	if err != nil {
		return fmt.Errorf("remove the leak protection inventory key: %w", err)
	}
	return nil
}

// sweepInventoryTemporaries removes what an interrupted write left. Every
// writer holds the inventory lock, so under it any such file is stale.
func sweepInventoryTemporaries(directory string) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), inventoryTempPrefix) {
			_ = os.Remove(filepath.Join(directory, entry.Name()))
		}
	}
}

func (inv *Inventory) path() string { return filepath.Join(inv.directory, inventoryFileName) }

func (inv *Inventory) header() []byte {
	header := make([]byte, 0, inventoryHeaderSize)
	header = append(header, inventoryMagic...)
	header = binary.BigEndian.AppendUint32(header, InventoryStoreFormat)
	return append(header, inv.keyID[:]...)
}

type inventoryFile struct {
	// present reports a file this build may replace was read: one of this
	// format, under this key.
	present bool
	// newer reports a file of a later store format, which is left alone.
	newer    bool
	records  []inventoryRecord
	damaged  int
	otherKey int
	// foreign reports the file was written under another key.
	foreign bool
	// unreadable reports a file that exists and could not be opened or
	// understood. It is never written over.
	unreadable bool
}

// read parses the file without trusting it: a file that is not a regular
// owner-only file of this user, or that is too large, is not read at all,
// and parsing stops at the first record that does not fit. Called with the
// inventory lock held.
func (inv *Inventory) read() inventoryFile {
	var file inventoryFile
	data, err := readInventoryFile(inv.path(), maxInventoryFileBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return file
	case errors.Is(err, errNewerInventory):
		file.newer = true
		return file
	case err != nil:
		file.unreadable = true
		return file
	}
	file.foreign = !bytes.Equal(data[len(inventoryMagic)+4:inventoryHeaderSize], inv.keyID[:])
	file.present = !file.foreign
	rest := data[inventoryHeaderSize:]
	seen := map[[inventoryTagSize]byte]struct{}{}
	for len(rest) > 0 {
		if len(file.records)+file.otherKey >= maxInventoryRecords {
			file.damaged++
			break
		}
		if len(rest) < 4 {
			file.damaged++
			break
		}
		length := int(binary.BigEndian.Uint32(rest))
		if length < inventoryRecordFixed+inventorySealOverhead+inventoryBodyFixed || length > maxInventoryRecordBytes || length > len(rest)-4 {
			file.damaged++
			break
		}
		raw := rest[:4+length]
		rest = rest[4+length:]
		if file.foreign {
			file.otherKey++
			continue
		}
		// The head says whose the record is; one that does not open is no
		// record of this key's, whatever its length said.
		sealed := raw[4+inventoryNonceSize : 4+inventoryNonceSize+inventoryHeadSize+inventorySealOverhead]
		head, err := inv.file.Open(nil, raw[4:4+inventoryNonceSize], sealed, inv.header())
		if err != nil {
			file.damaged++
			continue
		}
		record := inventoryRecord{raw: raw, head: head, scheme: binary.BigEndian.Uint32(head), registered: int64(binary.BigEndian.Uint64(head[4:]))}
		copy(record.tenant[:], head[12:])
		copy(record.login[:], head[12+inventoryTagSize:])
		copy(record.content[:], head[12+2*inventoryTagSize:])
		// No writer stores the same entries twice.
		if _, twice := seen[record.content]; twice {
			file.damaged++
			continue
		}
		seen[record.content] = struct{}{}
		file.records = append(file.records, record)
	}
	return file
}

type recordVerdict int

const (
	recordLoaded recordVerdict = iota
	recordExpired
	recordDamaged
	recordOtherScheme
)

// open authenticates a record and, when this build matches its scheme, reads
// its entries. Nothing in a record is used before the seal has confirmed it
// was written under this key, and the entries are validated as a
// registration's are.
func (inv *Inventory) open(record inventoryRecord, now time.Time) (StoredEntries, recordVerdict) {
	if now.Unix()-record.registered > int64(InventoryEntryLifetime/time.Second) {
		return StoredEntries{}, recordExpired
	}
	if record.registered-now.Unix() > int64(inventoryClockSlack/time.Second) {
		return StoredEntries{}, recordDamaged
	}
	fixed := 4 + inventoryRecordFixed
	nonce := record.raw[fixed-inventoryNonceSize : fixed]
	body, err := inv.seal.Open(nil, nonce, record.raw[fixed:], append(inv.header(), record.head...))
	if err != nil || len(body) < inventoryBodyFixed {
		return StoredEntries{}, recordDamaged
	}
	wire := body[inventoryBodyFixed:]
	if record.scheme > 1<<30 || !censor.SchemeSupported(int(record.scheme)) {
		return StoredEntries{}, recordOtherScheme
	}
	// No build stores a scheme whose entries carry whole rolling hashes.
	if !censor.SchemeStorable(int(record.scheme)) {
		return StoredEntries{}, recordDamaged
	}
	entries, err := censor.ParseEntries(wire)
	if err != nil || entries.Version != int(record.scheme) || !entries.Protected() ||
		inv.loginTag([inventoryTagSize]byte(body[1:inventoryBodyFixed])) != record.login || inv.tag("content", body[1:inventoryBodyFixed], wire) != record.content {
		return StoredEntries{}, recordDamaged
	}
	// The record says whose confirming key its hashes were made under.
	principal, err := inv.principal([inventoryTagSize]byte(body[1:inventoryBodyFixed]))
	if err != nil {
		return StoredEntries{}, recordDamaged
	}
	return StoredEntries{Entries: entries, KeyNamed: body[0]&1 != 0, Principal: principal}, recordLoaded
}

func (inv *Inventory) tag(label string, parts ...[]byte) [inventoryTagSize]byte {
	mac := hmac.New(sha256.New, inv.tagKey[:])
	mac.Write([]byte(label))
	for _, part := range parts {
		mac.Write([]byte{0})
		mac.Write(part)
	}
	var out [inventoryTagSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// loginTag is what a principal's records carry in their head: the same for
// every record of one login, and nothing two tenants or two logins share.
func (inv *Inventory) loginTag(principal [inventoryTagSize]byte) [inventoryTagSize]byte {
	return inv.tag("login", principal[:])
}

// sealRecord builds the record for one registered value.
func (inv *Inventory) sealRecord(stored StoredEntries, wire []byte, now time.Time) (inventoryRecord, error) {
	body := make([]byte, 0, inventoryBodyFixed+len(wire))
	if stored.KeyNamed {
		body = append(body, 1)
	} else {
		body = append(body, 0)
	}
	body = append(body, stored.Principal.id[:]...)
	body = append(body, wire...)
	return inv.sealBody(inventoryRecord{
		scheme: uint32(stored.Entries.Version), registered: now.Unix(), tenant: inv.tenant,
		login: inv.loginTag(stored.Principal.id), content: inv.contentTag(stored, wire),
	}, body)
}

// contentTag is the same for the same entries of the same principal.
func (inv *Inventory) contentTag(stored StoredEntries, wire []byte) [inventoryTagSize]byte {
	return inv.tag("content", stored.Principal.id[:], wire)
}

// sealBody seals a record: its head under the file key, and its body under
// the tenant's with the head as additional data.
func (inv *Inventory) sealBody(record inventoryRecord, body []byte) (inventoryRecord, error) {
	length := inventoryRecordFixed + len(body) + inventorySealOverhead
	if length > maxInventoryRecordBytes {
		return record, errors.New("the entries are too large to store")
	}
	head := make([]byte, 0, inventoryHeadSize)
	head = binary.BigEndian.AppendUint32(head, record.scheme)
	head = binary.BigEndian.AppendUint64(head, uint64(record.registered))
	head = append(head, record.tenant[:]...)
	head = append(head, record.login[:]...)
	head = append(head, record.content[:]...)
	nonces := make([]byte, 2*inventoryNonceSize)
	if _, err := rand.Read(nonces); err != nil {
		return record, err
	}
	raw := make([]byte, 0, 4+length)
	raw = binary.BigEndian.AppendUint32(raw, uint32(length))
	raw = append(raw, nonces[:inventoryNonceSize]...)
	raw = inv.file.Seal(raw, nonces[:inventoryNonceSize], head, inv.header())
	raw = append(raw, nonces[inventoryNonceSize:]...)
	record.head = head
	record.raw = inv.seal.Seal(raw, nonces[inventoryNonceSize:], body, append(inv.header(), head...))
	return record, nil
}

// Add stores registered values, so that a proxy started later knows them. It
// never fails a registration: the values are in the running proxy's index
// either way, and a store that cannot be written is reported by Status.
//
// The file is read again under the lock and written whole, so what another
// proxy stored since is kept. A value stored already only has its time
// brought forward, and not more than once a day; nothing else is replaced.
func (inv *Inventory) Add(batch []StoredEntries) {
	inv.adding.Lock()
	defer inv.adding.Unlock()
	now := inv.store.now()
	fresh := inv.fresh(batch, now)
	if len(fresh) == 0 {
		return
	}
	created, reason := inv.storeFresh(fresh, now, false)
	if reason == inventoryForeign {
		// A file gone or under another key means the key was replaced, unless
		// the keystore still names this one: asked with the lock released.
		current, err := inv.keyCurrent()
		if err != nil {
			return
		}
		if !current {
			inv.demote(InventoryReasonKeyReplaced)
			return
		}
		created, reason = inv.storeFresh(fresh, now, true)
	}
	if created && reason == "" {
		// A purge that ran between the question and the write removed the
		// file first: what was just written is taken back.
		if current, err := inv.keyCurrent(); err == nil && !current {
			inv.withdraw()
			reason = InventoryReasonKeyReplaced
		}
	}
	if reason != "" {
		inv.demote(reason)
	}
}

type pendingEntries struct {
	stored  StoredEntries
	wire    []byte
	content [inventoryTagSize]byte
}

// fresh is what of a batch is not stored already, or was last stored long
// enough ago to be worth a write. A stored inventory only.
func (inv *Inventory) fresh(batch []StoredEntries, now time.Time) []pendingEntries {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if !inv.status.Durable {
		return nil
	}
	// What was stored is forgotten once the file is gone or another's: a
	// value whose record went with it is stored again.
	if info, err := os.Stat(inv.path()); err != nil || inv.seen == nil || !os.SameFile(info, inv.seen) {
		clear(inv.known)
	}
	var fresh []pendingEntries
	for _, stored := range batch {
		// A value too short or plain to protect has nothing to store, and
		// entries that carry whole rolling hashes never reach the disk.
		if !stored.Entries.Protected() || !censor.SchemeStorable(stored.Entries.Version) || stored.Principal.key == nil {
			continue
		}
		wire, err := stored.Entries.Marshal()
		if err != nil {
			continue
		}
		content := inv.contentTag(stored, wire)
		if at, ok := inv.known[content]; ok && now.Unix()-at < int64(inventoryRefreshAfter/time.Second) && at <= now.Unix() {
			continue
		}
		fresh = append(fresh, pendingEntries{stored: stored, wire: wire, content: content})
	}
	return fresh
}

// storeFresh merges fresh into the file under the store's lock, and answers
// whether it made the file and why the store can no longer be written.
func (inv *Inventory) storeFresh(fresh []pendingEntries, now time.Time, keyConfirmed bool) (created bool, reason string) {
	unlock, err := lockInventory(inv.directory)
	if err != nil {
		return false, lockFailure(err)
	}
	defer unlock()
	file := inv.read()
	switch {
	case file.newer:
		return false, InventoryReasonNewerFormat
	case file.unreadable:
		return false, InventoryReasonUnreadable
	case !file.present && !keyConfirmed:
		return false, inventoryForeign
	}
	records := file.records[:0:0]
	for _, record := range file.records {
		if now.Unix()-record.registered <= int64(InventoryEntryLifetime/time.Second) {
			records = append(records, record)
		}
	}
	held := make(map[[inventoryTagSize]byte]int64, len(records))
	for _, record := range records {
		held[record.content] = record.registered
	}
	changed := len(records) != len(file.records) || !file.present
	writing := map[[inventoryTagSize]byte]bool{}
	for _, entry := range fresh {
		// Another proxy may have stored the same entries since.
		if at, ok := held[entry.content]; ok && now.Unix()-at < int64(inventoryRefreshAfter/time.Second) && at <= now.Unix() {
			continue
		}
		record, err := inv.sealRecord(entry.stored, entry.wire, now)
		if err != nil {
			continue
		}
		changed = true
		writing[record.login] = true
		// Only the same entries, registered again, make way: another value
		// under the same placeholder, in any scheme, stays.
		kept := records[:0]
		for _, existing := range records {
			if existing.content != record.content {
				kept = append(kept, existing)
			}
		}
		records = append(kept, record)
	}
	if changed {
		records = inv.bound(records, writing)
		if err := inv.write(records); err != nil {
			return false, InventoryReasonUnusable
		}
	}
	// What the file no longer holds is forgotten, so it can be stored again.
	inv.mu.Lock()
	inv.known = make(map[[inventoryTagSize]byte]int64, len(records))
	for _, record := range records {
		inv.known[record.content] = record.registered
	}
	inv.seen, _ = os.Stat(inv.path())
	inv.mu.Unlock()
	return !file.present, ""
}

// withdraw removes the file if it is still this key's.
func (inv *Inventory) withdraw() {
	unlock, err := lockInventory(inv.directory)
	if err != nil {
		return
	}
	defer unlock()
	if inv.read().present {
		_ = os.Remove(inv.path())
	}
}

// bound keeps what is stored within inventoryBounds, oldest first. Only the
// logins that are writing lose records: their own oldest, then their newest.
func (inv *Inventory) bound(records []inventoryRecord, writing map[[inventoryTagSize]byte]bool) []inventoryRecord {
	sort.SliceStable(records, func(i, j int) bool { return records[i].registered < records[j].registered })
	bounds := inventoryBounds
	file, tenant := storeBound{bytes: inventoryHeaderSize}, storeBound{}
	logins := map[[inventoryTagSize]byte]*storeBound{}
	others := 0
	for _, record := range records {
		file.records, file.bytes = file.records+1, file.bytes+len(record.raw)
		if record.tenant != inv.tenant {
			continue
		}
		tenant.records, tenant.bytes = tenant.records+1, tenant.bytes+len(record.raw)
		held := logins[record.login]
		if held == nil {
			held = &storeBound{}
			logins[record.login] = held
			if !writing[record.login] {
				others++
			}
		}
		held.records, held.bytes = held.records+1, held.bytes+len(record.raw)
	}
	// A tenant stores for so many logins: one more that is writing now gets
	// no room, the ones already there keep theirs.
	room := bounds.tenantLogins - others
	admitted := map[[inventoryTagSize]byte]bool{}
	for at := len(records) - 1; at >= 0; at-- {
		if login := records[at].login; records[at].tenant == inv.tenant && writing[login] && !admitted[login] && room > 0 {
			admitted[login] = true
			room--
		}
	}
	past := func(held, bound storeBound) bool { return held.records > bound.records || held.bytes > bound.bytes }
	kept := records[:0]
	for _, record := range records {
		held := logins[record.login]
		if record.tenant == inv.tenant && writing[record.login] &&
			(!admitted[record.login] || past(*held, bounds.login) || past(tenant, bounds.tenant) || past(file, bounds.file)) {
			size := len(record.raw)
			held.records, held.bytes = held.records-1, held.bytes-size
			tenant.records, tenant.bytes = tenant.records-1, tenant.bytes-size
			file.records, file.bytes = file.records-1, file.bytes-size
			continue
		}
		kept = append(kept, record)
	}
	return kept
}

// write replaces the file: a temporary file beside it, synced, then renamed
// over it, so a reader sees the old file or the new one and never a part.
// Called with the inventory lock held.
func (inv *Inventory) write(records []inventoryRecord) error {
	temp, err := os.CreateTemp(inv.directory, inventoryTempPrefix+"*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	err = temp.Chmod(0o600)
	if err == nil {
		_, err = temp.Write(inv.header())
	}
	for i := 0; err == nil && i < len(records); i++ {
		_, err = temp.Write(records[i].raw)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tempName, inv.path())
}

// errNewerInventory is a file of a later store format.
var errNewerInventory = errors.New("the leak protection inventory was written by a newer version of Phase")

// readInventoryFile reads the file as the runtime state is read: only a
// regular file that is not a symlink, is this user's and is closed to
// everyone else, and no more of it than limit. The header is read first: a
// file of a later format is reported as that whatever else is true of it,
// since nothing here knows that format's bounds, and a file that does not
// begin as an inventory does is refused.
func readInventoryFile(path string, limit int64) ([]byte, error) {
	file, err := openInventoryFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	header := make([]byte, inventoryHeaderSize)
	if _, err := io.ReadFull(file, header); err != nil || string(header[:len(inventoryMagic)]) != inventoryMagic {
		return nil, errors.New("the file is not a leak protection inventory")
	}
	switch format := binary.BigEndian.Uint32(header[len(inventoryMagic):]); {
	case format > InventoryStoreFormat:
		return nil, errNewerInventory
	case format < 1:
		return nil, errors.New("the file is not a leak protection inventory")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, errors.New("the leak protection inventory is too large")
	}
	rest, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(header)+len(rest)) > limit {
		return nil, errors.New("the leak protection inventory is too large")
	}
	return append(header, rest...), nil
}
