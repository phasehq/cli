package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

// The leak protection inventory is kept in two places, so that a proxy that
// starts again still knows the values registered with the one before it:
//
//   - the key every hash is keyed with, in the system keystore beside the CA
//     key, one per user, made on first use and never written to disk;
//   - the entries, in one owner-only file in the Phase AI directory.
//
// The file holds what censor.Entries hold (keyed hashes, lengths, weak flags,
// a placeholder's type and id) and whether an id is a key name, each record
// sealed under a key derived from the inventory key. Without the keystore the
// file is opaque. With both, a guessed chunk of a value can be confirmed: see
// the Limits in package censor.
//
// File layout, store format 1 (integers big-endian):
//
//	magic "PHLKINV1" | format uint32 | key id [8]
//	then records: length uint32 | scheme uint32 | registered int64 (Unix seconds)
//	              | owner tag [16] | content tag [16] | nonce [12] | sealed body
//
// The sealed body is one flag byte (1: the id is a key name) and the entries
// as censor.Entries.Marshal writes them, under AES-256-GCM with the file
// header and the record's fields before the nonce as additional data. The
// tags are keyed too: the owner tag is the same for every record of one
// placeholder, and the content tag for the same entries.
//
// Two numbers version what is stored. The store format is the layout above:
// a build reads every format up to its own, and leaves a file of a newer
// format alone, running from memory. The scheme of a record is the matching
// scheme of its entries (censor.EntriesVersion): a record whose scheme this
// build does not match is kept as it is, for the build that does, and
// counted; entries registered under a newer scheme replace the records an
// older scheme left for the same placeholder.
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
	// inventoryRecordFixed is a record after its length and before its body.
	inventoryRecordFixed = 4 + 8 + 2*inventoryTagSize + inventoryNonceSize

	// inventoryRefreshAfter is how stale a stored entry's time may get before
	// a registration of the same value writes the file again. Registrations
	// repeat with every command, and most of them change nothing.
	inventoryRefreshAfter = 24 * time.Hour
	// inventoryClockSlack is how far ahead of this machine's clock a record's
	// time may be before the record is taken for damaged.
	inventoryClockSlack = 24 * time.Hour

	// maxInventoryFileBytes and maxInventoryRecords bound the file. Past
	// either, the entries registered longest ago go first.
	maxInventoryFileBytes = 64 << 20
	maxInventoryRecords   = 1 << 16
	// maxInventoryRecordBytes bounds one record: a registration is at most
	// 4 MiB on the wire.
	maxInventoryRecordBytes = 8 << 20
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
	// InventoryReasonNotConfigured: the proxy was started without a store.
	InventoryReasonNotConfigured = "not_configured"
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
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// StoredEntries is one registered value: its entries, and whether its id is a
// secret's key name.
type StoredEntries struct {
	Entries  *censor.Entries
	KeyNamed bool
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
	// Damaged counts stored entries that could not be read or validated.
	Damaged int
	// Expired counts stored entries dropped for their age when the store was
	// opened.
	Expired int
}

// Inventory is an opened store: the key, and the file being added to. Each
// proxy process opens one.
type Inventory struct {
	store     InventoryStore
	directory string
	key       *censor.Key
	keyID     [inventoryKeyIDSize]byte
	seal      cipher.AEAD
	tagKey    [32]byte

	mu     sync.Mutex
	status InventoryStatus
	// known is when each entry this process has seen stored was registered,
	// by content tag, so a repeated registration costs no file access.
	known map[[inventoryTagSize]byte]int64
}

type inventoryRecord struct {
	scheme     uint32
	registered int64
	owner      [inventoryTagSize]byte
	content    [inventoryTagSize]byte
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
// before there was a store, with a key that goes with the process.
func memoryInventory(reason string) (*Inventory, error) {
	key, err := censor.NewKey()
	if err != nil {
		return nil, err
	}
	return &Inventory{key: key, status: InventoryStatus{Reason: reason}}, nil
}

// MemoryInventory is the inventory of a proxy started without a store.
func MemoryInventory() (*Inventory, error) {
	return memoryInventory(InventoryReasonNotConfigured)
}

// Key is the key the inventory's hashes are keyed with.
func (inv *Inventory) Key() *censor.Key { return inv.key }

// Status reports how the inventory is kept and what opening it found.
func (inv *Inventory) Status() InventoryStatus {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return inv.status
}

// Open loads the inventory, making the key on first use, and returns what
// the file held that this build can match, oldest registration first. It
// fails only when no key can be made at all. Whatever is wrong with the
// keystore, the directory or the file leaves an inventory that works from
// memory, or with what could be read, and says so in its status.
func (s InventoryStore) Open() (*Inventory, []StoredEntries, error) {
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
	// Every proxy of this user opens and writes under one lock, so the key
	// is made once and no write loses another's.
	unlock, err := lockCAFile(filepath.Join(directory, inventoryLockName))
	if err != nil {
		inv, err := memoryInventory(InventoryReasonUnusable)
		return inv, nil, err
	}
	defer unlock()

	id, raw, err := s.storedKey()
	if err != nil {
		// No key yet, or one that cannot be read: a new key, under which
		// whatever the file holds is not matched.
		if id, raw, err = s.newKey(); err != nil {
			inv, err := memoryInventory(InventoryReasonNoKeystore)
			return inv, nil, err
		}
	}
	inv, err := newInventory(s, directory, id, raw)
	clear(raw)
	if err != nil {
		inv, err := memoryInventory(InventoryReasonUnusable)
		return inv, nil, err
	}
	inv.status.Durable = true
	sweepInventoryTemporaries(directory)

	file := inv.read()
	if file.newer {
		inv.status.Durable, inv.status.Reason = false, InventoryReasonNewerFormat
		return inv, nil, nil
	}
	now := s.now()
	var loaded []StoredEntries
	var kept []inventoryRecord
	inv.status.Damaged, inv.status.OtherKey = file.damaged, file.otherKey
	for _, record := range file.records {
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
			inv.status.Durable, inv.status.Reason = false, InventoryReasonUnusable
		}
	}
	return inv, loaded, nil
}

func newInventory(s InventoryStore, directory string, id [inventoryKeyIDSize]byte, raw []byte) (*Inventory, error) {
	key, err := censor.KeyFromBytes(raw)
	if err != nil {
		return nil, err
	}
	// The sealing key and the tag key are derived from the inventory key
	// under their own labels, so neither is the key a client is handed's
	// hashing material.
	sealKey := sha256.Sum256(append([]byte("phase-leak-inventory-seal-v1"), raw...))
	block, err := aes.NewCipher(sealKey[:])
	if err != nil {
		return nil, err
	}
	seal, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Inventory{
		store: s, directory: directory, key: key, keyID: id, seal: seal,
		tagKey: sha256.Sum256(append([]byte("phase-leak-inventory-tag-v1"), raw...)),
		known:  map[[inventoryTagSize]byte]int64{},
	}, nil
}

// storedKey reads the key and its id from the keystore.
func (s InventoryStore) storedKey() (id [inventoryKeyIDSize]byte, raw []byte, err error) {
	value, err := s.keyring().Get(inventoryKeyringService, inventoryKeyringUser)
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

// newKey makes a key with a new id and stores it.
func (s InventoryStore) newKey() (id [inventoryKeyIDSize]byte, raw []byte, err error) {
	key, err := censor.NewKey()
	if err != nil {
		return id, nil, err
	}
	if _, err := rand.Read(id[:]); err != nil {
		return id, nil, err
	}
	raw = key.Bytes()
	value := "v1:" + hex.EncodeToString(id[:]) + ":" + base64.StdEncoding.EncodeToString(raw)
	if err := s.keyring().Set(inventoryKeyringService, inventoryKeyringUser, value); err != nil {
		return id, nil, err
	}
	return id, raw, nil
}

// ReplaceKey puts a new key, with a new id, in the keystore. Entries stored
// under the key before it are never matched again: the next proxy to start
// counts them and drops them. A proxy still running keeps what it holds in
// memory and stops writing to the store. Purge uses it where a key cannot be
// deleted; nothing else does, and there is no command for it.
func (s InventoryStore) ReplaceKey() error {
	if !s.KeystoreAvailable() {
		return nil
	}
	directory, err := s.directory()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	unlock, err := lockCAFile(filepath.Join(directory, inventoryLockName))
	if err != nil {
		return fmt.Errorf("lock leak protection inventory: %w", err)
	}
	defer unlock()
	_, raw, err := s.newKey()
	clear(raw)
	return err
}

// Remove deletes the stored entries and what was written beside them, and
// leaves the key. A missing file or directory is not an error.
func (s InventoryStore) Remove() error {
	directory, err := s.directory()
	if err != nil {
		return err
	}
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() {
		return nil
	}
	lockPath := filepath.Join(directory, inventoryLockName)
	unlock, err := lockCAFile(lockPath)
	if err != nil {
		return fmt.Errorf("lock leak protection inventory: %w", err)
	}
	sweepInventoryTemporaries(directory)
	err = os.Remove(filepath.Join(directory, inventoryFileName))
	// The lock file goes while it is held, so no other process is inside.
	lockErr := os.Remove(lockPath)
	unlock()
	for _, err := range []error{err, lockErr} {
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
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

// Purge removes the stored inventory: the entries, and the key from the
// keystore. It is what phase ai disable does. A key the keystore cannot
// delete is replaced, so that nothing stored under it is matched again.
func (s InventoryStore) Purge() error {
	return errors.Join(s.Remove(), s.deleteKey())
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
	// The proxy is stopped before a purge and the file is gone, so the new
	// key needs no lock.
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
		file.damaged = 1
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
		if length < inventoryRecordFixed+inv.seal.Overhead()+1 || length > maxInventoryRecordBytes || length > len(rest)-4 {
			file.damaged++
			break
		}
		raw := rest[:4+length]
		rest = rest[4+length:]
		if file.foreign {
			file.otherKey++
			continue
		}
		record := inventoryRecord{raw: raw, scheme: binary.BigEndian.Uint32(raw[4:]), registered: int64(binary.BigEndian.Uint64(raw[8:]))}
		copy(record.owner[:], raw[16:])
		copy(record.content[:], raw[16+inventoryTagSize:])
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
	additional := append(inv.header(), record.raw[4:fixed-inventoryNonceSize]...)
	body, err := inv.seal.Open(nil, nonce, record.raw[fixed:], additional)
	if err != nil || len(body) < 1 {
		return StoredEntries{}, recordDamaged
	}
	if record.scheme > 1<<30 || !censor.SchemeSupported(int(record.scheme)) {
		return StoredEntries{}, recordOtherScheme
	}
	entries, err := censor.ParseEntries(body[1:])
	if err != nil || entries.Version != int(record.scheme) || !entries.Protected() ||
		inv.ownerTag(entries) != record.owner || inv.tag("content", body[1:]) != record.content {
		return StoredEntries{}, recordDamaged
	}
	return StoredEntries{Entries: entries, KeyNamed: body[0]&1 != 0}, recordLoaded
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

func (inv *Inventory) ownerTag(entries *censor.Entries) [inventoryTagSize]byte {
	return inv.tag("owner", []byte(entries.Type), []byte(entries.ID))
}

// sealRecord builds the record for one registered value.
func (inv *Inventory) sealRecord(stored StoredEntries, wire []byte, now time.Time) (inventoryRecord, error) {
	body := make([]byte, 0, 1+len(wire))
	if stored.KeyNamed {
		body = append(body, 1)
	} else {
		body = append(body, 0)
	}
	body = append(body, wire...)
	return inv.sealBody(inventoryRecord{
		scheme: uint32(stored.Entries.Version), registered: now.Unix(),
		owner: inv.ownerTag(stored.Entries), content: inv.tag("content", wire),
	}, body)
}

// sealBody seals a record's body under its fields.
func (inv *Inventory) sealBody(record inventoryRecord, body []byte) (inventoryRecord, error) {
	length := inventoryRecordFixed + len(body) + inv.seal.Overhead()
	if length > maxInventoryRecordBytes {
		return record, errors.New("the entries are too large to store")
	}
	raw := make([]byte, 0, 4+length)
	raw = binary.BigEndian.AppendUint32(raw, uint32(length))
	raw = binary.BigEndian.AppendUint32(raw, record.scheme)
	raw = binary.BigEndian.AppendUint64(raw, uint64(record.registered))
	raw = append(raw, record.owner[:]...)
	raw = append(raw, record.content[:]...)
	additional := append(inv.header(), raw[4:]...)
	nonce := make([]byte, inventoryNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return record, err
	}
	raw = append(raw, nonce...)
	record.raw = inv.seal.Seal(raw, nonce, body, additional)
	return record, nil
}

// Add stores registered values, so that a proxy started later knows them. It
// never fails a registration: the values are in the running proxy's index
// either way, and a store that cannot be written is reported by Status.
//
// The file is read again under the lock and written whole, so what another
// proxy stored since is kept. Entries of a newer scheme replace the records
// of an older one for the same placeholder; a value stored already only has
// its time brought forward, and not more than once a day.
func (inv *Inventory) Add(batch []StoredEntries) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if !inv.status.Durable {
		return
	}
	now := inv.store.now()
	type pending struct {
		stored  StoredEntries
		wire    []byte
		content [inventoryTagSize]byte
	}
	var fresh []pending
	for _, stored := range batch {
		// A value too short or plain to protect has nothing to store.
		if !stored.Entries.Protected() {
			continue
		}
		wire, err := stored.Entries.Marshal()
		if err != nil {
			continue
		}
		content := inv.tag("content", wire)
		if at, ok := inv.known[content]; ok && now.Unix()-at < int64(inventoryRefreshAfter/time.Second) && at <= now.Unix() {
			continue
		}
		fresh = append(fresh, pending{stored: stored, wire: wire, content: content})
	}
	if len(fresh) == 0 {
		return
	}
	unlock, err := lockCAFile(filepath.Join(inv.directory, inventoryLockName))
	if err != nil {
		inv.status.Durable, inv.status.Reason = false, InventoryReasonUnusable
		return
	}
	defer unlock()
	file := inv.read()
	if file.newer {
		inv.status.Durable, inv.status.Reason = false, InventoryReasonNewerFormat
		return
	}
	// A file that is gone, or under another key, means the key was replaced
	// or removed while this process ran, unless the keystore still names this
	// process's key: then the file is what is stale.
	if !file.present {
		if id, raw, err := inv.store.storedKey(); err != nil || id != inv.keyID {
			inv.status.Durable, inv.status.Reason = false, InventoryReasonKeyReplaced
			return
		} else {
			clear(raw)
		}
	}
	records := file.records[:0:0]
	for _, record := range file.records {
		if now.Unix()-record.registered <= int64(InventoryEntryLifetime/time.Second) {
			records = append(records, record)
		}
	}
	for _, entry := range fresh {
		record, err := inv.sealRecord(entry.stored, entry.wire, now)
		if err != nil {
			continue
		}
		kept := records[:0]
		for _, existing := range records {
			sameValue := existing.content == record.content
			olderScheme := existing.owner == record.owner && existing.scheme < record.scheme
			if !sameValue && !olderScheme {
				kept = append(kept, existing)
			}
		}
		records = append(kept, record)
	}
	records = boundInventory(records)
	if err := inv.write(records); err != nil {
		inv.status.Durable, inv.status.Reason = false, InventoryReasonUnusable
		return
	}
	inv.known = make(map[[inventoryTagSize]byte]int64, len(records))
	for _, record := range records {
		inv.known[record.content] = record.registered
	}
}

// boundInventory keeps the file within its caps, dropping the entries
// registered longest ago, and orders it oldest first.
func boundInventory(records []inventoryRecord) []inventoryRecord {
	sort.SliceStable(records, func(i, j int) bool { return records[i].registered < records[j].registered })
	size := inventoryHeaderSize
	from := len(records)
	for from > 0 && len(records)-from < maxInventoryRecords && size+len(records[from-1].raw) <= maxInventoryFileBytes {
		from--
		size += len(records[from].raw)
	}
	return records[from:]
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
