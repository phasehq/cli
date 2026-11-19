package censor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

const (
	// DefaultMaxSecrets is how many values (distinct type and id) an index holds
	// unless IndexOptions says otherwise.
	DefaultMaxSecrets = 10000
	// DefaultMaxChunks bounds the index's memory, at roughly 80 bytes a chunk.
	DefaultMaxChunks = 1 << 20

	bloomMinBits = 1 << 16

	// maxRefsPerHash bounds how many chunks one rolling hash leads to across the
	// index, which is what a scan checks at each position the hash turns up.
	// Distinct values almost never share a 12-byte chunk; the ones that do are
	// structure (PEM armour) or one value registered under many ids, and either
	// is still found through its other chunks or its first owner.
	maxRefsPerHash = 64
)

// ErrIndexFull is returned by Add when the entries would take the index past one
// of its caps. Nothing of the refused entries is added.
var ErrIndexFull = errors.New("the censor index is full")

// IndexOptions tune an index. Zero values take the defaults.
type IndexOptions struct {
	// Rules are the pattern rules applied to every scan. Nil means DefaultRules.
	Rules      *Rules
	MaxSecrets int
	MaxChunks  int
	// MaxKeySecrets and MaxKeyChunks bound what one confirming key (one
	// principal) holds of the index. Zero is no bound of its own.
	MaxKeySecrets, MaxKeyChunks int
	// MaxGuestSecrets and MaxGuestChunks bound what is held under other lookup
	// keys than the index's (AddGuest), together. Zero is no bound of its own.
	MaxGuestSecrets, MaxGuestChunks int
}

// maxGuestKeys is how many lookup keys besides its own an index takes
// entries under. Each costs every scan a pass while it holds anything.
const maxGuestKeys = 4

// Index finds indexed values and pattern rule matches in requests. It holds keyed
// hashes only, never a value. It is safe for concurrent Add and scans.
type Index struct {
	key *Key
	// ruleKey keys the hashes rule matches are numbered by. It is the
	// index's own and goes with it.
	ruleKey    [32]byte
	rules      *Rules
	maxSecrets int
	maxChunks  int
	// The bounds of IndexOptions, zero when there is none.
	maxKeySecrets, maxKeyChunks     int
	maxGuestSecrets, maxGuestChunks int

	mu sync.RWMutex
	// windows hold the chunks, by chunk size: see window.
	windows    []*window
	chunkCount int
	// macKeys are the confirming keys entries were added under: one per
	// principal, and scheme 1's. A form names its own by position.
	macKeys [][32]byte
	// principals are the keys entries were added under, with what each holds,
	// and guests what is held under other lookup keys than the index's.
	principals []principal
	guests     keyUse
	guestKeys  int
	forms      []form
	owners     []owner
	ownerIndex map[ownerKey]int32
	secrets    map[secretKey]struct{}
	// withheldRefs numbers the values whose id is withheld, from 1.
	withheldRefs map[secretKey]int32
	types        map[string]struct{} // the types of the values indexed: the middle of their placeholders
	fingerprints map[[32]byte]struct{}

	ruleMu   sync.Mutex
	ruleNums map[[macSize]byte]int
	ruleNext map[string]int

	cache *blockCache
}

// rulesFor is the rule set one call applies.
func (ix *Index) rulesFor(opts ScanOptions) *Rules {
	if opts.Rules != nil {
		return opts.Rules
	}
	return ix.rules
}

// IndexStats describes what is indexed, never what the values are. Secrets
// counts a type and id once per principal that registered it, guests apart.
type IndexStats struct {
	Secrets, Owners, Forms, Chunks int
	// Guests counts the values held under other lookup keys (AddGuest).
	Guests int
}

// keyUse is how many values and chunks are held under a key.
type keyUse struct {
	secrets, chunks int
}

// principal is a key entries were added under, whatever their scheme.
type principal struct {
	lookup, confirm [KeySize]byte
	use             keyUse
}

// secretKey is a value as it is counted: by the principal that added it, so
// no count says what another principal holds.
type secretKey struct {
	principal int32
	typ, id   string
}

type ownerKey struct {
	typ, id, part string
	withheld      bool
	// principal is whose a withheld value is, and 0 otherwise.
	principal int32
}

type owner struct {
	typ, id, part string
	placeholder   string
	// withheld says the id is in no placeholder or finding: see AddWithheld.
	// Such a value is matched whole or not at all, and ref numbers it.
	withheld bool
	ref      int32
}

type form struct {
	owner   int32
	name    string
	length  int
	macs    [][macSize]byte
	tailLen int
	tail    [macSize]byte
	// macKey is which of the index's confirming keys the hashes were made under.
	macKey int32
	formShape
	// chunk is the size of the form's chunks, and tailBack how far before the
	// tail its hash begins: both are fixed by the entries' scheme.
	chunk    int
	tailBack int

	// weak marks chunks that are structure, such as PEM armour, a token's type
	// prefix or a URL's host. A partial match needs at least one chunk that isn't.
	weak []bool
}

type chunkRef struct {
	form int32
	idx  int32
}

// NewIndex makes an empty index under key's lookup key, which entries added
// share (Add, AddKeyed, AddWithheld) unless they are a guest's (AddGuest).
func NewIndex(key *Key, opts IndexOptions) (*Index, error) {
	if key == nil {
		return nil, errors.New("an index needs a key")
	}
	rules := opts.Rules
	if rules == nil {
		rules = DefaultRules()
	}
	ix := &Index{
		key:          key,
		rules:        rules,
		maxSecrets:   opts.MaxSecrets,
		maxChunks:    opts.MaxChunks,
		ownerIndex:   map[ownerKey]int32{},
		secrets:      map[secretKey]struct{}{},
		withheldRefs: map[secretKey]int32{},
		types:        map[string]struct{}{},
		fingerprints: map[[32]byte]struct{}{},
		ruleNums:     map[[macSize]byte]int{},
		ruleNext:     map[string]int{},
		cache:        newBlockCache(),
	}
	if _, err := rand.Read(ix.ruleKey[:]); err != nil {
		return nil, err
	}
	if ix.maxSecrets <= 0 {
		ix.maxSecrets = DefaultMaxSecrets
	}
	if ix.maxChunks <= 0 {
		ix.maxChunks = DefaultMaxChunks
	}
	ix.maxKeySecrets, ix.maxKeyChunks = max(opts.MaxKeySecrets, 0), max(opts.MaxKeyChunks, 0)
	ix.maxGuestSecrets, ix.maxGuestChunks = max(opts.MaxGuestSecrets, 0), max(opts.MaxGuestChunks, 0)
	return ix, nil
}

// Add indexes entries built by IndexValue under this index's key. It validates
// them first and refuses anything malformed. Adding the same value again
// changes nothing; adding another value under the same type and id protects
// both. Entries with no forms are accepted and do nothing.
//
// Entries of every supported scheme are matched side by side and none replaces
// another: an id may name several values, and nothing held tells them apart.
func (ix *Index) Add(e *Entries) error { return ix.add(ix.key, e, false, false) }

// AddKeyed is Add for entries built under key: this index's lookup key and
// another principal's confirming key, which a scan confirms their chunks with.
func (ix *Index) AddKeyed(key *Key, e *Entries) error { return ix.add(key, e, false, false) }

// AddWithheld is AddKeyed for entries whose id the reader of a scan may not
// see: the value is replaced by ph:<type>, whole or not at all (see Limits).
func (ix *Index) AddWithheld(key *Key, e *Entries) error { return ix.add(key, e, true, false) }

// AddGuest is AddWithheld for entries built under a key that shares nothing
// with the index's, its lookup key included: a scan makes a pass of its own.
func (ix *Index) AddGuest(key *Key, e *Entries) error { return ix.add(key, e, true, true) }

func (ix *Index) add(key *Key, e *Entries, withheld, guest bool) error {
	if err := e.validate(); err != nil {
		return err
	}
	if key == nil || (key.lookup == ix.key.lookup) == guest {
		return errors.New("the entries' key is not one this index takes them under")
	}
	s := schemes[e.Version]
	confirming := key.macFor(s)
	if confirming == nil {
		return errors.New("entries of this scheme need a confirming key")
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	// The keys are few: one per principal that ever registered here.
	macKey := int32(len(ix.macKeys))
	for at := range ix.macKeys {
		if ix.macKeys[at] == *confirming {
			macKey = int32(at)
			break
		}
	}

	type pending struct {
		form        *Form
		fingerprint [32]byte
	}
	var fresh []pending
	newChunks := 0
	seen := map[[32]byte]bool{}
	for i := range e.Forms {
		f := &e.Forms[i]
		fp := fingerprint(e.Version, macKey, withheld, e.Type, e.ID, f)
		if _, dup := ix.fingerprints[fp]; dup || seen[fp] {
			continue
		}
		seen[fp] = true
		fresh = append(fresh, pending{form: f, fingerprint: fp})
		c, _ := s.chunkOf(f)
		newChunks += f.Length / c
	}
	if len(fresh) == 0 {
		return nil
	}
	// Scheme 1 confirms with the lookup key, so its entries are counted with
	// those of the principal whose key they came under.
	who := int32(len(ix.principals))
	for at := range ix.principals {
		if ix.principals[at].lookup == key.lookup && ix.principals[at].confirm == key.confirm {
			who = int32(at)
			break
		}
	}
	var use keyUse
	if int(who) < len(ix.principals) {
		use = ix.principals[who].use
	}
	secret := secretKey{who, e.Type, e.ID}
	_, held := ix.secrets[secret]
	if !held && (len(ix.secrets) >= ix.maxSecrets || over(use.secrets+1, ix.maxKeySecrets) || (guest && over(ix.guests.secrets+1, ix.maxGuestSecrets))) {
		return fmt.Errorf("%w: no room for another value", ErrIndexFull)
	}
	if ix.chunkCount+newChunks > ix.maxChunks || over(use.chunks+newChunks, ix.maxKeyChunks) || (guest && over(ix.guests.chunks+newChunks, ix.maxGuestChunks)) {
		return fmt.Errorf("%w: no room for %d more chunks", ErrIndexFull, newChunks)
	}
	var known *window
	if guest {
		// A guest's lookup key is one more pass of every scan.
		for _, w := range ix.windows {
			if w.key.lookup == key.lookup {
				known = w
			}
		}
		if known == nil && ix.guestKeys >= maxGuestKeys {
			return fmt.Errorf("%w: no room for another lookup key", ErrIndexFull)
		}
		if known == nil {
			ix.guestKeys++
		}
	}
	if int(macKey) == len(ix.macKeys) {
		ix.macKeys = append(ix.macKeys, *confirming)
	}
	if int(who) == len(ix.principals) {
		ix.principals = append(ix.principals, principal{lookup: key.lookup, confirm: key.confirm})
	}
	if !held {
		ix.secrets[secret] = struct{}{}
		ix.principals[who].use.secrets++
		if guest {
			ix.guests.secrets++
		}
	}
	ix.principals[who].use.chunks += newChunks
	if guest {
		ix.guests.chunks += newChunks
	}
	ix.types[e.Type] = struct{}{}
	for _, p := range fresh {
		ix.addForm(key, s, macKey, who, withheld, e.Type, e.ID, p.form)
		ix.fingerprints[p.fingerprint] = struct{}{}
	}
	for _, w := range ix.windows {
		w.grow()
	}
	// Strings scanned before this value was known may have been cached as clean.
	ix.cache.reset()
	return nil
}

// over reports a count past a bound, where 0 is no bound.
func over(count, bound int) bool { return bound > 0 && count > bound }

func (ix *Index) addForm(key *Key, s *scheme, macKey, who int32, withheld bool, typ, id string, f *Form) {
	ok := ownerKey{typ: typ, id: id, part: f.Part, withheld: withheld}
	if withheld {
		// Two principals' values under one id are two values to a reader.
		ok.principal = who
	}
	ownerIdx, exists := ix.ownerIndex[ok]
	if !exists {
		ownerIdx = int32(len(ix.owners))
		added := owner{typ: typ, id: id, part: f.Part, placeholder: "ph:" + typ, withheld: withheld}
		if withheld {
			secret := secretKey{who, typ, id}
			if _, numbered := ix.withheldRefs[secret]; !numbered {
				ix.withheldRefs[secret] = int32(len(ix.withheldRefs) + 1)
			}
			added.ref = ix.withheldRefs[secret]
		} else {
			added.placeholder += ":" + id
		}
		ix.owners = append(ix.owners, added)
		ix.ownerIndex[ok] = ownerIdx
	}
	c, _ := s.chunkOf(f)
	n := f.Length / c
	w := ix.windowFor(key, c, f.Wide, s.lookupBits)
	stored := form{
		owner:     ownerIdx,
		name:      f.Form,
		length:    f.Length,
		macs:      make([][macSize]byte, n),
		weak:      make([]bool, n),
		tailLen:   f.Length - n*c,
		macKey:    macKey,
		formShape: s.shapes[f.Form],
		chunk:     c,
		tailBack:  s.tailBack(c),
	}
	formIdx := int32(len(ix.forms))
	// A chunk that repeats within a form is looked up through its first place
	// only: a match found there is extended over the rest, and indexing every
	// repeat would make a value of one repeated block cost a scan its length at
	// every position. A repeat is told by the confirming hash: two chunks may
	// share a short lookup value by chance.
	seen := make(map[[macSize]byte]struct{}, n)
	for i := 0; i < n; i++ {
		copy(stored.macs[i][:], f.MACs[i*macSize:])
		stored.weak[i] = f.Weak[i/8]&(1<<(i%8)) != 0
		if _, repeat := seen[stored.macs[i]]; repeat {
			continue
		}
		seen[stored.macs[i]] = struct{}{}
		w.add(s.lookupAt(f, i), chunkRef{form: formIdx, idx: int32(i)})
	}
	if stored.tailLen > 0 {
		copy(stored.tail[:], f.Tail)
	}
	ix.forms = append(ix.forms, stored)
	ix.chunkCount += n
}

// fingerprint identifies a form of a value under its owner, scheme and
// confirming key, so adding the same value twice adds nothing.
func fingerprint(version int, macKey int32, withheld bool, typ, id string, f *Form) [32]byte {
	h := sha256.New()
	if withheld {
		h.Write([]byte{1})
	}
	h.Write([]byte{byte(version), byte(version >> 8), byte(version >> 16), byte(version >> 24)})
	h.Write([]byte{byte(macKey), byte(macKey >> 8), byte(macKey >> 16), byte(macKey >> 24)})
	for _, s := range []string{typ, id, f.Part, f.Form} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	var length [8]byte
	binary.LittleEndian.PutUint64(length[:], uint64(f.Length))
	h.Write(length[:])
	h.Write(f.MACs)
	h.Write(f.Tail)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Stats summarises the index.
func (ix *Index) Stats() IndexStats {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return IndexStats{
		Secrets: len(ix.secrets) - ix.guests.secrets, Owners: len(ix.owners), Forms: len(ix.forms), Chunks: ix.chunkCount, Guests: ix.guests.secrets,
	}
}
