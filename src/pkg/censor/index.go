package censor

import (
	"container/list"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
)

const (
	// DefaultMaxSecrets is how many values (distinct type and id) an index holds
	// unless IndexOptions says otherwise.
	DefaultMaxSecrets = 10000
	// DefaultMaxChunks bounds the index's memory, at roughly 80 bytes a chunk.
	DefaultMaxChunks = 1 << 20

	bloomMinBits = 1 << 16

	// maxRefsPerHash bounds how many chunks one lookup value leads to for one
	// confirming key: each key's own bound, so no party crowds out another's.
	maxRefsPerHash = 64

	// wholeProbe is how many chunks of a withheld form a scan hashes where its
	// lookup value turns up, whatever they hold, before it hashes the rest.
	wholeProbe = 4
)

// ErrIndexFull is returned by Add when the entries would take the index past one
// of its caps. Nothing of the refused entries is added.
var ErrIndexFull = errors.New("the censor index is full")

// ErrPublic is returned by Add for entries of a value that stands whole in
// one of the index's public texts (IndexOptions.Public). Nothing is added.
var ErrPublic = errors.New("the entries are of a value every request holds")

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
	// Public are texts every scanned request holds, such as a host name or a
	// path. No value is found in one: see ErrPublic.
	Public [][]byte
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
	// live is the lookup key of the one live key entries came under (AddLive).
	live *[KeySize]byte
	// macKeys are the confirming keys entries were added under: one per
	// principal or guest, and scheme 1's. A form names its own by position.
	macKeys     [][32]byte
	macKeyUse   []int32
	macKeyIndex map[[32]byte]int32
	freeMacKeys []int32
	// principals are the keys entries were added under, with what each holds.
	// Guests are held apart: see guestEntry.
	principals []principal
	guests     keyUse
	guestKeys  int
	// guestAge lists the guests' entries, added or added again longest ago
	// first, and guestForms finds the one a form is of by its fingerprint.
	guestAge   list.List
	guestForms map[[32]byte]*guestEntry
	// forms and owners are slots: one a dropped guest's entry left is used again.
	forms      []form
	freeForms  []int32
	owners     []owner
	freeOwners []int32
	ownerIndex map[ownerKey]int32
	secrets    map[secretKey]struct{}
	// withheldRefs numbers the values whose id is withheld, and lastRef is
	// the last number given: a guest's entry takes one of its own.
	withheldRefs map[secretKey]int32
	lastRef      int32
	// types count the owners of each type: the middle of their placeholders.
	types map[string]int
	// fingerprints lead to the form each is of, guests' apart in guestForms.
	fingerprints map[[32]byte]int32
	// public are the texts no entry may be found in, and publicSets their
	// chunks' lookup values under each lookup key entries came under.
	public     [][]byte
	publicSets map[[KeySize]byte]publicSet

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
	// Guests counts the entries held under other lookup keys (AddGuest).
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
	// withheld says the form is found whole or not at all, through one chunk,
	// and probe names the chunks a scan hashes first where that one turns up.
	withheld bool
	probe    [wholeProbe]int32
	// loaded says a store handed the form over and no client has added it since.
	loaded bool

	// weak marks chunks that are structure, such as PEM armour, a token's type
	// prefix or a URL's host. A partial match needs at least one chunk that isn't.
	weak []bool
}

type chunkRef struct {
	form int32
	idx  int32
}

// holding is how entries are held: see AddWithheld, AddLoaded, AddLive,
// Registered and AddGuest.
type holding struct {
	withheld, loaded bool
	// again says only what the index holds of the entries is touched: it is
	// marked as added again, and nothing is added.
	again bool
	// batch is the registration a guest's entries are of, nil for anyone else's.
	batch *GuestBatch
	// of is the principal that entries under a live key are counted as.
	of *Key
}

// guestEntry is what one AddGuest added: the unit the guests' share is
// counted in and dropped by, whatever type and id it came under.
type guestEntry struct {
	forms  []guestForm
	prints [][32]byte
	owners []int32
	chunks int
	// batch is the last registration that added it, or added it again.
	batch *GuestBatch
	age   *list.Element
}

// guestForm is one form of a guest's entry and where its chunk was filed.
type guestForm struct {
	at     int32
	window *window
	lookup uint64
	filed  bool
}

// GuestBatch is one registration of guests' entries. When the guests' share is
// full their oldest entries make way for it, and never one of its own.
type GuestBatch struct {
	ix *Index
	// secrets and chunks are what the batch added, or found held and kept.
	secrets, chunks int
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
		macKeyIndex:  map[[32]byte]int32{},
		guestForms:   map[[32]byte]*guestEntry{},
		ownerIndex:   map[ownerKey]int32{},
		secrets:      map[secretKey]struct{}{},
		withheldRefs: map[secretKey]int32{},
		types:        map[string]int{},
		fingerprints: map[[32]byte]int32{},
		publicSets:   map[[KeySize]byte]publicSet{},
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
	for _, text := range opts.Public {
		if len(text) >= chunkSize {
			ix.public = append(ix.public, slices.Clone(text))
		}
	}
	return ix, nil
}

// Add indexes entries built by IndexValue under this index's key. It validates
// them first and refuses anything malformed. Adding the same value again
// changes nothing; adding another value under the same type and id protects
// both. Entries with no forms are accepted and do nothing.
//
// Entries of every supported scheme are matched side by side and none replaces
// another: an id may name several values, and nothing held tells them apart.
func (ix *Index) Add(e *Entries) error { return ix.add(ix.key, e, holding{}) }

// AddKeyed is Add for entries built under key: this index's lookup key and
// another principal's confirming key, which a scan confirms their chunks with.
func (ix *Index) AddKeyed(key *Key, e *Entries) error { return ix.add(key, e, holding{}) }

// AddWithheld is AddKeyed for entries whose id the reader of a scan may not
// see: the value is replaced by ph:<type>, whole or not at all (see Limits).
func (ix *Index) AddWithheld(key *Key, e *Entries) error {
	return ix.add(key, e, holding{withheld: true})
}

// AddLoaded is AddKeyed, or AddWithheld when withheld is set, for entries a
// daemon read back from its store: a Finding says so until they are added again.
func (ix *Index) AddLoaded(key *Key, e *Entries, withheld bool) error {
	return ix.add(key, e, holding{withheld: withheld, loaded: true})
}

// AddLive is AddKeyed for entries a client built under live, a key the daemon's
// process made and keeps nowhere, of a value principal registered: they are
// matched as they stand and counted and named as that principal's, beside any
// the index holds of the same value under the principal's own key. An index
// takes one live key.
func (ix *Index) AddLive(live *Key, e *Entries, principal *Key) error {
	if principal == nil {
		return errors.New("live entries need the principal they are counted as")
	}
	return ix.add(live, e, holding{of: principal})
}

// Registered is AddKeyed for entries of a value a client has just registered
// with the daemon another way (AddLive), where the index may hold them from a
// store: the forms it holds of them are no longer a store's alone, and
// nothing is added. Forms held withheld, another principal's, and a guest's
// are not these entries' and stay as they are.
func (ix *Index) Registered(key *Key, e *Entries) error {
	return ix.add(key, e, holding{again: true})
}

// AddGuest is AddWithheld for entries built under a key that shares nothing
// with the index's, its lookup key included: a scan makes a pass of its own.
func (ix *Index) AddGuest(key *Key, e *Entries) error { return ix.NewGuestBatch().Add(key, e) }

// NewGuestBatch begins one registration of guests' entries.
func (ix *Index) NewGuestBatch() *GuestBatch { return &GuestBatch{ix: ix} }

// Add is AddGuest for one of the registration's entries. ErrIndexFull says
// the registration alone is more than the guests' share holds.
func (b *GuestBatch) Add(key *Key, e *Entries) error {
	return b.ix.add(key, e, holding{withheld: true, batch: b})
}

// pendingForm is a form of entries being added that the index does not hold.
type pendingForm struct {
	form        *Form
	fingerprint [32]byte
	// public are its chunks that are a piece of a public text: structure.
	public []int
}

func (ix *Index) add(key *Key, e *Entries, how holding) error {
	if err := e.validate(); err != nil {
		return err
	}
	guest := how.batch != nil
	own := key != nil && key.lookup == ix.key.lookup
	if how.of != nil {
		// A live key is no lookup key of the index, and its principal's is.
		own = key != nil && !own && how.of.lookup == ix.key.lookup
	}
	if key == nil || own == guest {
		return errors.New("the entries' key is not one this index takes them under")
	}
	s := schemes[e.Version]
	confirming := key.macFor(s)
	if confirming == nil {
		return errors.New("entries of this scheme need a confirming key")
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	// The principal is whose the entries are, whichever key they came under.
	counted := key
	if how.of != nil {
		if ix.live != nil && *ix.live != key.lookup {
			return errors.New("the index takes entries under one live key")
		}
		counted = how.of
	}
	public, value := ix.publicIn(key, s, confirming, e)
	if value {
		return ErrPublic
	}
	if guest {
		return ix.addGuest(key, s, confirming, e, public, how.batch)
	}

	var fresh []pendingForm
	newChunks := 0
	seen := map[[32]byte]bool{}
	registered := false
	for i := range e.Forms {
		f := &e.Forms[i]
		// A line is a fragment of its value, and a withheld value is matched
		// whole. A form that is a piece of a public text is never held.
		if (how.withheld && f.Form == formLine) || public.whole[i] {
			continue
		}
		fp := fingerprint(e.Version, confirming, how.withheld, e.Type, e.ID, f)
		if at, dup := ix.fingerprints[fp]; dup {
			// Added again by a client: no longer only what a store handed over.
			if !how.loaded && ix.forms[at].loaded {
				ix.forms[at].loaded, registered = false, true
			}
			continue
		}
		if seen[fp] {
			continue
		}
		seen[fp] = true
		fresh = append(fresh, pendingForm{form: f, fingerprint: fp, public: public.pieces[i]})
		c, _ := s.chunkOf(f)
		newChunks += f.Length / c
	}
	if registered {
		ix.cache.reset()
	}
	if len(fresh) == 0 || how.again {
		return nil
	}
	// Scheme 1 confirms with the lookup key, so its entries are counted with
	// those of the principal whose key they came under.
	who := int32(len(ix.principals))
	for at := range ix.principals {
		if ix.principals[at].lookup == counted.lookup && ix.principals[at].confirm == counted.confirm {
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
	if !held && (len(ix.secrets)+ix.guests.secrets >= ix.maxSecrets || over(use.secrets+1, ix.maxKeySecrets)) {
		return fmt.Errorf("%w: no room for another value", ErrIndexFull)
	}
	if ix.chunkCount+newChunks > ix.maxChunks || over(use.chunks+newChunks, ix.maxKeyChunks) {
		return fmt.Errorf("%w: no room for %d more chunks", ErrIndexFull, newChunks)
	}
	macKey := ix.macKeySlot(confirming)
	if int(who) == len(ix.principals) {
		ix.principals = append(ix.principals, principal{lookup: counted.lookup, confirm: counted.confirm})
	}
	if how.of != nil && ix.live == nil {
		ix.live = &[KeySize]byte{}
		*ix.live = key.lookup
	}
	if !held {
		ix.secrets[secret] = struct{}{}
		ix.principals[who].use.secrets++
	}
	ix.principals[who].use.chunks += newChunks
	for _, p := range fresh {
		at, _, _, _ := ix.addForm(key, s, macKey, ix.ownerFor(who, how.withheld, e.Type, e.ID, p.form.Part), how, p)
		ix.fingerprints[p.fingerprint] = at
	}
	ix.settle()
	return nil
}

// addGuest adds a guest's entries as an entry of their own, whatever is held
// under their type and id: what it costs the share says nothing of an id.
func (ix *Index) addGuest(key *Key, s *scheme, confirming *[32]byte, e *Entries, public publicParts, batch *GuestBatch) error {
	var fresh []pendingForm
	newChunks := 0
	seen := map[[32]byte]bool{}
	for i := range e.Forms {
		f := &e.Forms[i]
		if f.Form == formLine || public.whole[i] {
			continue
		}
		fp := fingerprint(e.Version, confirming, true, e.Type, e.ID, f)
		if held := ix.guestForms[fp]; held != nil {
			// Registered again: the entry is as new, and this registration's.
			if held.batch != batch {
				held.batch, batch.secrets, batch.chunks = batch, batch.secrets+1, batch.chunks+held.chunks
			}
			ix.guestAge.MoveToBack(held.age)
			continue
		}
		if seen[fp] {
			continue
		}
		seen[fp] = true
		fresh = append(fresh, pendingForm{form: f, fingerprint: fp, public: public.pieces[i]})
		c, _ := s.chunkOf(f)
		newChunks += f.Length / c
	}
	if len(fresh) == 0 {
		return nil
	}
	// A guest's lookup key is one more pass of every scan.
	known := false
	for _, w := range ix.windows {
		known = known || w.key.lookup == key.lookup
	}
	if !known && ix.guestKeys >= maxGuestKeys {
		return fmt.Errorf("%w: no room for another lookup key", ErrIndexFull)
	}
	if !ix.guestRoom(batch, newChunks) {
		return fmt.Errorf("%w: one registration is more than the guests' share", ErrIndexFull)
	}
	if !known {
		ix.guestKeys++
	}
	macKey := ix.macKeySlot(confirming)
	entry := &guestEntry{chunks: newChunks, batch: batch}
	ix.lastRef++
	owners := map[string]int32{}
	for _, p := range fresh {
		ownerAt, made := owners[p.form.Part]
		if !made {
			ownerAt = ix.newOwner(owner{typ: e.Type, id: e.ID, part: p.form.Part, placeholder: "ph:" + e.Type, withheld: true, ref: ix.lastRef})
			owners[p.form.Part] = ownerAt
			entry.owners = append(entry.owners, ownerAt)
		}
		at, w, lookup, filed := ix.addForm(key, s, macKey, ownerAt, holding{withheld: true}, p)
		entry.forms = append(entry.forms, guestForm{at: at, window: w, lookup: lookup, filed: filed})
		entry.prints = append(entry.prints, p.fingerprint)
		ix.guestForms[p.fingerprint] = entry
	}
	entry.age = ix.guestAge.PushBack(entry)
	ix.guests.secrets, ix.guests.chunks = ix.guests.secrets+1, ix.guests.chunks+newChunks
	batch.secrets, batch.chunks = batch.secrets+1, batch.chunks+newChunks
	ix.settle()
	return nil
}

// guestRoom drops the guests' oldest entries until one more of newChunks
// fits. It drops none of batch's, and nothing when that would not be enough.
func (ix *Index) guestRoom(batch *GuestBatch, newChunks int) bool {
	others := ix.chunkCount - ix.guests.chunks
	fits := func(secrets, chunks int) bool {
		return !over(secrets+1, ix.maxGuestSecrets) && !over(chunks+newChunks, ix.maxGuestChunks) &&
			len(ix.secrets)+secrets < ix.maxSecrets && others+chunks+newChunks <= ix.maxChunks
	}
	if !fits(batch.secrets, batch.chunks) {
		return false
	}
	for oldest := ix.guestAge.Front(); oldest != nil && !fits(ix.guests.secrets, ix.guests.chunks); {
		entry, next := oldest.Value.(*guestEntry), oldest.Next()
		if entry.batch != batch {
			ix.dropGuest(entry)
		}
		oldest = next
	}
	return fits(ix.guests.secrets, ix.guests.chunks)
}

// dropGuest takes a guest's entry out of the index and frees what it held.
func (ix *Index) dropGuest(entry *guestEntry) {
	for _, held := range entry.forms {
		f := &ix.forms[held.at]
		if held.filed {
			held.window.remove(held.lookup, held.at)
		}
		ix.chunkCount -= len(f.macs)
		if ix.macKeyUse[f.macKey]--; ix.macKeyUse[f.macKey] == 0 {
			delete(ix.macKeyIndex, ix.macKeys[f.macKey])
			ix.macKeys[f.macKey] = [32]byte{}
			ix.freeMacKeys = append(ix.freeMacKeys, f.macKey)
		}
		*f = form{}
		ix.freeForms = append(ix.freeForms, held.at)
	}
	for _, at := range entry.owners {
		if typ := ix.owners[at].typ; ix.types[typ] <= 1 {
			delete(ix.types, typ)
		} else {
			ix.types[typ]--
		}
		ix.owners[at] = owner{}
		ix.freeOwners = append(ix.freeOwners, at)
	}
	for _, fp := range entry.prints {
		delete(ix.guestForms, fp)
	}
	ix.guestAge.Remove(entry.age)
	ix.guests.secrets, ix.guests.chunks = ix.guests.secrets-1, ix.guests.chunks-entry.chunks
}

// settle follows every change to what is held: the filters fit the chunks
// again, and strings cached as clean before this value was known are forgotten.
func (ix *Index) settle() {
	for _, w := range ix.windows {
		w.grow()
	}
	ix.cache.reset()
}

// over reports a count past a bound, where 0 is no bound.
func over(count, bound int) bool { return bound > 0 && count > bound }

// macKeySlot is where a confirming key sits among the index's, added if new.
func (ix *Index) macKeySlot(confirming *[32]byte) int32 {
	if at, held := ix.macKeyIndex[*confirming]; held {
		return at
	}
	at := int32(len(ix.macKeys))
	if free := len(ix.freeMacKeys); free > 0 {
		at, ix.freeMacKeys = ix.freeMacKeys[free-1], ix.freeMacKeys[:free-1]
		ix.macKeys[at] = *confirming
	} else {
		ix.macKeys, ix.macKeyUse = append(ix.macKeys, *confirming), append(ix.macKeyUse, 0)
	}
	ix.macKeyIndex[*confirming] = at
	return at
}

// namesID reports whether a placeholder of this index carries the id: a value
// of the type is held with it, whichever principal's. A withheld id is not one.
func (ix *Index) namesID(typ, id string) bool {
	for who := range ix.principals {
		secret := secretKey{int32(who), typ, id}
		if _, held := ix.secrets[secret]; !held {
			continue
		}
		if _, withheld := ix.withheldRefs[secret]; !withheld {
			return true
		}
	}
	return false
}

// newOwner puts an owner in a slot and counts its type.
func (ix *Index) newOwner(added owner) int32 {
	ix.types[added.typ]++
	if free := len(ix.freeOwners); free > 0 {
		at := ix.freeOwners[free-1]
		ix.freeOwners, ix.owners[at] = ix.freeOwners[:free-1], added
		return at
	}
	ix.owners = append(ix.owners, added)
	return int32(len(ix.owners) - 1)
}

// ownerFor is the owner of a part of a principal's value, made when new.
func (ix *Index) ownerFor(who int32, withheld bool, typ, id, part string) int32 {
	key := ownerKey{typ: typ, id: id, part: part, withheld: withheld}
	if withheld {
		// Two principals' values under one id are two values to a reader.
		key.principal = who
	}
	if at, exists := ix.ownerIndex[key]; exists {
		return at
	}
	added := owner{typ: typ, id: id, part: part, placeholder: "ph:" + typ, withheld: withheld}
	if withheld {
		secret := secretKey{who, typ, id}
		if _, numbered := ix.withheldRefs[secret]; !numbered {
			ix.lastRef++
			ix.withheldRefs[secret] = ix.lastRef
		}
		added.ref = ix.withheldRefs[secret]
	} else {
		added.placeholder += ":" + id
	}
	at := ix.newOwner(added)
	ix.ownerIndex[key] = at
	return at
}

// addForm stores a form and files its chunks. For a withheld form it answers
// where the one chunk that leads to it was filed, if it was.
func (ix *Index) addForm(key *Key, s *scheme, macKey, ownerAt int32, how holding, pending pendingForm) (at int32, w *window, lookup uint64, filed bool) {
	f := pending.form
	c, _ := s.chunkOf(f)
	n := f.Length / c
	stored := form{
		owner:     ownerAt,
		name:      f.Form,
		length:    f.Length,
		macs:      make([][macSize]byte, n),
		weak:      make([]bool, n),
		tailLen:   f.Length - n*c,
		macKey:    macKey,
		formShape: s.shapes[f.Form],
		chunk:     c,
		tailBack:  s.tailBack(c),
		withheld:  how.withheld,
		loaded:    how.loaded,
	}
	for i := 0; i < n; i++ {
		copy(stored.macs[i][:], f.MACs[i*macSize:])
		stored.weak[i] = f.Weak[i/8]&(1<<(i%8)) != 0
	}
	for _, i := range pending.public {
		stored.weak[i] = true
	}
	if stored.tailLen > 0 {
		copy(stored.tail[:], f.Tail)
	}
	at = int32(len(ix.forms))
	if free := len(ix.freeForms); free > 0 {
		at, ix.freeForms = ix.freeForms[free-1], ix.freeForms[:free-1]
		ix.forms[at] = stored
	} else {
		ix.forms = append(ix.forms, stored)
	}
	ix.macKeyUse[macKey]++
	ix.chunkCount += n
	w = ix.windowFor(key, c, f.Wide, s.lookupBits)
	if how.withheld {
		// One chunk leads to a form that is matched whole: the first that is
		// not structure and has room, so values of one format are found apart.
		led := 0
		for _, structure := range []bool{false, true} {
			for i := 0; i < n && !filed; i++ {
				if stored.weak[i] == structure {
					led, lookup = i, s.lookupAt(f, i)
					filed = ix.file(w, lookup, chunkRef{form: at, idx: int32(i)}, macKey)
				}
			}
		}
		// The probe: that chunk, then others that are not structure, then any.
		picked := []int32{int32(led)}
		for _, structure := range []bool{false, true} {
			for j := 1; j < n && len(picked) < wholeProbe; j++ {
				if next := (led + j) % n; stored.weak[next] == structure {
					picked = append(picked, int32(next))
				}
			}
		}
		copy(ix.forms[at].probe[:], picked)
		return at, w, lookup, filed
	}
	// A chunk that repeats within a form is looked up through its first place
	// only: a match found there is extended over the rest, and indexing every
	// repeat would make a value of one repeated block cost a scan its length at
	// every position. A repeat is told by the confirming hash: two chunks may
	// share a short lookup value by chance.
	seen := make(map[[macSize]byte]struct{}, n)
	for i := 0; i < n; i++ {
		if _, repeat := seen[stored.macs[i]]; repeat {
			continue
		}
		seen[stored.macs[i]] = struct{}{}
		ix.file(w, s.lookupAt(f, i), chunkRef{form: at, idx: int32(i)}, macKey)
	}
	return at, w, 0, false
}

// file puts a chunk under its lookup value, beside the others of its
// confirming key and within that key's own bound there.
func (ix *Index) file(w *window, h uint64, ref chunkRef, macKey int32) bool {
	refs, present := w.chunks[h]
	at, same := len(refs), 0
	for i, other := range refs {
		if ix.forms[other.form].macKey == macKey {
			at, same = i+1, same+1
		}
	}
	if same >= maxRefsPerHash {
		return false
	}
	if !present {
		w.setBloom(h)
	}
	w.chunks[h] = slices.Insert(refs, at, ref)
	return true
}

// fingerprint identifies a form of a value under its owner, scheme and
// confirming key, so adding the same value twice adds nothing.
func fingerprint(version int, confirming *[32]byte, withheld bool, typ, id string, f *Form) [32]byte {
	h := sha256.New()
	if withheld {
		h.Write([]byte{1})
	}
	h.Write([]byte{byte(version), byte(version >> 8), byte(version >> 16), byte(version >> 24)})
	h.Write(confirming[:])
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
		Secrets: len(ix.secrets), Owners: len(ix.owners) - len(ix.freeOwners), Forms: len(ix.forms) - len(ix.freeForms),
		Chunks: ix.chunkCount, Guests: ix.guests.secrets,
	}
}
