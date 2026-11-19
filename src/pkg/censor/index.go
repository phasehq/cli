package censor

import (
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
}

// Index finds indexed values and pattern rule matches in requests. It holds keyed
// hashes only, never a value. It is safe for concurrent Add and scans.
type Index struct {
	key        *Key
	rules      *Rules
	maxSecrets int
	maxChunks  int

	mu sync.RWMutex
	// windows hold the chunks, by chunk size: see window.
	windows    []*window
	chunkCount int
	forms      []form
	// liveForms counts the forms a scan still matches: all but those a newer
	// scheme's entries replaced.
	liveForms    int
	owners       []owner
	ownerIndex   map[ownerKey]int32
	secrets      map[secretKey]*secretForms
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

// IndexStats describes what is indexed, never what the values are.
type IndexStats struct {
	Secrets, Owners, Forms, Chunks int
}

type secretKey struct{ typ, id string }

// secretForms is what is indexed for one placeholder: its forms, and the
// newest matching scheme among them.
type secretForms struct {
	scheme int
	forms  []int32
}

type ownerKey struct{ typ, id, part string }

type owner struct {
	typ, id, part string
	placeholder   string
}

type form struct {
	owner   int32
	name    string
	length  int
	macs    [][macSize]byte
	tailLen int
	tail    [macSize]byte
	formShape
	// chunk is the size of the form's chunks, and tailBack how far before the
	// tail its hash begins: both are fixed by the entries' scheme.
	chunk    int
	tailBack int
	// dead marks a form that entries of a newer scheme replaced. Its chunks
	// stay filed until the index goes, and match nothing.
	dead bool

	// weak marks chunks that are structure, such as PEM armour, a token's type
	// prefix or a URL's host. A partial match needs at least one chunk that isn't.
	weak []bool
}

type chunkRef struct {
	form int32
	idx  int32
}

// NewIndex makes an empty index whose hashes are keyed with key. Entries added to
// it must have been built with the same key.
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
		secrets:      map[secretKey]*secretForms{},
		types:        map[string]struct{}{},
		fingerprints: map[[32]byte]struct{}{},
		ruleNums:     map[[macSize]byte]int{},
		ruleNext:     map[string]int{},
		cache:        newBlockCache(),
	}
	if ix.maxSecrets <= 0 {
		ix.maxSecrets = DefaultMaxSecrets
	}
	if ix.maxChunks <= 0 {
		ix.maxChunks = DefaultMaxChunks
	}
	return ix, nil
}

// Add indexes entries built by IndexValue under this index's key. It validates
// them first and refuses anything malformed. Adding the same value again
// changes nothing; adding another value under the same type and id protects
// both. Entries with no forms are accepted and do nothing.
//
// Entries of every supported scheme are matched side by side. Entries of a
// newer scheme than those held for the same type and id replace them: the
// value was indexed again, and the older entries are no longer needed.
func (ix *Index) Add(e *Entries) error {
	if err := e.validate(); err != nil {
		return err
	}
	s := schemes[e.Version]
	ix.mu.Lock()
	defer ix.mu.Unlock()

	type pending struct {
		form        *Form
		fingerprint [32]byte
	}
	var fresh []pending
	newChunks := 0
	seen := map[[32]byte]bool{}
	for i := range e.Forms {
		f := &e.Forms[i]
		fp := fingerprint(e.Version, e.Type, e.ID, f)
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
	secret := secretKey{e.Type, e.ID}
	held := ix.secrets[secret]
	if held == nil && len(ix.secrets) >= ix.maxSecrets {
		return fmt.Errorf("%w: it holds %d values already", ErrIndexFull, ix.maxSecrets)
	}
	// What these entries replace is not counted against them.
	replaced := 0
	if held != nil && held.scheme < e.Version {
		for _, at := range held.forms {
			if !ix.forms[at].dead {
				replaced += len(ix.forms[at].macs)
			}
		}
	}
	if ix.chunkCount-replaced+newChunks > ix.maxChunks {
		return fmt.Errorf("%w: %d more chunks would pass the limit of %d", ErrIndexFull, newChunks, ix.maxChunks)
	}

	if held == nil {
		held = &secretForms{scheme: e.Version}
		ix.secrets[secret] = held
	}
	if held.scheme < e.Version {
		ix.retire(held)
		held.scheme = e.Version
	}
	ix.types[e.Type] = struct{}{}
	for _, p := range fresh {
		held.forms = append(held.forms, int32(len(ix.forms)))
		ix.addForm(s, e.Type, e.ID, p.form)
		ix.fingerprints[p.fingerprint] = struct{}{}
	}
	for _, w := range ix.windows {
		w.grow()
	}
	// Strings scanned before this value was known may have been cached as clean.
	ix.cache.reset()
	return nil
}

// retire stops matching the forms held for a placeholder, when entries of a
// newer scheme arrive for it.
func (ix *Index) retire(held *secretForms) {
	for _, at := range held.forms {
		f := &ix.forms[at]
		if f.dead {
			continue
		}
		ix.chunkCount -= len(f.macs)
		ix.liveForms--
		f.dead, f.macs, f.weak = true, nil, nil
	}
	held.forms = nil
}

func (ix *Index) addForm(s *scheme, typ, id string, f *Form) {
	ok := ownerKey{typ, id, f.Part}
	ownerIdx, exists := ix.ownerIndex[ok]
	if !exists {
		ownerIdx = int32(len(ix.owners))
		ix.owners = append(ix.owners, owner{typ: typ, id: id, part: f.Part, placeholder: "ph:" + typ + ":" + id})
		ix.ownerIndex[ok] = ownerIdx
	}
	c, _ := s.chunkOf(f)
	n := f.Length / c
	w := ix.windowFor(c, f.Wide)
	stored := form{
		owner:     ownerIdx,
		name:      f.Form,
		length:    f.Length,
		macs:      make([][macSize]byte, n),
		weak:      make([]bool, n),
		tailLen:   f.Length - n*c,
		formShape: s.shapes[f.Form],
		chunk:     c,
		tailBack:  s.tailBack(c),
	}
	formIdx := int32(len(ix.forms))
	// A chunk that repeats within a form is looked up through its first place
	// only: a match found there is extended over the rest, and indexing every
	// repeat would make a value of one repeated block cost a scan its length at
	// every position.
	var seen map[uint64]struct{}
	for i := 0; i < n; i++ {
		copy(stored.macs[i][:], f.MACs[i*macSize:])
		stored.weak[i] = f.Weak[i/8]&(1<<(i%8)) != 0
		h := binary.LittleEndian.Uint64(f.Rolls[i*8:])
		if seen == nil {
			seen = make(map[uint64]struct{}, n)
		}
		if _, repeat := seen[h]; repeat {
			continue
		}
		seen[h] = struct{}{}
		w.add(h, chunkRef{form: formIdx, idx: int32(i)})
	}
	if stored.tailLen > 0 {
		copy(stored.tail[:], f.Tail)
	}
	ix.forms = append(ix.forms, stored)
	ix.liveForms++
	ix.chunkCount += n
}

// fingerprint identifies a form of a value under its owner and scheme, so
// adding the same value twice adds nothing.
func fingerprint(version int, typ, id string, f *Form) [32]byte {
	h := sha256.New()
	h.Write([]byte{byte(version), byte(version >> 8), byte(version >> 16), byte(version >> 24)})
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
	return IndexStats{Secrets: len(ix.secrets), Owners: len(ix.owners), Forms: ix.liveForms, Chunks: ix.chunkCount}
}
