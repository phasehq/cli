package censor

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
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

	mu           sync.RWMutex
	bloom        []uint64
	bloomShift   uint
	chunks       map[uint64][]chunkRef
	chunkCount   int
	forms        []form
	owners       []owner
	ownerIndex   map[ownerKey]int32
	secrets      map[secretKey]struct{}
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
		chunks:       map[uint64][]chunkRef{},
		ownerIndex:   map[ownerKey]int32{},
		secrets:      map[secretKey]struct{}{},
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
	ix.resizeBloom(bloomMinBits)
	return ix, nil
}

// Add indexes entries built by IndexValue under this index's key. It validates
// them first and refuses anything malformed. Adding the same value again
// changes nothing; adding another value under the same type and id protects
// both. Entries with no forms are accepted and do nothing.
func (ix *Index) Add(e *Entries) error {
	if err := e.validate(); err != nil {
		return err
	}
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
		fp := fingerprint(e.Type, e.ID, f)
		if _, dup := ix.fingerprints[fp]; dup || seen[fp] {
			continue
		}
		seen[fp] = true
		fresh = append(fresh, pending{form: f, fingerprint: fp})
		newChunks += f.Length / chunkSize
	}
	if len(fresh) == 0 {
		return nil
	}
	secret := secretKey{e.Type, e.ID}
	if _, known := ix.secrets[secret]; !known && len(ix.secrets) >= ix.maxSecrets {
		return fmt.Errorf("%w: it holds %d values already", ErrIndexFull, ix.maxSecrets)
	}
	if ix.chunkCount+newChunks > ix.maxChunks {
		return fmt.Errorf("%w: %d more chunks would pass the limit of %d", ErrIndexFull, newChunks, ix.maxChunks)
	}

	ix.secrets[secret] = struct{}{}
	ix.types[e.Type] = struct{}{}
	for _, p := range fresh {
		ix.addForm(e.Type, e.ID, p.form)
		ix.fingerprints[p.fingerprint] = struct{}{}
	}
	// The filter keeps 64 bits per distinct hash, which keeps lookups cheap, so it
	// grows once the hashes outnumber its words.
	if len(ix.chunks) > len(ix.bloom) {
		ix.resizeBloom(len(ix.chunks) * 64)
	}
	// Strings scanned before this value was known may have been cached as clean.
	ix.cache.reset()
	return nil
}

func (ix *Index) addForm(typ, id string, f *Form) {
	ok := ownerKey{typ, id, f.Part}
	ownerIdx, exists := ix.ownerIndex[ok]
	if !exists {
		ownerIdx = int32(len(ix.owners))
		ix.owners = append(ix.owners, owner{typ: typ, id: id, part: f.Part, placeholder: "ph:" + typ + ":" + id})
		ix.ownerIndex[ok] = ownerIdx
	}
	n := f.Length / chunkSize
	stored := form{
		owner:     ownerIdx,
		name:      f.Form,
		length:    f.Length,
		macs:      make([][macSize]byte, n),
		weak:      make([]bool, n),
		tailLen:   f.Length - n*chunkSize,
		formShape: formShapes[f.Form],
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
		refs, present := ix.chunks[h]
		if !present {
			ix.setBloom(h)
		}
		if len(refs) >= maxRefsPerHash {
			continue
		}
		ix.chunks[h] = append(refs, chunkRef{form: formIdx, idx: int32(i)})
	}
	if stored.tailLen > 0 {
		copy(stored.tail[:], f.Tail)
	}
	ix.forms = append(ix.forms, stored)
	ix.chunkCount += n
}

// fingerprint identifies a form of a value under its owner, so adding the same
// value twice adds nothing.
func fingerprint(typ, id string, f *Form) [32]byte {
	h := sha256.New()
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
	return IndexStats{Secrets: len(ix.secrets), Owners: len(ix.owners), Forms: len(ix.forms), Chunks: ix.chunkCount}
}

// resizeBloom rebuilds the filter with at least size bits, a power of two.
func (ix *Index) resizeBloom(size int) {
	bitsWanted := bloomMinBits
	for bitsWanted < size {
		bitsWanted <<= 1
	}
	ix.bloom = make([]uint64, bitsWanted/64)
	ix.bloomShift = uint(64 - bits.TrailingZeros(uint(bitsWanted)))
	for h := range ix.chunks {
		ix.setBloom(h)
	}
}

func (ix *Index) setBloom(h uint64) {
	bit := h >> ix.bloomShift
	ix.bloom[bit/64] |= 1 << (bit % 64)
}

func (ix *Index) bloomHas(h uint64) bool {
	bit := h >> ix.bloomShift
	return ix.bloom[bit/64]&(1<<(bit%64)) != 0
}
