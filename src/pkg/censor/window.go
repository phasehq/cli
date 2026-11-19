package censor

import "math/bits"

// A window is the chunks of one size, and what a scan needs to find them: the
// rolling hash's power for that size, the chunks by hash, and a filter in
// front of them. Schemes that cut chunks the same way share a window, and a
// scan makes one pass per window that holds anything, so an index of one
// scheme costs what it did before there were several.
type window struct {
	// key is the lookup key the chunks here are rolled under: the index's, or
	// a guest's, which is then a window, and a pass, of its own.
	key  *Key
	size int
	// runs says every chunk here is made of letters and digits, so the pass
	// only rolls inside runs of them that are at least a chunk long.
	runs bool
	// drop is how many low bits of a rolling hash chunks here are not filed
	// under: 0 for a whole hash, 40 for 24 bits. Windows differ by it.
	drop       uint
	outPow     uint64
	chunks     map[uint64][]chunkRef
	bloom      []uint64
	bloomShift uint
}

// classWide is what a wide chunk can hold: letters and digits. Hex digits
// are, and so is the base64 of text made of them: a hex digit's byte has
// 0011, 0100 or 0110 in its high half, which leaves no place in a group of
// three for the six set bits, or the five and a zero, of the two characters
// of a base64 alphabet that are not letters or digits. Paths, names with an
// underscore and identifiers with dashes are therefore not runs.
var classWide [256]bool

func init() {
	for _, b := range []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") {
		classWide[b] = true
	}
}

// windowFor returns the window for chunks of a size, making it when it is the
// first of them. Called with the index's lock held.
func (ix *Index) windowFor(key *Key, size int, runs bool, lookupBits int) *window {
	drop := uint(64 - lookupBits)
	for _, w := range ix.windows {
		if w.size == size && w.runs == runs && w.drop == drop && w.key.lookup == key.lookup {
			return w
		}
	}
	if key.lookup == ix.key.lookup {
		key = ix.key
	}
	w := &window{key: key, size: size, runs: runs, drop: drop, outPow: 1, chunks: map[uint64][]chunkRef{}}
	for i := 0; i < size-1; i++ {
		w.outPow *= key.base
	}
	w.resizeBloom(bloomMinBits)
	ix.windows = append(ix.windows, w)
	return w
}

// add files a chunk under its lookup value (its rolling hash less the bits
// the window drops), within the bound on how many chunks one value leads to.
func (w *window) add(h uint64, ref chunkRef) {
	refs, present := w.chunks[h]
	if !present {
		w.setBloom(h)
	}
	if len(refs) >= maxRefsPerHash {
		return
	}
	w.chunks[h] = append(refs, ref)
}

// grow keeps 64 bits of filter per distinct hash, which keeps lookups cheap.
func (w *window) grow() {
	if len(w.chunks) > len(w.bloom) && len(w.bloom)*64 < w.maxBloomBits() {
		w.resizeBloom(len(w.chunks) * 64)
	}
}

// maxBloomBits bounds the filter: it is read by the top bits of a hash, and
// has no more of them than a lookup value holds.
func (w *window) maxBloomBits() int { return 1 << min(64-w.drop, 30) }

// resizeBloom rebuilds the filter with at least size bits, a power of two.
func (w *window) resizeBloom(size int) {
	bitsWanted := bloomMinBits
	for bitsWanted < size && bitsWanted < w.maxBloomBits() {
		bitsWanted <<= 1
	}
	w.bloom = make([]uint64, bitsWanted/64)
	w.bloomShift = uint(64 - bits.TrailingZeros(uint(bitsWanted)))
	for h := range w.chunks {
		w.setBloom(h)
	}
}

func (w *window) setBloom(h uint64) {
	bit := h >> (w.bloomShift - w.drop)
	w.bloom[bit/64] |= 1 << (bit % 64)
}

// spanSearch is what the passes of one scan share.
type spanSearch struct {
	data  []byte
	tried map[tryKey]int
	// covered is how far each form's verified chunks already reach. A chunk
	// inside them is part of a match already extended, so trying it again would
	// only walk the same bytes, once per repeat of a repeating value.
	covered map[int32]int
	spans   []span
}

// findSpans returns every place in data where a chunk of an indexed form verified,
// widened to as much of the form's extent as could be confirmed.
func (ix *Index) findSpans(data []byte) []span {
	search := spanSearch{data: data}
	for _, w := range ix.windows {
		if len(data) < w.size || len(w.chunks) == 0 {
			continue
		}
		if !w.runs {
			ix.roll(w, &search, 0, len(data))
			continue
		}
		// A run long enough to hold a chunk covers one of every w.size
		// positions, so only those are looked at, and the run around one that
		// could be part of a chunk. Ordinary text costs a fraction of a look
		// per byte this way. Everything before floor has been looked at.
		floor := 0
		for at := w.size - 1; at < len(data); {
			if !classWide[data[at]] {
				floor = at + 1
				at += w.size
				continue
			}
			start, end := at, at+1
			for start > floor && classWide[data[start-1]] {
				start--
			}
			for end < len(data) && classWide[data[end]] {
				end++
			}
			if end-start >= w.size {
				ix.roll(w, &search, start, end)
			}
			floor = end + 1
			at = end + w.size
		}
	}
	return search.spans
}

// roll looks for the chunks of one window in data[from:to].
func (ix *Index) roll(w *window, search *spanSearch, from, to int) {
	c := w.size
	k := w.key
	data := search.data
	// The loop reads these at every byte.
	bloom, shift, drop, outPow, base, table := w.bloom, w.bloomShift, w.drop, w.outPow, k.base, &k.table
	h := k.roll(data[from : from+c])
	for p := from; ; p++ {
		if bit := h >> shift; bloom[bit/64]&(1<<(bit%64)) != 0 {
			if refs, ok := w.chunks[h>>drop]; ok {
				// One confirming hash per key the candidates here were made
				// under: nearly always one, and one per principal otherwise.
				var here [macSize]byte
				hashed := int32(-1)
				for _, ref := range refs {
					f := &ix.forms[ref.form]
					if end, ok := search.covered[ref.form]; ok && p+c <= end {
						continue
					}
					if hashed != f.macKey {
						here, hashed = mac(&ix.macKeys[f.macKey], data[p:p+c]), f.macKey
					}
					if here != f.macs[ref.idx] {
						continue
					}
					if search.tried == nil {
						search.tried = map[tryKey]int{}
						search.covered = map[int32]int{}
					}
					if found, ok := ix.try(data, p, ref, search.tried); ok {
						search.spans = append(search.spans, found)
						reach := found.checked
						// A base64 or hex match took its whole run, and another
						// copy further on in the run would take the same.
						if f.wholeRun {
							reach = found.end
						}
						search.covered[ref.form] = max(search.covered[ref.form], reach)
					}
				}
			}
		}
		if p+c >= to {
			break
		}
		h = (h-table[data[p]]*outPow)*base + table[data[p+c]]
	}
}
