package censor

import "bytes"

// publicSet is the lookup value of every chunk-sized piece of an index's
// public texts under one lookup key, by chunk size and bits kept.
type publicSet map[publicPiece][]publicAt

type publicPiece struct {
	size, bits int
	value      uint64
}

// publicAt is where a piece sits: which public text, and how far in.
type publicAt struct{ text, at int }

// publicPieces is the set for a lookup key, made the first time it is asked for.
func (ix *Index) publicPieces(key *Key) publicSet {
	if set, made := ix.publicSets[key.lookup]; made {
		return set
	}
	set := publicSet{}
	done := map[[2]int]bool{}
	for _, s := range schemes {
		for _, size := range []int{s.chunk, s.wide} {
			if size == 0 || done[[2]int{size, s.lookupBits}] {
				continue
			}
			done[[2]int{size, s.lookupBits}] = true
			for text, public := range ix.public {
				for at := 0; at+size <= len(public); at++ {
					piece := publicPiece{size: size, bits: s.lookupBits, value: s.lookup(key.roll(public[at : at+size]))}
					set[piece] = append(set[piece], publicAt{text: text, at: at})
				}
			}
		}
	}
	// The index's own key, its live key and the few guests' lookup keys.
	if len(ix.publicSets) <= maxGuestKeys+1 {
		ix.publicSets[key.lookup] = set
	}
	return set
}

// publicParts is what of one value's entries the index's public texts hold.
type publicParts struct {
	// whole are the forms that stand whole in a public text, by position, and
	// pieces the chunks of each form that are a piece of one.
	whole  map[int]bool
	pieces map[int][]int
}

// publicIn finds what of entries a public text holds. value says the value
// itself is in one, or every form of it: held, every request would hold it.
func (ix *Index) publicIn(key *Key, s *scheme, confirming *[32]byte, e *Entries) (parts publicParts, value bool) {
	if len(ix.public) == 0 || len(e.Forms) == 0 {
		return parts, false
	}
	set := ix.publicPieces(key)
	for i := range e.Forms {
		f := &e.Forms[i]
		c, _ := s.chunkOf(f)
		for j := 0; j < f.Length/c; j++ {
			for _, piece := range set[publicPiece{size: c, bits: s.lookupBits, value: s.lookupAt(f, j)}] {
				text := ix.public[piece.text]
				if sum := mac(confirming, text[piece.at:piece.at+c]); !bytes.Equal(sum[:], f.MACs[j*macSize:(j+1)*macSize]) {
					continue
				}
				if parts.pieces == nil {
					parts.whole, parts.pieces = map[int]bool{}, map[int][]int{}
				}
				parts.pieces[i] = append(parts.pieces[i], j)
				start := piece.at - j*c
				if parts.whole[i] || start < 0 || start+f.Length > len(text) || !s.stands(confirming, f, c, text[start:start+f.Length]) {
					continue
				}
				parts.whole[i] = true
				value = value || (f.Part == "" && f.Form != formLine)
			}
		}
	}
	return parts, value || len(parts.whole) == len(e.Forms)
}

// stands reports that text, as long as the form, is the form: every chunk
// and the tail confirm.
func (s *scheme) stands(confirming *[32]byte, f *Form, c int, text []byte) bool {
	n := f.Length / c
	for j := 0; j < n; j++ {
		if sum := mac(confirming, text[j*c:(j+1)*c]); !bytes.Equal(sum[:], f.MACs[j*macSize:(j+1)*macSize]) {
			return false
		}
	}
	if len(text) == n*c {
		return true
	}
	sum := mac(confirming, text[n*c-s.tailBack(c):])
	return bytes.Equal(sum[:], f.Tail)
}
