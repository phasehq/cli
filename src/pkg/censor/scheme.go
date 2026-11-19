package censor

import (
	"errors"
	"fmt"
	"sort"
)

// A scheme is one way of turning a value into Entries and of matching them:
// see "Matching schemes" in the package documentation for what a version
// covers. Entries name their scheme in Version, and an Index matches every
// scheme listed here side by side, so entries stored under an older scheme
// keep working beside those of the current one.
//
// Adding a scheme is adding a value here and to schemes. A scheme that only
// changes the fields below needs nothing else; one that changes the hash
// construction or the encoded forms also adds what it needs beside what the
// older schemes use, and leaves theirs alone.
type scheme struct {
	version int
	// chunk is the size of the chunks a form is cut into.
	chunk int
	// wide is the chunk of a form marked Wide, or 0 when no form may be. A
	// wide chunk is made of letters and digits only (see classWide), so the
	// scan looks for one only inside a run of them.
	wide int
	// tailWithChunk says the tail hash covers the last whole chunk as well as
	// the bytes after it, so that it cannot be tested on fewer bytes than a
	// chunk.
	tailWithChunk bool
	// shapes are the encoded forms the scheme knows, and how each is matched.
	shapes map[string]formShape
}

var (
	// scheme1 cuts every form into 12-byte chunks and hashes the tail alone.
	scheme1 = &scheme{version: 1, chunk: chunkSize, shapes: formShapes}
	// scheme2 stores the chunks of a form made of hex digits, and of the
	// base64 of a value made of hex digits, in pairs: one hash over 24
	// characters, where a 12-character chunk of such a form carries 48 bits of
	// the value or fewer and could be found by trying them all, by someone
	// who holds the key and the stored entries. The tail is hashed with the
	// chunk before it for the same reason.
	scheme2 = &scheme{version: 2, chunk: chunkSize, wide: 2 * chunkSize, tailWithChunk: true, shapes: formShapes}

	// schemes are the schemes this build matches. Tests add to it.
	schemes = map[int]*scheme{scheme1.version: scheme1, scheme2.version: scheme2}
)

// SchemeSupported reports whether this build matches entries of a scheme.
// Entries of any other scheme are refused by ParseEntries and Index.Add: a
// store that holds them keeps them for the build that reads them.
func SchemeSupported(version int) bool {
	return schemes[version] != nil
}

// SupportedSchemes lists the schemes this build matches, oldest first.
func SupportedSchemes() []int {
	versions := make([]int, 0, len(schemes))
	for version := range schemes {
		versions = append(versions, version)
	}
	sort.Ints(versions)
	return versions
}

// IndexValueScheme is IndexValue under a scheme this build still matches,
// for a client whose daemon reads an older one. IndexValue uses the current
// scheme, EntriesVersion.
func IndexValueScheme(key *Key, version int, typ, id, value string) (*Entries, error) {
	s := schemes[version]
	if s == nil {
		return nil, fmt.Errorf("entries version %d is not supported", version)
	}
	return indexValue(key, s, typ, id, value)
}

// chunkFor is the chunk one form of value is cut into, and whether that is
// the wide one. A form too short to hold a wide chunk keeps the plain one, so
// a short value is still found.
func (s *scheme) chunkFor(candidate rawForm, value string) (int, bool) {
	if s.wide == 0 || len(candidate.bytes) < s.wide {
		return s.chunk, false
	}
	base64Form := candidate.name == formBase64 || candidate.name == formBase64URL
	if isHex(string(candidate.bytes)) || (base64Form && isHex(value)) {
		return s.wide, true
	}
	return s.chunk, false
}

// chunkOf is the chunk a received form says it was cut into. A hex form long
// enough for wide chunks must use them: its plain chunks are what the scheme
// exists to keep out of an index.
func (s *scheme) chunkOf(f *Form) (int, error) {
	if !f.Wide {
		if s.wide != 0 && f.Form == formHex && f.Length >= s.wide {
			return 0, errors.New("a hex form must use wide chunks")
		}
		return s.chunk, nil
	}
	if s.wide == 0 {
		return 0, errors.New("this version has no wide chunks")
	}
	return s.wide, nil
}

// tailBack is how far before the tail its hash begins: over the last whole
// chunk too, from scheme 2.
func (s *scheme) tailBack(chunk int) int {
	if s.tailWithChunk {
		return chunk
	}
	return 0
}
