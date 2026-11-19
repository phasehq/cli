package censor

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// found is the placeholder of the one inventory finding in text, or "".
func found(t *testing.T, ix *Index, text string) string {
	t.Helper()
	out, report := ix.Redact([]byte(text))
	if len(report.Findings) == 0 {
		if string(out) != text {
			t.Fatalf("text changed with no finding: %q", out)
		}
		return ""
	}
	return report.Findings[0].Placeholder
}

// Entries of scheme 1 and of scheme 2 are matched by one index, each as its
// own scheme matches: a build that moves to a newer scheme keeps protecting
// what was stored under the older one.
func TestSchemesMatchSideBySide(t *testing.T) {
	key := newKey(t)
	ix, err := NewIndex(key, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	older, newer := randomString(t, alnum, 50), randomString(t, alnum, 50)
	for _, v := range []struct {
		scheme    int
		id, value string
	}{{1, "older", older}, {2, "newer", newer}} {
		e, err := IndexValueScheme(key, v.scheme, "secret", v.id, v.value)
		if err != nil || e.Version != v.scheme {
			t.Fatalf("%v %+v", err, e)
		}
		if err := ix.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	for name, tc := range map[string]struct{ text, want string }{
		"scheme 1, raw":    {"a " + older + " b", "ph:secret:older"},
		"scheme 2, raw":    {"a " + newer + " b", "ph:secret:newer"},
		"scheme 1, hex":    {"a " + hex.EncodeToString([]byte(older)) + " b", "ph:secret:older"},
		"scheme 2, hex":    {"a " + hex.EncodeToString([]byte(newer)) + " b", "ph:secret:newer"},
		"scheme 1, base64": {"a " + base64.StdEncoding.EncodeToString([]byte(older)) + " b", "ph:secret:older"},
		"scheme 2, base64": {"a " + base64.StdEncoding.EncodeToString([]byte(newer)) + " b", "ph:secret:newer"},
		// Twelve hex characters are a chunk in scheme 1 and half of one in
		// scheme 2: two of them next to each other are found in both.
		"scheme 1, part of hex": {"a " + hex.EncodeToString([]byte(older))[24:48] + " b", "ph:secret:older"},
		"scheme 2, part of hex": {"a " + hex.EncodeToString([]byte(newer))[24:48] + " b", "ph:secret:newer"},
	} {
		if got := found(t, ix, tc.text); got != tc.want {
			t.Errorf("%s: found %q", name, got)
		}
	}
	if stats := ix.Stats(); stats.Secrets != 2 {
		t.Fatalf("%+v", stats)
	}
}

// Entries of a newer scheme never replace an older scheme's under the same
// placeholder: a key name is shared, so they may be another value's.
func TestSchemesNeverReplaceByPlaceholder(t *testing.T) {
	key := newKey(t)
	ix, err := NewIndex(key, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	add := func(scheme int, value string) *Entries {
		t.Helper()
		e, err := IndexValueScheme(key, scheme, "secret", "DATABASE_URL", value)
		if err != nil {
			t.Fatal(err)
		}
		if err := ix.Add(e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	staging, production := randomString(t, alnum, 40), randomString(t, alnum, 40)
	older := add(1, staging)
	add(2, production)
	for name, value := range map[string]string{"the older scheme's value": staging, "the newer scheme's value": production} {
		if got := found(t, ix, "x "+value+" y"); got != "ph:secret:DATABASE_URL" {
			t.Fatalf("%s is no longer matched: %q", name, got)
		}
	}
	// The same value under both schemes is matched once and held twice.
	before := ix.Stats()
	add(2, staging)
	if after := ix.Stats(); after.Secrets != 1 || after.Chunks <= before.Chunks {
		t.Fatalf("before %+v, after %+v", before, after)
	}
	held := ix.Stats()
	if err := ix.Add(older); err != nil {
		t.Fatal(err)
	}
	if got, stats := found(t, ix, "x "+staging+" y"), ix.Stats(); got != "ph:secret:DATABASE_URL" || stats != held {
		t.Fatalf("adding the older entries again: %q, %+v then %+v", got, held, stats)
	}
}

// A scheme this build does not know is refused whole: nothing of it is
// matched, and nothing of it is taken into the index.
func TestUnknownSchemeIsRefused(t *testing.T) {
	key := newKey(t)
	e, err := IndexValue(key, "secret", "k", randomString(t, alnum, 40))
	if err != nil {
		t.Fatal(err)
	}
	e.Version = 7
	ix, _ := NewIndex(key, IndexOptions{})
	if err := ix.Add(e); err == nil || ix.Stats() != (IndexStats{}) {
		t.Fatalf("%v %+v", err, ix.Stats())
	}
	if SchemeSupported(7) || !SchemeSupported(1) || !SchemeSupported(EntriesVersion) {
		t.Fatal("SchemeSupported")
	}
	if _, err := IndexValueScheme(key, 7, "secret", "k", "0123456789abcdefgh"); err == nil {
		t.Fatal("indexed under an unknown scheme")
	}
	if got := SupportedSchemes(); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("%v", got)
	}
}

// A later scheme is a value beside the others: this one, known to the test
// only, cuts 16-byte chunks. Its entries match beside those of the shipped
// schemes, and replace none of them.
func TestAddingASchemeIsAddingAMatcher(t *testing.T) {
	const version = 90
	schemes[version] = &scheme{version: version, chunk: 16, tailWithChunk: true, lookupBits: 20, shapes: formShapes}
	t.Cleanup(func() { delete(schemes, version) })

	key := newKey(t)
	ix, err := NewIndex(key, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	current, later, older := everyChunkCounts(t, alnum, 64), everyChunkCounts(t, alnum, 64), everyChunkCounts(t, alnum, 64)
	for _, v := range []struct {
		scheme    int
		id, value string
	}{{EntriesVersion, "current", current}, {version, "later", later}, {1, "moved", older}} {
		e, err := IndexValueScheme(key, v.scheme, "secret", v.id, v.value)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := e.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseEntries(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := ix.Add(parsed); err != nil {
			t.Fatal(err)
		}
	}
	for name, tc := range map[string]struct{ text, want string }{
		"current, whole":             {"a " + current + " b", "ph:secret:current"},
		"later, whole":               {"a " + later + " b", "ph:secret:later"},
		"later, hex":                 {"a " + hex.EncodeToString([]byte(later)) + " b", "ph:secret:later"},
		"current, one of its chunks": {"a " + current[12:24] + " b", "ph:secret:current"},
		"later, one of its chunks":   {"a " + later[16:32] + " b", "ph:secret:later"},
		// Twelve bytes are no chunk of the later scheme.
		"later, less than a chunk": {"a " + later[16:28] + " b", ""},
	} {
		if got := found(t, ix, tc.text); got != tc.want {
			t.Errorf("%s: found %q", name, got)
		}
	}
	// The value indexed again under the later scheme is held under both.
	moved, err := IndexValueScheme(key, version, "secret", "moved", older)
	if err != nil {
		t.Fatal(err)
	}
	before := ix.Stats()
	if err := ix.Add(moved); err != nil {
		t.Fatal(err)
	}
	if after := ix.Stats(); after.Secrets != before.Secrets || after.Chunks <= before.Chunks {
		t.Fatalf("before %+v, after %+v", before, after)
	}
	if got := found(t, ix, "a "+older[12:24]+" b"); got != "ph:secret:moved" {
		t.Fatalf("the older scheme's chunk is no longer matched: %q", got)
	}
}

// holdsHashOf reports whether the entries hold the rolling hash or the
// confirming hash of data.
func holdsHashOf(key *Key, e *Entries, data []byte) bool {
	mac := mac(key.macFor(schemes[e.Version]), data)
	roll := binary.LittleEndian.AppendUint64(nil, key.roll(data))
	for _, f := range e.Forms {
		if bytes.Contains(f.MACs, mac[:]) || bytes.Equal(f.Tail, mac[:]) {
			return true
		}
		for at := 0; at+3 <= len(f.Lookups); at += 3 {
			if schemes[e.Version].lookupAt(&f, at/3) == key.roll(data)>>40 {
				return true
			}
		}
		for at := 0; at+8 <= len(f.Rolls); at += 8 {
			if bytes.Equal(f.Rolls[at:at+8], roll) {
				return true
			}
		}
	}
	return false
}

// In scheme 2 the entries hold no hash of fewer than 24 characters of a form
// made of hex digits or of the base64 of a hex value, and no hash of a tail
// alone: whoever has the key and the entries has no 12-character piece to
// try. Scheme 1 holds them, which is what the scheme changed.
func TestHexFormsAreStoredInPairs(t *testing.T) {
	key := newKey(t)
	hexValue := randomString(t, lowerHex, 70)
	text := randomString(t, alnum, 47)
	encode := base64.StdEncoding.EncodeToString
	thin := map[string]string{
		"a hex value":               hexValue,
		"the hex of a value, upper": strings.ToUpper(hex.EncodeToString([]byte(text))),
		"the hex of a value":        hex.EncodeToString([]byte(text)),
		"the base64 of a hex value": encode([]byte(hexValue)),
		"that base64, shifted":      encode([]byte("ab" + hexValue))[3 : 3+88],
	}
	for _, scheme := range []int{1, 2} {
		var all []*Entries
		for id, value := range map[string]string{"hexkey": hexValue, "text": text} {
			e, err := IndexValueScheme(key, scheme, "secret", id, value)
			if err != nil || !e.Protected() {
				t.Fatalf("%v", err)
			}
			all = append(all, e)
		}
		for name, form := range thin {
			short := 0
			for size := 1; size < 24; size++ {
				for at := 0; at+size <= len(form); at++ {
					for _, e := range all {
						if holdsHashOf(key, e, []byte(form[at:at+size])) {
							short++
						}
					}
				}
			}
			if scheme == 1 && short == 0 {
				t.Errorf("scheme 1, %s: the test finds no hash of a short piece, so it proves nothing of scheme 2", name)
			}
			if scheme == 2 && short != 0 {
				t.Errorf("scheme 2, %s: %d hashes of pieces shorter than 24 characters", name, short)
			}
		}
		// A form that is not thin keeps 12-byte chunks, and from scheme 2 its
		// tail is hashed with the chunk before it.
		for _, e := range all {
			if e.ID != "text" {
				continue
			}
			if !holdsHashOf(key, e, []byte(text[12:24])) {
				t.Errorf("scheme %d: the value's own chunks are not 12 bytes", scheme)
			}
			if alone := holdsHashOf(key, e, []byte(text[36:])); alone != (scheme == 1) {
				t.Errorf("scheme %d: a hash of the 11-byte tail alone: %v", scheme, alone)
			}
			if scheme == 2 && !holdsHashOf(key, e, []byte(text[24:])) {
				t.Error("scheme 2: no hash of the last chunk with the tail")
			}
		}
	}
}

// What a piece of a paired form does: it is caught for certain from 47
// characters (twice 24, less one), at some offsets from 24, and never below.
// The whole form is found as before, and so is the value in every other form.
func TestPiecesOfPairedForms(t *testing.T) {
	var hexValue string
	for plain := true; plain; {
		hexValue = randomString(t, lowerHex, 96)
		plain = false
		for at := 0; at+24 <= len(hexValue); at += 24 {
			plain = plain || entropy(hexValue[at:at+24]) < weakChunkEntropy
		}
	}
	ix := build(t, secret{ID: "hexkey", Value: hexValue})
	for _, length := range []int{12, 23, 24, 35, 46, 47, 60} {
		caught, total := 0, 0
		for offset := 0; offset+length <= len(hexValue); offset++ {
			total++
			if found(t, ix, "the key starts "+hexValue[offset:offset+length]+" and goes on") != "" {
				caught++
			}
		}
		t.Logf("%2d characters of a hex value: caught at %d of %d offsets", length, caught, total)
		switch {
		case length < 24 && caught != 0:
			t.Errorf("%d characters were caught at %d offsets", length, caught)
		case length >= 24 && length < 47 && (caught == 0 || caught == total):
			t.Errorf("%d characters: caught at %d of %d offsets", length, caught, total)
		case length >= 47 && caught != total:
			t.Errorf("%d characters must always be caught: %d of %d", length, caught, total)
		}
	}
	for name, text := range map[string]string{
		"whole":           hexValue,
		"base64":          base64.StdEncoding.EncodeToString([]byte(hexValue)),
		"base64, shifted": base64.StdEncoding.EncodeToString([]byte("user:" + hexValue)),
		"hex of it":       hex.EncodeToString([]byte(hexValue)),
		"in a URL":        "https://example.com/?key=" + hexValue + "&x=1",
	} {
		if got := found(t, ix, "see "+text+" there"); got != "ph:secret:hexkey" {
			t.Errorf("%s: found %q", name, got)
		}
	}
	// A hex value too short for a pair keeps a 12-character chunk, so it is
	// still found.
	short := randomString(t, lowerHex, 20)
	for entropy(short) < 3 {
		short = randomString(t, lowerHex, 20)
	}
	if got := found(t, build(t, secret{ID: "short", Value: short}), "pin "+short+" end"); got != "ph:secret:short" {
		t.Errorf("a 20-character hex value: found %q", got)
	}
}

// The scan looks for wide chunks only inside runs of letters and digits, so
// every form the indexer marks wide has to be made of them.
func TestWideFormsAreLettersAndDigits(t *testing.T) {
	for i := 0; i < 200; i++ {
		alphabet := []string{lowerHex, strings.ToUpper(lowerHex), lowerHex + "ABCDEF"}[i%3]
		value := randomString(t, alphabet, 24+i%41)
		wide := 0
		for _, candidate := range encodedForms(value) {
			if _, isWide := scheme2.chunkFor(candidate, value); !isWide {
				continue
			}
			wide++
			for _, b := range candidate.bytes {
				if !classWide[b] {
					t.Fatalf("a wide %s form of %d hex digits holds %q", candidate.name, len(value), b)
				}
			}
		}
		// The value, its hex in both cases, and its base64 at three alignments
		// in two alphabets.
		if wide < 9 {
			t.Fatalf("%d wide forms of a %d-digit hex value", wide, len(value))
		}
	}
}
