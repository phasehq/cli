package censor

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// Entries of the current scheme carry 24 bits of a chunk's rolling hash, never
// the whole: with the key, the whole gives a 12-character chunk in 2^36 steps.
func TestEntriesCarryNoWholeRollingHash(t *testing.T) {
	key := newKey(t)
	values := map[string]string{
		"letters and digits": randomString(t, alnum, 40),
		"a short hex value":  randomString(t, lowerHex, 20),
		"a hex key":          randomString(t, lowerHex, 64),
		"a PEM key":          fakePEM(t),
	}
	for name, value := range values {
		e, err := IndexValue(key, "secret", "id", value)
		if err != nil || !e.Protected() || e.Version != EntriesVersion {
			t.Fatalf("%s: %v", name, err)
		}
		for _, f := range e.Forms {
			c := chunkSize
			if f.Wide {
				c = 2 * chunkSize
			}
			n := f.Length / c
			if len(f.Rolls) != 0 || len(f.Lookups) != 3*n {
				t.Fatalf("%s, form %s: %d bytes of rolling hash and %d of lookups for %d chunks", name, f.Form, len(f.Rolls), len(f.Lookups), n)
			}
			// What is kept is the top 24 bits and nothing else of the hash.
			form := []byte(value)
			if f.Form != formRaw || f.Part != "" || strings.TrimSpace(value) != value {
				continue
			}
			for i := 0; i < n; i++ {
				roll := key.roll(form[i*c : (i+1)*c])
				if got := schemes[e.Version].lookupAt(&f, i); got != roll>>40 {
					t.Fatalf("%s: chunk %d is looked up by %x, the hash is %x", name, i, got, roll)
				}
				var whole [8]byte
				for at := range whole {
					whole[at] = byte(roll >> (8 * at))
				}
				if wire, _ := e.Marshal(); bytes.Contains(wire, whole[:]) {
					t.Fatalf("%s: the wire form holds a whole rolling hash", name)
				}
			}
		}
		wire, err := e.Marshal()
		if err != nil || bytes.Contains(wire, []byte(`"rolls"`)) {
			t.Fatalf("%s: the wire form names rolling hashes: %v", name, err)
		}
		// Entries that add the whole hash to a current-scheme form are refused.
		e.Forms[0].Rolls = make([]byte, 8*(len(e.Forms[0].Lookups)/3))
		if _, err := e.Marshal(); err == nil {
			t.Fatalf("%s: entries with a whole rolling hash were accepted", name)
		}
	}
	if SchemeStorable(1) || !SchemeStorable(EntriesVersion) || SchemeStorable(99) {
		t.Fatal("only schemes that keep no whole rolling hash may be stored")
	}
}

// Two chunks that share a lookup value are both found: the confirming hash
// tells them apart, within one form and across values.
func TestChunksSharingALookupValueAreBothFound(t *testing.T) {
	key := newKey(t)
	byLookup := map[uint64]string{}
	var first, second string
	for first == "" {
		chunk := randomString(t, alnum, chunkSize)
		if entropy(chunk) < weakChunkEntropy+0.2 {
			continue
		}
		at := key.roll([]byte(chunk)) >> 40
		if other, seen := byLookup[at]; seen && other != chunk {
			first, second = other, chunk
		}
		byLookup[at] = chunk
	}
	pad := func() string { return randomString(t, alnum, chunkSize) }
	one := pad() + first + pad() + second + pad()
	another := second + pad() + pad()
	ix, _ := buildWithEntries(t, key, secret{ID: "one", Type: "secret", Value: one}, secret{ID: "another", Type: "secret", Value: another})
	for name, text := range map[string]string{
		"the first of the pair":  "left " + one[:2*chunkSize] + " right",
		"the second of the pair": "left " + one[3*chunkSize:] + " right",
		"the other value":        "left " + another + " right",
	} {
		if got := found(t, ix, text); got == "" {
			t.Fatalf("%s was not found", name)
		}
	}
	// Each chunk alone, away from its neighbours, is found by its own hash.
	for name, chunk := range map[string]string{"first": first, "second": second} {
		if spans := ix.findSpans([]byte("-- " + chunk + " --")); len(spans) == 0 {
			t.Fatalf("the %s chunk of the pair is not looked up", name)
		}
	}
}

// Looked up by 24 bits or by the whole hash, a whole value is found in every
// form: what scheme 1 finds of one, scheme 2 finds.
func TestSchemeTwoFindsEveryWholeValueSchemeOneFinds(t *testing.T) {
	for _, alphabet := range []string{lowerHex, "0123456789ABCDEF", "0123456789"} {
		for L := 12; L <= 80; L++ {
			key, _ := NewKey()
			value := randomString(t, alphabet, L)
			ix1, _ := NewIndex(key, IndexOptions{})
			ix2, _ := NewIndex(key, IndexOptions{})
			e1, _ := IndexValueScheme(key, 1, "secret", "id", value)
			e2, _ := IndexValueScheme(key, 2, "secret", "id", value)
			if !e1.Protected() {
				continue
			}
			_ = ix1.Add(e1)
			_ = ix2.Add(e2)
			texts := map[string]string{
				"raw":        "x " + value + " y",
				"quoted":     `{"k":"` + value + `"}`,
				"b64":        "x " + base64.StdEncoding.EncodeToString([]byte(value)) + " y",
				"b64raw":     "x " + base64.RawStdEncoding.EncodeToString([]byte(value)) + " y",
				"b64basic":   "Basic " + base64.StdEncoding.EncodeToString([]byte("user:"+value)),
				"b64basic2":  "Basic " + base64.StdEncoding.EncodeToString([]byte("u:"+value+":zz")),
				"b64url":     "x " + base64.URLEncoding.EncodeToString([]byte("abcd"+value)) + " y",
				"hex":        "x " + hex.EncodeToString([]byte(value)) + " y",
				"HEX":        "x " + strings.ToUpper(hex.EncodeToString([]byte(value))) + " y",
				"adjacent":   "abc" + value + "xyz",
				"underscore": "key_" + value + "_end",
				"hexprefix":  "deadbeef" + value + "cafe",
			}
			for name, text := range texts {
				if len(ix1.Find([]byte(text))) > 0 && len(ix2.Find([]byte(text))) == 0 {
					t.Errorf("alphabet %q len %d %s: scheme 1 finds the whole value, scheme 2 does not", alphabet[:10], L, name)
				}
			}
		}
	}
}
