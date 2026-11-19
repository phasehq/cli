package censor

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// The walk over bytes whose length must not change reads the same index a
// scan of text does: forms cut into wide chunks, values held for another
// principal without their ids, and guests' values.

// A hex form is cut into 24-byte chunks. A value whose hex reads as a message
// of small numbers, a tag and a byte each, has no field long enough to be
// scanned alone: it is found only as the one string it is, and overwritten
// from its first chunk on in every byte that is no tag.
func TestBinaryViewTakesARunOfWideChunksFromItsStart(t *testing.T) {
	// Bytes whose two hex digits are a tag of a number and its one byte.
	const tagged = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0e\x0f\x80\x81\x82\x83\x84\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
	// 30 bytes are 60 hex digits: two wide chunks and a tail.
	hidden := "\x01" + randomString(t, tagged, 28) + "\x02"
	run := hex.EncodeToString([]byte(hidden))
	if fields, ok := shapeOf([]byte(run)); !ok || len(fields) != 30 {
		t.Fatalf("the run does not read as thirty numbers: %v", fields)
	}
	ix := build(t, secret{ID: "webhook", Value: hidden})
	out, report, _ := rewriteChecked(t, ix, protoString(protoString(nil, 1, []byte("auth")), 2, []byte(run)), ScanOptions{})
	left := out[len(out)-len(run):]
	want := []byte(run)
	for i, b := range []byte("ph:secret:webhook" + strings.Repeat("*", 30-len("ph:secret:webhook"))) {
		want[2*i+1] = b
	}
	if !bytes.Equal(left, want) || report.Inventory != 1 {
		t.Fatalf("the run became %q, want %q (%+v)", left, want, report)
	}
}

// A value another principal registered is overwritten whole and without its
// id, as it is in text: ph:<type> and padding, which no later pass reads
// again. A piece of it is left, since it is matched whole or not at all.
func TestBinaryOverwritesAWithheldValueWithoutItsID(t *testing.T) {
	const theirID = "id-only-its-own-login-may-see"
	home, another := twoPrincipals(t)
	ix, err := NewIndex(home, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The other principal's entries are added first, as a store hands them over.
	theirs, mine := strongValue(t, 40), strongValue(t, 40)
	held, _ := IndexValue(another, "secret", theirID, theirs)
	if err := ix.AddLoaded(another, held, true); err != nil {
		t.Fatal(err)
	}
	own, _ := IndexValue(home, "secret", "mine", mine)
	if err := ix.Add(own); err != nil {
		t.Fatal(err)
	}
	pad := func(placeholder string, length int) string {
		return placeholder + strings.Repeat("*", length-len(placeholder))
	}
	inHex, inBase64 := hex.EncodeToString([]byte(theirs)), base64.StdEncoding.EncodeToString([]byte(theirs))
	for text, want := range map[string]string{
		"the key is " + theirs + " and " + mine + " here": "the key is " + pad("ph:secret", 40) + " and " + pad("ph:secret:mine", 40) + " here",
		"hex " + inHex + " end":                           "hex " + pad("ph:secret", len(inHex)) + " end",
		"base64 " + inBase64 + " end":                     "base64 " + pad("ph:secret", len(inBase64)) + " end",
		// What an earlier pass, or the model, wrote of it is not read again.
		"again " + pad("ph:secret", 40) + " and " + pad("ph:secret", 12) + " end": "again " + pad("ph:secret", 40) + " and " + pad("ph:secret", 12) + " end",
		// A piece of the value, and the value cut short by one character.
		"a piece " + theirs[:30] + " and " + theirs[1:] + " end": "a piece " + theirs[:30] + " and " + theirs[1:] + " end",
	} {
		for _, input := range [][]byte{protoString(protoNumber(nil, 1, 7), 2, []byte(text)), []byte(text)} {
			out, report, _ := rewriteChecked(t, ix, input, ScanOptions{})
			if got := string(out[len(out)-len(text):]); got != want {
				t.Errorf("%q became %q, want %q (%+v)", text, got, want, report)
			}
			if bytes.Contains(out, []byte(theirID)) {
				t.Errorf("the id of another principal's value was written: %q", out)
			}
			for _, finding := range report.Findings {
				if strings.Contains(finding.Placeholder, theirID) {
					t.Errorf("a finding names the id of another principal's value: %+v", finding)
				}
			}
		}
	}
	// The index's own id is known whichever principal was added first: it
	// ends where it ends, and a token written right after it is read.
	token := "gh" + "p_" + randomString(t, alnum, 36)
	text := "DB=ph:secret:mine" + token + " end"
	out, report, _ := rewriteChecked(t, ix, protoString(nil, 1, []byte(text)), ScanOptions{})
	if bytes.Contains(out, []byte(token[4:])) || !report.Found() {
		t.Errorf("a token right after the index's own placeholder was left: %q", out)
	}
	// A withheld id is no id of a placeholder this index writes: text that
	// spells one is read like any other.
	text = "DB=ph:secret:" + theirID + token + " end"
	if out, report, _ := rewriteChecked(t, ix, protoString(nil, 1, []byte(text)), ScanOptions{}); !ix.namesID("secret", "mine") || ix.namesID("secret", theirID) || bytes.Contains(out, []byte(theirID+token)) && report.Found() {
		t.Errorf("a withheld id was taken for one this index writes: %q", out)
	}
}

// A guest's value is overwritten as a withheld one is: whole, by its type
// alone, under the guest's own key.
func TestBinaryOverwritesAGuestsValueWithoutItsID(t *testing.T) {
	const guestID = "id-a-guest-registered"
	home, guest := newKey(t), newKey(t)
	ix, err := NewIndex(home, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	theirs := strongValue(t, 40)
	entries, _ := IndexValue(guest, "sealed", guestID, theirs)
	if err := ix.AddGuest(guest, entries); err != nil {
		t.Fatal(err)
	}
	inHex := hex.EncodeToString([]byte(theirs))
	for text, want := range map[string]string{
		"the key is " + theirs + " here":  "the key is ph:sealed" + strings.Repeat("*", 40-len("ph:sealed")) + " here",
		"hex " + inHex + " end":           "hex ph:sealed" + strings.Repeat("*", len(inHex)-len("ph:sealed")) + " end",
		"a piece " + theirs[:30] + " end": "a piece " + theirs[:30] + " end",
	} {
		for _, input := range [][]byte{protoString(protoNumber(nil, 1, 7), 2, []byte(text)), []byte(text)} {
			out, report, _ := rewriteChecked(t, ix, input, ScanOptions{})
			if got := string(out[len(out)-len(text):]); got != want || bytes.Contains(out, []byte(guestID)) {
				t.Errorf("%q became %q, want %q (%+v)", text, got, want, report)
			}
		}
	}
}
