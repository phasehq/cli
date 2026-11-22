package censor

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// twoPrincipals is one lookup key with two principals' confirming keys.
func twoPrincipals(t testing.TB) (a, b *Key) {
	t.Helper()
	a = newKey(t)
	b, err := a.WithConfirm(newKey(t).ConfirmBytes())
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

// confirmingHashes are every hash in entries that confirms a chunk or a tail.
func confirmingHashes(e *Entries) map[[macSize]byte]bool {
	hashes := map[[macSize]byte]bool{}
	for _, f := range e.Forms {
		for at := 0; at+macSize <= len(f.MACs); at += macSize {
			hashes[[macSize]byte(f.MACs[at:at+macSize])] = true
		}
		if len(f.Tail) == macSize {
			hashes[[macSize]byte(f.Tail)] = true
		}
	}
	return hashes
}

// A client with the lookup key, its own confirming key and every stored
// entry guesses another principal's value outright, and confirms nothing.
func TestAClientConfirmsOnlyItsOwnPrincipalsEntries(t *testing.T) {
	keyA, keyB := twoPrincipals(t)
	valueA, valueB := randomString(t, alnum, 40), randomString(t, alnum, 40)
	hexB := randomHex(t, 32)
	storedA, err := IndexValue(keyA, "secret", "mine", valueA)
	if err != nil {
		t.Fatal(err)
	}
	for name, guess := range map[string]string{"letters and digits": valueB, "hex": hexB} {
		storedB, err := IndexValue(keyB, "secret", "theirs", guess)
		if err != nil {
			t.Fatal(err)
		}
		theirs := confirmingHashes(storedB)
		// The best the client can compute for a guess: every hash IndexValue
		// makes of it, under each key it holds and each scheme.
		attempts := map[string]*Entries{}
		if attempts["own confirming key"], err = IndexValue(keyA, "secret", "theirs", guess); err != nil {
			t.Fatal(err)
		}
		if attempts["lookup key, scheme 1"], err = IndexValueScheme(keyA, 1, "secret", "theirs", guess); err != nil {
			t.Fatal(err)
		}
		lookupOnly, err := LookupKeyFromBytes(keyA.LookupBytes())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := IndexValue(lookupOnly, "secret", "theirs", guess); err == nil {
			t.Fatal("a lookup key alone indexed under scheme 2")
		}
		for how, attempt := range attempts {
			if len(attempt.Forms) == 0 || len(theirs) == 0 {
				t.Fatalf("%s: nothing was hashed", name)
			}
			for hash := range confirmingHashes(attempt) {
				if theirs[hash] {
					t.Fatalf("%s: a guess hashed with the %s confirms the other principal's entry", name, how)
				}
			}
		}
		// What the lookup key does give, to anyone: the stored 24 bits.
		own := attempts["own confirming key"]
		for i := range storedB.Forms {
			if !bytes.Equal(own.Forms[i].Lookups, storedB.Forms[i].Lookups) || len(storedB.Forms[i].Lookups) != 3*(len(storedB.Forms[i].MACs)/macSize) {
				t.Fatalf("%s: the lookup values are not the shared 24 bits a chunk", name)
			}
		}
		// And through an index of its own: the other's entries taken for the
		// client's find nothing, in a text that holds the value whole.
		index, err := NewIndex(keyA, IndexOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := index.AddKeyed(keyA, storedB); err != nil {
			t.Fatal(err)
		}
		if hits := apply(index, []byte("a "+guess+" b")).Hits; len(hits) != 0 {
			t.Fatalf("%s: the client confirmed the other principal's value: %+v", name, hits)
		}
	}
	// Its own principal's entries it confirms, as it could read them anyway.
	again, err := IndexValue(keyA, "secret", "mine", valueA)
	if err != nil || !reflect.DeepEqual(again, storedA) {
		t.Fatalf("the client's own entries do not confirm: %v", err)
	}
}

// One index matches every principal: the same value registered by two is
// held, and counted, once for each, each confirmed with its own key.
func TestIndexMatchesEveryPrincipal(t *testing.T) {
	keyA, keyB := twoPrincipals(t)
	shared, onlyB := randomString(t, alnum, 40), randomString(t, alnum, 40)
	index, err := NewIndex(keyA, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	add := func(key *Key, id, value string) *Entries {
		e, err := IndexValue(key, "secret", id, value)
		if err != nil {
			t.Fatal(err)
		}
		if err := index.AddKeyed(key, e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	fromA := add(keyA, "shared", shared)
	one := index.Stats()
	fromB := add(keyB, "shared", shared)
	if two := index.Stats(); two.Forms != 2*one.Forms || two.Chunks != 2*one.Chunks || two.Secrets != 2 {
		t.Fatalf("the two principals' entries are not held apart: %+v then %+v", one, two)
	}
	for hash := range confirmingHashes(fromA) {
		if confirmingHashes(fromB)[hash] {
			t.Fatal("two principals share a confirming hash of one value")
		}
	}
	add(keyB, "theirs", onlyB)
	add(keyB, "theirs", onlyB)
	if out, _ := index.Redact([]byte("x " + shared + " y " + onlyB + " z")); string(out) != "x ph:secret:shared y ph:secret:theirs z" {
		t.Fatalf("redacted to %q", out)
	}
	// Each principal's record alone is enough.
	for name, key := range map[string]*Key{"A": keyA, "B": keyB} {
		alone, err := NewIndex(keyA, IndexOptions{})
		if err != nil {
			t.Fatal(err)
		}
		e, _ := IndexValue(key, "secret", "shared", shared)
		if err := alone.AddKeyed(key, e); err != nil {
			t.Fatal(err)
		}
		if got := found(t, alone, shared); got != "ph:secret:shared" {
			t.Fatalf("principal %s's record alone found %q", name, got)
		}
	}
	// Entries made under another lookup key are refused, not held unmatched:
	// only AddGuest takes them, and it takes none under the index's own.
	stranger := newKey(t)
	e, _ := IndexValue(stranger, "secret", "other", onlyB)
	if index.AddKeyed(stranger, e) == nil || index.AddWithheld(stranger, e) == nil {
		t.Fatal("entries under another lookup key were added")
	}
	own, _ := IndexValue(keyB, "secret", "other", onlyB)
	if index.AddGuest(keyB, own) == nil {
		t.Fatal("entries under the index's lookup key were added as a guest's")
	}
}

// BenchmarkApply1MBPrincipals is BenchmarkApply1MB with the values spread
// over four principals, so candidates are confirmed under four keys.
func BenchmarkApply1MBPrincipals(b *testing.B) {
	secrets := manySecrets(b, 300)
	keys := []*Key{newKey(b)}
	for len(keys) < 4 {
		key, err := keys[0].WithConfirm(newKey(b).ConfirmBytes())
		if err != nil {
			b.Fatal(err)
		}
		keys = append(keys, key)
	}
	ix, err := NewIndex(keys[0], IndexOptions{})
	if err != nil {
		b.Fatal(err)
	}
	for i, s := range secrets {
		e, err := IndexValue(keys[i%len(keys)], s.Type, s.ID, s.Value)
		if err != nil {
			b.Fatal(err)
		}
		if err := ix.AddKeyed(keys[i%len(keys)], e); err != nil {
			b.Fatal(err)
		}
	}
	text := corpus(b, 1<<20)
	var results []string
	for i := 0; i < len(text); i += 32 << 10 {
		results = append(results, string(text[i:min(i+(32<<10), len(text))]))
	}
	for i := 0; i < 5; i++ {
		results[i*len(results)/5] += "\nleaked " + secrets[i*7].Value
	}
	body := modelRequest(results...)
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	var last result
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ix.cache.reset()
		b.StartTimer()
		last = apply(ix, body)
	}
	b.StopTimer()
	if len(last.Hits) < 5 {
		b.Fatalf("expected at least 5 hits, got %d", len(last.Hits))
	}
}

// Entries added with their id withheld are replaced by ph:<type> alone, and
// no finding names the id. The same value held with its id keeps the id.
func TestWithheldEntriesNeverNameTheirID(t *testing.T) {
	keyA, keyB := twoPrincipals(t)
	theirs, both := randomString(t, alnum, 40), randomString(t, alnum, 40)
	index, err := NewIndex(keyA, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		key       *Key
		id, value string
		withheld  bool
	}{{keyB, "id-not-to-show", theirs, true}, {keyB, "other-not-to-show", both, true}, {keyA, "mine", both, false}} {
		e, err := IndexValue(v.key, "sealed", v.id, v.value)
		if err != nil {
			t.Fatal(err)
		}
		add := index.AddKeyed
		if v.withheld {
			add = index.AddWithheld
		}
		if err := add(v.key, e); err != nil {
			t.Fatal(err)
		}
	}
	text := "a " + theirs + " b " + both + " c " + hex.EncodeToString([]byte(theirs)) + " d"
	body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": text}}})
	for name, payload := range map[string][]byte{"text": []byte(text), "a body": body} {
		result := apply(index, payload)
		reported, _ := json.Marshal(result.Report)
		if !bytes.Contains(result.Out, []byte("a ph:sealed b ph:sealed:mine c ph:sealed d")) || len(result.Hits) != 3 {
			t.Fatalf("%s: %s", name, result.Out)
		}
		if bytes.Contains(result.Out, []byte("not-to-show")) || bytes.Contains(reported, []byte("not-to-show")) {
			t.Fatalf("%s: a withheld id was written: %s %s", name, result.Out, reported)
		}
		// What was rewritten is left alone when it is scanned again.
		if again := apply(index, result.Out); again.Changed || len(again.Hits)+len(again.Rules) != 0 {
			t.Fatalf("%s: scanning the rewritten text changed it: %s", name, again.Out)
		}
	}
}

// A value whose id is withheld is replaced where a whole form of it stands
// and nowhere else: not by a fragment or a line, as one held with its id is.
func TestWithheldValuesAreMatchedWholeOrNotAtAll(t *testing.T) {
	keyA, keyB := twoPrincipals(t)
	value := randomString(t, alnum, 60)
	lines := randomString(t, alnum, 40) + "\n" + randomString(t, alnum, 40) + "\n" + randomString(t, alnum, 40)
	index := func(withheld bool) *Index {
		ix, err := NewIndex(keyA, IndexOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for id, v := range map[string]string{"one": value, "many": lines} {
			e, err := IndexValue(keyB, "secret", id, v)
			if err != nil {
				t.Fatal(err)
			}
			add := ix.AddKeyed
			if withheld {
				add = ix.AddWithheld
			}
			if err := add(keyB, e); err != nil {
				t.Fatal(err)
			}
		}
		return ix
	}
	named, withheld := index(false), index(true)
	escaped, _ := json.Marshal(lines)
	for name, tc := range map[string]struct {
		text  string
		whole bool
	}{
		"the whole value":            {"a " + value + " b", true},
		"its hex":                    {"a " + hex.EncodeToString([]byte(value)) + " b", true},
		"a whole value of lines":     {"a\n" + lines + "\nb", true},
		"the same, escaped":          {"a " + string(escaped) + " b", true},
		"all but its last character": {"a " + value[:len(value)-1] + " b", false},
		"all but its first":          {"a " + value[1:] + " b", false},
		"two chunks of it":           {"a " + value[12:36] + " b", false},
		"one line of several":        {"a " + strings.Split(lines, "\n")[1] + " b", false},
		"its hex, cut short":         {"a " + hex.EncodeToString([]byte(value))[:96] + " b", false},
	} {
		if got := found(t, named, tc.text); !strings.HasPrefix(got, "ph:secret:") {
			t.Fatalf("%s is not found when the id may be written: %q", name, got)
		}
		got := found(t, withheld, tc.text)
		if tc.whole && got != "ph:secret" {
			t.Fatalf("%s of a withheld value was not replaced: %q", name, got)
		}
		if !tc.whole && got != "" {
			t.Fatalf("%s of a withheld value was matched: %q", name, got)
		}
	}
}

// Two withheld values of one type share a placeholder; a finding numbers
// them apart, the same value the same way every time, and names no id.
func TestWithheldFindingsTellTheirValuesApart(t *testing.T) {
	keyA, keyB := twoPrincipals(t)
	first, second := randomString(t, alnum, 40), randomString(t, alnum, 40)
	ix, err := NewIndex(keyA, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for id, v := range map[string]string{"id-one": first, "id-two": second} {
		e, _ := IndexValue(keyB, "secret", id, v)
		if err := ix.AddWithheld(keyB, e); err != nil {
			t.Fatal(err)
		}
	}
	mine, _ := IndexValue(keyA, "secret", "mine", randomString(t, alnum, 40))
	if err := ix.Add(mine); err != nil {
		t.Fatal(err)
	}
	refs := func(text string) []int {
		_, report := ix.Redact([]byte(text))
		var out []int
		for _, f := range report.Findings {
			if f.Placeholder != "ph:secret" {
				t.Fatalf("a withheld finding's placeholder: %q", f.Placeholder)
			}
			out = append(out, f.Withheld)
		}
		reported, _ := json.Marshal(report)
		if bytes.Contains(reported, []byte("id-")) || bytes.Contains(reported, []byte("ithheld")) {
			t.Fatalf("the report as it is written: %s", reported)
		}
		return out
	}
	both := refs(first + " " + second + " " + hex.EncodeToString([]byte(first)))
	if len(both) != 3 || both[0] == 0 || both[1] == 0 || both[0] == both[1] || both[2] != both[0] {
		t.Fatalf("the findings do not tell the two values apart: %v", both)
	}
	if again := refs(second); len(again) != 1 || again[0] != both[1] {
		t.Fatalf("a value's number changed: %v then %v", both, again)
	}
	if _, report := ix.Redact([]byte(randomString(t, alnum, 8) + " " + first)); report.Findings[0].Withheld != both[0] {
		t.Fatal("a value's number depends on the text around it")
	}
}

// A guest's entries are under a key that shares nothing with the index's:
// found by their own pass, with no id, whole, and counted and bounded apart.
func TestGuestEntriesAreMatchedUnderTheirOwnKey(t *testing.T) {
	home, guest, other := newKey(t), newKey(t), newKey(t)
	mine, theirs, another := randomString(t, alnum, 40), randomString(t, alnum, 40), randomString(t, alnum, 40)
	ix, err := NewIndex(home, IndexOptions{MaxGuestSecrets: 2})
	if err != nil {
		t.Fatal(err)
	}
	own, _ := IndexValue(home, "secret", "mine", mine)
	if err := ix.Add(own); err != nil {
		t.Fatal(err)
	}
	before := ix.Stats()
	for _, v := range []struct {
		key       *Key
		id, value string
	}{{guest, "guest-id", theirs}, {guest, "guest-id", theirs}, {other, "guest-id", another}} {
		e, _ := IndexValue(v.key, "secret", v.id, v.value)
		if err := ix.AddGuest(v.key, e); err != nil {
			t.Fatal(err)
		}
	}
	if after := ix.Stats(); after.Secrets != before.Secrets || after.Guests != 2 {
		t.Fatalf("guests are not counted apart, once per key: %+v then %+v", before, after)
	}
	text := mine + " " + theirs + " " + hex.EncodeToString([]byte(another)) + " " + theirs[:30]
	out, report := ix.Redact([]byte(text))
	if string(out) != "ph:secret:mine ph:secret ph:secret "+theirs[:30] {
		t.Fatalf("redacted to %q", out)
	}
	if reported, _ := json.Marshal(report); bytes.Contains(reported, []byte("guest-id")) {
		t.Fatalf("a guest's id was reported: %s", reported)
	}
	// The home key finds nothing of a guest's value, and a guest's nothing of
	// the home's: nothing is shared.
	alone, _ := NewIndex(guest, IndexOptions{})
	if err := alone.Add(own); err != nil {
		t.Fatal(err)
	}
	if got := found(t, alone, mine); got != "" {
		t.Fatalf("entries of one key matched under another: %q", got)
	}
	// The guests' bound is their own: past it their oldest entry goes, and
	// the index's own values are neither dropped nor refused.
	more, _ := IndexValue(guest, "secret", "one-more", randomString(t, alnum, 40))
	if err := ix.AddGuest(guest, more); err != nil {
		t.Fatalf("a guest past the guests' bound: %v", err)
	}
	if after := ix.Stats(); after.Guests != 2 || after.Secrets != before.Secrets || found(t, ix, theirs) != "" || found(t, ix, mine) != "ph:secret:mine" {
		t.Fatalf("past the guests' bound: %+v", after)
	}
	room, _ := IndexValue(home, "secret", "room", randomString(t, alnum, 40))
	if err := ix.Add(room); err != nil {
		t.Fatalf("the guests' bound refused the index's own: %v", err)
	}
}

// One principal's values cannot take the whole index: past its bound its own
// registrations are refused and another principal's are still taken.
func TestOnePrincipalCannotFillTheIndex(t *testing.T) {
	keyA, keyB := twoPrincipals(t)
	ix, err := NewIndex(keyA, IndexOptions{MaxSecrets: 4, MaxKeySecrets: 2})
	if err != nil {
		t.Fatal(err)
	}
	add := func(key *Key, id string) error {
		e, _ := IndexValue(key, "secret", id, randomString(t, alnum, 40))
		return ix.AddKeyed(key, e)
	}
	if add(keyA, "a1") != nil || add(keyA, "a2") != nil {
		t.Fatal("within the bound")
	}
	if err := add(keyA, "a3"); !errors.Is(err, ErrIndexFull) {
		t.Fatalf("past one principal's bound: %v", err)
	}
	// Another value under an id it holds is no new value.
	if err := add(keyA, "a2"); err != nil {
		t.Fatalf("an id already held: %v", err)
	}
	if add(keyB, "b1") != nil || add(keyB, "a1") != nil {
		t.Fatal("another principal was refused room the first had not taken")
	}
	if stats := ix.Stats(); stats.Secrets != 4 {
		t.Fatalf("%+v", stats)
	}
}
