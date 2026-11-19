package censor

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The findings cap keeps the first value a client registered as well as the
// first a store handed over: a caller that stops a request for the one and
// not for the other still sees it behind a crowd of other findings.
func TestTheFindingsCapKeepsARegisteredValueBehindALoadedOne(t *testing.T) {
	key := newKey(t)
	ix, err := NewIndex(key, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stored, registered := strongValue(t, 24), strongValue(t, 24)
	fromStore, _ := IndexValue(key, "secret", "stored", stored)
	if err := ix.AddLoaded(key, fromStore, false); err != nil {
		t.Fatal(err)
	}
	fromClient, _ := IndexValue(key, "secret", "registered", registered)
	if err := ix.Add(fromClient); err != nil {
		t.Fatal(err)
	}
	for _, headers := range []int{10, MaxFindings + 100} {
		text := "pw " + stored + "\n" + strings.Repeat("-----BEGIN PRIVATE KEY-----\n", headers) + "pw " + registered + "\n"
		matches := ix.Find([]byte(text))
		if want := min(headers+2, MaxFindings); len(matches) != want {
			t.Fatalf("%d headers: %d matches, want %d", headers, len(matches), want)
		}
		found := map[bool]string{}
		for i, m := range matches {
			if i > 0 && m.Start < matches[i-1].Start {
				t.Fatalf("%d headers: the matches are out of order at %d", headers, i)
			}
			if m.Kind == kindInventory {
				found[m.Loaded] = text[m.Start:m.End]
			}
		}
		if found[true] != stored || found[false] != registered {
			t.Errorf("%d headers: the value from the store or the one a client registered is not listed", headers)
		}
	}
}

// forged is entries of 63 one-chunk forms that all sit under one lookup value
// and confirm nothing: what a client posts to fill a lookup value's bound.
func forged(t testing.TB, id string, lookup []byte) *Entries {
	t.Helper()
	filler := &Entries{Version: 2, Type: "secret", ID: id}
	for i := 0; i < maxRefsPerHash-1; i++ {
		sum := make([]byte, macSize)
		if _, err := rand.Read(sum); err != nil {
			t.Fatal(err)
		}
		filler.Forms = append(filler.Forms, Form{Part: fmt.Sprintf("leaf:%d", i), Form: formRaw, Length: chunkSize, Lookups: lookup, MACs: sum, Weak: []byte{0}})
	}
	return filler
}

// A client fills a lookup value's bound with forged forms and registers its
// guess last: were the bound shared, the guess would be held only when wrong.
func TestALookupValuesBoundIsEachConfirmingKeysOwn(t *testing.T) {
	keyA, keyB := twoPrincipals(t)
	value := strongValue(t, 39)
	ix, err := NewIndex(keyA, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	theirs, _ := IndexValue(keyB, "secret", "theirs", value)
	if err := ix.AddWithheld(keyB, theirs); err != nil {
		t.Fatal(err)
	}
	n := 0
	held := func(guess string) bool {
		n++
		probe, err := IndexValue(keyA, "secret", fmt.Sprintf("probe-%d", n), guess)
		if err != nil || len(probe.Forms) == 0 || probe.Forms[0].Form != formRaw || probe.Forms[0].Length != chunkSize {
			t.Fatalf("the probe: %v", err)
		}
		probe.Forms = probe.Forms[:1]
		for _, e := range []*Entries{forged(t, fmt.Sprintf("fill-%d", n), probe.Forms[0].Lookups), probe} {
			if err := ix.AddKeyed(keyA, e); err != nil {
				t.Fatal(err)
			}
		}
		return found(t, ix, "x "+guess+" y") == fmt.Sprintf("ph:secret:probe-%d", n)
	}
	for name, guess := range map[string]string{
		"the first chunk of another's value": value[:12], "its second": value[12:24], "its third": value[24:36],
		"no chunk of it": strongValue(t, 12), "its first chunk, one byte off": value[:11] + "!",
	} {
		if !held(guess) {
			t.Errorf("a guess that is %s was not held: whether it was says whether it is right", name)
		}
	}
	// The bound is still there for one key's own chunks.
	late, _ := IndexValue(keyA, "secret", "late", value[:12])
	late.Forms = late.Forms[:1]
	if err := ix.AddKeyed(keyA, late); err != nil || !strings.HasPrefix(found(t, ix, "x "+value[:12]+" y"), "ph:secret:probe-") {
		t.Fatalf("one key past its own bound at a lookup value: %v", err)
	}
	// And a whole value of the other principal's is found through the crowd.
	if got := found(t, ix, "x "+value+" y"); got != "ph:secret" {
		t.Fatalf("the other principal's value, whole: %q", got)
	}
	// Guests share a lookup key and differ by confirming key: the same holds.
	g := newGuestIndex(t, IndexOptions{})
	lookup := newKey(t)
	victim, _ := lookup.WithConfirm(newKey(t).ConfirmBytes())
	if err := g.add(victim, "theirs", value); err != nil {
		t.Fatal(err)
	}
	for name, guess := range map[string]string{"right": value[:12], "wrong": strongValue(t, 12)} {
		probe, _ := IndexValue(lookup, "probe", "guess", guess)
		probe.Forms = probe.Forms[:1]
		for _, e := range []*Entries{forged(t, "fill-"+name, probe.Forms[0].Lookups), probe} {
			e.Type = "probe"
			if err := g.ix.AddGuest(lookup, e); err != nil {
				t.Fatal(err)
			}
		}
		if got := found(t, g.ix, "x "+guess+" y"); got != "ph:probe" {
			t.Errorf("a guest's %s guess of another guest's chunk: %q", name, got)
		}
	}
}

// hashesFor is how many confirming hashes a scan of text makes.
func hashesFor(ix *Index, text string) int {
	search := spanSearch{data: []byte(text)}
	ix.search(&search)
	return search.hashes
}

// What a scan does where a lookup value of a withheld form turns up does not
// depend on whether the text is the value's: the time it takes confirms no chunk.
func TestAWithheldLookupHitCostsTheSameWhateverConfirms(t *testing.T) {
	keyA, keyB := twoPrincipals(t)
	value, wrong := strongValue(t, 100), strongValue(t, 12)
	ix, err := NewIndex(keyA, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	theirs, _ := IndexValue(keyB, "secret", "theirs", value)
	if err := ix.AddWithheld(keyB, theirs); err != nil {
		t.Fatal(err)
	}
	// A form of the same shape that no text confirms, under the lookup value
	// of other text: a lookup hit with nothing behind it.
	other, _ := IndexValue(keyB, "secret", "other", wrong)
	decoy := theirs.Forms[0]
	if decoy.Form != formRaw || decoy.Length != len(value) {
		t.Fatalf("the first form is %s", decoy.Form)
	}
	decoy.Lookups = append(append([]byte{}, other.Forms[0].Lookups[:3]...), decoy.Lookups[3:]...)
	decoy.MACs, decoy.Tail = make([]byte, len(decoy.MACs)), make([]byte, len(decoy.Tail))
	_, _ = rand.Read(decoy.MACs)
	_, _ = rand.Read(decoy.Tail)
	if err := ix.AddWithheld(keyB, &Entries{Version: 2, Type: "secret", ID: "decoy", Forms: []Form{decoy}}); err != nil {
		t.Fatal(err)
	}
	const times = 50
	repeated := func(piece string) string { return strings.Repeat(piece+" ", times) + strings.Repeat(" ", 2*len(value)) }
	hit := hashesFor(ix, repeated(wrong))
	if hit != times*wholeProbe {
		t.Fatalf("a lookup hit that confirms nothing cost %d hashes, not %d", hit, times*wholeProbe)
	}
	for name, piece := range map[string]string{
		"the value's first chunk": value[:12], "its first two chunks": value[:24], "its first three and a half": value[:42],
	} {
		if got := hashesFor(ix, repeated(piece)); got != hit {
			t.Errorf("%s cost %d hashes where a lookup hit that confirms nothing costs %d", name, got, hit)
		}
	}
	// No other chunk of it is looked up at all, so none is told by a hit.
	for name, piece := range map[string]string{"its second chunk": value[12:24], "its last": value[84:96], "all but its first chunk": value[12:]} {
		if got := hashesFor(ix, repeated(piece)); got != 0 {
			t.Errorf("%s cost %d hashes", name, got)
		}
	}
	// Behind a probe that confirmed, all of the rest is hashed, wherever it differs.
	rest := len(value)/chunkSize + 1
	for name, piece := range map[string]string{"right but for its last byte": value[:99] + "!", "right but for its fifth chunk": value[:48] + strongValue(t, 12) + value[60:]} {
		if got := hashesFor(ix, repeated(piece)); got != times*rest {
			t.Errorf("a copy %s cost %d hashes, not %d", name, got, times*rest)
		}
		if got := found(t, ix, repeated(piece)); got != "" {
			t.Errorf("a copy %s was replaced: %q", name, got)
		}
	}
	if got := found(t, ix, "a "+value+" b"); got != "ph:secret" {
		t.Fatalf("the whole value: %q", got)
	}
	// A form that does not fit where its chunk stands costs nothing.
	if got := hashesFor(ix, strings.Repeat(" ", 300)+value[:12]); got != 0 {
		t.Errorf("a first chunk at the end of the text cost %d hashes", got)
	}
	// A value that begins with structure is led to by its first chunk that
	// is not, and the probe is that chunk and others that are not structure.
	format := strings.Repeat("a", 12) + strings.Repeat("b", 12) + strings.Repeat("c", 12)
	shaped := format + strongValue(t, 60)
	made, _ := IndexValue(keyB, "secret", "shaped", shaped)
	if err := ix.AddWithheld(keyB, made); err != nil {
		t.Fatal(err)
	}
	for name, piece := range map[string]string{
		"its format and the first chunk after it": shaped[:48], "its format and three chunks after it": shaped[:72],
	} {
		if got := hashesFor(ix, repeated(piece)); got != hit {
			t.Errorf("a value that begins with structure: %s cost %d hashes, not %d", name, got, hit)
		}
	}
	if got := hashesFor(ix, repeated(format)); got != 0 {
		t.Errorf("the format alone cost %d hashes", got)
	}
	if got := found(t, ix, "a "+shaped+" b"); got != "ph:secret" {
		t.Fatalf("the whole value: %q", got)
	}
}

// Withheld values of one format, or that begin alike, are each led to by a
// chunk of their own, so more of them than one lookup value holds are found.
func TestWithheldValuesThatBeginAlikeAreEachFound(t *testing.T) {
	keyA, keyB := twoPrincipals(t)
	ix, err := NewIndex(keyA, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	prefix := strongValue(t, 24)
	var values []string
	for i := 0; i < 3*maxRefsPerHash; i++ {
		values = append(values, prefix+strongValue(t, 30))
	}
	values = append(values, strings.TrimSpace(fakePEM(t)), strings.TrimSpace(fakePEM(t)), "postgres://app:"+strongValue(t, 24)+"@db.internal:5432/app", "postgres://app:"+strongValue(t, 24)+"@db.internal:5432/app")
	for i, value := range values {
		e, err := IndexValue(keyB, "secret", fmt.Sprintf("v%d", i), value)
		if err != nil {
			t.Fatal(err)
		}
		if err := ix.AddWithheld(keyB, e); err != nil {
			t.Fatal(err)
		}
	}
	for i, value := range values {
		for name, text := range map[string]string{"whole": value, "in hex": hex.EncodeToString([]byte(value))} {
			out, report := ix.Redact([]byte("a\n" + text + "\nb"))
			if string(out) != "a\nph:secret\nb" || len(report.Findings) != 1 || report.Findings[0].Partial {
				t.Fatalf("value %d, %s: %.80q", i, name, out)
			}
		}
	}
	// What they share is no match: the prefix, a PEM's armour, a URL without its password.
	armour := "-----BEGIN PRIVATE KEY-----\n" + strongValue(t, 64) + "\n-----END PRIVATE KEY-----"
	for name, text := range map[string]string{"the prefix": prefix, "a PEM's armour": armour, "the URL of another password": "postgres://app:" + strongValue(t, 24) + "@db.internal:5432/app"} {
		if hits := apply(ix, []byte("a "+text+" b")).Hits; len(hits) != 0 {
			t.Errorf("%s was taken for a value: %+v", name, hits)
		}
	}
}

// Entries a store handed over say so in a finding until a client adds them
// again, and a place found through both kinds is not a loaded one.
func TestLoadedEntriesSaySoUntilTheyAreAddedAgain(t *testing.T) {
	keyA, keyB := twoPrincipals(t)
	mine, theirs, live := strongValue(t, 40), strongValue(t, 40), strongValue(t, 40)
	ix, err := NewIndex(keyA, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	own, _ := IndexValue(keyA, "secret", "mine", mine)
	other, _ := IndexValue(keyB, "secret", "theirs", theirs)
	registered, _ := IndexValue(keyA, "secret", "live", live)
	if ix.AddLoaded(keyA, own, false) != nil || ix.AddLoaded(keyB, other, true) != nil || ix.AddKeyed(keyA, registered) != nil {
		t.Fatal("adding")
	}
	loaded := func(text string) []bool {
		var out []bool
		for _, match := range ix.Find([]byte(text)) {
			out = append(out, match.Loaded)
		}
		return out
	}
	text := mine + " " + theirs + " " + live + " " + mine[:30]
	if got := loaded(text); fmt.Sprint(got) != "[true true false true]" {
		t.Fatalf("what was loaded: %v", got)
	}
	// The same through every way of scanning, and never written anywhere.
	body, _ := json.Marshal(map[string]string{"content": strings.Repeat("padding ", 64) + text})
	_, report, err := ix.RewriteJSON(body, ScanOptions{})
	if err != nil || len(report.Findings) != 4 || !report.Findings[0].Loaded || report.Findings[2].Loaded {
		t.Fatalf("a JSON body: %+v %v", report.Findings, err)
	}
	if written, _ := json.Marshal(report); bytes.Contains(written, []byte("oaded")) {
		t.Fatalf("the report as it is written: %s", written)
	}
	// A client registers the loaded value again: it is a registered one now,
	// in a string scanned before as well.
	if err := ix.AddKeyed(keyA, own); err != nil {
		t.Fatal(err)
	}
	if got := loaded(text); fmt.Sprint(got) != "[false true false false]" {
		t.Fatalf("after the value was registered again: %v", got)
	}
	if _, report, _ := ix.RewriteJSON(body, ScanOptions{}); report.Findings[0].Loaded || !report.Findings[1].Loaded {
		t.Fatalf("a JSON body scanned before: %+v", report.Findings)
	}
	// Loading what is registered already changes nothing.
	if err := ix.AddLoaded(keyA, registered, false); err != nil || loaded(live)[0] {
		t.Fatalf("a registered value loaded afterwards: %v", err)
	}
	// One value held twice, loaded under one id and registered under another.
	twice, _ := IndexValue(keyA, "secret", "another-id", theirs)
	if err := ix.AddKeyed(keyA, twice); err != nil {
		t.Fatal(err)
	}
	if matches := ix.Find([]byte(theirs)); len(matches) != 1 || matches[0].Loaded || matches[0].Placeholder != "ph:secret:another-id" {
		t.Fatalf("a value loaded and registered: %+v", matches)
	}
}

// A value that is a piece of what every request holds is refused, and a piece
// of such a text inside a value is structure: nothing held is found in one.
func TestEntriesOfAPublicTextAreRefused(t *testing.T) {
	public := [][]byte{[]byte("api.anthropic.com"), []byte("/v1/messages"), []byte("/backend-api/models/responses"), []byte("/zen/")}
	keyA, keyB := twoPrincipals(t)
	guest := newKey(t)
	index := func(key *Key, scheme int, id, value string) *Entries {
		t.Helper()
		e, err := IndexValueScheme(key, scheme, "secret", id, value)
		if err != nil || !e.Protected() {
			t.Fatalf("%q is not indexed: %v", value, err)
		}
		return e
	}
	secretURL := "postgres://app:" + strongValue(t, 24) + "@api.anthropic.com:5432/app"
	for _, scheme := range []int{1, 2} {
		ix, err := NewIndex(keyA, IndexOptions{Public: public})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for name, c := range map[string]struct {
			value  string
			public bool
		}{
			"a path":                       {"/v1/messages", true},
			"a host":                       {"api.anthropic.com", true},
			"a piece of a host":            {"anthropic.com", true},
			"a longer path":                {"/backend-api/models/responses", true},
			"a path and a query":           {"/v1/messages?beta=tools-2024-04-04", false},
			"a path under a public one":    {"/backend-api/models/responses/compact", false},
			"a secret":                     {strongValue(t, 40), false},
			"a URL with a secret":          {secretURL, false},
			"a secret that ends in a host": {strongValue(t, 24) + "api.anthropic.com", false},
			"a secret that begins a path":  {"/v1/messages" + strongValue(t, 30), false},
		} {
			n++
			id := fmt.Sprintf("v%d", n)
			before := ix.Stats()
			for how, add := range map[string]func() error{
				"held with its id": func() error { return ix.AddKeyed(keyA, index(keyA, scheme, id, c.value)) },
				"withheld":         func() error { return ix.AddWithheld(keyB, index(keyB, scheme, id, c.value)) },
				"loaded":           func() error { return ix.AddLoaded(keyB, index(keyB, scheme, id+"-loaded", c.value), true) },
				"a guest's":        func() error { return ix.AddGuest(guest, index(guest, scheme, id, c.value)) },
			} {
				if err := add(); errors.Is(err, ErrPublic) != c.public || (err != nil && !c.public) {
					t.Errorf("%s, scheme %d, %s: %v", name, scheme, how, err)
				}
			}
			if c.public && ix.Stats() != before {
				t.Errorf("%s: refused entries changed the index", name)
			}
			// A value that was taken is found where it stands whole.
			if got := found(t, ix, "x "+c.value+" y"); !c.public && got != "ph:secret:"+id {
				t.Errorf("%s, scheme %d: found %q", name, scheme, got)
			}
		}
		// Nothing held is found in a public text, or in a request line made of them.
		for _, text := range append(public, []byte("POST /v1/messages?beta=true HTTP/1.1"), []byte("https://api.anthropic.com/v1/messages")) {
			if matches := ix.Find(text); len(matches) != 0 {
				t.Errorf("scheme %d: %s holds %+v", scheme, text, matches)
			}
		}
	}
	// An index with no public texts takes them all, as before.
	plain, _ := NewIndex(keyA, IndexOptions{})
	if err := plain.AddKeyed(keyA, index(keyA, 2, "id", "/v1/messages")); err != nil || found(t, plain, "GET /v1/messages") != "ph:secret:id" {
		t.Fatal(err)
	}
}
