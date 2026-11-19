package censor

import (
	"strings"
	"testing"
)

// A value a client registers in the daemon's own process is held under a live
// key in scheme 1, beside what a store handed over of it under the
// principal's key in scheme 2: one value to every count, one placeholder
// where both find it, pieces by the live entries, and no longer a store's alone.
func TestLiveEntriesAreTheirPrincipalsBesideItsStoredOnes(t *testing.T) {
	home, another := twoPrincipals(t)
	live := newKey(t)
	ix, err := NewIndex(home, IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	hexKey := randomString(t, lowerHex, 64)
	// A piece no 24-byte chunk of the value lies whole in.
	piece := hexKey[3:40]
	stored, err := IndexValue(home, "secret", "key-id", hexKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := ix.AddLoaded(home, stored, false); err != nil {
		t.Fatal(err)
	}
	find := func(text string) (string, []Match) {
		out, _ := ix.Redact([]byte(text))
		return string(out), ix.Find([]byte(text))
	}
	// From the store alone: whole, and a piece only where scheme 2 finds one.
	if out, matches := find("a " + hexKey + " b " + piece + " c"); out != "a ph:secret:key-id b "+piece+" c" || len(matches) != 1 || !matches[0].Loaded {
		t.Fatalf("from the store alone: %q %+v", out, matches)
	}
	before := ix.Stats()
	registered, err := IndexValueScheme(live, 1, "secret", "key-id", hexKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := ix.AddLive(live, registered, home); err != nil {
		t.Fatal(err)
	}
	after := ix.Stats()
	if after.Secrets != before.Secrets || after.Owners != before.Owners || after.Guests != 0 || after.Forms <= before.Forms {
		t.Fatalf("a value held both ways is counted %+v, and was %+v from the store alone", after, before)
	}
	out, matches := find("a " + hexKey + " b " + piece + " c")
	if out != "a ph:secret:key-id b ph:secret:key-id c" || len(matches) != 2 || matches[0].Loaded || matches[1].Loaded {
		t.Fatalf("registered in this process as well: %q %+v", out, matches)
	}
	if _, report := ix.Redact([]byte(hexKey)); report.Inventory != 1 || len(report.Findings) != 1 {
		t.Fatalf("one value found once is reported as %+v", report)
	}
	if !ix.namesID("secret", "key-id") {
		t.Fatal("the id of a value held under the live key is not one the index writes")
	}
	// Another principal's stored value is as it was: whole, by its type.
	theirs := randomString(t, lowerHex, 64)
	withheld, _ := IndexValue(another, "secret", "theirs", theirs)
	if err := ix.AddLoaded(another, withheld, true); err != nil {
		t.Fatal(err)
	}
	if out, _ := find(theirs + " " + theirs[3:40]); out != "ph:secret "+theirs[3:40] {
		t.Fatalf("another principal's value beside live entries: %q", out)
	}
	// One live key, and never a key the index already takes entries under.
	for name, attempt := range map[string]error{
		"a second live key":                 ix.AddLive(newKey(t), registered, home),
		"the index's own key as a live key": ix.AddLive(home, stored, home),
		"no principal":                      ix.AddLive(live, registered, nil),
		"a principal of another lookup key": ix.AddLive(live, registered, newKey(t)),
	} {
		if attempt == nil {
			t.Errorf("%s was taken", name)
		}
	}
	// Entries under the live key that are not live are a guest's, or refused.
	if err := ix.AddKeyed(live, registered); err == nil || !strings.Contains(err.Error(), "key") {
		t.Fatalf("entries under the live key were taken as a principal's own: %v", err)
	}
}

// heldIndex is the benchmarks' values as a daemon that keeps entries holds
// them: stored, from a store it started with; live, registered with the
// running process; or both, registered again after a start.
func heldIndex(b *testing.B, stored, live bool) (*Index, []secret) {
	secrets := manySecrets(b, 300)
	home, process := newKey(b), newKey(b)
	ix, err := NewIndex(home, IndexOptions{})
	if err != nil {
		b.Fatal(err)
	}
	for _, s := range secrets {
		if stored {
			e, err := IndexValue(home, s.Type, s.ID, s.Value)
			if err != nil {
				b.Fatal(err)
			}
			if err := ix.AddLoaded(home, e, false); err != nil {
				b.Fatal(err)
			}
		}
		if live {
			e, err := IndexValueScheme(process, 1, s.Type, s.ID, s.Value)
			if err != nil {
				b.Fatal(err)
			}
			if err := ix.AddLive(process, e, home); err != nil {
				b.Fatal(err)
			}
		}
	}
	return ix, secrets
}

// BenchmarkApply1MBLive is BenchmarkApply1MB as a running daemon holds values
// registered with it: one pass, as before entries were kept.
func BenchmarkApply1MBLive(b *testing.B) {
	ix, secrets := heldIndex(b, false, true)
	benchmarkApplyWith(b, ix, secrets, 1<<20, false)
}

// The same with every value held both ways, which costs a pass per key.
func BenchmarkApply1MBLiveAndStored(b *testing.B) {
	ix, secrets := heldIndex(b, true, true)
	benchmarkApplyWith(b, ix, secrets, 1<<20, false)
}

func BenchmarkApply10MBLiveAndStored(b *testing.B) {
	ix, secrets := heldIndex(b, true, true)
	benchmarkApplyWith(b, ix, secrets, 10<<20, false)
}

func BenchmarkRewriteBinary1MBLiveAndStored(b *testing.B) {
	ix, secrets := heldIndex(b, true, true)
	benchmarkBinaryWith(b, ix, secrets, 1<<20, true)
}
