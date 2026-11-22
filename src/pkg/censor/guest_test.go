package censor

import (
	"errors"
	"fmt"
	"testing"
)

// strongValue is a random value none of whose 12-byte pieces is plain enough
// to count as structure, so a test knows which of its chunks leads to it.
func strongValue(t testing.TB, n int) string {
	t.Helper()
	for {
		value, plain := randomString(t, alnum, n), false
		for at := 0; at+chunkSize <= len(value); at++ {
			plain = plain || entropy(value[at:at+chunkSize]) < weakChunkEntropy
		}
		if !plain {
			return value
		}
	}
}

// guestIndex is an index that takes guests' entries, with what a test adds.
type guestIndex struct {
	t  testing.TB
	ix *Index
}

func newGuestIndex(t testing.TB, opts IndexOptions) guestIndex {
	t.Helper()
	ix, err := NewIndex(newKey(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	return guestIndex{t: t, ix: ix}
}

func (g guestIndex) entries(key *Key, id, value string) *Entries {
	g.t.Helper()
	e, err := IndexValue(key, "secret", id, value)
	if err != nil || !e.Protected() {
		g.t.Fatalf("indexing %s: %v", id, err)
	}
	return e
}

func (g guestIndex) add(key *Key, id, value string) error {
	g.t.Helper()
	return g.ix.AddGuest(key, g.entries(key, id, value))
}

func (g guestIndex) finds(value string) bool {
	g.t.Helper()
	return found(g.t, g.ix, "a "+value+" b") == "ph:secret"
}

// The guests' share never refuses a guest: full, it drops the entries
// registered longest ago, and one registered again counts as new.
func TestAFullGuestShareDropsItsOldestEntries(t *testing.T) {
	g := newGuestIndex(t, IndexOptions{MaxGuestSecrets: 3})
	guest, other := newKey(t), newKey(t)
	values := make([]string, 6)
	for i := range values {
		values[i] = strongValue(t, 40)
	}
	for i := 0; i < 3; i++ {
		if err := g.add(guest, fmt.Sprintf("v%d", i), values[i]); err != nil {
			t.Fatal(err)
		}
	}
	// The first is registered again, so the second is now the oldest.
	if err := g.add(guest, "v0", values[0]); err != nil || g.ix.Stats().Guests != 3 {
		t.Fatalf("the same value again: %v, %+v", err, g.ix.Stats())
	}
	if err := g.add(other, "v3", values[3]); err != nil {
		t.Fatalf("a guest at a full share was refused: %v", err)
	}
	for i, want := range []bool{true, false, true, true} {
		if g.finds(values[i]) != want {
			t.Fatalf("value %d found: %v, want %v", i, !want, want)
		}
	}
	if stats := g.ix.Stats(); stats.Guests != 3 || stats.Secrets != 0 {
		t.Fatalf("%+v", stats)
	}
	// The share in chunks drops the oldest the same way.
	byChunks := newGuestIndex(t, IndexOptions{MaxGuestChunks: 2 * g.entries(guest, "v", values[0]).Chunks()})
	for i := 0; i < 4; i++ {
		if err := byChunks.add(guest, fmt.Sprintf("v%d", i), values[i]); err != nil {
			t.Fatalf("value %d: %v", i, err)
		}
	}
	if byChunks.finds(values[0]) || byChunks.finds(values[1]) || !byChunks.finds(values[2]) || !byChunks.finds(values[3]) || byChunks.ix.Stats().Guests != 2 {
		t.Fatalf("the share in chunks: %+v", byChunks.ix.Stats())
	}
	// And the index's own values are no guest's to drop.
	mine := strongValue(t, 40)
	own, _ := IndexValue(g.ix.key, "secret", "mine", mine)
	if err := g.ix.Add(own); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if err := g.add(guest, fmt.Sprintf("more%d", i), strongValue(t, 40)); err != nil {
			t.Fatal(err)
		}
	}
	if got := found(t, g.ix, mine); got != "ph:secret:mine" || g.ix.Stats().Secrets != 1 {
		t.Fatalf("the index's own value after guests came and went: %q", got)
	}
}

// What a dropped entry held is given back: guests that come and go for ever,
// each under a key and a type of its own, leave the index no larger.
func TestDroppedGuestEntriesLeaveNothingBehind(t *testing.T) {
	g := newGuestIndex(t, IndexOptions{MaxGuestSecrets: 8})
	lookup := newKey(t)
	for round := 0; round < 400; round++ {
		key, err := lookup.WithConfirm(newKey(t).ConfirmBytes())
		if err != nil {
			t.Fatal(err)
		}
		e, err := IndexValue(key, fmt.Sprintf("type%d", round), "id", strongValue(t, 40))
		if err != nil {
			t.Fatal(err)
		}
		if err := g.ix.AddGuest(key, e); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
	ix := g.ix
	stats, filed, chunks := ix.Stats(), 0, 0
	for _, w := range ix.windows {
		for _, refs := range w.chunks {
			filed += len(refs)
		}
	}
	for at := range ix.forms {
		chunks += len(ix.forms[at].macs)
	}
	// A value of letters and digits has at most twelve forms that differ.
	if stats.Guests != 8 || ix.guestAge.Len() != 8 || stats.Forms > 8*12 || len(ix.forms) > 2*8*12 || len(ix.owners) > 16 || len(ix.macKeys) > 9 {
		t.Fatalf("the index grew with guests that left: %+v, %d form slots, %d owner slots, %d key slots", stats, len(ix.forms), len(ix.owners), len(ix.macKeys))
	}
	if len(ix.macKeyIndex) != 8 || len(ix.types) != 8 || len(ix.guestForms) != stats.Forms || filed != stats.Forms || chunks != stats.Chunks || stats.Owners != 8 {
		t.Fatalf("something of a dropped entry is still held: %+v, %d keys, %d types, %d fingerprints, %d filed, %d chunks",
			stats, len(ix.macKeyIndex), len(ix.types), len(ix.guestForms), filed, chunks)
	}
}

// Only one registration that is larger than the share by itself is refused:
// none of its own entries is dropped to make room for another of them.
func TestARegistrationLargerThanTheGuestShareIsRefused(t *testing.T) {
	g := newGuestIndex(t, IndexOptions{MaxGuestSecrets: 3})
	guest := newKey(t)
	earlier := strongValue(t, 40)
	if err := g.add(guest, "earlier", earlier); err != nil {
		t.Fatal(err)
	}
	batch := g.ix.NewGuestBatch()
	values := []string{strongValue(t, 40), strongValue(t, 40), strongValue(t, 40), strongValue(t, 40)}
	for i, value := range values[:3] {
		if err := batch.Add(guest, g.entries(guest, fmt.Sprintf("b%d", i), value)); err != nil {
			t.Fatalf("entry %d of the registration: %v", i, err)
		}
	}
	if err := batch.Add(guest, g.entries(guest, "b3", values[3])); !errors.Is(err, ErrIndexFull) {
		t.Fatalf("a fourth entry of one registration into a share of three: %v", err)
	}
	if g.finds(earlier) || !g.finds(values[0]) || !g.finds(values[1]) || !g.finds(values[2]) || g.finds(values[3]) {
		t.Fatal("the registration's own entries were dropped for one another")
	}
	// An entry held before that the registration adds again is its own too.
	again := g.ix.NewGuestBatch()
	for i, value := range values[:3] {
		if err := again.Add(guest, g.entries(guest, fmt.Sprintf("b%d", i), value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := again.Add(guest, g.entries(guest, "b3", values[3])); !errors.Is(err, ErrIndexFull) {
		t.Fatalf("three held entries registered again and a fourth: %v", err)
	}
	// The next registration has the share to itself again.
	if err := g.add(guest, "later", values[3]); err != nil || !g.finds(values[3]) || g.finds(values[0]) {
		t.Fatalf("the registration after it: %v", err)
	}
	// One value with more chunks than the share holds is refused, and drops nothing.
	small := newGuestIndex(t, IndexOptions{MaxGuestChunks: g.entries(guest, "v", earlier).Chunks()})
	if err := small.add(guest, "fits", earlier); err != nil {
		t.Fatal(err)
	}
	if err := small.add(guest, "large", strongValue(t, 400)); !errors.Is(err, ErrIndexFull) || !small.finds(earlier) {
		t.Fatalf("a value larger than the share: %v", err)
	}
}

// What a guest's registration costs the share does not depend on whether its
// type and id are held: a guess at another guest's id is answered like any id.
func TestTheGuestShareSaysNothingOfAnIDHeld(t *testing.T) {
	victim, nobody := newKey(t), newKey(t)
	held := strongValue(t, 40)
	outcome := func(id string) (err error, guests int, first, second bool) {
		g := newGuestIndex(t, IndexOptions{MaxGuestSecrets: 4})
		junk := []string{strongValue(t, 40), strongValue(t, 40), strongValue(t, 40)}
		for i, value := range junk[:2] {
			if err := g.add(nobody, fmt.Sprintf("junk%d", i), value); err != nil {
				t.Fatal(err)
			}
		}
		if err := g.add(victim, "STRIPE_LIVE_KEY", held); err != nil {
			t.Fatal(err)
		}
		if err := g.add(nobody, "junk2", junk[2]); err != nil {
			t.Fatal(err)
		}
		// The share is full. A guess is registered in the victim's name.
		err = g.add(victim, id, strongValue(t, 40))
		return err, g.ix.Stats().Guests, g.finds(junk[0]), g.finds(junk[1])
	}
	heldErr, heldGuests, heldFirst, heldSecond := outcome("STRIPE_LIVE_KEY")
	otherErr, otherGuests, otherFirst, otherSecond := outcome("AWS_SECRET_ACCESS_KEY")
	if heldErr != nil || otherErr != nil || heldGuests != otherGuests || heldFirst != otherFirst || heldSecond != otherSecond {
		t.Fatalf("an id that is held: %v, %d entries, %v %v; one that is not: %v, %d entries, %v %v",
			heldErr, heldGuests, heldFirst, heldSecond, otherErr, otherGuests, otherFirst, otherSecond)
	}
	if heldGuests != 4 || heldFirst || !heldSecond {
		t.Fatalf("each made room by dropping the oldest entry: %d entries, %v %v", heldGuests, heldFirst, heldSecond)
	}
}
