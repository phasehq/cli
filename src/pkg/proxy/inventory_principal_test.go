package proxy

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/phasehq/cli/pkg/censor"
)

const (
	inventoryLoginA = "https://console.test\naccount\naccount-a"
	inventoryLoginB = "https://console.test\nagent\nagent-b"
)

// storedMaster is the master as the keystore holds it.
func storedMaster(t testing.TB, store InventoryStore) []byte {
	t.Helper()
	value, err := store.Keyring.Get(inventoryKeyringService, inventoryKeyringUser)
	if err != nil {
		t.Fatal(err)
	}
	master, err := base64.StdEncoding.DecodeString(value[strings.LastIndexByte(value, ':')+1:])
	if err != nil || len(master) != censor.KeySize {
		t.Fatalf("the keystore holds no master: %v", err)
	}
	return master
}

// Every login shares the lookup key and has a confirming key of its own,
// the same from the next proxy. No key handed out is the master.
func TestInventoryPrincipalsHaveTheirOwnConfirmingKeys(t *testing.T) {
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	a, b := principalOf(t, inv, inventoryLoginA), principalOf(t, inv, inventoryLoginB)
	if !bytes.Equal(a.Key().LookupBytes(), b.Key().LookupBytes()) {
		t.Fatal("two logins have different lookup keys")
	}
	if bytes.Equal(a.Key().ConfirmBytes(), b.Key().ConfirmBytes()) || a.id == b.id {
		t.Fatal("two logins share a confirming key")
	}
	master := storedMaster(t, store)
	for name, handed := range map[string][]byte{"lookup": a.Key().LookupBytes(), "A's confirming": a.Key().ConfirmBytes(), "B's confirming": b.Key().ConfirmBytes()} {
		if bytes.Equal(handed, master) || bytes.Contains(handed, master[:8]) {
			t.Fatalf("the %s key is the master", name)
		}
	}
	// An id says nothing of the login it stands for.
	for _, word := range []string{"console", "account-a", "agent-b"} {
		if bytes.Contains(a.id[:], []byte(word)) || bytes.Contains(b.id[:], []byte(word)) {
			t.Fatalf("a principal's id holds %q", word)
		}
	}
	again, _ := openInventory(t, store)
	if next := principalOf(t, again, inventoryLoginA); next.id != a.id || !bytes.Equal(next.Key().ConfirmBytes(), a.Key().ConfirmBytes()) {
		t.Fatal("a login's principal changed with the proxy")
	}
	// A login the session could not name is this process's alone.
	one, two := principalOf(t, inv, ""), principalOf(t, inv, "")
	if one.id == two.id || bytes.Equal(one.Key().ConfirmBytes(), two.Key().ConfirmBytes()) || bytes.Equal(one.Key().ConfirmBytes(), a.Key().ConfirmBytes()) {
		t.Fatal("unnamed logins share a principal")
	}
	// Another master, other keys throughout.
	if err := store.ReplaceKey(); err != nil {
		t.Fatal(err)
	}
	replaced, _ := openInventory(t, store)
	if next := principalOf(t, replaced, inventoryLoginA); next.id == a.id || bytes.Equal(next.Key().ConfirmBytes(), a.Key().ConfirmBytes()) || bytes.Equal(next.Key().LookupBytes(), a.Key().LookupBytes()) {
		t.Fatal("a replaced master left a key as it was")
	}
}

// Two logins that register one value keep a record each, matched through
// either. A client of one, given the other's record, confirms nothing.
func TestInventoryKeepsARecordPerPrincipal(t *testing.T) {
	store := newInventoryTestStore(t)
	inv, _ := openInventory(t, store)
	a, b := principalOf(t, inv, inventoryLoginA), principalOf(t, inv, inventoryLoginB)
	value, onlyB := inventoryTestValue(t, inventoryTestAlphabet, 40), inventoryTestValue(t, inventoryTestAlphabet, 40)
	index := func(principal InventoryPrincipal, id, value string) StoredEntries {
		entries, err := censor.IndexValue(principal.Key(), "secret", id, value)
		if err != nil {
			t.Fatal(err)
		}
		return StoredEntries{Entries: entries, Principal: principal}
	}
	inv.Add([]StoredEntries{index(a, "DATABASE_URL", value)})
	inv.Add([]StoredEntries{index(b, "DATABASE_URL", value), index(b, "theirs", onlyB)})
	// Registered again by each: nothing doubles.
	inv.Add([]StoredEntries{index(a, "DATABASE_URL", value), index(b, "DATABASE_URL", value)})

	// The proxy that starts next acts as A, and loads B's records too.
	reopened, loaded := openInventory(t, store)
	if status := reopened.Status(); len(loaded) != 3 || status.Damaged != 0 || status.OtherKey != 0 {
		t.Fatalf("%d loaded, %+v", len(loaded), status)
	}
	byPrincipal := map[[inventoryTagSize]byte][]StoredEntries{}
	for _, stored := range loaded {
		byPrincipal[stored.Principal.id] = append(byPrincipal[stored.Principal.id], stored)
	}
	if len(byPrincipal[a.id]) != 1 || len(byPrincipal[b.id]) != 2 {
		t.Fatalf("the records do not name their principals: %d and %d", len(byPrincipal[a.id]), len(byPrincipal[b.id]))
	}
	for name, id := range map[string][inventoryTagSize]byte{"A": a.id, "B": b.id} {
		if !finds(t, reopened, byPrincipal[id], value) {
			t.Fatalf("the value is not matched through %s's record", name)
		}
	}
	if !finds(t, reopened, loaded, value) || !finds(t, reopened, loaded, onlyB) {
		t.Fatal("a proxy does not match every principal's values")
	}
	// The client of A: the lookup key, A's confirming key, B's records opened.
	client, err := censor.KeyFromBytes(a.Key().LookupBytes(), a.Key().ConfirmBytes())
	if err != nil {
		t.Fatal(err)
	}
	mine, err := censor.NewIndex(client, censor.IndexOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, stored := range loaded {
		if err := mine.AddKeyed(client, stored.Entries); err != nil {
			t.Fatal(err)
		}
	}
	if out, _ := mine.Redact([]byte("guess " + onlyB)); !strings.Contains(string(out), onlyB) {
		t.Fatal("a client of A confirmed a guess of B's value")
	}
	if out, _ := mine.Redact([]byte("guess " + value)); strings.Contains(string(out), value) {
		t.Fatal("a client of A cannot confirm A's own value")
	}
}

// With the whole file and every key a proxy of tenant A derives, nothing of
// tenant B's records is unsealed, looked up or confirmed.
func TestInventoryTenantsShareNothing(t *testing.T) {
	storeA := newInventoryTestStore(t)
	storeB := storeA
	storeB.Tenant = "https://console.test\norganisation\nanother-organisation"
	invA, _ := openInventory(t, storeA)
	invB, _ := openInventory(t, storeB)
	// The same login string in each: unrelated keys throughout.
	a, b := principalOf(t, invA, inventoryLoginA), principalOf(t, invB, inventoryLoginA)
	if a.id == b.id || invA.tenant == invB.tenant || invA.tagKey == invB.tagKey || bytes.Equal(invA.confirmRoot, invB.confirmRoot) ||
		bytes.Equal(a.Key().LookupBytes(), b.Key().LookupBytes()) || bytes.Equal(a.Key().ConfirmBytes(), b.Key().ConfirmBytes()) {
		t.Fatal("two tenants share a key or a tag")
	}
	value := inventoryTestValue(t, inventoryTestAlphabet, 40)
	index := func(principal InventoryPrincipal, id string) StoredEntries {
		entries, err := censor.IndexValue(principal.Key(), "secret", id, value)
		if err != nil {
			t.Fatal(err)
		}
		return StoredEntries{Entries: entries, Principal: principal}
	}
	ofA, ofB := index(a, "of-a"), index(b, "of-b")
	// The same value in two tenants: no lookup value and no hash in common.
	for i, form := range ofA.Entries.Forms {
		other := ofB.Entries.Forms[i]
		if bytes.Equal(form.Lookups, other.Lookups) || bytes.Equal(form.MACs, other.MACs) || (len(form.Tail) > 0 && bytes.Equal(form.Tail, other.Tail)) {
			t.Fatalf("form %d of one value is the same bytes in two tenants", i)
		}
		for at := 0; at+16 <= len(form.MACs); at += 16 {
			if bytes.Contains(other.MACs, form.MACs[at:at+16]) {
				t.Fatalf("form %d: a confirming hash is in both tenants' entries", i)
			}
		}
	}
	invB.Add([]StoredEntries{ofB})
	invA.Add([]StoredEntries{ofA})

	// A's next proxy: B's record is counted and nothing else.
	nextA, loaded := openInventory(t, storeA)
	if status := nextA.Status(); len(loaded) != 1 || loaded[0].Entries.ID != "of-a" || status != (InventoryStatus{Durable: true, Loaded: 1, OtherTenant: 1}) {
		t.Fatalf("%d loaded, %+v", len(loaded), status)
	}
	// Every record in the file, opened with all that A's proxy holds, with
	// the tenant tag as written and with A's own in its place.
	unlock, err := lockInventory(nextA.directory)
	if err != nil {
		t.Fatal(err)
	}
	file := nextA.read()
	unlock()
	foreign := 0
	for _, record := range file.records {
		if record.tenant == nextA.tenant {
			continue
		}
		foreign++
		// Any proxy of the user can seal a head: one that says the record is
		// A's still leaves a body sealed under B's key.
		forged := record
		forged.head = append([]byte{}, record.head...)
		copy(forged.head[12:], nextA.tenant[:])
		forged.tenant = nextA.tenant
		headEnd := 4 + inventoryNonceSize + inventoryHeadSize + inventorySealOverhead
		forged.raw = nextA.file.Seal(append([]byte{}, record.raw[:4+inventoryNonceSize]...), record.raw[4:4+inventoryNonceSize], forged.head, nextA.header())
		forged.raw = append(forged.raw, record.raw[headEnd:]...)
		for name, attempt := range map[string]inventoryRecord{"as written": record, "retagged as A's": forged} {
			if _, verdict := nextA.open(attempt, nextA.store.now()); verdict != recordDamaged {
				t.Fatalf("A's proxy opened B's record %s", name)
			}
		}
		if record.login == nextA.loginTag(principalOf(t, nextA, inventoryLoginB).id) || record.content == nextA.contentTag(ofB, mustMarshal(t, ofB.Entries)) {
			t.Fatal("A's proxy can compute a tag of B's record")
		}
	}
	if foreign != 1 {
		t.Fatalf("%d records of another tenant in the file", foreign)
	}
	// B's entries out of their seal, under every key A's proxy can derive:
	// the value is neither looked up nor confirmed.
	for _, login := range []string{inventoryLoginA, inventoryLoginB, inventoryTestLogin} {
		key := principalOf(t, nextA, login).Key()
		mine, err := censor.NewIndex(key, censor.IndexOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := mine.AddKeyed(key, ofB.Entries); err != nil {
			t.Fatal(err)
		}
		if out, report := mine.Redact([]byte("guess " + value)); !strings.Contains(string(out), value) || report.Inventory != 0 {
			t.Fatal("a key of tenant A confirmed tenant B's value")
		}
	}
	// B's own next proxy still finds it, after A wrote the file around it.
	nextB, loaded := openInventory(t, storeB)
	if status := nextB.Status(); len(loaded) != 1 || loaded[0].Entries.ID != "of-b" || status.OtherTenant != 1 || !finds(t, nextB, loaded, value) {
		t.Fatalf("B's next proxy: %d loaded, %+v", len(loaded), status)
	}
	// With no tenant nothing of the user's master is derived or stored.
	none := storeA
	none.Tenant = ""
	alone, loaded := openInventory(t, none)
	if status := alone.Status(); status != (InventoryStatus{Reason: InventoryReasonNoTenant}) || len(loaded) != 0 ||
		bytes.Equal(principalOf(t, alone, inventoryLoginA).Key().LookupBytes(), a.Key().LookupBytes()) {
		t.Fatalf("a store with no tenant: %+v", status)
	}
}

func mustMarshal(t testing.TB, entries *censor.Entries) []byte {
	t.Helper()
	wire, err := entries.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
