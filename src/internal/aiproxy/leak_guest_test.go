package aiproxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// keyAnswerHolds reports a key answer that holds a secret or half of one, raw
// or in hex or base64, in its keys or anywhere in its JSON.
func keyAnswerHolds(t testing.TB, answer remoteapi.InventoryKeyResponse, secret []byte) bool {
	t.Helper()
	decoded, _ := json.Marshal(answer)
	for _, field := range []string{answer.Key, answer.ConfirmKey} {
		raw, err := base64.StdEncoding.DecodeString(field)
		if err != nil || len(raw) != censor.KeySize {
			t.Fatalf("a key in the answer is not %d bytes: %v", censor.KeySize, err)
		}
		decoded = append(append(decoded, 0), raw...)
	}
	for _, part := range [][]byte{secret, secret[:16], secret[16:]} {
		for _, spelling := range [][]byte{part, []byte(hex.EncodeToString(part)), []byte(base64.StdEncoding.EncodeToString(part)), []byte(base64.RawURLEncoding.EncodeToString(part))} {
			if bytes.Contains(decoded, spelling) {
				return true
			}
		}
	}
	return false
}

// confirmingHashes are the hashes entries confirm a value with: each chunk's
// and each tail's. The 24 lookup bits a chunk is found by confirm nothing.
func confirmingHashes(entries *censor.Entries) [][]byte {
	var hashes [][]byte
	for _, form := range entries.Forms {
		for at := 0; at+16 <= len(form.MACs); at += 16 {
			hashes = append(hashes, form.MACs[at:at+16])
		}
		if len(form.Tail) > 0 {
			hashes = append(hashes, form.Tail)
		}
	}
	return hashes
}

// confirmedBy counts the confirming hashes of a guess that held entries hold.
func confirmedBy(held, guess *censor.Entries) int {
	known := map[string]bool{}
	for _, hash := range confirmingHashes(held) {
		known[string(hash)] = true
	}
	confirmed := 0
	for _, hash := range confirmingHashes(guess) {
		if known[string(hash)] {
			confirmed++
		}
	}
	return confirmed
}

// opensARecord tries a key on every seal of the store's file, as the file
// lays them out: a head and a body per record, after a header of 20 bytes.
func opensARecord(file, key []byte) bool {
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	seal, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	const nonce, head = 12, 60 + 16
	header := file[:20]
	for rest := file[20:]; len(rest) >= 4; {
		length := int(binary.BigEndian.Uint32(rest))
		record := rest[4 : 4+length]
		rest = rest[4+length:]
		sealedHead, body := record[nonce:nonce+head], record[nonce+head:]
		for _, additional := range [][]byte{header, nil} {
			if _, err := seal.Open(nil, record[:nonce], sealedHead, additional); err == nil {
				return true
			}
			if _, err := seal.Open(nil, body[:nonce], body[nonce:], additional); err == nil {
				return true
			}
		}
	}
	return false
}

// The attack the stored inventory must not allow: a command at A's proxy says
// it is B, another login of A's organisation, to test a guess at B's value.
func TestACommandStatingAnotherLoginConfirmsNothingOfItsStore(t *testing.T) {
	store := newTestInventoryStore(t)
	const idOfB, wrongGuess = "9f1c2d3e-id-only-b-may-see", "Qw7Er8Ty9Ui0Op1As2Df3Gh4Jk5Lz6Xc"
	asB := newStoredLeakRigAs(t, store, leakLoginB)
	if answer := registerThroughControl(t, asB.proxy, []leakguard.Value{{Type: "secret", ID: idOfB, Value: leakSecretTwo}}, phaseIDs(1)); answer == nil || answer.Added != 1 {
		t.Fatalf("B's registration with its own proxy: %+v", answer)
	}
	keyOfB := asB.guard.key
	asB.proxy.CloseHijacked()
	// A's proxy, and a second one like it: same master, tenant and login.
	asA, twin := newStoredLeakRigAs(t, store, leakLoginA), newStoredLeakRigAs(t, store, leakLoginA)
	if status, _ := rawStatus(t, asA); status.Inventory.Loaded != 1 {
		t.Fatalf("A's proxy did not load B's stored value: %+v", status.Inventory)
	}

	// What the command is handed for saying it is B.
	handed := statedKey(t, asA.proxy, leakLoginB)
	stored, err := store.Keyring.Get("phase-cli-ai-leak-inventory", "key-v1")
	if err != nil {
		t.Fatal(err)
	}
	master, err := base64.StdEncoding.DecodeString(stored[strings.LastIndexByte(stored, ':')+1:])
	if err != nil || len(master) != censor.KeySize {
		t.Fatalf("the keystore holds no master: %v", err)
	}
	for name, secret := range map[string][]byte{
		"the master": master, "the tenant's lookup key": keyOfB.LookupBytes(), "B's confirming key": keyOfB.ConfirmBytes(), "A's confirming key": asA.guard.key.ConfirmBytes(),
	} {
		if keyAnswerHolds(t, handed, secret) {
			t.Fatalf("a command that says it is B was handed %s", name)
		}
	}
	// Whatever the master gives is the same from both proxies, as the own
	// login's keys are. What B's name gets is not: it comes from neither's store.
	if statedKey(t, twin.proxy, leakLoginA) != statedKey(t, asA.proxy, leakLoginA) {
		t.Fatal("two proxies of one store hand their own login different keys")
	}
	if again := statedKey(t, twin.proxy, leakLoginB); again.Key == handed.Key || again.ConfirmKey == handed.ConfirmKey || again.KeyID == handed.KeyID {
		t.Fatal("what a command that says it is B is handed follows from the store's master")
	}

	// The guess is right. B's stored entries, out of their seal, do not confirm
	// it under the handed keys, as they would under the key B's own proxy hands B.
	_, loaded, err := store.Open()
	if err != nil || len(loaded) != 1 {
		t.Fatalf("the store holds %d values: %v", len(loaded), err)
	}
	index := func(key *censor.Key, value string) *censor.Entries {
		t.Helper()
		entries, err := censor.IndexValue(key, "secret", idOfB, value)
		if err != nil {
			t.Fatal(err)
		}
		return entries
	}
	guess := index(answeredKey(t, handed), leakSecretTwo)
	if confirmed := confirmedBy(loaded[0].Entries, guess); confirmed != 0 {
		t.Fatalf("%d hashes of a right guess, made with the handed keys, are B's stored ones", confirmed)
	}
	if own := index(keyOfB, leakSecretTwo); confirmedBy(loaded[0].Entries, own) != len(confirmingHashes(own)) || len(confirmingHashes(own)) == 0 {
		t.Fatal("B's own key does not confirm B's value: the check above shows nothing")
	}
	// The file adds nothing: no hash stands in it, and no handed key opens it.
	path := filepath.Join(store.Directory, "leak-inventory.bin")
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range append(confirmingHashes(loaded[0].Entries), confirmingHashes(guess)...) {
		if bytes.Contains(file, hash) {
			t.Fatal("the file holds a confirming hash in the clear")
		}
	}
	lookup, _ := base64.StdEncoding.DecodeString(handed.Key)
	confirm, _ := base64.StdEncoding.DecodeString(handed.ConfirmKey)
	if opensARecord(file, lookup) || opensARecord(file, confirm) || storedRecords(t, store) != 1 {
		t.Fatal("a handed key opens a record of the store")
	}

	// Nor does the proxy answer the guess: registered as B, right or wrong, it
	// is taken alike, counted alike, and written nowhere.
	counts := func() (known, unstored int) {
		status, _ := rawStatus(t, asA)
		return status.SecretsKnown, status.Inventory.Unstored
	}
	var answers []remoteapi.InventoryResponse
	for _, value := range []string{leakSecretTwo, wrongGuess} {
		known, unstored := counts()
		answer := registerThroughControlAs(t, asA.proxy, leakLoginB, []leakguard.Value{{Type: "secret", ID: idOfB, Value: value}}, phaseIDs(1))
		if answer == nil {
			t.Fatal("a registration as B was refused")
		}
		if after, afterUnstored := counts(); after != known || afterUnstored != unstored+1 {
			t.Fatalf("a registration as B moved the counts from %d, %d to %d, %d", known, unstored, after, afterUnstored)
		}
		answers = append(answers, *answer)
	}
	if answers[0] != answers[1] || answers[0].Added != 1 {
		t.Fatalf("the right guess was answered %+v and the wrong one %+v", answers[0], answers[1])
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, file) {
		t.Fatal("a command that says it is B wrote to the store")
	}
	asA.proxy.CloseHijacked()
	// B's next proxy holds what B's own proxy stored, and nothing said in its name.
	next := newStoredLeakRigAs(t, store, leakLoginB)
	if status, _ := rawStatus(t, next); status.SecretsKnown != 1 || status.Inventory.Loaded != 1 {
		t.Fatalf("B's next proxy: %+v", status.Inventory)
	}
	if out, _ := next.guard.index.Redact([]byte(leakSecretTwo + " " + wrongGuess)); string(out) != "ph:secret:"+idOfB+" "+wrongGuess {
		t.Fatalf("B's next proxy: %q", out)
	}
}

// Two commands that state no identity are two guests: each key request gets a
// confirming key of its own, and neither confirms what the other registered.
func TestCommandsThatStateNothingShareNoConfirmingKey(t *testing.T) {
	store := newTestInventoryStore(t)
	rig := newStoredLeakRigAs(t, store, leakLoginA)
	nobody := phaseproxy.InventoryIdentity{}
	first, second := statedKey(t, rig.proxy, nobody), statedKey(t, rig.proxy, nobody)
	if first.Key != second.Key || first.ConfirmKey == second.ConfirmKey || first.KeyID == second.KeyID {
		t.Fatal("two commands that state nothing were not handed a confirming key each")
	}
	entries := func(answer remoteapi.InventoryKeyResponse, value string) *censor.Entries {
		t.Helper()
		made, err := censor.IndexValue(answeredKey(t, answer), "secret", "an-id", value)
		if err != nil {
			t.Fatal(err)
		}
		return made
	}
	// The same value, indexed by each: no confirming hash in common.
	mine, theirs := entries(first, leakSecretOne), entries(second, leakSecretOne)
	if confirmedBy(mine, theirs) != 0 || len(confirmingHashes(theirs)) == 0 {
		t.Fatal("one guest's keys confirm another guest's entries")
	}
	register := func(proxy *httpProxy, made *censor.Entries, keyID string) (int, string) {
		t.Helper()
		encoded, _ := made.Marshal()
		body, _ := json.Marshal(remoteapi.InventoryRequest{SchemaVersion: 1, Entries: []json.RawMessage{encoded}, KeyID: keyID})
		recorder := controlCall(proxy, http.MethodPost, "/v1/inventory", "application/json", body)
		return recorder.Code, errorCode(recorder)
	}
	// Entries that name no key request of this process are under no key the
	// proxy can confirm with: refused, so the command fetches a key again.
	other := newStoredLeakRigAs(t, store, leakLoginA)
	for name, c := range map[string]struct {
		proxy *httpProxy
		keyID string
	}{
		"no key id":                  {rig.proxy, ""},
		"half of one":                {rig.proxy, first.KeyID[:16]},
		"one this proxy never made":  {rig.proxy, strings.Repeat("0", len(first.KeyID))},
		"another request's ending":   {rig.proxy, first.KeyID[:16] + second.KeyID[16:]},
		"a key id of a proxy before": {other.proxy, first.KeyID},
	} {
		if code, said := register(c.proxy, mine, c.keyID); code != http.StatusConflict || said != "inventory_key_changed" {
			t.Fatalf("a registration that states nothing, with %s: HTTP %d %s", name, code, said)
		}
	}
	if status, _ := rawStatus(t, rig); status.Inventory.Unstored != 0 {
		t.Fatalf("a refused registration was kept: %+v", status.Inventory)
	}
	// Each registers under the key it was handed, and its value is replaced.
	for name, c := range map[string]struct {
		made  *censor.Entries
		keyID string
	}{"the first": {mine, first.KeyID}, "the second": {entries(second, leakSecretTwo), second.KeyID}} {
		if code, said := register(rig.proxy, c.made, c.keyID); code != http.StatusOK {
			t.Fatalf("%s guest's registration: HTTP %d %s", name, code, said)
		}
	}
	if out, _ := rig.guard.index.Redact([]byte(leakSecretOne + " and " + leakSecretTwo)); string(out) != "ph:secret and ph:secret" {
		t.Fatalf("the guests' values: %q", out)
	}
	if status, _ := rawStatus(t, rig); status.SecretsKnown != 0 || status.Inventory.Unstored != 2 || storedRecords(t, store) != 0 {
		t.Fatalf("guests' registrations: %+v", status.Inventory)
	}
}
