package aiproxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// postInventory posts entries as a command that states an identity and a key id.
func postInventory(t *testing.T, proxy *httpProxy, stated phaseproxy.InventoryIdentity, keyID string, entries ...*censor.Entries) *httptest.ResponseRecorder {
	t.Helper()
	request := remoteapi.InventoryRequest{SchemaVersion: 1, Tenant: stated.Tenant, Login: stated.Login, KeyID: keyID}
	for _, made := range entries {
		encoded, err := made.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		request.Entries = append(request.Entries, encoded)
		request.IDKinds = append(request.IDKinds, remoteapi.InventoryIDPhase)
	}
	body, _ := json.Marshal(request)
	return controlCall(proxy, http.MethodPost, "/v1/inventory", "application/json", body)
}

// Commands that state no identity are one guest: one confirming key for the
// life of the proxy, so a value such a command registers again is held once.
func TestCommandsThatStateNothingAreOneGuest(t *testing.T) {
	store := newTestInventoryStore(t)
	rig := newStoredLeakRigAs(t, store, leakLoginA)
	nobody := phaseproxy.InventoryIdentity{}
	first, second := statedKey(t, rig.proxy, nobody), statedKey(t, rig.proxy, nobody)
	if first != second {
		t.Fatal("two commands that state nothing were handed different keys: each run would be a new guest")
	}
	// Two runs of one command register the same value: one entry, counted twice.
	for run := 0; run < 2; run++ {
		if answer := registerThroughControlAs(t, rig.proxy, nobody, []leakguard.Value{{Type: "secret", ID: "an-id", Value: leakSecretOne}}, phaseIDs(1)); answer == nil || answer.Added != 1 {
			t.Fatalf("run %d: %+v", run, answer)
		}
	}
	if status, _ := rawStatus(t, rig); rig.guard.index.Stats().Guests != 1 || status.Inventory.Unstored != 2 || status.SecretsKnown != 0 {
		t.Fatalf("the same value from two runs: %+v, %+v", rig.guard.index.Stats(), status.Inventory)
	}
	// It is a guest's key all the same: nothing of the store, another from a
	// guest that says who it is, and gone with the proxy.
	stated := statedKey(t, rig.proxy, otherTenantA)
	if stated.Key != first.Key || stated.ConfirmKey == first.ConfirmKey || stated.KeyID == first.KeyID || first.Key == base64.StdEncoding.EncodeToString(rig.guard.key.LookupBytes()) {
		t.Fatal("a command that states nothing shares more than the guests' lookup key")
	}
	next := newStoredLeakRigAs(t, store, leakLoginA)
	if again := statedKey(t, next.proxy, nobody); again.Key == first.Key || again.ConfirmKey == first.ConfirmKey || again.KeyID == first.KeyID {
		t.Fatal("the key of commands that state nothing outlived the proxy")
	}
	made, err := censor.IndexValue(answeredKey(t, first), "secret", "another-id", leakSecretTwo)
	if err != nil {
		t.Fatal(err)
	}
	// Entries under a key this proxy does not hand such a command are refused,
	// so the command fetches the key again.
	for name, c := range map[string]struct {
		proxy *httpProxy
		keyID string
	}{
		"half a key id":              {rig.proxy, first.KeyID[:8]},
		"one this proxy never made":  {rig.proxy, strings.Repeat("0", len(first.KeyID))},
		"a stated guest's":           {rig.proxy, stated.KeyID},
		"a key id of a proxy before": {next.proxy, first.KeyID},
	} {
		if recorder := postInventory(t, c.proxy, nobody, c.keyID, made); recorder.Code != http.StatusConflict || errorCode(recorder) != "inventory_key_changed" {
			t.Fatalf("a registration that states nothing, with %s: HTTP %d %s", name, recorder.Code, errorCode(recorder))
		}
	}
	if recorder := postInventory(t, rig.proxy, nobody, first.KeyID, made); recorder.Code != http.StatusOK {
		t.Fatalf("the registration under the key it was handed: HTTP %d", recorder.Code)
	}
	if out, _ := rig.guard.index.Redact([]byte(leakSecretOne + " and " + leakSecretTwo)); string(out) != "ph:secret and ph:secret" {
		t.Fatalf("the values: %q", out)
	}
	if storedRecords(t, store) != 0 {
		t.Fatal("a registration that states nothing was stored")
	}
}

// A client older than key ids fetches the key with a GET, indexes under
// scheme 1 with the one key it reads, and names no key: taken, in memory only.
func TestAClientOlderThanKeyIDsStillRegisters(t *testing.T) {
	for name, identity := range map[string]phaseproxy.InventoryIdentity{"a proxy the Console named": leakLoginA, "a proxy it named nobody for": {}} {
		store := newTestInventoryStore(t)
		rig := newStoredLeakRigAs(t, store, identity)
		recorder := controlCall(rig.proxy, http.MethodGet, "/v1/inventory/key", "", nil)
		var answer struct {
			Key    string `json:"key"`
			Format int    `json:"format"`
		}
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &answer) != nil {
			t.Fatalf("%s: the key: HTTP %d", name, recorder.Code)
		}
		raw, _ := base64.StdEncoding.DecodeString(answer.Key)
		key, err := censor.LookupKeyFromBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		made, err := censor.IndexValueScheme(key, 1, "secret", "an-id", leakSecretOne)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := made.Marshal()
		// All such a client sends: no identity, no key id, no kinds.
		body, _ := json.Marshal(map[string]any{"schemaVersion": 1, "entries": []json.RawMessage{encoded}})
		recorder = controlCall(rig.proxy, http.MethodPost, "/v1/inventory", "application/json", body)
		var added remoteapi.InventoryResponse
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &added) != nil || added.Added != 1 {
			t.Fatalf("%s: the registration of a client older than key ids: HTTP %d %s", name, recorder.Code, recorder.Body.String())
		}
		want := "a ph:secret b"
		if !identity.Known() {
			want = "a ph:secret:an-id b"
		}
		if out, _ := rig.guard.index.Redact([]byte("a " + leakSecretOne + " b")); string(out) != want {
			t.Fatalf("%s: the value it registered: %q", name, out)
		}
		rig.proxy.CloseHijacked()
		if storedRecords(t, store) != 0 {
			t.Fatalf("%s: entries of scheme 1 were stored", name)
		}
	}
}

// The same commands run again and again, and more values than the guests'
// share holds, never get a guest refused: the oldest entries make way.
func TestGuestsAreNeverRefusedForAFullShare(t *testing.T) {
	leakIndexMaxSecrets = 400 // the guests' share is a hundred
	t.Cleanup(func() { leakIndexMaxSecrets = 0 })
	rig := newStoredLeakRigAs(t, newTestInventoryStore(t), leakLoginA)
	nobody := phaseproxy.InventoryIdentity{}
	value := func(i int) string { return fmt.Sprintf("Val%03dQw7Er8Ty9Ui0Op1As2Df3Gh4Jk5", i) }
	var values []leakguard.Value
	for i := 0; i < 50; i++ {
		values = append(values, leakguard.Value{Type: "secret", ID: fmt.Sprintf("KEY_%d", i), Value: value(i)})
	}
	// The review found the 51st run of one command refused, and every guest after it.
	for run := 0; run < 120; run++ {
		if answer := registerThroughControlAs(t, rig.proxy, nobody, values, nil); answer == nil || answer.Added != 50 {
			t.Fatalf("run %d of a command that states nothing: %+v", run, answer)
		}
	}
	if guests := rig.guard.index.Stats().Guests; guests != 50 {
		t.Fatalf("%d entries held for 50 values registered again and again", guests)
	}
	// A hundred more values, one command each: the share is full, and the
	// values registered longest ago go.
	for i := 50; i < 150; i++ {
		if answer := registerThroughControlAs(t, rig.proxy, nobody, []leakguard.Value{{Type: "secret", ID: fmt.Sprintf("KEY_%d", i), Value: value(i)}}, nil); answer == nil || answer.Added != 1 {
			t.Fatalf("value %d at a full share: %+v", i, answer)
		}
	}
	for i, held := range map[int]bool{0: false, 49: false, 50: true, 149: true} {
		if out, _ := rig.guard.index.Redact([]byte("v=" + value(i))); (string(out) == "v=ph:secret") != held {
			t.Fatalf("value %d after the share filled: %q", i, out)
		}
	}
	// A guest of another account, and the session's own login, still register.
	fresh := []leakguard.Value{{Type: "secret", ID: "fresh", Value: leakSecretThree}}
	if answer := registerThroughControlAs(t, rig.proxy, otherTenantB, fresh, nil); answer == nil || answer.Added != 1 {
		t.Fatalf("a guest of another account at a full share: %+v", answer)
	}
	if out, _ := rig.guard.index.Redact([]byte("v=" + leakSecretThree)); string(out) != "v=ph:secret" {
		t.Fatalf("its value: %q", out)
	}
	if answer := registerThroughControl(t, rig.proxy, fresh, nil); answer == nil || answer.Added != 1 || rig.guard.index.Stats().Guests != 100 {
		t.Fatalf("the session's own login: %+v, %+v", answer, rig.guard.index.Stats())
	}
	// Only one registration that is larger than the share by itself is refused.
	keyAnswer := statedKey(t, rig.proxy, nobody)
	var large []*censor.Entries
	for i := 0; i < 101; i++ {
		made, err := censor.IndexValue(answeredKey(t, keyAnswer), "secret", fmt.Sprintf("LARGE_%d", i), value(200+i))
		if err != nil {
			t.Fatal(err)
		}
		large = append(large, made)
	}
	if recorder := postInventory(t, rig.proxy, nobody, keyAnswer.KeyID, large...); recorder.Code != http.StatusInsufficientStorage || errorCode(recorder) != "leak_inventory_full" {
		t.Fatalf("one registration of 101 values into a share of 100: HTTP %d %s", recorder.Code, errorCode(recorder))
	}
	if recorder := postInventory(t, rig.proxy, nobody, keyAnswer.KeyID, large[:100]...); recorder.Code != http.StatusOK {
		t.Fatalf("one registration of 100 values: HTTP %d %s", recorder.Code, errorCode(recorder))
	}
}

// A guest that fills the guests' share and then registers a guess in another
// guest's name is answered alike whether that guest holds the type and id.
func TestTheGuestsShareSaysNothingOfAnotherGuestsID(t *testing.T) {
	leakIndexMaxSecrets = 40 // the guests' share is ten
	t.Cleanup(func() { leakIndexMaxSecrets = 0 })
	nobody := phaseproxy.InventoryIdentity{}
	junk := func(i int) string { return fmt.Sprintf("junk%04dQw7Er8Ty9Ui0Op1As2", i) }
	guess := func(id string) (code int, body string, guests int, oldest, second bool) {
		rig := newStoredLeakRigAs(t, newTestInventoryStore(t), leakLoginA)
		register := func(stated phaseproxy.InventoryIdentity, id, value string) {
			t.Helper()
			if answer := registerThroughControlAs(t, rig.proxy, stated, []leakguard.Value{{Type: "secret", ID: id, Value: value}}, nil); answer == nil {
				t.Fatalf("registering %s", id)
			}
		}
		for i := 0; i < 5; i++ {
			register(nobody, fmt.Sprintf("j%d", i), junk(i))
		}
		register(otherTenantA, "STRIPE_LIVE_KEY", leakSecretThree)
		for i := 5; i < 9; i++ {
			register(nobody, fmt.Sprintf("j%d", i), junk(i))
		}
		// The share is full. The guess is registered in the other guest's name.
		asVictim := statedKey(t, rig.proxy, otherTenantA)
		made, err := censor.IndexValue(answeredKey(t, asVictim), "secret", id, "anything-at-all-0123456789")
		if err != nil {
			t.Fatal(err)
		}
		recorder := postInventory(t, rig.proxy, otherTenantA, asVictim.KeyID, made)
		held := func(i int) bool {
			out, _ := rig.guard.index.Redact([]byte(junk(i)))
			return string(out) == "ph:secret"
		}
		return recorder.Code, recorder.Body.String(), rig.guard.index.Stats().Guests, held(0), held(1)
	}
	heldCode, heldBody, heldGuests, heldOldest, heldSecond := guess("STRIPE_LIVE_KEY")
	for _, id := range []string{"AWS_SECRET_ACCESS_KEY", "DATABASE_URL"} {
		code, body, guests, oldest, second := guess(id)
		if code != heldCode || body != heldBody || guests != heldGuests || oldest != heldOldest || second != heldSecond {
			t.Fatalf("an id the other guest holds: HTTP %d %s, %d entries, %v %v; %s, which it does not: HTTP %d %s, %d entries, %v %v",
				heldCode, heldBody, heldGuests, heldOldest, heldSecond, id, code, body, guests, oldest, second)
		}
	}
	if heldCode != http.StatusOK || heldGuests != 10 || heldOldest || !heldSecond {
		t.Fatalf("a guess at a full share: HTTP %d, %d entries, the oldest held %v, the next %v", heldCode, heldGuests, heldOldest, heldSecond)
	}
}

// A guest fills a lookup value with forged forms and registers its guess of a
// chunk of another guest's value last: the guess is held, right or wrong.
func TestAFilledLookupValueConfirmsNoChunkOfAnotherGuestsValue(t *testing.T) {
	rig := newStoredLeakRigAs(t, newTestInventoryStore(t), leakLoginA)
	const theirs = "Hy6Gs4Fp0Ju7Ke2Ma9Zk3Qw9Lm2Xr7Tb5Nc8Vd1"
	if answer := registerThroughControlAs(t, rig.proxy, otherTenantA, []leakguard.Value{{Type: "secret", ID: "theirs", Value: theirs}}, phaseIDs(1)); answer == nil || answer.Added != 1 {
		t.Fatalf("the other guest: %+v", answer)
	}
	nobody := phaseproxy.InventoryIdentity{}
	keyAnswer := statedKey(t, rig.proxy, nobody)
	for name, chunk := range map[string]string{"right": theirs[:12], "wrong": "Aa1Bb2Cc3Dd4"} {
		filler, probe := forgedProbe(t, answeredKey(t, keyAnswer), "probe", name, chunk)
		if recorder := postInventory(t, rig.proxy, nobody, keyAnswer.KeyID, filler, probe); recorder.Code != http.StatusOK {
			t.Fatalf("the %s guess: HTTP %d %s", name, recorder.Code, errorCode(recorder))
		}
		if out, _ := rig.guard.index.Redact([]byte("x " + chunk + " y")); string(out) != "x ph:probe y" {
			t.Fatalf("a %s guess of a chunk of another guest's value: %q", name, out)
		}
	}
}

// forgedProbe is what a client posts to learn whether a lookup value is in
// use: 63 forms that sit under a guess's lookup value, and the guess itself.
func forgedProbe(t *testing.T, key *censor.Key, typ, id, guess string) (filler, probe *censor.Entries) {
	t.Helper()
	probe, err := censor.IndexValue(key, typ, "probe-"+id, guess)
	if err != nil || len(probe.Forms) == 0 || probe.Forms[0].Form != "raw" || probe.Forms[0].Length != 12 {
		t.Fatalf("the probe: %v", err)
	}
	probe.Forms = probe.Forms[:1]
	filler = &censor.Entries{Version: 2, Type: typ, ID: "fill-" + id}
	for i := 0; i < 63; i++ {
		sum := make([]byte, 16)
		if _, err := rand.Read(sum); err != nil {
			t.Fatal(err)
		}
		filler.Forms = append(filler.Forms, censor.Form{Part: fmt.Sprintf("leaf:%d", i), Form: "raw", Length: 12, Lookups: probe.Forms[0].Lookups, MACs: sum, Weak: []byte{0}})
	}
	return filler, probe
}

// Guests, the session's own login and scans at once, with a guests' share so
// small that every registration drops an entry a scan may be reading.
func TestGuestsComeAndGoWhileRequestsAreScanned(t *testing.T) {
	leakIndexMaxSecrets = 16 // the guests' share is four
	t.Cleanup(func() { leakIndexMaxSecrets = 0 })
	rig := newStoredLeakRigAs(t, newTestInventoryStore(t), leakLoginA)
	value := func(i int) string { return fmt.Sprintf("conc%04dQw7Er8Ty9Ui0Op1As2Df3", i) }
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 90; i++ {
			stated := []phaseproxy.InventoryIdentity{{}, leakLoginB, otherTenantA}[i%3]
			if answer := registerThroughControlAs(t, rig.proxy, stated, []leakguard.Value{{Type: "secret", ID: fmt.Sprintf("k%d", i), Value: value(i)}}, nil); answer == nil || answer.Added != 1 {
				t.Errorf("registration %d: %+v", i, answer)
				return
			}
		}
	}()
	for i := 0; ; i++ {
		select {
		case <-done:
			// The four registered last are the ones held.
			out, _ := rig.guard.index.Redact([]byte(value(85) + " " + value(86) + " " + value(89)))
			if string(out) != value(85)+" ph:secret ph:secret" || rig.guard.index.Stats().Guests != 4 {
				t.Fatalf("after the guests came and went: %q, %+v", out, rig.guard.index.Stats())
			}
			return
		default:
		}
		_, _ = rig.guard.index.Redact([]byte(fmt.Sprintf("text %d %s and %s", i, value(i%90), value((i+1)%90))))
		_, _ = rawStatus(t, rig)
	}
}
