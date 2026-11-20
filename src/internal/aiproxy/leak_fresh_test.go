package aiproxy

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// Secrets of hex digits, as openssl rand -hex 16, 20 and 32 make them, and
// one of letters and digits.
const (
	freshHex32 = "9f1c2d3e4b5a69788796a5b4c3d2e1f0"
	freshHex40 = "3b7e1a9c5d2f4e6081a2b3c4d5e6f70812345678"
	freshHex64 = "c0ffee11deadbeef0123456789abcdef7a6b5c4d3e2f10980192a3b4c5d6e7f8"
	freshPlain = "Qw7Er2Ty9Ui4Op6As1Df8Gh3Jk5Lz0XcVb4N"
)

var freshValues = []leakguard.Value{
	{Type: "secret", ID: "hex32", Value: freshHex32}, {Type: "secret", ID: "hex40", Value: freshHex40},
	{Type: "secret", ID: "hex64", Value: freshHex64}, {Type: "secret", ID: "plain", Value: freshPlain},
}

// freshPieces are pieces of them the proxy before a store replaced, by the id
// each is written as. stored says the stored scheme finds the piece too: it
// holds 24 characters that scheme hashes together, or is no run of hex digits.
var freshPieces = []struct {
	name, text, id string
	stored         bool
}{
	{"32 hex digits without the first", freshHex32[1:], "hex32", false},
	{"the first 23 of 32 hex digits", freshHex32[:23], "hex32", false},
	{"40 hex digits without the first", freshHex40[1:], "hex40", false},
	{"the last 30 of 40 hex digits", freshHex40[10:], "hex40", false},
	{"37 from inside 64 hex digits", freshHex64[3:40], "hex64", false},
	{"32 hex digits without the last", freshHex32[:31], "hex32", true},
	{"the last 40 of 64 hex digits", freshHex64[24:], "hex64", true},
	{"32 hex digits whole", freshHex32, "hex32", true},
	{"64 hex digits whole", freshHex64, "hex64", true},
	{"letters and digits without the first", freshPlain[1:], "plain", true},
	{"24 from inside letters and digits", freshPlain[6:30], "plain", true},
}

// registerWithClient registers with a rig's proxy through the CLI's own
// client, as a command that states an identity does.
func registerWithClient(t *testing.T, rig *leakRig, stated phaseproxy.InventoryIdentity, values []leakguard.Value) leakguard.Result {
	t.Helper()
	environment := map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": rig.proxyURL.String()}
	previous := leakguard.Environment
	leakguard.Environment = func(key string) string { return environment[key] }
	defer func() { leakguard.Environment = previous }()
	result, err := registerAsCommand(stated, values)
	if err != nil {
		t.Fatalf("the registration: %v", err)
	}
	return result
}

// sentFor is the tool result the provider received for one a client sent.
func sentFor(t *testing.T, rig *leakRig, content string) string {
	t.Helper()
	if response := postMessages(t, rig.client(rig.phaseRoots), "https://api.anthropic.com/v1/messages", anthropicBody(content), ""); response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	return toolResult(t, rig.lastReceived().body)
}

// A value a command registers with a running proxy is found by every piece
// the proxy before a store found it by, hex digits included: for a proxy with
// no identity, and for the values of an identified proxy's own login.
func TestAValueRegisteredWithARunningProxyIsFoundByItsPieces(t *testing.T) {
	for name, identity := range map[string]phaseproxy.InventoryIdentity{"a proxy with no identity": {}, "a login's own proxy": leakLoginA} {
		store := newTestInventoryStore(t)
		rig := newStoredLeakRigAs(t, store, identity)
		if result := registerWithClient(t, rig, identity, freshValues); result.Added != len(freshValues) || result.Unprotected != 0 {
			t.Fatalf("%s: the registration: %+v", name, result)
		}
		for _, piece := range freshPieces {
			if sent := sentFor(t, rig, "the key is "+piece.text+" ok"); sent != "the key is ph:secret:"+piece.id+" ok" {
				t.Errorf("%s: %s: the provider received %q", name, piece.name, sent)
			}
		}
		if status, _ := rawStatus(t, rig); status.SecretsKnown != len(freshValues) {
			t.Errorf("%s: %d values are known of %d registered", name, status.SecretsKnown, len(freshValues))
		}
		rig.proxy.CloseHijacked()
		// Only the stored scheme's entries reach the file, and only a login's.
		_, kept, err := openLeakInventory(store, leakLoginA)
		if err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: len(freshValues)}[identity.Known()]; len(kept) != want || storedRecords(t, store) != want {
			t.Fatalf("%s: the store holds %d values, want %d", name, len(kept), want)
		}
		for _, stored := range kept {
			if stored.Entries.Version != censor.EntriesVersion || !censor.SchemeStorable(stored.Entries.Version) {
				t.Fatalf("%s: the store holds entries of scheme %d", name, stored.Entries.Version)
			}
		}
	}
}

// A proxy that starts again knows a stored value whole, and by the pieces the
// stored scheme hashes, until a command registers the value with it: then by
// every piece again, as one value with one placeholder, and no longer as one
// only a store handed over.
func TestAStoredValueIsFoundByEveryPieceOnceRegisteredAgain(t *testing.T) {
	store := newTestInventoryStore(t)
	first := newStoredLeakRigAs(t, store, leakLoginA)
	if result := registerWithClient(t, first, leakLoginA, freshValues); result.Added != len(freshValues) {
		t.Fatalf("the registration: %+v", result)
	}
	first.proxy.CloseHijacked()
	next := newStoredLeakRigAs(t, store, leakLoginA)
	if status, _ := rawStatus(t, next); status.SecretsKnown != len(freshValues) || status.Inventory.Loaded != len(freshValues) {
		t.Fatalf("the next proxy loaded %+v", status.Inventory)
	}
	// From the store alone, a piece of hex digits is found only where 24
	// characters the stored scheme hashed together are in it.
	for _, piece := range freshPieces {
		want := "the key is ph:secret:" + piece.id + " ok"
		if !piece.stored {
			want = "the key is " + piece.text + " ok"
		}
		if sent := sentFor(t, next, "the key is "+piece.text+" ok"); sent != want {
			t.Errorf("from the store alone, %s: the provider received %q", piece.name, sent)
		}
	}
	// In a URL it is reported and does not stop the request.
	query := "https://api.anthropic.com/v1/messages?k=" + freshHex40
	if response := postMessages(t, next.client(next.phaseRoots), query, anthropicBody("nothing"), ""); response.StatusCode != http.StatusOK {
		t.Fatalf("a value known only from the store, in a URL: status %d", response.StatusCode)
	}
	before, chunks := next.guard.index.Stats(), next.guard.index.Stats().Chunks
	if result := registerWithClient(t, next, leakLoginA, freshValues); result.Added != len(freshValues) {
		t.Fatalf("registering again: %+v", result)
	}
	for _, piece := range freshPieces {
		if sent := sentFor(t, next, "the key is "+piece.text+" ok"); sent != "the key is ph:secret:"+piece.id+" ok" {
			t.Errorf("registered again, %s: the provider received %q", piece.name, sent)
		}
	}
	// Held both ways it is still one value, written once where it stands.
	after := next.guard.index.Stats()
	if after.Secrets != before.Secrets || after.Owners != before.Owners || after.Guests != 0 || after.Chunks <= chunks {
		t.Fatalf("the index held %+v from the store, and %+v once registered again", before, after)
	}
	if status, _ := rawStatus(t, next); status.SecretsKnown != len(freshValues) || status.Inventory.Loaded != len(freshValues) || status.Unprotected != 0 {
		t.Fatalf("status once registered again: %+v %+v", status, status.Inventory)
	}
	if sent := sentFor(t, next, freshHex40+" and "+freshPlain+" and "+freshHex40); sent != "ph:secret:hex40 and ph:secret:plain and ph:secret:hex40" {
		t.Fatalf("values held both ways: the provider received %q", sent)
	}
	out, report := next.guard.index.Redact([]byte(freshHex64 + " " + freshPlain))
	if string(out) != "ph:secret:hex64 ph:secret:plain" || report.Inventory != 2 || len(report.Findings) != 2 || report.Findings[0].Loaded || report.Findings[1].Loaded {
		t.Fatalf("values held both ways are reported as %q %+v", out, report)
	}
	for _, value := range []string{freshHex40, freshPlain} {
		target := "https://api.anthropic.com/v1/messages?k=" + value
		if response := postMessages(t, next.client(next.phaseRoots), target, anthropicBody("nothing"), ""); response.StatusCode != http.StatusForbidden {
			t.Fatalf("a value registered with this proxy, in a URL: status %d", response.StatusCode)
		}
	}
	// The file is as it was: the same values, registered again.
	next.proxy.CloseHijacked()
	if records := storedRecords(t, store); records != len(freshValues) {
		t.Fatalf("the store holds %d records of %d values", records, len(freshValues))
	}
}

// postLive registers one value's stored entries and what is sent as its live
// ones, made under an answer of the key route, and returns the status.
func postLive(t *testing.T, proxy *httpProxy, stated phaseproxy.InventoryIdentity, keys remoteapi.InventoryKeyResponse, stored *censor.Entries, live ...*censor.Entries) int {
	t.Helper()
	request := remoteapi.InventoryRequest{SchemaVersion: 1, Tenant: stated.Tenant, Login: stated.Login, KeyID: keys.KeyID}
	encoded, _ := stored.Marshal()
	request.Entries = []json.RawMessage{encoded}
	for _, entry := range live {
		encoded, _ := entry.Marshal()
		request.LiveEntries = append(request.LiveEntries, encoded)
	}
	body, _ := json.Marshal(request)
	return controlCall(proxy, http.MethodPost, "/v1/inventory", "application/json", body).Code
}

// Live entries are for a command of the session's own login, made under the
// key that login was handed: no other command's are taken, and none is
// matched under a key the proxy did not hand out.
func TestLiveEntriesAreTakenFromTheSessionsOwnLoginAlone(t *testing.T) {
	store := newTestInventoryStore(t)
	rig := newStoredLeakRigAs(t, store, leakLoginA)
	own := statedKey(t, rig.proxy, leakLoginA)
	raw, err := base64.StdEncoding.DecodeString(own.LiveKey)
	if err != nil {
		t.Fatal(err)
	}
	live, err := censor.LookupKeyFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	made := func(key *censor.Key, scheme int, id string) *censor.Entries {
		t.Helper()
		entries, err := censor.IndexValueScheme(key, scheme, "secret", id, freshHex40)
		if err != nil {
			t.Fatal(err)
		}
		return entries
	}
	// A guest, with the live key itself in hand, is still refused.
	for name, stated := range map[string]phaseproxy.InventoryIdentity{"another login of the tenant": leakLoginB, "another tenant": otherTenantA, "nobody": {}} {
		keys := statedKey(t, rig.proxy, stated)
		if keys.LiveKey != "" || keys.LiveFormat != 0 {
			t.Fatalf("a command of %s was handed a live key", name)
		}
		if code := postLive(t, rig.proxy, stated, keys, made(answeredKey(t, keys), keys.Format, "an-id"), made(live, leakLiveScheme, "an-id")); code != http.StatusBadRequest {
			t.Fatalf("live entries from a command of %s: HTTP %d", name, code)
		}
	}
	// From its own login: one for each value, of that value's name, in the live scheme.
	ownKey := answeredKey(t, own)
	stored := made(ownKey, own.Format, "an-id")
	for name, sent := range map[string][]*censor.Entries{
		"in the stored scheme": {made(ownKey, censor.EntriesVersion, "an-id")},
		"under another id":     {made(live, leakLiveScheme, "another-id")},
		"two for one value":    {made(live, leakLiveScheme, "an-id"), made(live, leakLiveScheme, "an-id")},
	} {
		if code := postLive(t, rig.proxy, leakLoginA, own, stored, sent...); code != http.StatusBadRequest {
			t.Fatalf("live entries %s: HTTP %d", name, code)
		}
	}
	if out, _ := rig.guard.index.Redact([]byte(freshHex40)); string(out) != freshHex40 || storedRecords(t, store) != 0 {
		t.Fatalf("a refused registration was kept: %q", out)
	}
	// Under a key the proxy did not hand out, the entries match nothing.
	another, err := censor.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if code := postLive(t, rig.proxy, leakLoginA, own, stored, made(another, leakLiveScheme, "an-id")); code != http.StatusOK {
		t.Fatalf("live entries under another key: HTTP %d", code)
	}
	if out, _ := rig.guard.index.Redact([]byte(freshHex40)); string(out) != freshHex40 {
		t.Fatalf("entries under a key the proxy did not hand out matched: %q", out)
	}
	// A value whose stored entries the client found too large to send is
	// matched by its live ones, and nothing more is stored.
	records := storedRecords(t, store)
	tooLong := &censor.Entries{Version: own.Format, Type: "secret", ID: "an-id", Forms: []censor.Form{}, Unprotected: []censor.Unprotected{{Reason: censor.ReasonTooLong}}}
	if code := postLive(t, rig.proxy, leakLoginA, own, tooLong, made(live, leakLiveScheme, "an-id")); code != http.StatusOK {
		t.Fatalf("live entries beside stored ones too large to send: HTTP %d", code)
	}
	if out, _ := rig.guard.index.Redact([]byte(freshHex40[1:])); string(out) != "ph:secret:an-id" || storedRecords(t, store) != records {
		t.Fatalf("a value too large to store: %q, %d records then %d", out, records, storedRecords(t, store))
	}
	// The process before this one handed out another live key: its key id is
	// not this proxy's, and the client fetches the key again.
	rig.proxy.CloseHijacked()
	next := newStoredLeakRigAs(t, store, leakLoginA)
	if code := postLive(t, next.proxy, leakLoginA, own, stored, made(live, leakLiveScheme, "an-id")); code != http.StatusConflict {
		t.Fatalf("entries made under the last process's live key: HTTP %d", code)
	}
	if result := registerWithClient(t, next, leakLoginA, freshValues[:1]); result.Added != 1 {
		t.Fatalf("a client's registration with the next proxy: %+v", result)
	}
	if sent := sentFor(t, next, "x "+freshHex32[:23]+" y"); sent != "x ph:secret:hex32 y" {
		t.Fatalf("a piece of a value registered with the next proxy: %q", sent)
	}
}

// A value a proxy loaded from the store, and a command then registered with
// it again, stops a request wherever a value that was only registered does:
// whole, in pieces and encoded. The stored scheme finds some of those where
// the live one does not, and what it finds is registered too. A value the
// store holds that was not registered again is still only reported.
func TestAValueRegisteredAgainStopsARequestAsOneOnlyRegisteredDoes(t *testing.T) {
	values := append([]leakguard.Value(nil), freshValues...)
	for i := 0; i < 8; i++ {
		values = append(values, leakguard.Value{Type: "secret", ID: fmt.Sprintf("token-%d", i), Value: randomLeakValue(t, 40)})
	}
	kept := leakguard.Value{Type: "secret", ID: "kept", Value: randomLeakValue(t, 40)}
	store := newTestInventoryStore(t)
	first := newStoredLeakRigAs(t, store, leakLoginA)
	if result := registerWithClient(t, first, leakLoginA, append([]leakguard.Value{kept}, values...)); result.Added != len(values)+1 {
		t.Fatalf("the first registration: %+v", result)
	}
	first.proxy.CloseHijacked()
	again := newStoredLeakRigAs(t, store, leakLoginA)
	if result := registerWithClient(t, again, leakLoginA, values); result.Added != len(values) {
		t.Fatalf("registering again: %+v", result)
	}
	only := newStoredLeakRigAs(t, newTestInventoryStore(t), leakLoginA)
	if result := registerWithClient(t, only, leakLoginA, values); result.Added != len(values) {
		t.Fatalf("registering with a proxy that loaded nothing: %+v", result)
	}
	// What a proxy's index says of a URL: a value is in it, and one that stops it.
	says := func(rig *leakRig, query string) (found, stops bool) {
		for _, match := range rig.guard.index.Find([]byte("/v1/messages?k=" + query)) {
			found = found || match.Kind == "inventory"
			stops = stops || (match.Kind == "inventory" && !match.Loaded)
		}
		return found, stops
	}
	status := func(rig *leakRig, query string) int {
		t.Helper()
		return postMessages(t, rig.client(rig.phaseRoots), "https://api.anthropic.com/v1/messages?k="+query, anthropicBody("nothing"), "").StatusCode
	}
	// A value whole, cut and encoded, and its hex from every start, 48
	// characters and longer.
	arrangements := func(value string) []string {
		inHex := hex.EncodeToString([]byte(value))
		out := []string{value, value[1:], value[:len(value)-1], value[4:30], inHex, strings.ToUpper(inHex),
			url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(value))), url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("x:" + value)))}
		for from := 0; from+48 <= len(inHex); from++ {
			out = append(out, inHex[from:min(len(inHex), from+48+(from*7)%40)])
		}
		return out
	}
	stopped, sent := 0, 0
	for _, value := range values {
		for _, query := range arrangements(value.Value) {
			if _, stops := says(only, query); !stops {
				continue
			}
			stopped++
			if _, stops := says(again, query); !stops {
				t.Errorf("%s as %q stops a request at a proxy it was only registered with, and not at one that loaded it first", value.ID, query)
				continue
			}
			// Every sixth of them as a request.
			if stopped%6 != 0 {
				continue
			}
			sent++
			if at, here := status(only, query), status(again, query); at != http.StatusForbidden || here != http.StatusForbidden {
				t.Errorf("%s as %q in a URL: HTTP %d where it was only registered, HTTP %d where it was loaded first", value.ID, query, at, here)
			}
		}
	}
	if stopped < 20*len(values) || sent < 3*len(values) {
		t.Fatalf("%d arrangements stop a request and %d were sent: too few to say anything", stopped, sent)
	}
	// The value nobody registered again: found, reported, and never a stop.
	for _, query := range arrangements(kept.Value) {
		if _, stops := says(again, query); stops {
			t.Errorf("a value known only from the store stops a request as %q", query)
		}
	}
	if found, _ := says(again, kept.Value); !found || status(again, kept.Value) != http.StatusOK {
		t.Fatal("a value known only from the store is not found in a URL, or stopped the request")
	}
	if found, _ := says(only, kept.Value); found {
		t.Fatal("a proxy that loaded nothing knows a value it was never given")
	}
	// Nothing was added for it: one value each, as loaded.
	if status, _ := rawStatus(t, again); status.SecretsKnown != len(values)+1 || status.Inventory.Loaded != len(values)+1 {
		t.Fatalf("status once registered again: %+v %+v", status, status.Inventory)
	}
}
