package aiproxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// What the tenant under test registers, what both do, and what only the other does.
const (
	isolationOwn    = "Tg5Wq2Nc8Jv4Ks7Lp1Zd6Mb3Xr9Fh0Ye"
	isolationLater  = "Pk3Zm7Qd1Vx5Hc9Jb2Ns6Lf0Gt4Rw8Ua"
	isolationShared = "Bn7Hc3Vx9Qm1Lk5Jd8Fs2Gp6Wz4Ty0Ra"
	isolationTheirs = "Uy6Rt2Ew8Qa4Sd0Fg5Hj1Kl7Zx3Cv9Bn"
)

// isolationProbe holds every one of them, whole, encoded and in pieces, as a
// request might.
var isolationProbe = []byte("a " + isolationOwn + " b " + isolationShared + " c " + isolationTheirs + " d " + isolationLater +
	" e " + hex.EncodeToString([]byte(isolationTheirs)) + " f " + base64.StdEncoding.EncodeToString([]byte(isolationShared)) +
	" g " + isolationOwn[3:29] + " h " + isolationShared[1:] + " i " + isolationTheirs[:31] + " j " + hex.EncodeToString([]byte(isolationShared))[5:41])

// tenantView is all a tenant's session and its commands can read while they
// use a store: its proxy's answers, what a scan writes and reports, what an
// event would name, and status. meanwhile is what another tenant does with
// the same store before, during and after.
func tenantView(t *testing.T, store *phaseproxy.InventoryStore, self phaseproxy.InventoryIdentity, meanwhile func(stage int)) string {
	t.Helper()
	var view strings.Builder
	note := func(what string, value any) {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&view, "%s: %s\n", what, encoded)
	}
	start := func() *httpProxy {
		t.Helper()
		guard, err := newStoredLeakGuard(leakModeCensor, store, self)
		if err != nil {
			t.Fatal(err)
		}
		return inventoryProxy(t, guard)
	}
	look := func(when string, proxy *httpProxy) {
		t.Helper()
		recorder := controlCall(proxy, http.MethodGet, "/v1/status", "", nil)
		var status remoteapi.StatusResponse
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &status) != nil || status.LeakProtection == nil {
			t.Fatalf("%s: status: %d %s", when, recorder.Code, recorder.Body.String())
		}
		note(when+", status", status.LeakProtection)
		// The live key is random in each process: all of the answer but that.
		keys := statedKey(t, proxy, self)
		note(when+", the key route", storeKeys(keys))
		note(when+", a live key", []any{keys.LiveKey != "", keys.LiveFormat})
		out, report := proxy.leak.index.Redact(isolationProbe)
		note(when+", a scan writes", string(out))
		note(when+", a scan reports", report)
		var found []string
		for _, finding := range report.Findings {
			found = append(found, fmt.Sprintf("%q loaded=%v", leakFound(finding), finding.Loaded))
		}
		note(when+", a scan found", found)
		var placeholders []string
		for _, finding := range report.Findings {
			placeholders = append(placeholders, leakFound(finding))
		}
		note(when+", an event names", proxy.leak.eventPlaceholders(placeholders))
		note(when+", the index counts", proxy.leak.index.Stats())
	}
	register := func(when string, proxy *httpProxy, id, value string) {
		t.Helper()
		answer := registerThroughControlAs(t, proxy, self, []leakguard.Value{{Type: "secret", ID: id, Value: value}}, phaseIDs(1))
		if answer == nil || answer.Added != 1 {
			t.Fatalf("%s: registering %s: %+v", when, id, answer)
		}
		note(when+", registering "+id, answer)
	}

	meanwhile(0)
	first := start()
	look("a first start", first)
	register("a first start", first, "own", isolationOwn)
	register("a first start", first, "shared", isolationShared)
	look("after registering", first)
	meanwhile(1)
	look("while the other registers", first)
	register("while the other registers", first, "later", isolationLater)
	// An error the proxy answers with: entries under a key it does not hand out.
	entry, err := censor.IndexValue(first.leak.key, "secret", "refused", isolationTheirs)
	if err != nil {
		t.Fatal(err)
	}
	refused := postInventory(t, first, self, "0000000000000000", entry)
	note("a registration under another key", fmt.Sprintf("%d %s", refused.Code, refused.Body.String()))
	meanwhile(2)
	second := start()
	look("a restart", second)
	register("a restart", second, "own", isolationOwn)
	look("after registering again", second)
	return view.String()
}

// Nothing a tenant can read depends on what another tenant registered: with
// the same store and the same master, its answers, scans, events and status
// are the same to the byte whether the other stored nothing, the same value,
// other values, or many.
func TestWhatATenantReadsNeverDependsOnAnotherTenant(t *testing.T) {
	const organisation, account = "test-organisation", "account-a"
	pairs := map[string][2]phaseproxy.InventoryIdentity{
		"another organisation of the host": {
			phaseproxy.NewInventoryIdentity("https://console.test", organisation, phaseproxy.InventoryLoginUser, account),
			phaseproxy.NewInventoryIdentity("https://console.test", "another-organisation", phaseproxy.InventoryLoginUser, account),
		},
		"the same organisation and login ids on another host": {
			phaseproxy.NewInventoryIdentity("https://console.test", organisation, phaseproxy.InventoryLoginUser, account),
			phaseproxy.NewInventoryIdentity("https://phase.other.test", organisation, phaseproxy.InventoryLoginUser, account),
		},
		// Two Consoles of one origin, with the ids a copied database has.
		"the same organisation and login ids under another path of the origin": {
			phaseproxy.NewInventoryIdentity("https://console.test/one", organisation, phaseproxy.InventoryLoginUser, account),
			phaseproxy.NewInventoryIdentity("https://console.test/two", organisation, phaseproxy.InventoryLoginUser, account),
		},
		"the same ids at the origin's root and under a path of it": {
			phaseproxy.NewInventoryIdentity("https://console.test", organisation, phaseproxy.InventoryLoginUser, account),
			phaseproxy.NewInventoryIdentity("https://console.test/one", organisation, phaseproxy.InventoryLoginUser, account),
		},
	}
	// What the other registers before the tenant's proxy starts, while it
	// runs, and before it starts again.
	many := func(n int) []string {
		values := make([]string, n)
		for i := range values {
			values[i] = randomLeakValue(t, 40)
		}
		return values
	}
	others := map[string][3][]string{
		"the same value":             {{isolationShared}, {isolationShared, isolationOwn}, {isolationLater}},
		"other values":               {{isolationTheirs}, {randomLeakValue(t, 40)}, {randomLeakValue(t, 24)}},
		"the same and many of other": {append(many(150), isolationShared, isolationTheirs), many(150), {isolationOwn}},
	}
	for name, pair := range pairs {
		for _, swapped := range []bool{false, true} {
			self, other := pair[0], pair[1]
			if swapped {
				self, other = other, self
			}
			if !self.Known() || !other.Known() || self.SameTenant(other) {
				t.Fatalf("%s: %q and %q are not two tenants", name, self.Tenant, other.Tenant)
			}
			// One keystore, so one master, for every store of the comparison.
			keystore := &testKeystore{values: map[string]string{}}
			newStore := func() *phaseproxy.InventoryStore {
				return &phaseproxy.InventoryStore{Directory: filepath.Join(t.TempDir(), "ai"), Keyring: keystore}
			}
			alone := tenantView(t, newStore(), self, func(int) {})
			if !strings.Contains(alone, "ph:secret:own") || !strings.Contains(alone, isolationTheirs) || strings.Contains(alone, "otherTenants") {
				t.Fatalf("%s: the view of a tenant alone is not what it should be:\n%s", name, alone)
			}
			for what, stages := range others {
				store := newStore()
				with := tenantView(t, store, self, func(stage int) {
					guard, err := newStoredLeakGuard(leakModeCensor, store, other)
					if err != nil {
						t.Fatal(err)
					}
					var values []leakguard.Value
					for i, value := range stages[stage] {
						values = append(values, leakguard.Value{Type: "secret", ID: fmt.Sprintf("theirs-%d-%d", stage, i), Value: value})
					}
					if answer := registerThroughControlAs(t, inventoryProxy(t, guard), other, values, phaseIDs(len(values))); answer == nil || answer.Added != len(values) {
						t.Fatalf("%s: the other's registration: %+v", name, answer)
					}
				})
				// The other's records are in the file all the while.
				if records := storedRecords(t, store); records <= 3 {
					t.Fatalf("%s, %s: the file holds %d records", name, what, records)
				}
				if with != alone {
					t.Errorf("%s (swapped: %v): what the tenant reads changed when the other registered %s:\n%s", name, swapped, what, viewDifference(alone, with))
				}
			}
		}
	}
}

// randomLeakValue is a random value of n letters and digits.
func randomLeakValue(t *testing.T, n int) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(raw)
}

// viewDifference is the lines of two views that differ.
func viewDifference(alone, with string) string {
	a, b := strings.Split(alone, "\n"), strings.Split(with, "\n")
	var out strings.Builder
	for i := 0; i < len(a) || i < len(b); i++ {
		var left, right string
		if i < len(a) {
			left = a[i]
		}
		if i < len(b) {
			right = b[i]
		}
		if left != right {
			fmt.Fprintf(&out, "  alone: %s\n  with:  %s\n", left, right)
		}
	}
	return out.String()
}

// waitingKeystore is a keystore whose answers wait while a gate is set, as a
// keychain's do while it asks a person.
type waitingKeystore struct {
	*testKeystore
	gate atomic.Pointer[chan struct{}]
}

func (k *waitingKeystore) Get(service, user string) (string, error) {
	if gate := k.gate.Load(); gate != nil {
		<-*gate
	}
	return k.testKeystore.Get(service, user)
}

// A registration is answered inside the second its client gives it, however
// long the store takes: the value is matched from memory at once, and the
// write finishes behind the answer.
func TestARegistrationIsAnsweredWithoutWaitingOnTheStore(t *testing.T) {
	previous := leakStoreWait
	leakStoreWait = 250 * time.Millisecond
	t.Cleanup(func() { leakStoreWait = previous })
	keystore := &waitingKeystore{testKeystore: &testKeystore{values: map[string]string{}}}
	store := &phaseproxy.InventoryStore{Directory: filepath.Join(t.TempDir(), "ai"), Keyring: keystore}
	guard, err := newStoredLeakGuard(leakModeCensor, store, leakTestIdentity)
	if err != nil {
		t.Fatal(err)
	}
	proxy := inventoryProxy(t, guard)
	register := func(id, value string) time.Duration {
		t.Helper()
		began := time.Now()
		answer := registerThroughControlAs(t, proxy, leakTestIdentity, []leakguard.Value{{Type: "secret", ID: id, Value: value}}, phaseIDs(1))
		if answer == nil || answer.Added != 1 {
			t.Fatalf("registering %s: %+v", id, answer)
		}
		return time.Since(began)
	}
	register("first", isolationOwn)
	if records := storedRecords(t, store); records != 1 {
		t.Fatalf("%d records stored by a registration the store was free for", records)
	}
	// The file goes, so the next write asks the keystore whether its key is
	// still the one: and the keystore waits on a person.
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	keystore.gate.Store(&gate)
	// It answers after longer than a client waits.
	var answered atomic.Bool
	time.AfterFunc(leakguard.Timeout+leakguard.Timeout/2, func() {
		answered.Store(true)
		keystore.gate.Store(nil)
		close(gate)
	})
	took := register("second", isolationLater)
	if took >= leakguard.Timeout {
		t.Fatalf("the answer took %v: a client gives a registration %v", took, leakguard.Timeout)
	}
	if out, _ := guard.index.Redact([]byte("x " + isolationLater + " y")); string(out) != "x ph:secret:second y" {
		t.Fatalf("a value registered while the store waited is not matched: %q", out)
	}
	if records := storedRecords(t, store); records != 0 && !answered.Load() {
		t.Fatalf("%d records were stored while the keystore had not answered", records)
	}
	// Once the keystore answers, what was acknowledged is stored after all.
	for deadline := time.Now().Add(10 * time.Second); storedRecords(t, store) != 1; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the value was never stored after the keystore answered")
		}
	}
	next, err := newStoredLeakGuard(leakModeCensor, store, leakTestIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := next.index.Redact([]byte("x " + isolationLater + " y")); string(out) != "x ph:secret:second y" {
		t.Fatalf("the next proxy does not know the value: %q", out)
	}
}

// toolResult is the text of the tool result a model request (anthropicBody)
// carried, as the provider received it.
func toolResult(t *testing.T, body []byte) string {
	t.Helper()
	var request struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	var parts []struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(body, &request); err != nil || len(request.Messages) != 2 || json.Unmarshal(request.Messages[1].Content, &parts) != nil || len(parts) != 1 {
		t.Fatalf("the provider received no tool result: %s", body)
	}
	return parts[0].Content
}

// A document one login registered, a kubeconfig and a JSON value, is indexed
// value by value, and stays so through the store. After a restart its own
// login's proxy replaces each value, and a piece of one, by its id; another
// login of the tenant sees each value replaced whole, by its type alone, and
// no piece; and another tenant's proxy does what one that never heard of the
// document does.
func TestADocumentOneLoginRegisteredAfterARestart(t *testing.T) {
	const kubeconfigID, accountID = "kubeconfig-id-of-a", "account-id-of-a"
	private, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyData := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	token, password := randomLeakValue(t, 40), randomLeakValue(t, 16)
	keyID, clientSecret := hex.EncodeToString([]byte(randomLeakValue(t, 20))), randomLeakValue(t, 35)
	kubeconfig := func(keyData, token, password string) string {
		return "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n  name: prod\nusers:\n- name: admin\n  user:\n    client-key-data: " + keyData +
			"\n    token: " + token + "\n    password: \"" + password + "\"\n"
	}
	account := func(keyID, clientSecret string) string {
		return fmt.Sprintf(`{"type": "service_account", "private_key_id": %q, "client_secret": %q, "token_uri": "https://oauth2.example.com/token"}`, keyID, clientSecret)
	}
	// What a session sends: both documents whole, then values and pieces of
	// them on their own.
	conversation := func(keyData, token, password, keyID, clientSecret, piece, short string) string {
		return "cat ~/.kube/config\n" + kubeconfig(keyData, token, password) + "then\n" + account(keyID, clientSecret) +
			"\nfirst " + token + " then " + piece + " then " + short + " then " + keyID + " then " + keyData + " end\n"
	}
	piece, short := token[5:38], token[:39]
	content := conversation(keyData, token, password, keyID, clientSecret, piece, short)

	store := newTestInventoryStore(t)
	registering := newStoredLeakRigAs(t, store, leakLoginA)
	if answer := registerThroughControl(t, registering.proxy, []leakguard.Value{
		{Type: "secret", ID: kubeconfigID, Value: kubeconfig(keyData, token, password)},
		{Type: "sealed", ID: accountID, Value: account(keyID, clientSecret)},
	}, phaseIDs(2)); answer == nil || answer.Added != 2 {
		t.Fatalf("A's registration: %+v", answer)
	}
	registering.proxy.CloseHijacked()
	if records := storedRecords(t, store); records != 2 {
		t.Fatalf("%d records stored for two documents", records)
	}
	send := func(rig *leakRig) (string, []byte) {
		t.Helper()
		postMessages(t, rig.client(rig.phaseRoots), "https://api.anthropic.com/v1/messages", anthropicBody(content), "")
		received := rig.lastReceived().body
		return toolResult(t, received), received
	}
	named := func(text ...[]byte) string {
		for _, one := range text {
			for _, id := range []string{kubeconfigID, accountID} {
				if bytes.Contains(one, []byte(id)) {
					return id
				}
			}
		}
		return ""
	}

	// A's own proxy, started again: every value by its id, and a piece of one.
	asA := newStoredLeakRigAs(t, store, leakLoginA)
	if status, _ := rawStatus(t, asA); status.SecretsKnown != 2 || status.Inventory.Loaded != 2 {
		t.Fatalf("A's next proxy: %+v %+v", status, status.Inventory)
	}
	ofKube, ofAccount := "ph:secret:"+kubeconfigID, "ph:sealed:"+accountID
	if got, _ := send(asA); got != conversation(ofKube, ofKube, ofKube, ofAccount, ofAccount, ofKube, ofKube) {
		t.Fatalf("A's own proxy sent:\n%s", got)
	}

	// Another login of the tenant: each value whole, by its type alone. A
	// piece of a value, and a value cut short by a character, pass.
	asB := newStoredLeakRigAs(t, store, leakLoginB)
	statusB, statusBodyB := rawStatus(t, asB)
	if statusB.SecretsKnown != 2 || statusB.Inventory.Loaded != 2 {
		t.Fatalf("B's proxy: %+v %+v", statusB, statusB.Inventory)
	}
	got, received := send(asB)
	if got != conversation("ph:secret", "ph:secret", "ph:secret", "ph:sealed", "ph:sealed", piece, short) {
		t.Fatalf("B's proxy sent:\n%s", got)
	}
	events := asB.distinctLeakEvents(t, 1)
	shipped, _ := json.Marshal(events)
	if id := named(received, shipped, asB.shippedPayloads(), []byte(statusBodyB)); id != "" {
		t.Fatalf("B's proxy named %q, an id of another login", id)
	}
	if detail := events[0].Detail; sortedList(detail["placeholders"]) != "ph:sealed,ph:secret" {
		t.Fatalf("B's event: %+v", detail)
	}

	// Another tenant: what a proxy that was never told of the document sends,
	// to the byte, and nothing of the store in its counts.
	asY := newStoredLeakRigAs(t, store, otherTenantA)
	never := newStoredLeakRigAs(t, newTestInventoryStore(t), otherTenantA)
	statusY, statusBodyY := rawStatus(t, asY)
	_, receivedY := send(asY)
	_, receivedNever := send(never)
	if !bytes.Equal(receivedY, receivedNever) || statusY.SecretsKnown != 0 || statusY.Inventory.Loaded != 0 {
		t.Fatalf("another tenant's proxy knew something of the document: %+v\n%s", statusY.Inventory, receivedY)
	}
	if sent := toolResult(t, receivedY); strings.Contains(sent, "ph:secret") || strings.Contains(sent, "ph:sealed") || !strings.Contains(sent, keyID) || !strings.Contains(sent, piece) {
		t.Fatalf("another tenant's proxy replaced a value as one of an inventory: %s", sent)
	}
	if events := asY.leakEventsNow(); len(events) > 0 && events[0].Detail["inventoryHits"] != nil && events[0].Detail["inventoryHits"] != float64(0) {
		t.Fatalf("another tenant's proxy reported an indexed value: %+v", events[0].Detail)
	}
	if id := named(receivedY, asY.shippedPayloads(), []byte(statusBodyY)); id != "" {
		t.Fatalf("another tenant's proxy named %q", id)
	}
}

// What a running proxy matches its own login's values by, the entries made
// under its process's key, and what a guest registered with it, give another
// login and another tenant nothing: no key, no id and no piece. Another login
// of the tenant knows the stored values whole, by their type; another tenant
// knows none of it; a guest's value is known to the one process it went to.
func TestWhatARunningProxyMatchesByGivesAnotherLoginOrTenantNothing(t *testing.T) {
	store := newTestInventoryStore(t)
	hexKey, token, guests := freshHex40, randomLeakValue(t, 40), randomLeakValue(t, 36)
	// A piece only entries of the process find, one the store's find too, and
	// one of the guest's value.
	hexPiece, tokenPiece, guestPiece := hexKey[1:], token[5:38], guests[3:30]
	asA := newStoredLeakRigAs(t, store, leakLoginA)
	if result := registerWithClient(t, asA, leakLoginA, []leakguard.Value{{Type: "secret", ID: "hex-of-a", Value: hexKey}, {Type: "secret", ID: "token-of-a", Value: token}}); result.Added != 2 {
		t.Fatalf("A's registration: %+v", result)
	}
	if result := registerWithClient(t, asA, otherTenantB, []leakguard.Value{{Type: "secret", ID: "guest-id", Value: guests}}); result.Added != 1 {
		t.Fatalf("the guest's registration: %+v", result)
	}
	content := "whole " + hexKey + " " + token + " " + guests + " pieces " + hexPiece + " " + tokenPiece + " " + guestPiece + " end"
	if sent := sentFor(t, asA, content); sent != "whole ph:secret:hex-of-a ph:secret:token-of-a ph:secret pieces ph:secret:hex-of-a ph:secret:token-of-a "+guestPiece+" end" {
		t.Fatalf("A's own proxy sent %q", sent)
	}
	// The file holds A's two values in the stored scheme, and nothing made
	// under the process's key or for the guest.
	_, kept, err := openLeakInventory(store, leakLoginA)
	if err != nil || len(kept) != 2 || storedRecords(t, store) != 2 {
		t.Fatalf("the store holds %d values: %v", len(kept), err)
	}
	live := map[string]*censor.Entries{}
	for id, value := range map[string]string{"hex-of-a": hexKey, "token-of-a": token} {
		if live[id], err = censor.IndexValueScheme(asA.guard.live, leakLiveScheme, "secret", id, value); err != nil {
			t.Fatal(err)
		}
	}
	for _, stored := range kept {
		if stored.Entries.Version != censor.EntriesVersion || confirmedBy(live[stored.Entries.ID], stored.Entries) != 0 {
			t.Fatalf("the store holds entries of scheme %d that the process's key confirms", stored.Entries.Version)
		}
	}
	file, err := os.ReadFile(filepath.Join(store.Directory, "leak-inventory.bin"))
	if err != nil || opensARecord(file, asA.guard.live.LookupBytes()) {
		t.Fatalf("the process's key opens a record of the store: %v", err)
	}
	liveKey := asA.guard.live.LookupBytes()
	names := func(text ...[]byte) string {
		for _, one := range text {
			for _, id := range []string{"hex-of-a", "token-of-a", "guest-id"} {
				if bytes.Contains(one, []byte(id)) {
					return id
				}
			}
		}
		return ""
	}
	// Every other proxy of the store, while A's still runs.
	for name, c := range map[string]struct {
		identity phaseproxy.InventoryIdentity
		want     string
	}{
		"another login of the tenant": {leakLoginB, "whole ph:secret ph:secret " + guests + " pieces " + hexPiece + " " + tokenPiece + " " + guestPiece + " end"},
		"the guest's own tenant":      {otherTenantB, content},
		"another login of it":         {otherTenantA, content},
		"the tenant on another host":  {otherHostTenant, content},
	} {
		rig := newStoredLeakRigAs(t, store, c.identity)
		sent := sentFor(t, rig, content)
		if sent != c.want {
			t.Errorf("the proxy of %s sent %q", name, sent)
		}
		_, statusBody := rawStatus(t, rig)
		if id := names(rig.lastReceived().body, rig.shippedPayloads(), []byte(statusBody)); id != "" {
			t.Errorf("the proxy of %s named %q", name, id)
		}
		// Whoever a command says it is there, it is handed nothing of A's process.
		for _, stated := range []phaseproxy.InventoryIdentity{c.identity, leakLoginA, {}} {
			if answer := statedKey(t, rig.proxy, stated); keyAnswerHolds(t, answer, liveKey) || answer.LiveKey == base64.StdEncoding.EncodeToString(liveKey) {
				t.Errorf("the proxy of %s handed out the key of A's process", name)
			}
		}
		if c.want != content {
			continue
		}
		// Another tenant's proxy does what one that never saw the store does.
		never := newStoredLeakRigAs(t, newTestInventoryStore(t), c.identity)
		if sentFor(t, never, content) != sent || !bytes.Equal(never.lastReceived().body, rig.lastReceived().body) {
			t.Errorf("the proxy of %s sent other bytes than one that never saw the store", name)
		}
		if status, _ := rawStatus(t, rig); status.SecretsKnown != 0 || status.Inventory.Loaded != 0 {
			t.Errorf("the proxy of %s counts %+v", name, status.Inventory)
		}
	}
	// At A's proxy, a command of anyone else is handed no key of the process,
	// and what it can make of a guess confirms nothing the process matches by.
	for name, stated := range map[string]phaseproxy.InventoryIdentity{"another login of the tenant": leakLoginB, "another tenant": otherTenantA, "nobody": {}} {
		answer := statedKey(t, asA.proxy, stated)
		if answer.LiveKey != "" || keyAnswerHolds(t, answer, liveKey) {
			t.Fatalf("a command of %s was handed the key of A's process", name)
		}
		for _, scheme := range censor.SupportedSchemes() {
			guess, err := censor.IndexValueScheme(answeredKey(t, answer), scheme, "secret", "hex-of-a", hexKey)
			if err != nil {
				t.Fatal(err)
			}
			if confirmed := confirmedBy(live["hex-of-a"], guess); confirmed != 0 {
				t.Fatalf("a command of %s confirms %d hashes of A's value with what it was handed", name, confirmed)
			}
		}
	}
	// The process ends: what the guest registered is known nowhere, and A's
	// next proxy starts from the store.
	asA.proxy.CloseHijacked()
	next := newStoredLeakRigAs(t, store, leakLoginA)
	if sent := sentFor(t, next, content); sent != "whole ph:secret:hex-of-a ph:secret:token-of-a "+guests+" pieces "+hexPiece+" ph:secret:token-of-a "+guestPiece+" end" {
		t.Fatalf("A's next proxy sent %q", sent)
	}
}
