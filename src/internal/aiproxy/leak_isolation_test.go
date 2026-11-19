package aiproxy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
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

// isolationProbe holds every one of them, whole and encoded, as a request might.
var isolationProbe = []byte("a " + isolationOwn + " b " + isolationShared + " c " + isolationTheirs + " d " + isolationLater +
	" e " + hex.EncodeToString([]byte(isolationTheirs)) + " f " + base64.StdEncoding.EncodeToString([]byte(isolationShared)))

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
		note(when+", the key route", statedKey(t, proxy, self))
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
