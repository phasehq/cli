package aiproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/phasehq/cli/internal/censortest"
	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/pkg/censor"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// A proxy the Console named nobody for sends the provider what the proxy sent
// before there was a store: one key, one index of it, every value with its id.
func TestAnAnonymousProxyProtectsAsBeforeThereWasAStore(t *testing.T) {
	fixture := censortest.NewFixture()
	// The guard as it was made then, whatever a command said of itself.
	before := newLeakRig(t, leakModeCensor)
	key, err := censor.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	index, err := censor.NewIndex(key, censor.IndexOptions{Rules: censor.DefaultRules()})
	if err != nil {
		t.Fatal(err)
	}
	before.guard.key, before.guard.index = key, index
	store := newTestInventoryStore(t)
	anonymous := newStoredLeakRigAs(t, store, phaseproxy.InventoryIdentity{})
	// Commands that state nothing, a login, and another account's.
	commands := []phaseproxy.InventoryIdentity{{}, leakLoginA, otherTenantB}
	registered := 0
	for _, entry := range fixture.Entries {
		if entry.Expect == "rule" {
			continue
		}
		made, err := censor.IndexValue(key, entry.Type, entry.ID, entry.Value)
		if err != nil {
			t.Fatal(err)
		}
		if err := index.Add(made); err != nil {
			t.Fatal(err)
		}
		stated := commands[registered%len(commands)]
		if answer := registerThroughControlAs(t, anonymous.proxy, stated, []leakguard.Value{{Type: entry.Type, ID: entry.ID, Value: entry.Value}}, phaseIDs(1)); answer == nil || answer.Added+answer.Unprotected != 1 {
			t.Fatalf("registering %s with a proxy that has no identity: %+v", entry.ID, answer)
		}
		registered++
	}
	if then, now := index.Stats(), anonymous.guard.index.Stats(); then != now || now.Guests != 0 {
		t.Fatalf("the index then held %+v, an anonymous proxy's holds %+v", then, now)
	}
	verifier := censortest.NewVerifier(fixture.Entries)
	names := make([]string, 0, len(fixture.Files))
	for name := range fixture.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := gzipBytes(t, anthropicBody(fixture.Files[name]))
		var received [2][]byte
		for at, rig := range []*leakRig{before, anonymous} {
			if response := postMessages(t, rig.client(rig.phaseRoots), "https://api.anthropic.com/v1/messages", body, "gzip"); response.StatusCode != http.StatusOK {
				t.Fatalf("%s: status %d", name, response.StatusCode)
			}
			received[at] = gunzipBytes(t, rig.lastReceived().body)
		}
		if !json.Valid(received[1]) || !bytes.Equal(received[0], received[1]) {
			t.Errorf("%s: an anonymous proxy sent the provider other bytes than the proxy before a store did", name)
		}
		for _, miss := range verifier.Check(received[1]) {
			if !miss.Expected {
				t.Errorf("%s: %s reached the provider (%s %s)", name, miss.ID, miss.Form, miss.Part)
			}
		}
	}
	for _, miss := range verifier.Check(anonymous.shippedPayloads()) {
		if !miss.Expected {
			t.Errorf("an event carries %s", miss.ID)
		}
	}
	anonymous.proxy.CloseHijacked()
	if storedRecords(t, store) != 0 {
		t.Fatal("a proxy with no identity stored what was registered")
	}
}

// A proxy with no identity has no logins or guests to share its index among:
// one command fills all of it, as before, and the next value is refused.
func TestAProxyWithNoIdentityHasTheWholeIndex(t *testing.T) {
	leakIndexMaxSecrets = 40
	t.Cleanup(func() { leakIndexMaxSecrets = 0 })
	rig := newStoredLeakRigAs(t, newTestInventoryStore(t), phaseproxy.InventoryIdentity{})
	value := func(i int) leakguard.Value {
		return leakguard.Value{Type: "secret", ID: fmt.Sprintf("KEY_%d", i), Value: fmt.Sprintf("Val%03dQw7Er8Ty9Ui0Op1As2Df3Gh4Jk5", i)}
	}
	for i := 0; i < 40; i++ {
		stated := []phaseproxy.InventoryIdentity{{}, leakLoginA}[i%2]
		if answer := registerThroughControlAs(t, rig.proxy, stated, []leakguard.Value{value(i)}, nil); answer == nil || answer.Added != 1 {
			t.Fatalf("value %d of 40: %+v", i, answer)
		}
	}
	for _, i := range []int{0, 39} {
		if out, _ := rig.guard.index.Redact([]byte(value(i).Value)); string(out) != "ph:secret:"+value(i).ID {
			t.Fatalf("value %d: %q", i, out)
		}
	}
	keys := statedKey(t, rig.proxy, phaseproxy.InventoryIdentity{})
	made, err := censor.IndexValue(answeredKey(t, keys), "secret", "KEY_40", value(40).Value)
	if err != nil {
		t.Fatal(err)
	}
	if recorder := postInventory(t, rig.proxy, phaseproxy.InventoryIdentity{}, keys.KeyID, made); recorder.Code != http.StatusInsufficientStorage {
		t.Fatalf("a value past a full index: HTTP %d", recorder.Code)
	}
}
