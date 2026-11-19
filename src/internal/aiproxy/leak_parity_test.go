package aiproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// What a proxy does with a value a command registered with it is what the
// proxy did before there was a store, to the byte: with a store and no
// identity, and for the values of an identified proxy's own login.
// What it is held to was recorded from that proxy: leak_parity_probe_test.go
// says how.
func TestAFreshValueIsMatchedAsBeforeAStore(t *testing.T) {
	recorded, err := os.ReadFile(filepath.Join("testdata", "leak_parity_base.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Split(strings.TrimSuffix(string(recorded), "\n"), "\n")
	events := 0
	for _, line := range want {
		if strings.HasPrefix(line, "event: ") {
			events++
		}
	}
	type registering func(rig *leakRig, values []leakguard.Value, kinds []string) *remoteapi.InventoryResponse
	// As a command that states who it is, and through the CLI's own client.
	stating := func(stated ...phaseproxy.InventoryIdentity) registering {
		calls := 0
		return func(rig *leakRig, values []leakguard.Value, kinds []string) *remoteapi.InventoryResponse {
			calls++
			return registerThroughControlAs(t, rig.proxy, stated[(calls-1)%len(stated)], values, kinds)
		}
	}
	client := func(stated phaseproxy.InventoryIdentity) registering {
		return func(rig *leakRig, values []leakguard.Value, _ []string) *remoteapi.InventoryResponse {
			result := registerWithClient(t, rig, stated, values)
			return &remoteapi.InventoryResponse{Added: result.Added, Unprotected: result.Unprotected}
		}
	}
	for name, c := range map[string]struct {
		identity phaseproxy.InventoryIdentity
		stored   bool
		register registering
	}{
		"a store and no identity":                   {stored: true, register: stating(leakLoginA, phaseproxy.InventoryIdentity{}, otherTenantB)},
		"a store and no identity, the CLI's client": {stored: true, register: client(phaseproxy.InventoryIdentity{})},
		"a login's own values":                      {identity: leakLoginA, stored: true, register: stating(leakLoginA)},
		"a login's own values, the CLI's client":    {identity: leakLoginA, stored: true, register: client(leakLoginA)},
		"a login's own values, kept in memory":      {identity: leakTestIdentity, register: stating(leakTestIdentity)},
	} {
		t.Run(name, func(t *testing.T) {
			rig := newLeakRig(t, leakModeCensor)
			store := newTestInventoryStore(t)
			if c.stored {
				rig = newStoredLeakRigAs(t, store, c.identity)
			}
			got := leakParityProbe(t, rig, func(values []leakguard.Value, kinds []string) *remoteapi.InventoryResponse {
				return c.register(rig, values, kinds)
			}, events)
			differing := 0
			for at := 0; at < len(want) || at < len(got); at++ {
				var was, is string
				if at < len(want) {
					was = want[at]
				}
				if at < len(got) {
					is = got[at]
				}
				if was == is {
					continue
				}
				if differing++; differing <= 12 {
					t.Errorf("line %d:\n  before a store: %s\n  now:            %s", at+1, was, is)
				}
			}
			if differing > 0 {
				t.Fatalf("%d of %d lines differ from the proxy before a store", differing, len(want))
			}
			// The values of a login went to the store; with no identity nothing did.
			rig.proxy.CloseHijacked()
			if records := storedRecords(t, store); (records > 0) != (c.stored && c.identity.Known()) {
				t.Fatalf("the store holds %d records", records)
			}
		})
	}
}
