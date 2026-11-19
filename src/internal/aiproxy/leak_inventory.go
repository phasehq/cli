package aiproxy

import (
	"errors"
	"os"

	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// The inventory outlives the proxy process when there is a system keystore:
// the master key is kept there and the entries in a file beside the CA
// (phaseproxy.InventoryStore). A proxy loads what the file holds when it
// starts, so a conversation resumed after the hook-managed proxy's idle
// exit, an upgrade or a reboot still has its values replaced, and it adds
// what is registered with it. Every proxy of one user shares the store.
//
// A proxy hands out the confirming key of its own login alone, and matches
// what every login stored, each record under its own principal's key.
//
// Entries are loaded as a registration's are taken: through the index's own
// validation, so nothing in the file is trusted further than a client is.

// newStoredLeakGuard makes the guard over a store, for the login the session
// acts as. With no store or no keystore the inventory is in memory only.
func newStoredLeakGuard(mode string, store *phaseproxy.InventoryStore, login string) (*leakGuard, error) {
	if store == nil {
		return newLeakGuard(mode)
	}
	inventory, loaded, err := store.Open()
	if err != nil {
		return nil, err
	}
	guard, err := newLeakGuardWithInventory(mode, censor.DefaultRules(), inventory, login)
	if err != nil {
		return nil, err
	}
	guard.load(loaded)
	return guard, nil
}

// load indexes what the store held, newest first: what a full index leaves
// out is then what was used longest ago, and it is counted.
func (g *leakGuard) load(loaded []phaseproxy.StoredEntries) {
	for at := len(loaded) - 1; at >= 0; at-- {
		if _, err := g.addOne(loaded[at].Principal, loaded[at].Entries, loaded[at].KeyNamed); errors.Is(err, censor.ErrIndexFull) {
			g.notLoaded++
		}
	}
	g.loaded = g.index.Stats().Secrets
}

// inventoryStatus is how the inventory is kept, in counts.
func (g *leakGuard) inventoryStatus() *remoteapi.LeakInventoryStatus {
	stored := g.inventory.Status()
	status := &remoteapi.LeakInventoryStatus{
		Storage: remoteapi.LeakInventoryMemory, Reason: stored.Reason, Loaded: g.loaded, NotLoaded: g.notLoaded,
		UnmatchedScheme: stored.OtherScheme, UnmatchedKey: stored.OtherKey, OtherTenants: stored.OtherTenant, Damaged: stored.Damaged,
	}
	if stored.Durable {
		status.Storage, status.Reason = remoteapi.LeakInventoryStored, ""
	}
	return status
}

// leakHosts is the guard for a question about hosts alone, which a capture
// layer may ask before any session is served. The process's guard answers
// when there is one. Otherwise one that is not kept does, so that the guard
// made with the first session still opens the store.
func (e *Engine) leakHosts() (*leakGuard, error) {
	engineRuntimeInitMu.Lock()
	defer engineRuntimeInitMu.Unlock()
	if e.runtime != nil && e.runtime.leak != nil {
		return e.runtime.leak, nil
	}
	return newLeakGuard(os.Getenv(LeakProtectionEnvironmentKey))
}
