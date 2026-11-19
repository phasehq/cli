package aiproxy

import (
	"errors"
	"os"

	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// A proxy loads what its tenant's logins stored (phaseproxy.InventoryStore),
// through the index's own validation, and stores what its own login registers.

// newStoredLeakGuard makes the guard over a store, opened for the tenant of
// the session the Console named. With no store or identity nothing is kept.
func newStoredLeakGuard(mode string, store *phaseproxy.InventoryStore, identity phaseproxy.InventoryIdentity) (*leakGuard, error) {
	if !identity.Known() {
		identity = phaseproxy.InventoryIdentity{}
	}
	inventory, loaded, err := openLeakInventory(store, identity)
	if err != nil {
		return nil, err
	}
	guard, err := newLeakGuardWithInventory(mode, censor.DefaultRules(), inventory, identity)
	if err != nil {
		return nil, err
	}
	guard.load(loaded)
	return guard, nil
}

func openLeakInventory(store *phaseproxy.InventoryStore, identity phaseproxy.InventoryIdentity) (*phaseproxy.Inventory, []phaseproxy.StoredEntries, error) {
	if store == nil {
		inventory, err := phaseproxy.MemoryInventory()
		return inventory, nil, err
	}
	// The tenant is the session's, whatever the store was made with.
	own := *store
	own.Tenant = identity.Tenant
	return own.Open()
}

// load indexes what the store held, the session's own login's first and each
// newest first, within leakIndexBounds. What is left out is counted.
func (g *leakGuard) load(loaded []phaseproxy.StoredEntries) {
	bounds := leakIndexBounds(nil, g.identity.Known())
	var all leakShare
	used := map[[16]byte]*leakShare{}
	take := func(stored phaseproxy.StoredEntries) {
		login := used[stored.Principal.ID()]
		if login == nil {
			login = &leakShare{}
			used[stored.Principal.ID()] = login
		}
		chunks := stored.Entries.Chunks()
		if login.secrets+1 > bounds.loadPerLogin.secrets || login.chunks+chunks > bounds.loadPerLogin.chunks ||
			all.secrets+1 > bounds.load.secrets || all.chunks+chunks > bounds.load.chunks {
			g.notLoaded++
			return
		}
		// What is loaded is replaced and reported, and never blocks a request.
		if protected, err := g.addOne(stored.Principal, stored.Entries, stored.KeyNamed, true); err != nil || !protected {
			if errors.Is(err, censor.ErrIndexFull) {
				g.notLoaded++
			}
			return
		}
		login.secrets, login.chunks = login.secrets+1, login.chunks+chunks
		all.secrets, all.chunks = all.secrets+1, all.chunks+chunks
	}
	for _, own := range []bool{true, false} {
		for at := len(loaded) - 1; at >= 0; at-- {
			if loaded[at].Principal.Is(g.principal) == own {
				take(loaded[at])
			}
		}
	}
	g.loaded = g.index.Stats().Secrets
}

// inventoryStatus is how the inventory is kept, in counts of the session's
// own tenant: nothing in it says how much any other tenant stored.
func (g *leakGuard) inventoryStatus() *remoteapi.LeakInventoryStatus {
	stored := g.inventory.Status()
	status := &remoteapi.LeakInventoryStatus{
		Storage: remoteapi.LeakInventoryMemory, Reason: stored.Reason, Loaded: g.loaded, NotLoaded: g.notLoaded,
		UnmatchedScheme: stored.OtherScheme, UnmatchedKey: stored.OtherKey, Damaged: stored.Damaged,
		Unstored: int(g.unstored.Load()), Dropped: stored.Dropped,
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
