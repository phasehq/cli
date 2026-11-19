package cmd

import (
	"fmt"

	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// aiInventoryStore is where the proxy keeps its leak protection inventory:
// in the CA store's directory, with its key in the CA store's keystore.
func aiInventoryStore() phaseproxy.InventoryStore {
	return phaseproxy.InventoryStore{Directory: aiCAStore.Directory, Keyring: aiCAStore.Keyring}
}

// leakInventorySummary says, for phase ai status, whether the values the
// proxy knows outlive it, and what the store held that it could not use.
func leakInventorySummary(inventory remoteapi.LeakInventoryStatus) string {
	if inventory.Storage != remoteapi.LeakInventoryStored {
		why := "no store"
		switch inventory.Reason {
		case phaseproxy.InventoryReasonNoKeystore:
			return "inventory " + phaseproxy.NoKeystoreInventoryNotice
		case phaseproxy.InventoryReasonNewerFormat:
			why = "the stored inventory was written by a newer version of Phase and is left as it is"
		case phaseproxy.InventoryReasonKeyReplaced:
			why = "its key was replaced while the proxy ran; the next proxy start stores again"
		case phaseproxy.InventoryReasonUnusable:
			why = "the inventory file could not be written"
		case phaseproxy.InventoryReasonKeyUnreadable:
			why = "the system keystore did not give its key; the key and the stored inventory are left as they are"
		case phaseproxy.InventoryReasonUnreadable:
			why = "the inventory file could not be read and is left as it is; phase ai disable removes it"
		case phaseproxy.InventoryReasonBusy:
			why = "another process held the inventory file; the next proxy start stores again"
		}
		return "inventory kept in memory only (" + why + ")"
	}
	line := fmt.Sprintf("inventory kept across restarts (%d loaded at start)", inventory.Loaded)
	if inventory.NotLoaded > 0 {
		line += fmt.Sprintf(", %d more not loaded because the inventory is full", inventory.NotLoaded)
	}
	if inventory.UnmatchedScheme > 0 {
		line += fmt.Sprintf(", %d stored by another version of Phase and not matched until read again", inventory.UnmatchedScheme)
	}
	if inventory.UnmatchedKey > 0 {
		line += fmt.Sprintf(", %d stored under a replaced key and dropped", inventory.UnmatchedKey)
	}
	if inventory.Damaged > 0 {
		line += fmt.Sprintf(", %d unreadable and dropped", inventory.Damaged)
	}
	return line
}
