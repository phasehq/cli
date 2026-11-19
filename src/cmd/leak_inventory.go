package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/phase"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// aiInventoryStore is where the proxy keeps its leak protection inventory:
// in the CA store's directory, with its key in the CA store's keystore.
func aiInventoryStore() phaseproxy.InventoryStore {
	return phaseproxy.InventoryStore{Directory: aiCAStore.Directory, Keyring: aiCAStore.Keyring}
}

// savedLoginIdentities are the identities a saved login may have registered
// under at a host: a record that is not an Agent's is a user's or a service account's.
func savedLoginIdentities(host string, user config.UserConfig) []phaseproxy.InventoryIdentity {
	var identities []phaseproxy.InventoryIdentity
	for _, kind := range []string{phaseproxy.InventoryLoginAgent, phaseproxy.InventoryLoginUser, phaseproxy.InventoryLoginServiceAccount} {
		if identity := phase.SavedLoginIdentity(host, kind, user); identity.Known() {
			identities = append(identities, identity)
		}
	}
	return identities
}

// forgetLeakInventory removes what the inventory stored for a login that
// logged out, and all its tenant stored when no saved login of it is left.
func forgetLeakInventory(user config.UserConfig, remaining []config.UserConfig) error {
	hosts := []string{user.Host}
	if override := os.Getenv("PHASE_HOST"); override != "" && override != user.Host {
		hosts = append(hosts, override)
	}
	var failed error
	for _, host := range hosts {
		identities := savedLoginIdentities(host, user)
		if len(identities) == 0 {
			continue
		}
		store := aiInventoryStore()
		store.Tenant = identities[0].Tenant
		last := true
		var logins []string
		for _, identity := range identities {
			logins = append(logins, identity.Login)
		}
		for _, other := range remaining {
			for _, identity := range savedLoginIdentities(other.Host, other) {
				last = last && identity.Tenant != store.Tenant
			}
		}
		failed = errors.Join(failed, store.Forget(logins, last))
	}
	return failed
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
		case phaseproxy.InventoryReasonNoTenant:
			why = "the Console did not say which organisation and login this session is"
		case phaseproxy.InventoryReasonBusy:
			why = "another process held the inventory file; the next registration tries again"
		}
		return "inventory kept in memory only (" + why + ")" + leakUnstoredSummary(inventory)
	}
	line := fmt.Sprintf("inventory kept across restarts (%d loaded at start)", inventory.Loaded)
	if inventory.NotLoaded > 0 {
		line += fmt.Sprintf(", %d registered longer ago left out to keep room", inventory.NotLoaded)
	}
	if inventory.UnmatchedScheme > 0 {
		line += fmt.Sprintf(", %d stored by another version of Phase and not matched until read again", inventory.UnmatchedScheme)
	}
	if inventory.UnmatchedKey > 0 {
		line += fmt.Sprintf(", %d stored under a replaced key and dropped", inventory.UnmatchedKey)
	}
	if inventory.OtherTenants > 0 {
		line += fmt.Sprintf(", %d of other hosts or organisations left unopened", inventory.OtherTenants)
	}
	if inventory.Damaged > 0 {
		line += fmt.Sprintf(", %d unreadable and dropped", inventory.Damaged)
	}
	if inventory.Dropped > 0 {
		line += fmt.Sprintf(", %d not stored to keep the store within its bounds", inventory.Dropped)
	}
	return line + leakUnstoredSummary(inventory)
}

// leakUnstoredSummary says how often a command that is not of the session's
// own login registered with this proxy: values it never stores.
func leakUnstoredSummary(inventory remoteapi.LeakInventoryStatus) string {
	if inventory.Unstored == 0 {
		return ""
	}
	return fmt.Sprintf(", %d registrations from commands of another login, or of none they could state, protected until this proxy exits", inventory.Unstored)
}
