package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/offline"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/spf13/cobra"
)

var usersLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "🏃 Logout from phase-cli",
	RunE:  runUsersLogout,
}

// caTrustLeftover reads the user's trust store; tests replace it.
var caTrustLeftover = phaseproxy.UserCATrustLeftover

func init() {
	usersLogoutCmd.Flags().Bool("purge", false, "Purge all local data")
	usersCmd.AddCommand(usersLogoutCmd)
}

func runUsersLogout(cmd *cobra.Command, args []string) error {
	purge, _ := cmd.Flags().GetBool("purge")

	if purge {
		// Delete all keyring entries and remove local data
		ids, err := config.GetDefaultAccountID(true)
		if err != nil {
			return err
		}
		for _, id := range ids {
			keyring.DeleteCredentials(id)
		}
		// ~/.phase also holds the Phase AI directory: its logs, spooled audit
		// events and trust files. Stop the proxy first so it writes nothing
		// back, and drop the CA key from the system keystore with them.
		stopContext, cancel := context.WithTimeout(cmd.Context(), 3*time.Second)
		if err := stopHookRuntime(stopContext); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Could not stop the running Phase AI proxy: %v\n", err)
		}
		cancel()
		if err := phaseproxy.DeleteStoredCAKey(); errors.Is(err, phaseproxy.ErrKeystoreUnreachable) {
			// Only a machine that made a Phase AI CA can have stored its key.
			if directory, dirErr := hookRuntimeDir(); dirErr == nil {
				if _, statErr := os.Stat(filepath.Join(directory, "ca.pem")); statErr == nil {
					fmt.Fprintln(cmd.ErrOrStderr(), "The system keystore could not be reached, so a Phase AI CA key stored in it was not removed.")
				}
			}
		} else if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Could not remove the Phase AI CA key from the system keystore: %v\n", err)
		}
		// The leak protection inventory's entries go with ~/.phase below; its
		// key is in the keystore beside the CA key.
		if err := phaseproxy.DeleteStoredInventoryKey(); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Could not remove the leak protection inventory key from the system keystore: %v\n", err)
		}
		phaseHomeDir := filepath.Dir(config.PhaseSecretsDir)
		if _, err := os.Stat(phaseHomeDir); err == nil {
			if err := os.RemoveAll(phaseHomeDir); err != nil {
				return fmt.Errorf("failed to purge local data: %w", err)
			}
			fmt.Println("Logged out and purged all local data.")
		} else {
			fmt.Println("No local data found to purge.")
		}
		// The purge leaves the user's trust store alone, and says so.
		if leftover := caTrustLeftover(); leftover != "" {
			fmt.Println(leftover)
		}
	} else {
		// Remove current user
		ids, err := config.GetDefaultAccountID(false)
		if err != nil {
			return fmt.Errorf("no configuration found. Please run 'phase auth' to set up your configuration")
		}
		if len(ids) == 0 || ids[0] == "" {
			return fmt.Errorf("no default user in configuration found")
		}

		accountID := ids[0]
		// What the leak protection inventory stored for this login goes with
		// it: read who it is before its record does.
		var leaving *config.UserConfig
		var staying []config.UserConfig
		if saved, err := config.LoadConfig(); err == nil {
			for _, user := range saved.PhaseUsers {
				if user.ID == accountID {
					leaving = &user
				} else {
					staying = append(staying, user)
				}
			}
		}
		keyring.DeleteCredentials(accountID)

		// Clean up offline cache for this user
		cacheDir := offline.CacheDir(config.PhaseSecretsDir, accountID)
		os.RemoveAll(cacheDir)

		if err := config.RemoveUser(accountID); err != nil {
			return fmt.Errorf("failed to update config: %w", err)
		}
		if leaving != nil {
			if err := forgetLeakInventory(*leaving, staying); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Could not remove this login's values from the leak protection inventory: %v\n", err)
			}
		}
		fmt.Println("Logged out successfully.")
	}

	return nil
}
