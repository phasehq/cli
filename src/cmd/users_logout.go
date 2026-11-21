package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
		stopRuntimeForLoginChange(cmd)
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
		stopRuntimeForLoginChange(cmd)
		keyring.DeleteCredentials(accountID)

		// Clean up offline cache for this user
		if cacheDir, ok := offlineCacheDir(accountID); ok {
			os.RemoveAll(cacheDir)
		}

		if err := config.RemoveUser(accountID); err != nil {
			return fmt.Errorf("failed to update config: %w", err)
		}
		fmt.Println("Logged out successfully.")
	}

	return nil
}

// stopHookRuntimeForLogin is stopHookRuntime; tests replace it.
var stopHookRuntimeForLogin = stopHookRuntime

// stopRuntimeForLoginChange stops a running Phase AI proxy. It holds the login
// it started with, and would keep using one that was logged out or switched
// away from; the next harness session starts it on the current login.
func stopRuntimeForLoginChange(cmd *cobra.Command) {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	stopContext, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := stopHookRuntimeForLogin(stopContext); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Could not stop the running Phase AI proxy: %v\n", err)
	}
}

// offlineCacheDir returns the account's offline cache directory, and false
// when the id would name a path outside the Phase offline directory.
func offlineCacheDir(accountID string) (string, bool) {
	if !config.ValidAccountID(accountID) {
		return "", false
	}
	base := filepath.Join(config.PhaseSecretsDir, "offline")
	cacheDir := offline.CacheDir(config.PhaseSecretsDir, accountID)
	relative, err := filepath.Rel(base, cacheDir)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", false
	}
	return cacheDir, true
}
