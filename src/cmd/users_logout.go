package cmd

import (
	"fmt"
	"os"

	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/spf13/cobra"
)

var usersLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "🏃 Logout from phase-cli",
	RunE:  runUsersLogout,
}

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
		if _, err := os.Stat(config.PhaseSecretsDir); err == nil {
			if err := os.RemoveAll(config.PhaseSecretsDir); err != nil {
				return fmt.Errorf("failed to purge local data: %w", err)
			}
			fmt.Println("Logged out and purged all local data.")
		} else {
			fmt.Println("No local data found to purge.")
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
		keyring.DeleteCredentials(accountID)

		if err := config.RemoveUser(accountID); err != nil {
			return fmt.Errorf("failed to update config: %w", err)
		}
		fmt.Println("Logged out successfully.")
	}

	return nil
}
