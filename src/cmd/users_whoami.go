package cmd

import (
	"fmt"

	"github.com/phasehq/cli/pkg/config"
	"github.com/spf13/cobra"
)

var usersWhoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "🙋 See details of the current user",
	RunE:  runUsersWhoami,
}

func init() {
	usersCmd.AddCommand(usersWhoamiCmd)
}

func runUsersWhoami(cmd *cobra.Command, args []string) error {
	user, err := config.GetDefaultUser()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	writeWhoami(cmd.OutOrStdout(), *user)
	return nil
}
