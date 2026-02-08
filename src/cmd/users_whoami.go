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

	email := user.Email
	if email == "" {
		email = "N/A (Service Account)"
	}

	fmt.Printf("✉️\u200A Email: %s\n", email)
	fmt.Printf("🙋 Account ID: %s\n", user.ID)
	orgName := "N/A"
	if user.OrganizationName != nil {
		orgName = *user.OrganizationName
	}
	fmt.Printf("🏢 Organization: %s\n", orgName)
	fmt.Printf("☁️\u200A Host: %s\n", user.Host)
	return nil
}
