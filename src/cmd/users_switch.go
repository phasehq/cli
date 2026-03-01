package cmd

import (
	"fmt"

	"github.com/manifoldco/promptui"
	"github.com/phasehq/cli/pkg/config"
	"github.com/spf13/cobra"
)

var usersSwitchCmd = &cobra.Command{
	Use:   "switch",
	Short: "🪄\u200A Switch between Phase users, orgs and hosts",
	RunE:  runUsersSwitch,
}

func init() {
	usersCmd.AddCommand(usersSwitchCmd)
}

func runUsersSwitch(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if len(cfg.PhaseUsers) == 0 {
		return fmt.Errorf("no users found. Please authenticate first with 'phase auth'")
	}

	// Build display labels for each user
	items := make([]string, len(cfg.PhaseUsers))
	for i, user := range cfg.PhaseUsers {
		orgName := "N/A"
		if user.OrganizationName != nil {
			orgName = *user.OrganizationName
		}
		email := "Service Account"
		if user.Email != "" {
			email = user.Email
		}
		shortID := user.ID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		marker := ""
		if user.ID == cfg.DefaultUser {
			marker = " (current)"
		}
		items[i] = fmt.Sprintf("🏢 %s, ✉️  %s, ☁️  %s, 🆔 %s%s", orgName, email, user.Host, shortID, marker)
	}

	prompt := promptui.Select{
		Label: "Select a user",
		Items: items,
	}
	idx, _, err := prompt.Run()
	if err != nil {
		return fmt.Errorf("prompt cancelled")
	}

	selectedUser := cfg.PhaseUsers[idx]
	if err := config.SetDefaultUser(selectedUser.ID); err != nil {
		return fmt.Errorf("failed to switch user: %w", err)
	}

	orgName := "N/A"
	if selectedUser.OrganizationName != nil {
		orgName = *selectedUser.OrganizationName
	}
	email := "Service Account"
	if selectedUser.Email != "" {
		email = selectedUser.Email
	}

	fmt.Printf("Switched to account 🙋: %s (%s)\n", email, orgName)
	return nil
}
