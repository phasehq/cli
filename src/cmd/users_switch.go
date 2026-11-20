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
		items[i] = switchUserLabel(user, user.ID == cfg.DefaultUser)
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

	fmt.Println(switchedUserMessage(selectedUser))
	return nil
}
