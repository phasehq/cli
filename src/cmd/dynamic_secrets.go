package cmd

import (
	"github.com/phasehq/cli/pkg/phase"
	"github.com/spf13/cobra"
)

var dynamicSecretsCmd = &cobra.Command{
	Use:   "dynamic-secrets",
	Short: "⚡️ Manage dynamic secrets",
	// Applies to every dynamic-secrets subcommand: no other hook is set on
	// the root, so this is the nearest one for each of them.
	PersistentPreRunE: func(*cobra.Command, []string) error {
		if phase.ActiveLoginIsAgent() {
			return phase.ErrAgentDynamicSecrets
		}
		return nil
	},
}

var dynamicSecretsLeaseCmd = &cobra.Command{
	Use:   "lease",
	Short: "📜 Manage dynamic secret leases",
}

func init() {
	dynamicSecretsCmd.AddCommand(dynamicSecretsLeaseCmd)
	rootCmd.AddCommand(dynamicSecretsCmd)
}
