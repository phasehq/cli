package cmd

import (
	"github.com/spf13/cobra"
)

var dynamicSecretsCmd = &cobra.Command{
	Use:   "dynamic-secrets",
	Short: "⚡️ Manage dynamic secrets",
}

var dynamicSecretsLeaseCmd = &cobra.Command{
	Use:   "lease",
	Short: "📜 Manage dynamic secret leases",
}

func init() {
	dynamicSecretsCmd.AddCommand(dynamicSecretsLeaseCmd)
	rootCmd.AddCommand(dynamicSecretsCmd)
}
