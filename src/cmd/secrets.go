package cmd

import (
	"github.com/spf13/cobra"
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "🗝️\u200A Manage your secrets",
}

func init() {
	rootCmd.AddCommand(secretsCmd)
}
