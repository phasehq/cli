package cmd

import (
	"github.com/spf13/cobra"
)

var aiCmd = &cobra.Command{
	Use:   "ai",
	Short: "🥷  Integrate Phase with AI Agents",
	Long:  "Run AI coding agents through Phase's workflow-scoped local credential proxy.",
}

func init() {
	rootCmd.AddCommand(aiCmd)
}
