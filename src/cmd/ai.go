package cmd

import (
	"github.com/spf13/cobra"
)

var aiCmd = &cobra.Command{
	Use:   "ai",
	Short: "🥷  Integrate Phase with AI Agents",
	Long:  "Configure how AI coding agents interact with your Phase secrets.",
}

func init() {
	rootCmd.AddCommand(aiCmd)
}
