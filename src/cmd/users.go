package cmd

import (
	"github.com/spf13/cobra"
)

var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "👥 Manage users and accounts",
}

func init() {
	rootCmd.AddCommand(usersCmd)
}
