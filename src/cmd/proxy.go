package cmd

import (
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "🛡  Egress proxy for AI agents",
	Long:  "Run a transparent egress proxy that injects secrets at call time, enforces per-action policy, and audits agent traffic to third-party services — so agents hold a Phase token, never real credentials.",
}

func init() {
	rootCmd.AddCommand(proxyCmd)
}
