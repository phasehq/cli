package cmd

import (
	"github.com/spf13/cobra"
)

// The egress-proxy commands also live under `phase ai` — their most natural home,
// since routing an AI agent's traffic through the credential-injection proxy is
// an AI-integration feature. These delegate to the exact same run functions and
// flags as `phase proxy run` / `phase proxy connect` (both spellings work; the
// proxy ones are not removed).

var aiRunCmd = &cobra.Command{
	Use:   "run -- <command>",
	Short: "🚀 Run a command/agent routed through the egress proxy (alias of 'phase proxy run')",
	Long:  proxyRunCmd.Long,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runProxyRun,
}

var aiServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "🔐 Approve (Touch ID) and run the egress proxy in this shell (alias of 'phase proxy connect')",
	Long:  proxyConnectCmd.Long,
	RunE:  runProxyConnect,
}

func init() {
	addProxyRunFlags(aiRunCmd)
	aiCmd.AddCommand(aiRunCmd)

	addProxyConnectFlags(aiServeCmd)
	aiCmd.AddCommand(aiServeCmd)
}
