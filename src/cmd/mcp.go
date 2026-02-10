package cmd

import (
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "🤖 Model Context Protocol (MCP) server for AI assistants (BETA)",
	Long: `🤖 Model Context Protocol (MCP) server for AI assistants (BETA)

Allows AI assistants like Claude Code, Cursor, VS Code Copilot, Zed, and OpenCode
to securely manage Phase secrets via the MCP protocol.

Subcommands:
  serve      Start the MCP stdio server
  install    Install Phase MCP for an AI client
  uninstall  Uninstall Phase MCP from an AI client`,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
