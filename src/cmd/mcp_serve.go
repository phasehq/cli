package cmd

import (
	phasemcp "github.com/phasehq/cli/pkg/mcp"
	"github.com/spf13/cobra"
)

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "🚀 Start the Phase MCP server (stdio transport)",
	Long: `🚀 Start the Phase MCP server using stdio transport.

This command is typically invoked by AI clients (Claude Code, Cursor, etc.)
and communicates via stdin/stdout using the MCP JSON-RPC protocol.

Requires either PHASE_SERVICE_TOKEN environment variable or an authenticated
user session (via 'phase auth').`,
	RunE: runMCPServe,
}

func init() {
	mcpCmd.AddCommand(mcpServeCmd)
}

func runMCPServe(cmd *cobra.Command, args []string) error {
	return phasemcp.RunServer(cmd.Context())
}
