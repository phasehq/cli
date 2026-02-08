package cmd

import (
	"fmt"
	"strings"

	phasemcp "github.com/phasehq/cli/pkg/mcp"
	"github.com/spf13/cobra"
)

var mcpUninstallCmd = &cobra.Command{
	Use:   "uninstall [client]",
	Short: "🗑️\u200A Uninstall Phase MCP server from AI clients",
	Long: fmt.Sprintf(`🗑️  Uninstall Phase MCP server configuration from AI clients.

If no client is specified, uninstalls from all clients.

Supported clients: %s

Examples:
  phase mcp uninstall              # Uninstall from all clients
  phase mcp uninstall claude-code  # Uninstall from Claude Code only`, strings.Join(phasemcp.SupportedClientNames(), ", ")),
	Args: cobra.MaximumNArgs(1),
	RunE: runMCPUninstall,
}

func init() {
	mcpCmd.AddCommand(mcpUninstallCmd)
}

func runMCPUninstall(cmd *cobra.Command, args []string) error {
	var client string
	if len(args) > 0 {
		client = args[0]
	}

	if err := phasemcp.Uninstall(client); err != nil {
		return err
	}

	if client != "" {
		fmt.Printf("✅ Phase MCP server uninstalled from %s.\n", client)
	} else {
		fmt.Println("✅ Phase MCP server uninstalled from all clients.")
	}
	return nil
}
