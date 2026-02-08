package cmd

import (
	"fmt"
	"strings"

	phasemcp "github.com/phasehq/cli/pkg/mcp"
	"github.com/spf13/cobra"
)

var mcpInstallCmd = &cobra.Command{
	Use:   "install [client]",
	Short: "📦 Install Phase MCP server for AI clients",
	Long: fmt.Sprintf(`📦 Install Phase MCP server configuration for AI clients.

If no client is specified, installs for all detected clients.

Supported clients: %s

Examples:
  phase mcp install                    # Install for all detected clients
  phase mcp install claude-code        # Install for Claude Code only
  phase mcp install cursor --scope project  # Install in project scope`, strings.Join(phasemcp.SupportedClientNames(), ", ")),
	Args: cobra.MaximumNArgs(1),
	RunE: runMCPInstall,
}

func init() {
	mcpInstallCmd.Flags().String("scope", "user", "Installation scope: user or project")
	mcpCmd.AddCommand(mcpInstallCmd)
}

func runMCPInstall(cmd *cobra.Command, args []string) error {
	scope, _ := cmd.Flags().GetString("scope")

	var client string
	if len(args) > 0 {
		client = args[0]
	}

	if err := phasemcp.Install(client, scope); err != nil {
		return err
	}

	if client != "" {
		fmt.Printf("✅ Phase MCP server installed for %s (scope: %s).\n", client, scope)
	} else {
		fmt.Println("✅ Phase MCP server installed for all detected clients.")
	}
	return nil
}
