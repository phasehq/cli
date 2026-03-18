package cmd

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

var mcpInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the Phase MCP server for Claude Code",
	Long:  "Registers the Phase MCP server with Claude Code so it can manage secrets via AI.",
	RunE:  runMCPInstall,
}

var mcpUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the Phase MCP server from Claude Code",
	RunE:  runMCPUninstall,
}

func init() {
	mcpCmd.AddCommand(mcpInstallCmd)
	mcpCmd.AddCommand(mcpUninstallCmd)
}

func runMCPInstall(cmd *cobra.Command, args []string) error {
	claudePath, err := exec.LookPath("claude")
	if err != nil {
		return fmt.Errorf("claude CLI not found on PATH. Install Claude Code first: https://docs.anthropic.com/en/docs/claude-code")
	}

	// Find the phase binary path
	phasePath, err := exec.LookPath("phase")
	if err != nil {
		// Fall back to just "phase" and hope it's on PATH at runtime
		phasePath = "phase"
	}

	// claude mcp add phase-secrets -- phase ai mcp serve
	c := exec.Command(claudePath, "mcp", "add", "phase-secrets", "--", phasePath, "ai", "mcp", "serve")
	output, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to register MCP server: %s\n%s", err, string(output))
	}

	fmt.Println("✅ Phase MCP server registered with Claude Code.")
	fmt.Println("   Restart Claude Code to activate.")
	return nil
}

func runMCPUninstall(cmd *cobra.Command, args []string) error {
	claudePath, err := exec.LookPath("claude")
	if err != nil {
		return fmt.Errorf("claude CLI not found on PATH")
	}

	c := exec.Command(claudePath, "mcp", "remove", "phase-secrets")
	output, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to unregister MCP server: %s\n%s", err, string(output))
	}

	fmt.Println("✅ Phase MCP server removed from Claude Code.")
	return nil
}
