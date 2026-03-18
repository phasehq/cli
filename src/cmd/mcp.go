package cmd

import "github.com/spf13/cobra"

var aiCmd = &cobra.Command{
	Use:   "ai",
	Short: "🤖 AI integrations for Phase (BETA)",
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "🔌 MCP server for AI-assisted secret management (BETA)",
	Long:  "Model Context Protocol (MCP) server that lets AI coding assistants manage Phase secrets. (BETA)",
}

func init() {
	rootCmd.AddCommand(aiCmd)
	aiCmd.AddCommand(mcpCmd)
}
