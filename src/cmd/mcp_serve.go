package cmd

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	phasemcp "github.com/phasehq/cli/pkg/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Phase MCP server (stdio transport)",
	Long:  "Starts a local MCP server over stdin/stdout. Used by AI clients like Claude Code.",
	RunE:  runMCPServe,
}

func init() {
	mcpCmd.AddCommand(mcpServeCmd)
}

func runMCPServe(cmd *cobra.Command, args []string) error {
	s, handlers := phasemcp.NewServer()

	// Clean up managed processes on shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		handlers.Processes.StopAll()
		os.Exit(0)
	}()

	// Redirect any stray log output to stderr so it doesn't corrupt the JSON-RPC stream
	log.SetOutput(os.Stderr)

	if err := server.ServeStdio(s); err != nil {
		handlers.Processes.StopAll()
		return err
	}
	return nil
}
