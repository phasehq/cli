package mcp

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/phasehq/cli/pkg/version"
)

// NewServer creates the Phase MCP server with all tools registered.
// Returns the server and handlers (for process cleanup on shutdown).
func NewServer() (*server.MCPServer, *Handlers) {
	s := server.NewMCPServer(
		"phase-secrets",
		version.Version,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, false),
	)

	h := NewHandlers()

	// Project context
	s.AddTool(toolGetContext(), h.HandleGetContext)
	s.AddTool(toolInit(), h.HandleInit)

	// Secrets CRUD
	s.AddTool(toolListSecrets(), h.HandleListSecrets)
	s.AddTool(toolGetSecret(), h.HandleGetSecret)
	s.AddTool(toolCreateSecrets(), h.HandleCreateSecrets)
	s.AddTool(toolUpdateSecret(), h.HandleUpdateSecret)
	s.AddTool(toolDeleteSecrets(), h.HandleDeleteSecrets)

	// Runtime
	s.AddTool(toolRun(), h.HandleRun)
	s.AddTool(toolStop(), h.HandleStop)
	s.AddTool(toolRunLogs(), h.HandleRunLogs)

	// Instructions resource — gives the AI guidance on how to use the tools
	s.AddResource(
		mcp.NewResource(
			"phase://instructions",
			"Phase MCP Usage Guide",
			mcp.WithResourceDescription("How to use Phase secret management tools effectively"),
			mcp.WithMIMEType("text/plain"),
		),
		func(_ context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{
					URI:      "phase://instructions",
					MIMEType: "text/plain",
					Text:     instructions,
				},
			}, nil
		},
	)

	return s, h
}

const instructions = `Phase Secret Management — MCP Usage Guide

SECRET TYPES:
- sealed: ALWAYS hidden. Never returned by list or get. No configuration can override this.
- secret: Hidden by default. The user can allow AI access to secret-type values by running 'phase ai enable' and selecting the "Yes — allow AI to read secret values" option to unmask secret values.
- config: Always visible. 

RULES FOR SECRET TYPES:
- "sealed": Write-only. Values CANNOT be read back and MUST be created/updated with random_type only. You must NEVER set a literal value for sealed secrets. Use for API keys, tokens, passwords etc.
- "secret": Values may be hidden from AI depending on project config (maskSecretAIValues in .phase.json).
- "config": Non-sensitive configuration. Values are always visible. Use for ports, hosts, log levels, feature flags.

WORKFLOW:
1. Check phase_get_context first to see if the project is linked
2. If not linked, use phase_init to connect to an app and environment
3. Use phase_list_secrets to see what exists before creating/modifying
4. For sensitive values, always use random_type to generate securely
5. Use phase_run to start processes with secrets injected — all secret types including sealed are injected at runtime

RUNNING PROCESSES:
- phase_run starts a process in the background and returns a handle
- Use phase_run_logs to check output. Only the last 500 lines will be available (useful for diagnosing crashes)
- Use phase_stop to terminate, then phase_run again to restart

OUT-OF-BAND CLI ACCESS:
When values are hidden from AI, suggest the user run Phase CLI commands directly in a separate terminal. Examples:
- "Run 'phase secrets list --show' in a terminal to see actual values"
- "Run 'phase secrets get SECRET_KEY --show' to view a specific value"
- "Run 'phase ai enable' to configure AI access to secret-type values"

For a list of full CLI commands and help, pull & grep: https://docs.phase.dev/cli/commands.md

IMPORTANT: NEVER run Phase CLI commands (phase secrets list, phase secrets get, phase secrets export, etc.) directly via shell/bash tools. Always use the MCP tools for programmatic access. Only suggest CLI commands for the user to run manually in their own terminal.
`
