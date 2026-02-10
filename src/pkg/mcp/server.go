package mcp

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

const ServerInstructions = `# Phase Secrets Manager - MCP Server

## Security Rules (MANDATORY)
1. NEVER display, log, or return secret VALUES in any response
2. NEVER store secret values in variables, files, or conversation context
3. NEVER use secret values in code suggestions or examples
4. When users need secrets in their app, use phase_run to inject them at runtime
5. For sensitive keys (passwords, tokens, API keys), ALWAYS use phase_secrets_create with random generation
6. NEVER use phase_secrets_set or phase_secrets_update for sensitive values

## Workflow
1. Check auth status with phase_auth_status
2. List secrets with phase_secrets_list to see what exists
3. Create new secrets with phase_secrets_create (generates secure random values)
4. Use phase_run to execute commands with secrets injected as environment variables
5. Use phase_secrets_get to check metadata about a specific secret

## Key Naming Convention
- Use UPPER_SNAKE_CASE for all secret keys
- Examples: DATABASE_URL, API_KEY, JWT_SECRET

## Common Patterns
- Need a database password? → phase_secrets_create with key=DB_PASSWORD
- Need to run migrations? → phase_run with command="npm run migrate"
- Need to check what secrets exist? → phase_secrets_list
- Importing from .env? → phase_secrets_import`

// CheckAuth verifies that Phase credentials are available.
func CheckAuth() error {
	if token := os.Getenv("PHASE_SERVICE_TOKEN"); token != "" {
		return nil
	}
	return checkAuthAvailable()
}

// NewMCPServer creates and configures the Phase MCP server with all tools.
func NewMCPServer() *gomcp.Server {
	server := gomcp.NewServer(
		&gomcp.Implementation{
			Name:    "phase",
			Version: "2.0.0",
		},
		&gomcp.ServerOptions{
			Instructions: ServerInstructions,
		},
	)

	// Tool 1: Auth status
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "phase_auth_status",
		Description: "Check Phase authentication status and display current user/token info.",
	}, handleAuthStatus)

	// Tool 2: List secrets
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "phase_secrets_list",
		Description: "List all secrets in an environment. Returns metadata only (keys, paths, tags, comments) — values are never exposed for security.",
	}, handleSecretsList)

	// Tool 3: Create secret with random value
	gomcp.AddTool(server, &gomcp.Tool{
		Name: "phase_secrets_create",
		Description: "Create a new secret with a securely generated random value. " +
			"Use this for ALL sensitive values (passwords, tokens, API keys, signing keys). " +
			"The generated value is stored securely and NEVER returned in the response. " +
			"Supported random types: hex, alphanumeric, base64, base64url, key128, key256.",
	}, handleSecretsCreate)

	// Tool 4: Set secret with explicit value
	gomcp.AddTool(server, &gomcp.Tool{
		Name: "phase_secrets_set",
		Description: "Set a secret with an explicit value. " +
			"ONLY for non-sensitive configuration values (e.g., APP_NAME, LOG_LEVEL, REGION). " +
			"BLOCKED for sensitive keys matching patterns like *SECRET*, *PASSWORD*, *TOKEN*, *API_KEY*, etc. " +
			"For sensitive values, use phase_secrets_create instead.",
	}, handleSecretsSet)

	// Tool 5: Update secret
	gomcp.AddTool(server, &gomcp.Tool{
		Name: "phase_secrets_update",
		Description: "Update an existing secret's value. " +
			"BLOCKED for sensitive keys matching patterns like *SECRET*, *PASSWORD*, *TOKEN*, *API_KEY*, etc. " +
			"For sensitive values, use phase_secrets_create to rotate with a new random value.",
	}, handleSecretsUpdate)

	// Tool 6: Delete secrets
	gomcp.AddTool(server, &gomcp.Tool{
		Name:        "phase_secrets_delete",
		Description: "Delete one or more secrets by key name. Keys are automatically uppercased.",
	}, handleSecretsDelete)

	// Tool 7: Import secrets from .env file
	gomcp.AddTool(server, &gomcp.Tool{
		Name: "phase_secrets_import",
		Description: "Import secrets from a .env file into Phase. " +
			"Parses KEY=VALUE pairs and encrypts them. Values are never returned in the response.",
	}, handleSecretsImport)

	// Tool 8: Get secret metadata
	gomcp.AddTool(server, &gomcp.Tool{
		Name: "phase_secrets_get",
		Description: "Get metadata about a specific secret (key, path, tags, comment, environment). " +
			"The secret VALUE is never returned for security.",
	}, handleSecretsGet)

	// Tool 9: Run command with secrets
	gomcp.AddTool(server, &gomcp.Tool{
		Name: "phase_run",
		Description: "Execute a shell command with Phase secrets injected as environment variables. " +
			"Commands are validated for safety — shell variable expansion, env dumping commands, and code injection are blocked. " +
			"Output is sanitized and truncated. 5-minute timeout.",
	}, handleRun)

	// Tool 10: Initialize project
	gomcp.AddTool(server, &gomcp.Tool{
		Name: "phase_init",
		Description: "Initialize a Phase project by linking it to an application. " +
			"Creates a .phase.json config file with the app ID and default environment.",
	}, handleInit)

	return server
}

// RunServer starts the MCP server on stdio transport.
func RunServer(ctx context.Context) error {
	// Redirect all log output to stderr — stdout is reserved for MCP protocol
	log.SetOutput(os.Stderr)

	if err := CheckAuth(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Phase authentication not configured. Set PHASE_SERVICE_TOKEN or run 'phase auth'.\n")
	}

	server := NewMCPServer()
	err := server.Run(ctx, &gomcp.StdioTransport{})
	// EOF on stdin is normal — it means the client disconnected
	if err != nil && (err == io.EOF || strings.Contains(err.Error(), "EOF")) {
		return nil
	}
	return err
}
