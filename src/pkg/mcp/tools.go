package mcp

import "github.com/mark3labs/mcp-go/mcp"

func toolGetContext() mcp.Tool {
	return mcp.NewTool("phase_get_context",
		mcp.WithDescription("Read the current Phase config context (.phase.json). Returns the initialized App, Environment, and config, or indicates the local project is not linked."),
	)
}

func toolInit() mcp.Tool {
	return mcp.NewTool("phase_init",
		mcp.WithDescription("Link this project to a Phase app and environment. Call with no args to get numbered lists of available apps and environments for selection. Call with app_id and env_name to complete the link."),
		mcp.WithString("app_id", mcp.Description("Application ID to link to. Omit to list available apps.")),
		mcp.WithString("env_name", mcp.Description("Environment name to set as default. Omit to list available environments.")),
		mcp.WithBoolean("monorepo", mcp.Description("If true, this config applies to subdirectories too."), mcp.DefaultBool(false)),
	)
}

func toolListSecrets() mcp.Tool {
	return mcp.NewTool("phase_list_secrets",
		mcp.WithDescription("List secret keys with metadata (type, path, tags, comments). Fetches all paths by default. Sealed values are always hidden. Secret-type values are hidden by default but can be enabled by the user via 'phase ai enable'. Config values are always visible. When displaying results, always show the app name, environment, and path context."),
		mcp.WithString("env", mcp.Description("Environment name. Defaults to .phase.json setting.")),
		mcp.WithString("app", mcp.Description("Application name. Defaults to .phase.json setting.")),
		mcp.WithString("app_id", mcp.Description("Application ID. Takes precedence over app name.")),
		mcp.WithString("path", mcp.Description("Path filter. Omit to fetch all paths.")),
	)
}

func toolGetSecret() mcp.Tool {
	return mcp.NewTool("phase_get_secret",
		mcp.WithDescription("Get a single secret's details. Sealed values are always hidden. Secret-type values are hidden by default but can be enabled by the user via 'phase ai enable'. Config values are always visible."),
		mcp.WithString("key", mcp.Required(), mcp.Description("The secret key to fetch.")),
		mcp.WithString("env", mcp.Description("Environment name.")),
		mcp.WithString("app", mcp.Description("Application name.")),
		mcp.WithString("app_id", mcp.Description("Application ID.")),
		mcp.WithString("path", mcp.Description("Path of the secret. Default: /")),
	)
}

func toolCreateSecrets() mcp.Tool {
	return mcp.NewTool("phase_create_secrets",
		mcp.WithDescription("Create one or more secrets. For sensitive values, use random_type to generate values securely without them appearing in this conversation. Supported random types: hex, alphanumeric, base64, base64url, key128, key256. IMPORTANT: sealed-type secrets MUST use random_type — you cannot set a literal value for sealed secrets."),
		mcp.WithArray("secrets",
			mcp.Required(),
			mcp.Description("Array of secrets to create."),
			mcp.Items(map[string]any{
				"type": "object",
				"properties": map[string]any{
					"key":         map[string]any{"type": "string", "description": "Secret key (will be uppercased)."},
					"value":       map[string]any{"type": "string", "description": "Secret value. Omit if using random_type."},
					"random_type": map[string]any{"type": "string", "description": "Generate random value: hex, alphanumeric, base64, base64url, key128, key256."},
					"length":      map[string]any{"type": "number", "description": "Length for random value. Default: 32. Ignored for key128/key256."},
				},
				"required": []string{"key"},
			}),
		),
		mcp.WithString("env", mcp.Description("Environment name.")),
		mcp.WithString("app", mcp.Description("Application name.")),
		mcp.WithString("app_id", mcp.Description("Application ID.")),
		mcp.WithString("path", mcp.Description("Path for the secrets. Default: /")),
		mcp.WithString("type", mcp.Description("Secret type for all secrets in this batch: secret (default), sealed, or config.")),
	)
}

func toolUpdateSecret() mcp.Tool {
	return mcp.NewTool("phase_update_secret",
		mcp.WithDescription("Update an existing secret's value, type, or path. Supports random generation for secure value rotation. IMPORTANT: sealed-type secrets MUST use random_type — you cannot set a literal value for sealed secrets."),
		mcp.WithString("key", mcp.Required(), mcp.Description("The secret key to update.")),
		mcp.WithString("value", mcp.Description("New literal value. Omit to keep existing. Cannot be used for sealed-type secrets.")),
		mcp.WithString("random_type", mcp.Description("Generate random value: hex, alphanumeric, base64, base64url, key128, key256.")),
		mcp.WithNumber("length", mcp.Description("Length for random value. Default: 32. Ignored for key128/key256.")),
		mcp.WithString("type", mcp.Description("New type: secret, sealed, or config. Omit to keep existing.")),
		mcp.WithString("dest_path", mcp.Description("Move the secret to this path.")),
		mcp.WithString("env", mcp.Description("Environment name.")),
		mcp.WithString("app", mcp.Description("Application name.")),
		mcp.WithString("app_id", mcp.Description("Application ID.")),
		mcp.WithString("path", mcp.Description("Current path of the secret. Default: /")),
	)
}

func toolDeleteSecrets() mcp.Tool {
	return mcp.NewTool("phase_delete_secrets",
		mcp.WithDescription("Delete one or more secrets by key."),
		mcp.WithArray("keys",
			mcp.Required(),
			mcp.Description("Keys of secrets to delete."),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithString("env", mcp.Description("Environment name.")),
		mcp.WithString("app", mcp.Description("Application name.")),
		mcp.WithString("app_id", mcp.Description("Application ID.")),
		mcp.WithString("path", mcp.Description("Path filter. Default: /")),
	)
}

func toolRun() mcp.Tool {
	return mcp.NewTool("phase_run",
		mcp.WithDescription("Start a command with Phase secrets injected as environment variables. The process runs in the background. Returns a handle to use with phase_stop and phase_run_logs."),
		mcp.WithString("command", mcp.Required(), mcp.Description("Shell command to run (e.g. 'yarn dev', 'docker compose up').")),
		mcp.WithString("env", mcp.Description("Environment name.")),
		mcp.WithString("app", mcp.Description("Application name.")),
		mcp.WithString("app_id", mcp.Description("Application ID.")),
		mcp.WithString("path", mcp.Description("Path filter for secrets. Default: /")),
	)
}

func toolStop() mcp.Tool {
	return mcp.NewTool("phase_stop",
		mcp.WithDescription("Stop a running process by its handle (returned from phase_run)."),
		mcp.WithNumber("handle", mcp.Required(), mcp.Description("Process handle from phase_run.")),
	)
}

func toolRunLogs() mcp.Tool {
	return mcp.NewTool("phase_run_logs",
		mcp.WithDescription("Get recent stdout/stderr output from a managed process (running or recently stopped)."),
		mcp.WithNumber("handle", mcp.Required(), mcp.Description("Process handle from phase_run.")),
		mcp.WithNumber("lines", mcp.Description("Number of recent lines to return. Default: 50.")),
	)
}
