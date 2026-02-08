package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
)

// SecretMetadata is a safe output struct that never includes secret values.
type SecretMetadata struct {
	Key         string   `json:"key"`
	Path        string   `json:"path"`
	Tags        []string `json:"tags"`
	Comment     string   `json:"comment"`
	Environment string   `json:"environment"`
	Application string   `json:"application"`
	Overridden  bool     `json:"overridden"`
}

func newPhaseClient() (*phase.Phase, error) {
	return phase.NewPhase(true, "", "")
}

func textResult(msg string) *gomcp.CallToolResult {
	return &gomcp.CallToolResult{
		Content: []gomcp.Content{
			&gomcp.TextContent{Text: msg},
		},
	}
}

func errorResult(msg string) (*gomcp.CallToolResult, any, error) {
	return &gomcp.CallToolResult{
		Content: []gomcp.Content{
			&gomcp.TextContent{Text: "Error: " + msg},
		},
		IsError: true,
	}, nil, nil
}

// --- Tool argument types ---

type AuthStatusArgs struct{}

type SecretsListArgs struct {
	Env   string `json:"env,omitempty" jsonschema:"Environment name"`
	App   string `json:"app,omitempty" jsonschema:"Application name"`
	AppID string `json:"app_id,omitempty" jsonschema:"Application ID"`
	Path  string `json:"path,omitempty" jsonschema:"Secret path (default: /)"`
	Tags  string `json:"tags,omitempty" jsonschema:"Filter by tags"`
}

type SecretsCreateArgs struct {
	Key        string `json:"key" jsonschema:"Secret key name (uppercase, letters/digits/underscores)"`
	Env        string `json:"env,omitempty" jsonschema:"Environment name"`
	App        string `json:"app,omitempty" jsonschema:"Application name"`
	AppID      string `json:"app_id,omitempty" jsonschema:"Application ID"`
	Path       string `json:"path,omitempty" jsonschema:"Secret path (default: /)"`
	RandomType string `json:"random_type,omitempty" jsonschema:"Random value type: hex, alphanumeric, base64, base64url, key128, key256"`
	Length     int    `json:"length,omitempty" jsonschema:"Length for random secret (default: 32)"`
}

type SecretsSetArgs struct {
	Key   string `json:"key" jsonschema:"Secret key name"`
	Value string `json:"value" jsonschema:"Secret value to set"`
	Env   string `json:"env,omitempty" jsonschema:"Environment name"`
	App   string `json:"app,omitempty" jsonschema:"Application name"`
	AppID string `json:"app_id,omitempty" jsonschema:"Application ID"`
	Path  string `json:"path,omitempty" jsonschema:"Secret path (default: /)"`
}

type SecretsUpdateArgs struct {
	Key   string `json:"key" jsonschema:"Secret key name to update"`
	Value string `json:"value" jsonschema:"New secret value"`
	Env   string `json:"env,omitempty" jsonschema:"Environment name"`
	App   string `json:"app,omitempty" jsonschema:"Application name"`
	AppID string `json:"app_id,omitempty" jsonschema:"Application ID"`
	Path  string `json:"path,omitempty" jsonschema:"Secret path"`
}

type SecretsDeleteArgs struct {
	Keys  []string `json:"keys" jsonschema:"List of secret key names to delete"`
	Env   string   `json:"env,omitempty" jsonschema:"Environment name"`
	App   string   `json:"app,omitempty" jsonschema:"Application name"`
	AppID string   `json:"app_id,omitempty" jsonschema:"Application ID"`
	Path  string   `json:"path,omitempty" jsonschema:"Secret path"`
}

type SecretsImportArgs struct {
	FilePath string `json:"file_path" jsonschema:"Path to .env file to import"`
	Env      string `json:"env,omitempty" jsonschema:"Environment name"`
	App      string `json:"app,omitempty" jsonschema:"Application name"`
	AppID    string `json:"app_id,omitempty" jsonschema:"Application ID"`
	Path     string `json:"path,omitempty" jsonschema:"Secret path (default: /)"`
}

type SecretsGetArgs struct {
	Key   string `json:"key" jsonschema:"Secret key name to fetch"`
	Env   string `json:"env,omitempty" jsonschema:"Environment name"`
	App   string `json:"app,omitempty" jsonschema:"Application name"`
	AppID string `json:"app_id,omitempty" jsonschema:"Application ID"`
	Path  string `json:"path,omitempty" jsonschema:"Secret path (default: /)"`
}

type RunArgs struct {
	Command string `json:"command" jsonschema:"Shell command to execute with secrets injected"`
	Env     string `json:"env,omitempty" jsonschema:"Environment name"`
	App     string `json:"app,omitempty" jsonschema:"Application name"`
	AppID   string `json:"app_id,omitempty" jsonschema:"Application ID"`
	Path    string `json:"path,omitempty" jsonschema:"Secret path"`
	Tags    string `json:"tags,omitempty" jsonschema:"Filter by tags"`
}

type InitArgs struct {
	AppID string `json:"app_id" jsonschema:"Application ID to initialize with"`
}

// --- Tool handlers ---

func handleAuthStatus(_ context.Context, _ *gomcp.CallToolRequest, _ AuthStatusArgs) (*gomcp.CallToolResult, any, error) {
	// Check service token first
	if token := os.Getenv("PHASE_SERVICE_TOKEN"); token != "" {
		host := os.Getenv("PHASE_HOST")
		if host == "" {
			host = config.PhaseCloudAPIHost
		}
		return textResult(fmt.Sprintf("Authenticated via PHASE_SERVICE_TOKEN\nHost: %s\nToken type: Service Token", host)), nil, nil
	}

	// Check user config
	user, err := config.GetDefaultUser()
	if err != nil {
		return errorResult("Not authenticated. Set PHASE_SERVICE_TOKEN or run 'phase auth'.")
	}

	host, _ := config.GetDefaultUserHost()
	info := fmt.Sprintf("Authenticated as user\nUser ID: %s\nEmail: %s\nHost: %s", user.ID, user.Email, host)
	if user.OrganizationName != nil && *user.OrganizationName != "" {
		info += fmt.Sprintf("\nOrganization: %s", *user.OrganizationName)
	}

	return textResult(info), nil, nil
}

func handleSecretsList(_ context.Context, _ *gomcp.CallToolRequest, args SecretsListArgs) (*gomcp.CallToolResult, any, error) {
	p, err := newPhaseClient()
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to initialize Phase client: %v", err))
	}

	secrets, err := p.Get(phase.GetOptions{
		EnvName: args.Env,
		AppName: args.App,
		AppID:   args.AppID,
		Path:    args.Path,
		Tag:     args.Tags,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to list secrets: %v", err))
	}

	metadata := make([]SecretMetadata, len(secrets))
	for i, s := range secrets {
		metadata[i] = SecretMetadata{
			Key:         s.Key,
			Path:        s.Path,
			Tags:        s.Tags,
			Comment:     s.Comment,
			Environment: s.Environment,
			Application: s.Application,
			Overridden:  s.Overridden,
		}
	}

	data, _ := json.MarshalIndent(metadata, "", "  ")
	return textResult(fmt.Sprintf("Found %d secrets (values hidden for security):\n%s", len(metadata), string(data))), nil, nil
}

func handleSecretsCreate(_ context.Context, _ *gomcp.CallToolRequest, args SecretsCreateArgs) (*gomcp.CallToolResult, any, error) {
	key := strings.ToUpper(strings.ReplaceAll(args.Key, " ", "_"))

	if ok, reason := IsSafeKeyName(key); !ok {
		return errorResult(fmt.Sprintf("Invalid key name: %s", reason))
	}

	randomType := args.RandomType
	if randomType == "" {
		randomType = "hex"
	}

	length := args.Length
	if length <= 0 {
		length = 32
	}

	value, err := util.GenerateRandomSecret(randomType, length)
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to generate random secret: %v", err))
	}

	p, err := newPhaseClient()
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to initialize Phase client: %v", err))
	}

	path := args.Path
	if path == "" {
		path = "/"
	}

	err = p.Create(phase.CreateOptions{
		KeyValuePairs: []phase.KeyValuePair{{Key: key, Value: value}},
		EnvName:       args.Env,
		AppName:       args.App,
		AppID:         args.AppID,
		Path:          path,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to create secret: %v", err))
	}

	return textResult(fmt.Sprintf("Successfully created secret '%s' with a random %s value (value hidden for security).", key, randomType)), nil, nil
}

func handleSecretsSet(_ context.Context, _ *gomcp.CallToolRequest, args SecretsSetArgs) (*gomcp.CallToolResult, any, error) {
	key := strings.ToUpper(strings.ReplaceAll(args.Key, " ", "_"))

	if ok, reason := IsSafeKeyName(key); !ok {
		return errorResult(fmt.Sprintf("Invalid key name: %s", reason))
	}

	if IsSensitiveKey(key) {
		return errorResult(fmt.Sprintf(
			"Cannot set '%s' directly — this key name matches a sensitive pattern (secrets, passwords, tokens, API keys, etc.). "+
				"For security, use 'phase_secrets_create' to generate a random value instead, which ensures the value is never exposed in conversation.",
			key,
		))
	}

	p, err := newPhaseClient()
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to initialize Phase client: %v", err))
	}

	path := args.Path
	if path == "" {
		path = "/"
	}

	err = p.Create(phase.CreateOptions{
		KeyValuePairs: []phase.KeyValuePair{{Key: key, Value: args.Value}},
		EnvName:       args.Env,
		AppName:       args.App,
		AppID:         args.AppID,
		Path:          path,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to set secret: %v", err))
	}

	return textResult(fmt.Sprintf("Successfully set secret '%s'.", key)), nil, nil
}

func handleSecretsUpdate(_ context.Context, _ *gomcp.CallToolRequest, args SecretsUpdateArgs) (*gomcp.CallToolResult, any, error) {
	key := strings.ToUpper(strings.ReplaceAll(args.Key, " ", "_"))

	if IsSensitiveKey(key) {
		return errorResult(fmt.Sprintf(
			"Cannot update '%s' directly — this key name matches a sensitive pattern (secrets, passwords, tokens, API keys, etc.). "+
				"For security, use 'phase_secrets_create' to generate a random value instead.",
			key,
		))
	}

	p, err := newPhaseClient()
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to initialize Phase client: %v", err))
	}

	result, err := p.Update(phase.UpdateOptions{
		EnvName:    args.Env,
		AppName:    args.App,
		AppID:      args.AppID,
		Key:        key,
		Value:      args.Value,
		SourcePath: args.Path,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to update secret: %v", err))
	}

	if result == "Success" {
		return textResult(fmt.Sprintf("Successfully updated secret '%s'.", key)), nil, nil
	}
	return textResult(result), nil, nil
}

func handleSecretsDelete(_ context.Context, _ *gomcp.CallToolRequest, args SecretsDeleteArgs) (*gomcp.CallToolResult, any, error) {
	if len(args.Keys) == 0 {
		return errorResult("No keys specified for deletion.")
	}

	// Uppercase all keys
	keys := make([]string, len(args.Keys))
	for i, k := range args.Keys {
		keys[i] = strings.ToUpper(k)
	}

	p, err := newPhaseClient()
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to initialize Phase client: %v", err))
	}

	keysNotFound, err := p.Delete(phase.DeleteOptions{
		EnvName:      args.Env,
		AppName:      args.App,
		AppID:        args.AppID,
		KeysToDelete: keys,
		Path:         args.Path,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to delete secrets: %v", err))
	}

	deleted := len(keys) - len(keysNotFound)
	msg := fmt.Sprintf("Deleted %d secret(s).", deleted)
	if len(keysNotFound) > 0 {
		msg += fmt.Sprintf(" Keys not found: %s", strings.Join(keysNotFound, ", "))
	}
	return textResult(msg), nil, nil
}

func handleSecretsImport(_ context.Context, _ *gomcp.CallToolRequest, args SecretsImportArgs) (*gomcp.CallToolResult, any, error) {
	if args.FilePath == "" {
		return errorResult("file_path is required.")
	}

	pairs, err := util.ParseEnvFile(args.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to read env file: %v", err))
	}

	if len(pairs) == 0 {
		return textResult("No secrets found in the file."), nil, nil
	}

	var kvPairs []phase.KeyValuePair
	for _, pair := range pairs {
		kvPairs = append(kvPairs, phase.KeyValuePair{
			Key:   pair.Key,
			Value: pair.Value,
		})
	}

	p, err := newPhaseClient()
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to initialize Phase client: %v", err))
	}

	path := args.Path
	if path == "" {
		path = "/"
	}

	err = p.Create(phase.CreateOptions{
		KeyValuePairs: kvPairs,
		EnvName:       args.Env,
		AppName:       args.App,
		AppID:         args.AppID,
		Path:          path,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to import secrets: %v", err))
	}

	return textResult(fmt.Sprintf("Successfully imported %d secrets from %s (values hidden for security).", len(kvPairs), args.FilePath)), nil, nil
}

func handleSecretsGet(_ context.Context, _ *gomcp.CallToolRequest, args SecretsGetArgs) (*gomcp.CallToolResult, any, error) {
	key := strings.ToUpper(args.Key)

	p, err := newPhaseClient()
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to initialize Phase client: %v", err))
	}

	secrets, err := p.Get(phase.GetOptions{
		EnvName: args.Env,
		AppName: args.App,
		AppID:   args.AppID,
		Keys:    []string{key},
		Path:    args.Path,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to get secret: %v", err))
	}

	for _, s := range secrets {
		if s.Key == key {
			meta := SecretMetadata{
				Key:         s.Key,
				Path:        s.Path,
				Tags:        s.Tags,
				Comment:     s.Comment,
				Environment: s.Environment,
				Application: s.Application,
				Overridden:  s.Overridden,
			}
			data, _ := json.MarshalIndent(meta, "", "  ")
			return textResult(fmt.Sprintf("Secret metadata (value hidden for security):\n%s", string(data))), nil, nil
		}
	}

	return textResult(fmt.Sprintf("Secret '%s' not found.", key)), nil, nil
}

func handleRun(ctx context.Context, _ *gomcp.CallToolRequest, args RunArgs) (*gomcp.CallToolResult, any, error) {
	if err := ValidateRunCommand(args.Command); err != nil {
		return errorResult(fmt.Sprintf("Command validation failed: %v", err))
	}

	p, err := newPhaseClient()
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to initialize Phase client: %v", err))
	}

	secrets, err := p.Get(phase.GetOptions{
		EnvName: args.Env,
		AppName: args.App,
		AppID:   args.AppID,
		Tag:     args.Tags,
		Path:    args.Path,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to fetch secrets: %v", err))
	}

	// Resolve references
	resolvedSecrets := map[string]string{}
	for _, secret := range secrets {
		if secret.Value == "" {
			continue
		}
		resolvedValue := phase.ResolveAllSecrets(secret.Value, secrets, p, secret.Application, secret.Environment)
		resolvedSecrets[secret.Key] = resolvedValue
	}

	// Build environment
	cleanEnv := util.CleanSubprocessEnv()
	for k, v := range resolvedSecrets {
		cleanEnv[k] = v
	}

	var envSlice []string
	for k, v := range cleanEnv {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
	}

	// Execute with 5 minute timeout
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	shell := util.GetDefaultShell()
	var cmd *exec.Cmd
	if shell != nil && len(shell) > 0 {
		cmd = exec.CommandContext(runCtx, shell[0], "-c", args.Command)
	} else {
		cmd = exec.CommandContext(runCtx, "sh", "-c", args.Command)
	}
	cmd.Env = envSlice

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	output := stdout.String()
	if stderr.Len() > 0 {
		if output != "" {
			output += "\n"
		}
		output += "STDERR:\n" + stderr.String()
	}

	output = SanitizeOutput(output, 10000)

	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return errorResult("Command timed out after 5 minutes.")
		}
		return textResult(fmt.Sprintf("Command exited with error: %v\n\nOutput:\n%s", err, output)), nil, nil
	}

	return textResult(fmt.Sprintf("Command completed successfully.\n\nOutput:\n%s", output)), nil, nil
}

func handleInit(_ context.Context, _ *gomcp.CallToolRequest, args InitArgs) (*gomcp.CallToolResult, any, error) {
	if args.AppID == "" {
		return errorResult("app_id is required.")
	}

	p, err := newPhaseClient()
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to initialize Phase client: %v", err))
	}

	data, err := p.Init()
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to fetch app data: %v", err))
	}

	// Find the app by ID
	var selectedApp *struct {
		Name string
		ID   string
		Envs []string
	}
	for _, app := range data.Apps {
		if app.ID == args.AppID {
			var envs []string
			for _, ek := range app.EnvironmentKeys {
				envs = append(envs, ek.Environment.Name)
			}
			selectedApp = &struct {
				Name string
				ID   string
				Envs []string
			}{Name: app.Name, ID: app.ID, Envs: envs}
			break
		}
	}

	if selectedApp == nil {
		return errorResult(fmt.Sprintf("Application with ID '%s' not found.", args.AppID))
	}

	if len(selectedApp.Envs) == 0 {
		return errorResult(fmt.Sprintf("No environments found for application '%s'.", selectedApp.Name))
	}

	// Pick first environment as default
	defaultEnv := selectedApp.Envs[0]

	// Find the env ID
	var envID string
	for _, app := range data.Apps {
		if app.ID == args.AppID {
			for _, ek := range app.EnvironmentKeys {
				if ek.Environment.Name == defaultEnv {
					envID = ek.Environment.ID
					break
				}
			}
			break
		}
	}

	phaseConfig := &config.PhaseJSONConfig{
		Version:    "2",
		PhaseApp:   selectedApp.Name,
		AppID:      selectedApp.ID,
		DefaultEnv: defaultEnv,
		EnvID:      envID,
	}

	if err := config.WritePhaseConfig(phaseConfig); err != nil {
		return errorResult(fmt.Sprintf("Failed to write .phase.json: %v", err))
	}

	os.Chmod(config.PhaseEnvConfig, 0600)

	return textResult(fmt.Sprintf(
		"Initialized Phase project:\n  Application: %s\n  Default Environment: %s\n  Available Environments: %s",
		selectedApp.Name, defaultEnv, strings.Join(selectedApp.Envs, ", "),
	)), nil, nil
}

// checkAuthAvailable verifies that authentication credentials are available
// without importing the keyring package at the tool handler level.
func checkAuthAvailable() error {
	_, err := keyring.GetCredentials()
	return err
}
