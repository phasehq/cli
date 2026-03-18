package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/phase"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
	"github.com/phasehq/golang-sdk/v2/phase/misc"
)

// Handlers holds shared state for MCP tool handlers.
type Handlers struct {
	Processes *ProcessManager
}

func NewHandlers() *Handlers {
	return &Handlers{
		Processes: NewProcessManager(),
	}
}

// newPhaseClient creates a Phase SDK client using keyring/config credentials.
func newPhaseClient() (*sdk.Phase, error) {
	return phase.NewPhase(true, "", "")
}

// resolveConfig fills in app/env/appID from .phase.json defaults.
func resolveConfig(appName, envName, appID string) (string, string, string) {
	return phase.GetConfig(appName, envName, appID)
}

// isMaskedType returns true if the given secret type should have its value hidden from the AI.
// Sealed secrets are ALWAYS masked. Secret-type values are masked when maskSecretAIValues is true.
func isMaskedType(secretType string, maskSecretValues bool) bool {
	if secretType == sdk.SecretTypeSealed {
		return true
	}
	if secretType == sdk.SecretTypeSecret && maskSecretValues {
		return true
	}
	return false
}

// getMaskConfig reads the maskSecretValues setting from ~/.phase/ai.json. Defaults to true.
func getMaskConfig() bool {
	cfg := config.LoadAIConfig()
	if cfg == nil {
		return true // default: mask secret values
	}
	return cfg.MaskSecretValues
}

var validRandomTypes = map[string]bool{
	"hex": true, "alphanumeric": true, "base64": true,
	"base64url": true, "key128": true, "key256": true,
}

// generateRandom generates a random secret value. Returns the value and any error.
func generateRandom(randomType string, length int) (string, error) {
	if !validRandomTypes[randomType] {
		return "", fmt.Errorf("unsupported random_type: %s. Supported: hex, alphanumeric, base64, base64url, key128, key256", randomType)
	}
	return misc.GenerateRandomSecret(randomType, length)
}

// --- phase_get_context ---

func (h *Handlers) HandleGetContext(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cfg := config.FindPhaseConfig(8)
	if cfg == nil {
		return mcp.NewToolResultText("Project is not linked to Phase. Use phase_init to link it."), nil
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return mcp.NewToolResultError("failed to read config"), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

// --- phase_init ---

func (h *Handlers) HandleInit(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	appID := request.GetString("app_id", "")
	envName := request.GetString("env_name", "")
	monorepo := request.GetBool("monorepo", false)

	p, err := newPhaseClient()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("auth error: %v", err)), nil
	}

	data, err := phase.Init(p)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to fetch apps: %v", err)), nil
	}

	if len(data.Apps) == 0 {
		return mcp.NewToolResultError("no applications found in your Phase account"), nil
	}

	// If no app_id provided, return numbered list of apps
	if appID == "" {
		var sb strings.Builder
		sb.WriteString("Available applications:\n")
		for i, app := range data.Apps {
			sb.WriteString(fmt.Sprintf("  %d. %s (id: %s)\n", i+1, app.Name, app.ID))
		}
		sb.WriteString("\nCall phase_init again with app_id and env_name to link this project.")
		return mcp.NewToolResultText(sb.String()), nil
	}

	// Find the selected app
	var selectedApp *misc.App
	for i := range data.Apps {
		if data.Apps[i].ID == appID || strings.EqualFold(data.Apps[i].Name, appID) {
			selectedApp = &data.Apps[i]
			break
		}
	}
	if selectedApp == nil {
		return mcp.NewToolResultError(fmt.Sprintf("app not found: %s", appID)), nil
	}

	// If no env_name provided, return numbered list of environments
	if envName == "" {
		envSortOrder := map[string]int{"DEV": 1, "STAGING": 2, "PROD": 3}
		type envEntry struct {
			idx  int
			sort int
		}
		entries := make([]envEntry, len(selectedApp.EnvironmentKeys))
		for i, ek := range selectedApp.EnvironmentKeys {
			order, ok := envSortOrder[ek.Environment.EnvType]
			if !ok {
				order = 4
			}
			entries[i] = envEntry{i, order}
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].sort < entries[j].sort
		})

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Environments for %s:\n", selectedApp.Name))
		for i, e := range entries {
			env := selectedApp.EnvironmentKeys[e.idx].Environment
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, env.Name))
		}
		sb.WriteString("\nCall phase_init again with app_id and env_name to complete the link.")
		return mcp.NewToolResultText(sb.String()), nil
	}

	// Find the environment
	var selectedEnvKey *misc.EnvironmentKey
	for i := range selectedApp.EnvironmentKeys {
		if strings.EqualFold(selectedApp.EnvironmentKeys[i].Environment.Name, envName) {
			selectedEnvKey = &selectedApp.EnvironmentKeys[i]
			break
		}
	}
	if selectedEnvKey == nil {
		return mcp.NewToolResultError(fmt.Sprintf("environment not found: %s", envName)), nil
	}

	// Write .phase.json
	cfg := &config.PhaseJSONConfig{
		Version:         "2",
		PhaseApp:        selectedApp.Name,
		AppID:           selectedApp.ID,
		DefaultEnv:      selectedEnvKey.Environment.Name,
		EnvID:           selectedEnvKey.Environment.ID,
		MonorepoSupport: monorepo,
	}
	if err := config.WritePhaseConfig(cfg); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to write .phase.json: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Linked project to %s / %s", selectedApp.Name, selectedEnvKey.Environment.Name)), nil
}

// --- phase_list_secrets ---

func (h *Handlers) HandleListSecrets(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	appName, envName, appID := resolveConfig(
		request.GetString("app", ""),
		request.GetString("env", ""),
		request.GetString("app_id", ""),
	)
	path := request.GetString("path", "") // empty = all paths, like `phase secrets list`

	p, err := newPhaseClient()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("auth error: %v", err)), nil
	}

	secrets, err := p.Get(sdk.GetOptions{
		EnvName: envName,
		AppName: appName,
		AppID:   appID,
		Path:    path,
		Raw:     true,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list secrets: %v", err)), nil
	}

	if len(secrets) == 0 {
		return mcp.NewToolResultText("No secrets found."), nil
	}

	type secretEntry struct {
		Key          string   `json:"key"`
		Value        string   `json:"value,omitempty"`
		Type         string   `json:"type"`
		Path         string   `json:"path"`
		Tags         []string `json:"tags,omitempty"`
		Comment      string   `json:"comment,omitempty"`
		Overridden bool `json:"overridden,omitempty"`
	}

	mask := getMaskConfig()
	entries := make([]secretEntry, len(secrets))
	for i, s := range secrets {
		e := secretEntry{
			Key:        s.Key,
			Type:       s.Type,
			Path:       s.Path,
			Overridden: s.Overridden,
		}
		// Include value only for types that aren't masked
		if !isMaskedType(s.Type, mask) {
			e.Value = s.Value
		}
		if len(s.Tags) > 0 {
			e.Tags = s.Tags
		}
		if s.Comment != "" {
			e.Comment = s.Comment
		}
		entries[i] = e
	}

	// Build response with context
	type listResponse struct {
		App         string        `json:"app"`
		Environment string        `json:"environment"`
		Path        string        `json:"path,omitempty"`
		Count       int           `json:"count"`
		Secrets     []secretEntry `json:"secrets"`
	}

	// Get app/env from the API response (authoritative), fall back to resolved config
	respApp := appName
	respEnv := envName
	if len(secrets) > 0 {
		if secrets[0].Application != "" {
			respApp = secrets[0].Application
		}
		if secrets[0].Environment != "" {
			respEnv = secrets[0].Environment
		}
	}

	resp := listResponse{
		App:         respApp,
		Environment: respEnv,
		Path:        path,
		Count:       len(entries),
		Secrets:     entries,
	}

	data, _ := json.MarshalIndent(resp, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// --- phase_get_secret ---

func (h *Handlers) HandleGetSecret(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	key, err := request.RequireString("key")
	if err != nil {
		return mcp.NewToolResultError("key is required"), nil
	}

	appName, envName, appID := resolveConfig(
		request.GetString("app", ""),
		request.GetString("env", ""),
		request.GetString("app_id", ""),
	)
	path := request.GetString("path", "/")

	p, err := newPhaseClient()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("auth error: %v", err)), nil
	}

	secrets, err := p.Get(sdk.GetOptions{
		EnvName: envName,
		AppName: appName,
		AppID:   appID,
		Keys:    []string{key},
		Path:    path,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to get secret: %v", err)), nil
	}

	if len(secrets) == 0 {
		return mcp.NewToolResultError(fmt.Sprintf("secret not found: %s", key)), nil
	}

	s := secrets[0]
	result := map[string]any{
		"key":         s.Key,
		"type":        s.Type,
		"path":        s.Path,
		"application": s.Application,
		"environment": s.Environment,
		"overridden":  s.Overridden,
	}

	// Include value only for types that aren't masked
	if !isMaskedType(s.Type, getMaskConfig()) {
		result["value"] = s.Value
	}

	if len(s.Tags) > 0 {
		result["tags"] = s.Tags
	}
	if s.Comment != "" {
		result["comment"] = s.Comment
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// --- phase_create_secrets ---

func (h *Handlers) HandleCreateSecrets(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	secretsRaw := request.GetArguments()["secrets"]
	secretsList, ok := secretsRaw.([]any)
	if !ok || len(secretsList) == 0 {
		return mcp.NewToolResultError("secrets array is required"), nil
	}

	secretType := request.GetString("type", "")
	if err := sdk.ValidateSecretType(secretType); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	isSealed := secretType == sdk.SecretTypeSealed

	appName, envName, appID := resolveConfig(
		request.GetString("app", ""),
		request.GetString("env", ""),
		request.GetString("app_id", ""),
	)
	path := request.GetString("path", "/")

	var pairs []sdk.KeyValuePair
	var created []string

	for _, raw := range secretsList {
		entry, ok := raw.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("each secret must be an object with at least a 'key' field"), nil
		}

		key, _ := entry["key"].(string)
		if key == "" {
			return mcp.NewToolResultError("each secret must have a 'key'"), nil
		}
		key = strings.ToUpper(strings.ReplaceAll(key, " ", "_"))

		value, _ := entry["value"].(string)
		randomType, _ := entry["random_type"].(string)

		// Sealed secrets MUST use random generation — AI must never set literal values
		if isSealed && randomType == "" {
			return mcp.NewToolResultError(fmt.Sprintf("sealed secrets must use random_type for secure generation. Cannot set a literal value for sealed secret %s.", key)), nil
		}

		if randomType != "" {
			length := 32
			if l, ok := entry["length"].(float64); ok && l > 0 {
				length = int(l)
			}
			generated, err := generateRandom(randomType, length)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("failed to generate random value for %s: %v", key, err)), nil
			}
			value = generated
		}

		pairs = append(pairs, sdk.KeyValuePair{Key: key, Value: value})
		created = append(created, key)
	}

	p, err := newPhaseClient()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("auth error: %v", err)), nil
	}

	err = p.Create(sdk.CreateOptions{
		KeyValuePairs: pairs,
		EnvName:       envName,
		AppName:       appName,
		AppID:         appID,
		Path:          path,
		Type:          secretType,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create secrets: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Created %d secret(s): %s", len(created), strings.Join(created, ", "))), nil
}

// --- phase_update_secret ---

func (h *Handlers) HandleUpdateSecret(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	key, err := request.RequireString("key")
	if err != nil {
		return mcp.NewToolResultError("key is required"), nil
	}

	value := request.GetString("value", "")
	randomType := request.GetString("random_type", "")
	randomLength := request.GetInt("length", 32)
	secretType := request.GetString("type", "")
	destPath := request.GetString("dest_path", "")

	if secretType != "" {
		if err := sdk.ValidateSecretType(secretType); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
	}

	appName, envName, appID := resolveConfig(
		request.GetString("app", ""),
		request.GetString("env", ""),
		request.GetString("app_id", ""),
	)
	path := request.GetString("path", "/")

	// If updating to sealed type (or updating an existing sealed secret), enforce random generation.
	// First check if the target type is sealed. If type isn't being changed, look up the existing secret.
	effectiveType := secretType
	if effectiveType == "" {
		p, err := newPhaseClient()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("auth error: %v", err)), nil
		}
		existing, err := p.Get(sdk.GetOptions{
			EnvName: envName, AppName: appName, AppID: appID,
			Keys: []string{key}, Path: path,
		})
		if err == nil && len(existing) > 0 {
			effectiveType = existing[0].Type
		}
	}

	if effectiveType == sdk.SecretTypeSealed {
		// Sealed secrets cannot have literal values set by the AI
		if value != "" && randomType == "" {
			return mcp.NewToolResultError("sealed secrets must use random_type for secure value generation. Cannot set a literal value for sealed secrets."), nil
		}
		// Allow type-only change (value="" + randomType="") — SDK preserves existing value
	}

	// Generate random value if requested
	if randomType != "" {
		generated, err := generateRandom(randomType, randomLength)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		value = generated
	}

	p, err := newPhaseClient()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("auth error: %v", err)), nil
	}

	err = p.Update(sdk.UpdateOptions{
		EnvName:         envName,
		AppName:         appName,
		AppID:           appID,
		Key:             key,
		Value:           value,
		SourcePath:      path,
		DestinationPath: destPath,
		Type:            secretType,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to update secret: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Updated secret: %s", key)), nil
}

// --- phase_delete_secrets ---

func (h *Handlers) HandleDeleteSecrets(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	keysRaw := request.GetArguments()["keys"]
	keysArr, ok := keysRaw.([]any)
	if !ok || len(keysArr) == 0 {
		return mcp.NewToolResultError("keys array is required"), nil
	}

	var keys []string
	for _, k := range keysArr {
		if s, ok := k.(string); ok {
			keys = append(keys, s)
		}
	}

	appName, envName, appID := resolveConfig(
		request.GetString("app", ""),
		request.GetString("env", ""),
		request.GetString("app_id", ""),
	)
	path := request.GetString("path", "/")

	p, err := newPhaseClient()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("auth error: %v", err)), nil
	}

	notFound, err := p.Delete(sdk.DeleteOptions{
		EnvName:      envName,
		AppName:      appName,
		AppID:        appID,
		KeysToDelete: keys,
		Path:         path,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to delete secrets: %v", err)), nil
	}

	if len(notFound) > 0 {
		return mcp.NewToolResultText(fmt.Sprintf("Deleted %d secret(s). Keys not found: %s",
			len(keys)-len(notFound), strings.Join(notFound, ", "))), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Deleted %d secret(s): %s", len(keys), strings.Join(keys, ", "))), nil
}

// --- phase_run ---

// blockedRunCommands are commands that would dump secrets injected into the environment.
var blockedRunCommands = []string{"printenv", "env", "export", "set"}

// isBlockedCommand checks whether the command string contains any blocked command
// as a standalone word (handles pipes, subshells, &&, ||, ;, etc.)
func isBlockedCommand(command string) (string, bool) {
	// Split on shell metacharacters to get individual command segments
	fields := strings.FieldsFunc(command, func(r rune) bool {
		return r == '|' || r == ';' || r == '&' || r == '(' || r == ')' || r == '`' || r == '\n'
	})
	for _, field := range fields {
		parts := strings.Fields(strings.TrimSpace(field))
		if len(parts) == 0 {
			continue
		}
		cmd := filepath.Base(parts[0]) // handle /usr/bin/env etc.
		for _, blocked := range blockedRunCommands {
			if cmd == blocked {
				return blocked, true
			}
		}
	}
	return "", false
}

func (h *Handlers) HandleRun(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command, err := request.RequireString("command")
	if err != nil {
		return mcp.NewToolResultError("command is required"), nil
	}

	if blocked, ok := isBlockedCommand(command); ok {
		return mcp.NewToolResultError(fmt.Sprintf("refused: '%s' would expose injected secrets. Use phase_get_secret or phase_list_secrets instead.", blocked)), nil
	}

	appName, envName, appID := resolveConfig(
		request.GetString("app", ""),
		request.GetString("env", ""),
		request.GetString("app_id", ""),
	)
	path := request.GetString("path", "/")

	p, err := newPhaseClient()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("auth error: %v", err)), nil
	}

	secrets, err := p.Get(sdk.GetOptions{
		EnvName: envName,
		AppName: appName,
		AppID:   appID,
		Path:    path,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to fetch secrets: %v", err)), nil
	}

	env := make(map[string]string, len(secrets))
	for _, s := range secrets {
		env[s.Key] = s.Value
	}

	handle, mp, err := h.Processes.Start(command, env)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to start process: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Started process.\n  Handle: %d\n  PID: %d\n  Command: %s\n  Secrets injected: %d",
		handle, mp.PID, command, len(secrets))), nil
}

// --- phase_stop ---

func (h *Handlers) HandleStop(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	handle := request.GetInt("handle", 0)
	if handle == 0 {
		return mcp.NewToolResultError("handle is required"), nil
	}

	mp, ok := h.Processes.Get(handle)
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("no process with handle %d", handle)), nil
	}

	err := h.Processes.Stop(handle)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to stop process: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Stopped process (handle: %d, command: %q, exit code: %d)",
		handle, mp.Command, mp.ExitCode)), nil
}

// --- phase_run_logs ---

func (h *Handlers) HandleRunLogs(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	handle := request.GetInt("handle", 0)
	if handle == 0 {
		return mcp.NewToolResultError("handle is required"), nil
	}

	lines := request.GetInt("lines", 50)

	mp, ok := h.Processes.Get(handle)
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("no process with handle %d", handle)), nil
	}

	status := "running"
	if !h.Processes.IsRunning(mp) {
		status = fmt.Sprintf("exited (code %d)", mp.ExitCode)
	}

	logLines := mp.LogBuffer.Lines(lines)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Process %d (%s) — %s\n", handle, mp.Command, status))
	sb.WriteString(fmt.Sprintf("--- last %d lines ---\n", len(logLines)))
	for _, line := range logLines {
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return mcp.NewToolResultText(sb.String()), nil
}
