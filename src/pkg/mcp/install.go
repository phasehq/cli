package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type clientConfig struct {
	UserConfigPath    string
	ProjectConfigPath string
	JSONKey           string
	ServerConfig      map[string]interface{}
}

var supportedClients = map[string]clientConfig{
	"claude-code": {
		UserConfigPath:    filepath.Join(homeDir(), ".claude.json"),
		ProjectConfigPath: ".mcp.json",
		JSONKey:           "mcpServers",
		ServerConfig: map[string]interface{}{
			"command": "phase",
			"args":    []interface{}{"mcp", "serve"},
		},
	},
	"cursor": {
		UserConfigPath:    filepath.Join(homeDir(), ".cursor", "mcp.json"),
		ProjectConfigPath: filepath.Join(".cursor", "mcp.json"),
		JSONKey:           "mcpServers",
		ServerConfig: map[string]interface{}{
			"command": "phase",
			"args":    []interface{}{"mcp", "serve"},
		},
	},
	"vscode": {
		UserConfigPath:    filepath.Join(homeDir(), ".vscode", "mcp.json"),
		ProjectConfigPath: filepath.Join(".vscode", "mcp.json"),
		JSONKey:           "servers",
		ServerConfig: map[string]interface{}{
			"type":    "stdio",
			"command": "phase",
			"args":    []interface{}{"mcp", "serve"},
		},
	},
	"zed": {
		UserConfigPath:    filepath.Join(zedConfigDir(), "settings.json"),
		ProjectConfigPath: filepath.Join(".zed", "settings.json"),
		JSONKey:           "context_servers",
		ServerConfig: map[string]interface{}{
			"command": "phase",
			"args":    []interface{}{"mcp", "serve"},
		},
	},
	"opencode": {
		UserConfigPath:    filepath.Join(opencodeConfigDir(), "opencode.json"),
		ProjectConfigPath: "opencode.json",
		JSONKey:           "mcp",
		ServerConfig: map[string]interface{}{
			"type":    "local",
			"command": []interface{}{"phase", "mcp", "serve"},
			"enabled": true,
		},
	},
}

func homeDir() string {
	home, _ := os.UserHomeDir()
	return home
}

func zedConfigDir() string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(homeDir(), ".config", "zed")
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "zed")
	}
	return filepath.Join(homeDir(), ".config", "zed")
}

func opencodeConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "opencode")
	}
	return filepath.Join(homeDir(), ".config", "opencode")
}

// SupportedClientNames returns the list of supported client names.
func SupportedClientNames() []string {
	return []string{"claude-code", "cursor", "vscode", "zed", "opencode"}
}

// DetectInstalledClients checks which AI client config directories exist.
func DetectInstalledClients() []string {
	var detected []string
	checks := map[string][]string{
		"claude-code": {filepath.Join(homeDir(), ".claude")},
		"cursor":      {filepath.Join(homeDir(), ".cursor")},
		"vscode":      {filepath.Join(homeDir(), ".vscode")},
		"zed":         {zedConfigDir()},
		"opencode":    {opencodeConfigDir()},
	}
	for name, paths := range checks {
		for _, p := range paths {
			if info, err := os.Stat(p); err == nil && info.IsDir() {
				detected = append(detected, name)
				break
			}
		}
	}
	return detected
}

// Install adds Phase MCP server config for the specified client (or all detected clients).
func Install(client, scope string) error {
	if client != "" {
		return InstallForClient(client, scope)
	}

	detected := DetectInstalledClients()
	if len(detected) == 0 {
		return fmt.Errorf("no supported AI clients detected. Supported clients: %s", strings.Join(SupportedClientNames(), ", "))
	}

	var errors []string
	for _, c := range detected {
		if err := InstallForClient(c, scope); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", c, err))
		} else {
			fmt.Fprintf(os.Stderr, "Installed Phase MCP server for %s\n", c)
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("some installations failed:\n%s", strings.Join(errors, "\n"))
	}
	return nil
}

// Uninstall removes Phase MCP server config from the specified client (or all).
func Uninstall(client string) error {
	if client != "" {
		return UninstallForClient(client)
	}

	var errors []string
	for _, name := range SupportedClientNames() {
		if err := UninstallForClient(name); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("some uninstalls failed:\n%s", strings.Join(errors, "\n"))
	}
	return nil
}

// InstallForClient adds Phase MCP server to a specific client's config.
func InstallForClient(client, scope string) error {
	cfg, ok := supportedClients[client]
	if !ok {
		return fmt.Errorf("unsupported client: %s. Supported: %s", client, strings.Join(SupportedClientNames(), ", "))
	}

	var configPath string
	switch scope {
	case "project":
		configPath = cfg.ProjectConfigPath
	default:
		configPath = cfg.UserConfigPath
	}

	return addToConfig(configPath, cfg.JSONKey, cfg.ServerConfig)
}

// UninstallForClient removes Phase MCP server from a specific client's config (both scopes).
func UninstallForClient(client string) error {
	cfg, ok := supportedClients[client]
	if !ok {
		return fmt.Errorf("unsupported client: %s. Supported: %s", client, strings.Join(SupportedClientNames(), ", "))
	}

	var errors []string
	for _, path := range []string{cfg.UserConfigPath, cfg.ProjectConfigPath} {
		if err := removeFromConfig(path, cfg.JSONKey); err != nil {
			if !os.IsNotExist(err) {
				errors = append(errors, err.Error())
			}
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return nil
}

func addToConfig(configPath, jsonKey string, serverConfig map[string]interface{}) error {
	// Create parent directories
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Read existing config or start with empty object
	config := map[string]interface{}{}
	data, err := os.ReadFile(configPath)
	if err == nil {
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse %s: %w", configPath, err)
		}
	}

	// Get or create the servers section
	servers, ok := config[jsonKey].(map[string]interface{})
	if !ok {
		servers = map[string]interface{}{}
	}

	// Add/update phase entry
	servers["phase"] = serverConfig
	config[jsonKey] = servers

	// Write back
	out, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(configPath, out, 0600)
}

func removeFromConfig(configPath, jsonKey string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	config := map[string]interface{}{}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse %s: %w", configPath, err)
	}

	servers, ok := config[jsonKey].(map[string]interface{})
	if !ok {
		return nil // Nothing to remove
	}

	if _, exists := servers["phase"]; !exists {
		return nil // Already removed
	}

	delete(servers, "phase")
	config[jsonKey] = servers

	out, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(configPath, out, 0600)
}
