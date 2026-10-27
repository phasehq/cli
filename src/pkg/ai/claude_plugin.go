package ai

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const ClaudeBootstrapPluginName = "phase-ai-bootstrap"

type claudePluginManifest struct {
	Schema      string             `json:"$schema,omitempty"`
	Name        string             `json:"name"`
	Version     string             `json:"version"`
	Description string             `json:"description"`
	Author      claudePluginAuthor `json:"author"`
}

type claudePluginAuthor struct {
	Name string `json:"name"`
}

type claudeHookFile struct {
	Description string                         `json:"description,omitempty"`
	Hooks       map[string][]claudeHookMatcher `json:"hooks"`
}

type claudeHookMatcher struct {
	Matcher string              `json:"matcher,omitempty"`
	Hooks   []claudeHookHandler `json:"hooks"`
}

type claudeHookHandler struct {
	Type          string   `json:"type"`
	Command       string   `json:"command"`
	Args          []string `json:"args"`
	Timeout       int      `json:"timeout"`
	StatusMessage string   `json:"statusMessage,omitempty"`
}

// DefaultClaudeBootstrapPluginPath returns Claude's auto-loaded, user-scoped
// skills-directory plugin path. The existing phase-cli-ai-relay skill stays standalone;
// this companion plugin owns only the lifecycle hook.
func DefaultClaudeBootstrapPluginPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".claude", "skills", ClaudeBootstrapPluginName), nil
}

// InstallClaudeBootstrapPlugin installs a hook-only Claude adapter. Exec form
// avoids shell parsing and launches the stable shared v1 helper even when
// Claude Desktop's PATH differs from the user's interactive shell.
func InstallClaudeBootstrapPlugin(root, phaseExecutable string) error {
	if root == "" {
		return errors.New("Claude bootstrap plugin path is required")
	}
	if !filepath.IsAbs(phaseExecutable) {
		return errors.New("Phase executable path for the Claude hook must be absolute")
	}
	manifestDirectory := filepath.Join(root, ".claude-plugin")
	hooksDirectory := filepath.Join(root, "hooks")
	for _, directory := range []string{root, manifestDirectory, hooksDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("create Claude bootstrap plugin directory %s: %w", directory, err)
		}
	}
	hookExecutable := phaseExecutable

	manifest := claudePluginManifest{
		Schema: "https://json.schemastore.org/claude-code-plugin-manifest.json",
		Name:   ClaudeBootstrapPluginName, Version: HarnessAdapterProtocolVersion,
		Description: "Gives Claude's shell the Phase AI environment while the Phase proxy is running.",
		Author:      claudePluginAuthor{Name: "Phase"},
	}
	hooks := claudeHookFile{
		Description: "Source the Phase AI environment before each shell command; fail open to ambient tools when the proxy is unavailable.",
		Hooks: map[string][]claudeHookMatcher{
			"SessionStart": {{
				Matcher: "startup|resume|clear|compact|fork",
				Hooks: []claudeHookHandler{{
					Type: "command", Command: hookExecutable,
					Args: []string{"ai", "__claude-hook"}, Timeout: 45,
					StatusMessage: "Preparing Phase AI",
				}},
			}},
			"UserPromptSubmit": {{
				Hooks: []claudeHookHandler{{
					Type: "command", Command: hookExecutable,
					Args: []string{"ai", "__claude-event", "heartbeat"}, Timeout: 3,
				}},
			}},
			"SessionEnd": {{
				Hooks: []claudeHookHandler{{
					Type: "command", Command: hookExecutable,
					Args: []string{"ai", "__claude-event", "session-end"}, Timeout: 1,
				}},
			}},
		},
	}
	if err := writeJSONFile(filepath.Join(manifestDirectory, "plugin.json"), manifest, 0o600); err != nil {
		return fmt.Errorf("write Claude bootstrap plugin manifest: %w", err)
	}
	if err := writeJSONFile(filepath.Join(hooksDirectory, "hooks.json"), hooks, 0o600); err != nil {
		return fmt.Errorf("write Claude bootstrap hooks: %w", err)
	}
	return nil
}

func copyClaudeHookExecutable(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<20 {
		return errors.New("Phase executable must be a bounded regular file")
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".phase-hook-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o700); err != nil {
		_ = temporary.Close()
		return err
	}
	if written, err := io.CopyN(temporary, input, info.Size()+1); err != nil && !errors.Is(err, io.EOF) {
		_ = temporary.Close()
		return err
	} else if written != info.Size() {
		_ = temporary.Close()
		return errors.New("Phase executable changed while being copied")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	if err := os.Chmod(destination, 0o700); err != nil {
		return err
	}
	// Dirty development builds include executable mtime and size in their
	// runtime identity. Preserve the source mtime so the stable shared copy has
	// the same runtime fingerprint as the current Phase executable. Go does
	// not expose a portable source atime; using the same stable timestamp for
	// both fields is supported by os.Chtimes on Unix and Windows.
	return os.Chtimes(destination, info.ModTime(), info.ModTime())
}

// UninstallClaudeBootstrapPlugin removes only the Phase-owned companion
// plugin. It refuses arbitrary paths even if ai.json was manually edited.
func UninstallClaudeBootstrapPlugin(root string) error {
	if root == "" || filepath.Base(filepath.Clean(root)) != ClaudeBootstrapPluginName {
		return errors.New("refusing to remove an unexpected Claude bootstrap plugin path")
	}
	manifestPath := filepath.Join(root, ".claude-plugin", "plugin.json")
	payload, err := os.ReadFile(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Claude bootstrap plugin manifest: %w", err)
	}
	var manifest claudePluginManifest
	if err := json.Unmarshal(payload, &manifest); err != nil || manifest.Name != ClaudeBootstrapPluginName {
		return errors.New("refusing to remove a Claude plugin not owned by Phase")
	}
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("remove Claude bootstrap plugin: %w", err)
	}
	return nil
}

// jsonFilePayload is exactly what writeJSONFile writes for value.
func jsonFilePayload(value any) ([]byte, error) {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func writeJSONFile(path string, value any, mode os.FileMode) error {
	payload, err := jsonFilePayload(value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".phase-plugin-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
