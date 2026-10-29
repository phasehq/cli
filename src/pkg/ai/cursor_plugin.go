package ai

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const CursorBootstrapPluginName = "phase-ai-bootstrap"

type cursorPluginManifest struct {
	Name        string             `json:"name"`
	Version     string             `json:"version"`
	Description string             `json:"description"`
	Author      cursorPluginAuthor `json:"author"`
	Hooks       string             `json:"hooks"`
}

type cursorPluginAuthor struct {
	Name string `json:"name"`
}

type cursorPluginMarker struct {
	Owner           string `json:"owner"`
	Plugin          string `json:"plugin"`
	AdapterProtocol string `json:"adapterProtocol,omitempty"`
}

type cursorHookFile struct {
	Version int                            `json:"version"`
	Hooks   map[string][]cursorHookHandler `json:"hooks"`
}

type cursorHookHandler struct {
	Type       string `json:"type,omitempty"`
	Command    string `json:"command"`
	Timeout    int    `json:"timeout,omitempty"`
	Matcher    string `json:"matcher,omitempty"`
	FailClosed bool   `json:"failClosed,omitempty"`
}

// DefaultCursorBootstrapPluginPath returns Cursor's official user-local plugin
// development path. Cursor loads the plugin after a window reload or restart.
func DefaultCursorBootstrapPluginPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".cursor", "plugins", "local", CursorBootstrapPluginName), nil
}

// InstallCursorBootstrapPlugin installs Phase's hook-only Cursor adapter. Its
// stable shared helper path does not depend on the interactive-shell PATH.
func InstallCursorBootstrapPlugin(root, phaseExecutable string) error {
	if root == "" {
		return errors.New("Cursor bootstrap plugin path is required")
	}
	if !filepath.IsAbs(phaseExecutable) {
		return errors.New("Phase executable path for the Cursor hook must be absolute")
	}
	if err := claimCursorBootstrapPlugin(root); err != nil {
		return err
	}

	manifestDirectory := filepath.Join(root, ".cursor-plugin")
	hooksDirectory := filepath.Join(root, "hooks")
	for _, directory := range []string{root, manifestDirectory, hooksDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("create Cursor bootstrap plugin directory %s: %w", directory, err)
		}
	}

	hookExecutable := phaseExecutable

	manifest := cursorPluginManifest{
		Name:        CursorBootstrapPluginName,
		Version:     HarnessAdapterProtocolVersion,
		Description: "Makes explicitly selected Phase-managed Connections available to Cursor.",
		Author:      cursorPluginAuthor{Name: "Phase"},
		Hooks:       "./hooks/hooks.json",
	}
	hooks := cursorHookFile{
		Version: 1,
		Hooks: map[string][]cursorHookHandler{
			"sessionStart": {{
				Type: "command", Command: cursorHookCommand(hookExecutable, "ai", "__cursor-hook"), Timeout: 45,
			}},
			// The guard prints nothing for ordinary commands by design, and Cursor
			// counts "no output" as a hook failure. With failClosed that failure
			// blocks every Shell call; fail open keeps ordinary work on Cursor's
			// normal approval flow. Explicit phase.invalid calls still receive an
			// explicit allow (with updated_input) or deny, which Cursor enforces
			// regardless of this setting.
			"preToolUse": {{
				Type: "command", Command: cursorHookCommand(hookExecutable, "ai", "__cursor-event", "guard"),
				Timeout: 45, Matcher: "Shell", FailClosed: false,
			}},
			"beforeSubmitPrompt": {{
				Type: "command", Command: cursorHookCommand(hookExecutable, "ai", "__cursor-event", "heartbeat"), Timeout: 3,
			}},
			"sessionEnd": {{
				Type: "command", Command: cursorHookCommand(hookExecutable, "ai", "__cursor-event", "session-end"), Timeout: 1,
			}},
		},
	}
	if err := writeJSONFile(filepath.Join(manifestDirectory, "plugin.json"), manifest, 0o600); err != nil {
		return fmt.Errorf("write Cursor bootstrap plugin manifest: %w", err)
	}
	if err := writeJSONFile(filepath.Join(hooksDirectory, "hooks.json"), hooks, 0o600); err != nil {
		return fmt.Errorf("write Cursor bootstrap hooks: %w", err)
	}
	if err := writeJSONFile(filepath.Join(root, ".phase-owned.json"), cursorPluginMarker{
		Owner: "phase-cli", Plugin: CursorBootstrapPluginName, AdapterProtocol: HarnessAdapterProtocolVersion,
	}, 0o600); err != nil {
		return fmt.Errorf("write Cursor bootstrap ownership marker: %w", err)
	}
	return nil
}

func cursorBootstrapExecutablePath(root string) string {
	name := "phase-hook"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(root, "bin", name)
}

func cursorHookCommand(executable string, args ...string) string {
	if runtime.GOOS == "windows" {
		return WindowsShellCommand(append([]string{executable}, args...))
	}
	command := quotePOSIXCommandArgument(executable)
	for _, arg := range args {
		command += " " + quotePOSIXCommandArgument(arg)
	}
	return command
}

// UninstallCursorBootstrapPlugin removes only Phase's canonical companion
// plugin. It refuses arbitrary directories, even when passed by a caller.
func UninstallCursorBootstrapPlugin(root string) error {
	if root == "" || filepath.Base(filepath.Clean(root)) != CursorBootstrapPluginName {
		return errors.New("refusing to remove an unexpected Cursor bootstrap plugin path")
	}
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect Cursor bootstrap plugin: %w", err)
	}
	if err := validateCursorBootstrapOwnership(root); err != nil {
		return err
	}
	paths := []string{
		filepath.Join(root, ".phase-owned.json"),
		filepath.Join(root, ".cursor-plugin", "plugin.json"),
		filepath.Join(root, "hooks", "hooks.json"),
		cursorBootstrapExecutablePath(root),
	}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove Cursor bootstrap file %s: %w", path, err)
		}
	}
	for _, directory := range []string{filepath.Join(root, ".cursor-plugin"), filepath.Join(root, "hooks"), filepath.Join(root, "bin"), root} {
		_ = os.Remove(directory)
	}
	return nil
}

func claimCursorBootstrapPlugin(root string) error {
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect Cursor bootstrap plugin: %w", err)
	}
	return validateCursorBootstrapOwnership(root)
}

func validateCursorBootstrapOwnership(root string) error {
	markerPayload, markerErr := os.ReadFile(filepath.Join(root, ".phase-owned.json"))
	if markerErr == nil {
		var marker cursorPluginMarker
		if json.Unmarshal(markerPayload, &marker) == nil && marker.Owner == "phase-cli" && marker.Plugin == CursorBootstrapPluginName &&
			(marker.AdapterProtocol == "" || marker.AdapterProtocol == HarnessAdapterProtocolVersion) {
			return nil
		}
		return errors.New("refusing to modify a Cursor plugin directory not owned by Phase")
	}
	if !errors.Is(markerErr, os.ErrNotExist) {
		return fmt.Errorf("read Cursor bootstrap ownership marker: %w", markerErr)
	}

	return errors.New("refusing to modify a Cursor plugin directory not owned by Phase")
}
