package ai

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type DevinHooksInstall struct {
	ConfigPath      string
	ExecutablePath  string
	AdapterProtocol string
}

type devinHookGroup struct {
	Matcher string             `json:"matcher,omitempty"`
	Hooks   []devinHookHandler `json:"hooks"`
}

type devinHookHandler struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

func DefaultDevinConfigPath() (string, error) {
	if runtime.GOOS == "windows" {
		configDirectory, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("resolve user config directory: %w", err)
		}
		return filepath.Join(configDirectory, "devin", "config.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".config", "devin", "config.json"), nil
}

func InstallDevinHooks(configPath, phaseExecutable string) (DevinHooksInstall, error) {
	installation := DevinHooksInstall{
		ConfigPath: configPath, ExecutablePath: phaseExecutable, AdapterProtocol: HarnessAdapterProtocolVersion,
	}
	if configPath == "" {
		return installation, errors.New("Devin config path is required")
	}
	if !filepath.IsAbs(phaseExecutable) {
		return installation, errors.New("Phase executable path for Devin must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return installation, fmt.Errorf("create Devin config directory: %w", err)
	}
	helperPath := phaseExecutable
	root, hooks, err := readDevinConfig(configPath)
	if err != nil {
		return installation, err
	}
	removePhaseDevinGroups(hooks, windowsExecutableForms(helperPath)...)
	for event, groups := range phaseDevinHooks(helperPath) {
		for _, group := range groups {
			payload, err := json.Marshal(group)
			if err != nil {
				return installation, err
			}
			hooks[event] = append(hooks[event], payload)
		}
	}
	hooksPayload, err := json.Marshal(hooks)
	if err != nil {
		return installation, err
	}
	root["hooks"] = hooksPayload
	if err := writeJSONFile(configPath, root, 0o600); err != nil {
		return installation, fmt.Errorf("write Devin config: %w", err)
	}
	return installation, nil
}

func UninstallDevinHooks(configPath string) error {
	if configPath == "" {
		return errors.New("Devin config path is required")
	}
	helperPath, err := DefaultSharedHookExecutablePath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect Devin config: %w", err)
	}
	root, hooks, err := readDevinConfig(configPath)
	if err != nil {
		return err
	}
	removePhaseDevinGroups(hooks, windowsExecutableForms(helperPath)...)
	hooksPayload, err := json.Marshal(hooks)
	if err != nil {
		return err
	}
	root["hooks"] = hooksPayload
	if err := writeJSONFile(configPath, root, 0o600); err != nil {
		return fmt.Errorf("write Devin config: %w", err)
	}
	return nil
}

func readDevinConfig(path string) (map[string]json.RawMessage, map[string][]json.RawMessage, error) {
	root := make(map[string]json.RawMessage)
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return root, make(map[string][]json.RawMessage), nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read Devin config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&root); err != nil {
		return nil, nil, fmt.Errorf("parse Devin config: %w", err)
	}
	hooks := make(map[string][]json.RawMessage)
	if raw := root["hooks"]; len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &hooks); err != nil {
			return nil, nil, fmt.Errorf("parse Devin hooks: %w", err)
		}
	}
	return root, hooks, nil
}

func phaseDevinHooks(helperPath string) map[string][]devinHookGroup {
	command := func(action ...string) devinHookHandler {
		arguments := append([]string{helperPath, "ai"}, action...)
		return devinHookHandler{Type: "command", Command: shellCommand(arguments), Timeout: 8}
	}
	start := command("__devin-hook")
	start.Timeout = 45
	end := command("__devin-event", "session-end")
	end.Timeout = 1
	guard := command("__devin-event", "guard")
	guard.Timeout = 45
	heartbeat := command("__devin-event", "heartbeat")
	heartbeat.Timeout = 45
	return map[string][]devinHookGroup{
		"SessionStart":     {{Hooks: []devinHookHandler{start}}},
		"PreToolUse":       {{Matcher: "exec", Hooks: []devinHookHandler{guard}}},
		"UserPromptSubmit": {{Hooks: []devinHookHandler{heartbeat}}},
		"PostCompaction":   {{Hooks: []devinHookHandler{command("__devin-event", "context")}}},
		"SessionEnd":       {{Hooks: []devinHookHandler{end}}},
	}
}

func shellCommand(arguments []string) string {
	if runtime.GOOS == "windows" {
		return WindowsShellCommand(arguments)
	}
	quoted := make([]string, len(arguments))
	for index, argument := range arguments {
		quoted[index] = quotePOSIXCommandArgument(argument)
	}
	return strings.Join(quoted, " ")
}

func removePhaseDevinGroups(hooks map[string][]json.RawMessage, helperPaths ...string) {
	for event, groups := range hooks {
		kept := groups[:0]
		for _, raw := range groups {
			if group, changed := withoutPhaseDevinHandlers(raw, helperPaths); !changed {
				kept = append(kept, raw)
			} else if group != nil {
				kept = append(kept, group)
			}
		}
		hooks[event] = kept
	}
}

// withoutPhaseDevinHandlers drops Phase's handlers from a group and keeps the
// rest of it as written. It returns nil when no handler is left.
func withoutPhaseDevinHandlers(raw json.RawMessage, helperPaths []string) (json.RawMessage, bool) {
	var group map[string]json.RawMessage
	var handlers []json.RawMessage
	if json.Unmarshal(raw, &group) != nil || json.Unmarshal(group["hooks"], &handlers) != nil {
		return raw, false
	}
	kept := handlers[:0]
	for _, handler := range handlers {
		var parsed devinHookHandler
		if json.Unmarshal(handler, &parsed) != nil || !isPhaseDevinCommand(parsed.Command, helperPaths) {
			kept = append(kept, handler)
		}
	}
	if len(kept) == len(handlers) {
		return raw, false
	}
	if len(kept) == 0 {
		return nil, true
	}
	payload, err := json.Marshal(kept)
	if err != nil {
		return raw, false
	}
	group["hooks"] = payload
	if payload, err = json.Marshal(group); err != nil {
		return raw, false
	}
	return payload, true
}

func isPhaseDevinCommand(command string, helperPaths []string) bool {
	for _, helperPath := range helperPaths {
		if strings.Contains(command, helperPath) && strings.Contains(command, "__devin-") {
			return true
		}
	}
	return false
}
