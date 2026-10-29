package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallDevinHooksPreservesConfigAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, ".config", "devin", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	existing := `{"model":"test-model","hooks":{"PreToolUse":[{"matcher":"read","hooks":[{"type":"command","command":"keep-me"}]}]}}`
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(home, "phase")
	if err := os.WriteFile(executable, []byte("first"), 0o700); err != nil {
		t.Fatal(err)
	}
	shared, err := InstallSharedHookExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	installation, err := InstallDevinHooks(configPath, shared.ExecutablePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InstallDevinHooks(configPath, shared.ExecutablePath); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(payload, &root); err != nil {
		t.Fatal(err)
	}
	if string(root["model"]) != `"test-model"` || !strings.Contains(string(root["hooks"]), "keep-me") {
		t.Fatalf("existing Devin config was not preserved: %s", payload)
	}
	if got := strings.Count(string(root["hooks"]), "__devin-event"); got != 4 {
		t.Fatalf("Phase Devin hooks duplicated or missing, event command count=%d: %s", got, root["hooks"])
	}
	if data, err := os.ReadFile(installation.ExecutablePath); err != nil || string(data) != "first" {
		t.Fatalf("unexpected Devin helper: %q, %v", data, err)
	}
	if installation.AdapterProtocol != HarnessAdapterProtocolVersion {
		t.Fatalf("unexpected Devin adapter protocol: %#v", installation)
	}
}

func TestUninstallDevinHooksPreservesUnrelatedHooks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, ".config", "devin", "config.json")
	executable := filepath.Join(home, "phase")
	if err := os.WriteFile(executable, []byte("phase"), 0o700); err != nil {
		t.Fatal(err)
	}
	shared, err := InstallSharedHookExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InstallDevinHooks(configPath, shared.ExecutablePath); err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	payload, _ := os.ReadFile(configPath)
	if err := json.Unmarshal(payload, &root); err != nil {
		t.Fatal(err)
	}
	var hooks map[string][]json.RawMessage
	if err := json.Unmarshal(root["hooks"], &hooks); err != nil {
		t.Fatal(err)
	}
	hooks["PreToolUse"] = append(hooks["PreToolUse"], json.RawMessage(`{"matcher":"read","hooks":[{"type":"command","command":"keep-me"}]}`))
	root["hooks"], _ = json.Marshal(hooks)
	if err := writeJSONFile(configPath, root, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := UninstallDevinHooks(configPath); err != nil {
		t.Fatal(err)
	}
	payload, _ = os.ReadFile(configPath)
	if strings.Contains(string(payload), "__devin-") || !strings.Contains(string(payload), "keep-me") {
		t.Fatalf("Devin uninstall removed unrelated hooks or retained Phase hooks: %s", payload)
	}
}

func TestDevinRefreshKeepsUserHandlersInPhaseGroups(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, ".config", "devin", "config.json")
	executable := filepath.Join(home, "phase")
	if err := os.WriteFile(executable, []byte("phase"), 0o700); err != nil {
		t.Fatal(err)
	}
	shared, err := InstallSharedHookExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InstallDevinHooks(configPath, shared.ExecutablePath); err != nil {
		t.Fatal(err)
	}
	payload, _ := os.ReadFile(configPath)
	var root map[string]json.RawMessage
	var hooks map[string][]map[string]any
	if err := json.Unmarshal(payload, &root); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(root["hooks"], &hooks); err != nil {
		t.Fatal(err)
	}
	group := hooks["PreToolUse"][0]
	group["hooks"] = append(group["hooks"].([]any), map[string]any{"type": "command", "command": "user-security-check"})
	group["description"] = "user field"
	root["hooks"], _ = json.Marshal(hooks)
	if err := writeJSONFile(configPath, root, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := InstallDevinHooks(configPath, shared.ExecutablePath); err != nil {
		t.Fatal(err)
	}
	payload, _ = os.ReadFile(configPath)
	guard := phaseDevinHooks(shared.ExecutablePath)["PreToolUse"][0].Hooks[0].Command
	if !strings.Contains(string(payload), "user-security-check") || !strings.Contains(string(payload), "user field") ||
		devinHandlerCount(t, payload, guard) != 1 {
		t.Fatalf("refresh dropped the user handler or duplicated the guard: %s", payload)
	}
	if err := UninstallDevinHooks(configPath); err != nil {
		t.Fatal(err)
	}
	payload, _ = os.ReadFile(configPath)
	if err := json.Unmarshal(payload, &root); err != nil {
		t.Fatal(err)
	}
	hooks = nil
	if err := json.Unmarshal(root["hooks"], &hooks); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "__devin-") || len(hooks["PreToolUse"]) != 1 || len(hooks["SessionStart"]) != 0 ||
		hooks["PreToolUse"][0]["matcher"] != "exec" || hooks["PreToolUse"][0]["description"] != "user field" ||
		len(hooks["PreToolUse"][0]["hooks"].([]any)) != 1 {
		t.Fatalf("uninstall must drop only Phase handlers and their emptied groups: %s", payload)
	}
}

func devinHandlerCount(t *testing.T, payload []byte, command string) int {
	t.Helper()
	var config struct {
		Hooks map[string][]devinHookGroup `json:"hooks"`
	}
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, groups := range config.Hooks {
		for _, group := range groups {
			for _, handler := range group.Hooks {
				if handler.Command == command {
					count++
				}
			}
		}
	}
	return count
}

func TestDevinCleanupMatchesAQuotedHelperPath(t *testing.T) {
	home := filepath.Join(t.TempDir(), "O'Brien")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, ".config", "devin", "config.json")
	executable := filepath.Join(home, "phase")
	if err := os.WriteFile(executable, []byte("phase"), 0o700); err != nil {
		t.Fatal(err)
	}
	shared, err := InstallSharedHookExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := InstallDevinHooks(configPath, shared.ExecutablePath); err != nil {
			t.Fatal(err)
		}
	}
	payload, _ := os.ReadFile(configPath)
	if got := strings.Count(string(payload), "__devin-hook"); got != 1 {
		t.Fatalf("reinstall left %d SessionStart hooks: %s", got, payload)
	}
	if err := UninstallDevinHooks(configPath); err != nil {
		t.Fatal(err)
	}
	if payload, _ = os.ReadFile(configPath); strings.Contains(string(payload), "__devin-") {
		t.Fatalf("uninstall left Phase hooks behind: %s", payload)
	}
}
