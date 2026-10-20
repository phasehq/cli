package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func overrideAIConfigPath(t *testing.T, path string) {
	t.Helper()
	original := AIConfigPath
	AIConfigPath = path
	t.Cleanup(func() { AIConfigPath = original })
}

func TestLoadAIConfigMigratesLegacyVisibilityConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.json")
	overrideAIConfigPath(t, path)
	if err := os.WriteFile(path, []byte(`{"version":"1","maskSecretValues":false}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := LoadAIConfig()
	if cfg == nil {
		t.Fatal("expected migrated config")
	}
	if cfg.Version != AIConfigVersion || !cfg.Enabled || cfg.ProxyMode != AIProxyModeLocal || cfg.MaskSecretValues {
		t.Fatalf("unexpected migrated config: %+v", cfg)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == `{"version":"1","maskSecretValues":false}` {
		t.Fatal("legacy AI config was not persisted as the current version")
	}
}

func TestAIConfigWithNoHarnessesFailsClosed(t *testing.T) {
	cfg := &AIConfig{Enabled: true, ProxyMode: AIProxyModeLocal}
	if cfg.HarnessEnabled("codex") {
		t.Fatal("empty v3 harness list authorized an automatic integration")
	}
}

func TestSaveAIConfigWritesV3And0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".phase", "ai.json")
	overrideAIConfigPath(t, path)
	skillPath := filepath.Join(t.TempDir(), "skills", "phase-cli", "SKILL.md")
	cfg := &AIConfig{Enabled: true, ProxyMode: AIProxyModeLocal, MaskSecretValues: true, DefaultWorkflowID: "workflow-123", SkillInstallPath: skillPath, HarnessID: "codex"}
	if err := SaveAIConfig(cfg); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	var raw map[string]any
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["version"] != AIConfigVersion || raw["enabled"] != true || raw["proxyMode"] != AIProxyModeLocal {
		t.Fatalf("unexpected persisted config: %s", data)
	}
	if raw["skillInstallPath"] != skillPath {
		t.Fatalf("skillInstallPath = %v, want %q", raw["skillInstallPath"], skillPath)
	}
	if raw["harnessId"] != "codex" {
		t.Fatalf("harnessId = %v, want codex", raw["harnessId"])
	}
	if harnesses, ok := raw["harnessIds"].([]any); !ok || len(harnesses) != 1 || harnesses[0] != "codex" {
		t.Fatalf("harnessIds = %#v, want [codex]", raw["harnessIds"])
	}
	if paths, ok := raw["skillInstallPaths"].([]any); !ok || len(paths) != 1 || paths[0] != skillPath {
		t.Fatalf("skillInstallPaths = %#v, want [%s]", raw["skillInstallPaths"], skillPath)
	}
	loaded := LoadAIConfig()
	if loaded == nil || loaded.HarnessID != "codex" || !loaded.HarnessConfigured("codex") {
		t.Fatalf("harness selection did not round trip: %+v", loaded)
	}
	if raw["maskSecretValues"] != true || !loaded.MaskSecretValues {
		t.Fatalf("masking preference did not round trip: %s", data)
	}
}

func TestAIConfigAddsHarnessesWithoutReplacingExistingIntegrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.json")
	overrideAIConfigPath(t, path)
	cursorSkill := filepath.Join(t.TempDir(), "cursor", "SKILL.md")
	codexSkill := filepath.Join(t.TempDir(), "codex", "SKILL.md")
	cfg := &AIConfig{
		Enabled: true, ProxyMode: AIProxyModeLocal,
		HarnessID: aiHarnessCursorForTest, SkillInstallPath: cursorSkill,
	}
	cfg.AddHarnessInstallation("codex", codexSkill)
	if err := SaveAIConfig(cfg); err != nil {
		t.Fatal(err)
	}

	loaded := LoadAIConfig()
	if loaded == nil || !loaded.HarnessEnabled(aiHarnessCursorForTest) || !loaded.HarnessEnabled("codex") || loaded.HarnessEnabled("claude-code") {
		t.Fatalf("unexpected multi-harness config: %+v", loaded)
	}
	if got := loaded.ConfiguredHarnessIDs(); len(got) != 2 || got[0] != aiHarnessCursorForTest || got[1] != "codex" {
		t.Fatalf("configured harnesses = %v, want [cursor codex]", got)
	}
	if got := loaded.ConfiguredSkillInstallPaths(); len(got) != 2 || got[0] != cursorSkill || got[1] != codexSkill {
		t.Fatalf("configured skill paths = %v", got)
	}
	loaded.ClearHarnessInstallations()
	if len(loaded.ConfiguredHarnessIDs()) != 0 || len(loaded.ConfiguredSkillInstallPaths()) != 0 {
		t.Fatalf("cleared installation state remained configured: %+v", loaded)
	}
	if loaded.ProxyMode != AIProxyModeLocal {
		t.Fatalf("clearing installations changed proxy mode: %+v", loaded)
	}
}

const aiHarnessCursorForTest = "cursor"

func TestAIConfigDisabledStateRetainsWorkflow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.json")
	overrideAIConfigPath(t, path)
	skillPath := filepath.Join(t.TempDir(), "SKILL.md")
	if err := SaveAIConfig(&AIConfig{Enabled: false, ProxyMode: AIProxyModeLocal, DefaultWorkflowID: "workflow-123", SkillInstallPath: skillPath}); err != nil {
		t.Fatal(err)
	}
	cfg := LoadAIConfig()
	if cfg == nil || cfg.Enabled || cfg.DefaultWorkflowID != "workflow-123" || cfg.SkillInstallPath != skillPath {
		t.Fatalf("unexpected disabled config: %+v", cfg)
	}
}

func TestSaveAIConfigRejectsUnknownProxyMode(t *testing.T) {
	overrideAIConfigPath(t, filepath.Join(t.TempDir(), "ai.json"))
	err := SaveAIConfig(&AIConfig{Enabled: true, ProxyMode: "remote"})
	if err == nil {
		t.Fatal("expected unsupported proxy mode error")
	}
}

func TestLoadAIConfigRejectsUnknownFutureVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.json")
	overrideAIConfigPath(t, path)
	if err := os.WriteFile(path, []byte(`{"version":"99","enabled":true,"proxyMode":"local"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg := LoadAIConfig(); cfg != nil {
		t.Fatalf("unexpectedly interpreted future config: %+v", cfg)
	}
}
