package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func overrideAIConfigPath(t *testing.T, path string) {
	t.Helper()
	original := AIConfigPath
	AIConfigPath = path
	t.Cleanup(func() { AIConfigPath = original })
}

func TestLoadAIConfigReadsReleasedFileAndIgnoresUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.json")
	overrideAIConfigPath(t, path)
	if err := os.WriteFile(path, []byte(`{"version":"1","maskSecretValues":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	released := LoadAIConfig()
	if released == nil || !released.Enabled || len(released.ConfiguredHarnessIDs()) != 0 || len(released.ConfiguredSkillInstallPaths()) != 0 || released.HarnessEnabled("claude-code") {
		t.Fatalf("a released file did not read as enabled with no harnesses: %+v", released)
	}
	if err := RecordOpenCodePlugin("/tmp/plugin.js"); err != nil {
		t.Fatalf("a released file blocked setup: %v", err)
	}
	if upgraded := LoadAIConfig(); upgraded == nil || upgraded.Version != AIConfigVersion || !upgraded.Enabled {
		t.Fatalf("a released file was not saved in the current shape: %+v", upgraded)
	}
	payload := `{"version":"3","enabled":true,"proxyMode":"local","maskSecretValues":true,"harnessId":"codex","skillInstallPath":"/old/SKILL.md","harnessIds":["cursor"]}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := LoadAIConfig()
	if cfg == nil || !cfg.Enabled || len(cfg.ConfiguredHarnessIDs()) != 1 || cfg.ConfiguredHarnessIDs()[0] != "cursor" || len(cfg.ConfiguredSkillInstallPaths()) != 0 {
		t.Fatalf("unknown keys changed the loaded config: %+v", cfg)
	}
	if err := SaveAIConfig(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{"proxyMode", "maskSecretValues", "harnessId", "skillInstallPath"} {
		if _, present := raw[removed]; present {
			t.Fatalf("save kept %s: %s", removed, data)
		}
	}
}

func TestLoadAIConfigNeverSeesAPartialSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.json")
	overrideAIConfigPath(t, path)
	cfg := &AIConfig{Enabled: true, DefaultWorkflowID: "workflow-123"}
	if err := SaveAIConfig(cfg); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	failures := make(chan string, 4)
	var readers sync.WaitGroup
	// Paced so a Windows rename, which waits for readers to close the file,
	// is not starved.
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if loaded := LoadAIConfig(); loaded == nil || loaded.DefaultWorkflowID != "workflow-123" {
					failures <- "a reader saw an unreadable AI config during a save"
					return
				}
				time.Sleep(time.Millisecond)
			}
		}()
	}
	for range 200 {
		if err := SaveAIConfig(cfg); err != nil {
			close(stop)
			readers.Wait()
			t.Fatal(err)
		}
	}
	close(stop)
	readers.Wait()
	select {
	case failure := <-failures:
		t.Fatal(failure)
	default:
	}
}

func TestAIConfigWithNoHarnessesFailsClosed(t *testing.T) {
	cfg := &AIConfig{Enabled: true}
	if cfg.HarnessEnabled("codex") {
		t.Fatal("empty v3 harness list authorized an automatic integration")
	}
}

func TestSaveAIConfigWritesV3And0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".phase", "ai.json")
	overrideAIConfigPath(t, path)
	skillPath := filepath.Join(t.TempDir(), "skills", "phase-cli", "SKILL.md")
	cfg := &AIConfig{Enabled: true, DefaultWorkflowID: "workflow-123"}
	cfg.AddHarnessInstallation("codex", skillPath)
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
	if raw["version"] != AIConfigVersion || raw["enabled"] != true || len(raw) != 5 {
		t.Fatalf("unexpected persisted config: %s", data)
	}
	if harnesses, ok := raw["harnessIds"].([]any); !ok || len(harnesses) != 1 || harnesses[0] != "codex" {
		t.Fatalf("harnessIds = %#v, want [codex]", raw["harnessIds"])
	}
	if paths, ok := raw["skillInstallPaths"].([]any); !ok || len(paths) != 1 || paths[0] != skillPath {
		t.Fatalf("skillInstallPaths = %#v, want [%s]", raw["skillInstallPaths"], skillPath)
	}
	loaded := LoadAIConfig()
	if loaded == nil || !loaded.HarnessConfigured("codex") || loaded.DefaultWorkflowID != "workflow-123" {
		t.Fatalf("config did not round trip: %+v", loaded)
	}
}

func TestAIConfigAddsHarnessesWithoutReplacingExistingIntegrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.json")
	overrideAIConfigPath(t, path)
	cursorSkill := filepath.Join(t.TempDir(), "cursor", "SKILL.md")
	codexSkill := filepath.Join(t.TempDir(), "codex", "SKILL.md")
	cfg := &AIConfig{Enabled: true}
	cfg.AddHarnessInstallation(aiHarnessCursorForTest, cursorSkill)
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
}

const aiHarnessCursorForTest = "cursor"

func TestRecordOpenCodePluginKeepsTheSavedConfig(t *testing.T) {
	overrideAIConfigPath(t, filepath.Join(t.TempDir(), "ai.json"))
	first := filepath.Join(t.TempDir(), "first.js")
	if err := RecordOpenCodePlugin(first); err != nil {
		t.Fatal(err)
	}
	if cfg := LoadAIConfig(); cfg == nil || cfg.Enabled || len(cfg.OpenCodePlugins) != 1 || cfg.OpenCodePlugins[0] != first {
		t.Fatalf("recording into a missing config: %+v", cfg)
	}

	if err := SaveAIConfig(&AIConfig{Enabled: true, DefaultWorkflowID: "workflow-123", HarnessIDs: []string{"opencode"}, OpenCodePlugins: []string{first}}); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(t.TempDir(), "second.js")
	for _, path := range []string{first, second} {
		if err := RecordOpenCodePlugin(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg := LoadAIConfig()
	if cfg == nil || !cfg.Enabled || cfg.DefaultWorkflowID != "workflow-123" || !cfg.HarnessConfigured("opencode") ||
		len(cfg.OpenCodePlugins) != 2 || cfg.OpenCodePlugins[1] != second {
		t.Fatalf("recording changed the saved config: %+v", cfg)
	}

	unreadable := []byte(`{"version":"99"}`)
	if err := os.WriteFile(AIConfigPath, unreadable, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecordOpenCodePlugin(second); err == nil {
		t.Fatal("recording replaced an ai.json this build cannot read")
	}
	if payload, err := os.ReadFile(AIConfigPath); err != nil || string(payload) != string(unreadable) {
		t.Fatalf("unreadable ai.json was changed: %q (%v)", payload, err)
	}
}

func TestAIConfigDisabledStateRetainsWorkflow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.json")
	overrideAIConfigPath(t, path)
	skillPath := filepath.Join(t.TempDir(), "SKILL.md")
	if err := SaveAIConfig(&AIConfig{Enabled: false, DefaultWorkflowID: "workflow-123", SkillInstallPaths: []string{skillPath}}); err != nil {
		t.Fatal(err)
	}
	cfg := LoadAIConfig()
	if cfg == nil || cfg.Enabled || cfg.DefaultWorkflowID != "workflow-123" || len(cfg.SkillInstallPaths) != 1 || cfg.SkillInstallPaths[0] != skillPath {
		t.Fatalf("unexpected disabled config: %+v", cfg)
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
