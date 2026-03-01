package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writePhaseConfigFile(t *testing.T, dir string, monorepoSupport bool) {
	t.Helper()
	cfg := PhaseJSONConfig{
		Version:         "2",
		PhaseApp:        "TestApp",
		AppID:           "00000000-0000-0000-0000-000000000000",
		DefaultEnv:      "Development",
		EnvID:           "00000000-0000-0000-0000-000000000001",
		MonorepoSupport: monorepoSupport,
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, PhaseEnvConfig), data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func withWorkingDir(t *testing.T, dir string) {
	t.Helper()
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir to %s: %v", dir, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(original)
	})
}

func TestFindPhaseConfig_InCurrentDir(t *testing.T) {
	base := t.TempDir()
	writePhaseConfigFile(t, base, false)
	withWorkingDir(t, base)

	cfg := FindPhaseConfig(8)
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}
	if cfg.PhaseApp != "TestApp" {
		t.Fatalf("unexpected phase app: %s", cfg.PhaseApp)
	}
}

func TestFindPhaseConfig_InParentWithMonorepoSupport(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	grandchild := filepath.Join(parent, "child", "grandchild")
	if err := os.MkdirAll(grandchild, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	writePhaseConfigFile(t, parent, true)
	withWorkingDir(t, grandchild)

	cfg := FindPhaseConfig(8)
	if cfg == nil {
		t.Fatal("expected parent config, got nil")
	}
	if cfg.AppID != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("unexpected app id: %s", cfg.AppID)
	}
}

func TestFindPhaseConfig_InParentWithoutMonorepoSupport(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	grandchild := filepath.Join(parent, "child", "grandchild")
	if err := os.MkdirAll(grandchild, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	writePhaseConfigFile(t, parent, false)
	withWorkingDir(t, grandchild)

	cfg := FindPhaseConfig(8)
	if cfg != nil {
		t.Fatalf("expected nil config, got %+v", cfg)
	}
}

func TestFindPhaseConfig_RespectsMaxDepthAndEnvOverride(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	grandchild := filepath.Join(parent, "child", "grandchild")
	if err := os.MkdirAll(grandchild, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	writePhaseConfigFile(t, parent, true)
	withWorkingDir(t, grandchild)

	if cfg := FindPhaseConfig(1); cfg != nil {
		t.Fatalf("expected nil with maxDepth=1, got %+v", cfg)
	}
	if cfg := FindPhaseConfig(2); cfg == nil {
		t.Fatal("expected config with maxDepth=2")
	}

	t.Setenv("PHASE_CONFIG_PARENT_DIR_SEARCH_DEPTH", "1")
	if cfg := FindPhaseConfig(8); cfg != nil {
		t.Fatalf("expected nil with env override depth=1, got %+v", cfg)
	}
}

func TestFindPhaseConfig_InvalidJSONAndNoConfig(t *testing.T) {
	base := t.TempDir()
	withWorkingDir(t, base)

	if cfg := FindPhaseConfig(8); cfg != nil {
		t.Fatalf("expected nil with no config, got %+v", cfg)
	}

	if err := os.WriteFile(filepath.Join(base, PhaseEnvConfig), []byte("{invalid"), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	if cfg := FindPhaseConfig(8); cfg != nil {
		t.Fatalf("expected nil with invalid json, got %+v", cfg)
	}
}
