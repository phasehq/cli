package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	"github.com/spf13/cobra"
)

// isolateAISetup points enable and disable at a throwaway home and ai.json. It
// returns the home and an executable to install as the shared helper.
func isolateAISetup(t *testing.T) (string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	for _, marker := range []string{"CLAUDECODE", "CURSOR_AGENT", "CODEX", "OPENCODE", "AGENT"} {
		t.Setenv(marker, "")
	}
	withClaudeHookRuntimeDirectory(t)
	originalAIConfig := config.AIConfigPath
	config.AIConfigPath = filepath.Join(t.TempDir(), "ai.json")
	t.Cleanup(func() { config.AIConfigPath = originalAIConfig })
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return home, source
}

func runAIDisableForTest() error {
	command := &cobra.Command{}
	command.SetContext(context.Background())
	return runAIDisable(command, nil)
}

func TestOpenCodePluginIsRefreshedAndRemovedWhereItWasInstalled(t *testing.T) {
	home, source := isolateAISetup(t)
	customRoot := filepath.Join(t.TempDir(), "opencode")
	t.Setenv("OPENCODE_CONFIG_DIR", customRoot)
	customPlugin := filepath.Join(customRoot, "plugins", ai.OpenCodePluginName+".js")
	cfg := &config.AIConfig{Enabled: true, ProxyMode: config.AIProxyModeLocal, HarnessIDs: []string{ai.HarnessOpenCode}}
	if _, _, err := installConfiguredAIHarnessAdapters(context.Background(), cfg, ai.HarnessOpenCode, source); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveAIConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// A later enable for another harness runs without OpenCode's environment.
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	defaultPlugin, err := ai.DefaultOpenCodePluginPath()
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(customPlugin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ai.InstallOpenCodePlugin(customPlugin, filepath.Join(home, "old-phase"), filepath.Join(home, "env.json")); err != nil {
		t.Fatal(err)
	}
	cfg = config.LoadAIConfig()
	cfg.AddHarnessInstallation(ai.HarnessCursor, "")
	if _, _, err := installConfiguredAIHarnessAdapters(context.Background(), cfg, ai.HarnessCursor, source); err != nil {
		t.Fatal(err)
	}
	if payload, err := os.ReadFile(customPlugin); err != nil || string(payload) != string(current) {
		t.Fatalf("refresh did not rewrite the installed OpenCode plugin: %v", err)
	}
	if _, err := os.Stat(defaultPlugin); !os.IsNotExist(err) {
		t.Fatalf("refresh installed a second OpenCode plugin at %s: %v", defaultPlugin, err)
	}
	if err := config.SaveAIConfig(cfg); err != nil {
		t.Fatal(err)
	}

	if err := runAIDisableForTest(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(customPlugin); !os.IsNotExist(err) {
		t.Fatalf("disable left the OpenCode plugin at %s: %v", customPlugin, err)
	}
	if cfg := config.LoadAIConfig(); cfg == nil || len(cfg.OpenCodePlugins) != 0 {
		t.Fatalf("disable kept the recorded OpenCode plugin paths: %+v", cfg)
	}
}

func TestOpenCodePluginOfAnEarlierBuildIsFoundBesideItsSkill(t *testing.T) {
	home, source := isolateAISetup(t)
	customRoot := filepath.Join(t.TempDir(), "opencode")
	customPlugin := filepath.Join(customRoot, "plugins", ai.OpenCodePluginName+".js")
	defaultPlugin, err := ai.DefaultOpenCodePluginPath()
	if err != nil {
		t.Fatal(err)
	}
	// An earlier build, run with OPENCODE_CONFIG_DIR, recorded the skill but
	// not the plugin beside it.
	installEarlierBuild := func() []byte {
		t.Helper()
		if err := config.SaveAIConfig(&config.AIConfig{
			Enabled: true, ProxyMode: config.AIProxyModeLocal, HarnessIDs: []string{ai.HarnessOpenCode},
			SkillInstallPaths: []string{filepath.Join(customRoot, "skills", ai.AgentSkillName, "SKILL.md")},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := ai.InstallOpenCodePlugin(customPlugin, filepath.Join(home, "old-phase"), filepath.Join(home, "env.json")); err != nil {
			t.Fatal(err)
		}
		payload, err := os.ReadFile(customPlugin)
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}

	stale := installEarlierBuild()
	cfg := config.LoadAIConfig()
	cfg.AddHarnessInstallation(ai.HarnessCursor, "")
	if _, _, err := installConfiguredAIHarnessAdapters(context.Background(), cfg, ai.HarnessCursor, source); err != nil {
		t.Fatal(err)
	}
	if payload, err := os.ReadFile(customPlugin); err != nil || string(payload) == string(stale) {
		t.Fatalf("refresh did not rewrite the OpenCode plugin beside the recorded skill: %v", err)
	}
	if _, err := os.Stat(defaultPlugin); !os.IsNotExist(err) {
		t.Fatalf("refresh installed a second OpenCode plugin at %s: %v", defaultPlugin, err)
	}

	installEarlierBuild()
	if err := runAIDisableForTest(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(customPlugin); !os.IsNotExist(err) {
		t.Fatalf("disable left the OpenCode plugin beside the recorded skill: %v", err)
	}
}

func TestOpenCodePluginIsRecordedBeforeALaterAdapterFails(t *testing.T) {
	_, source := isolateAISetup(t)
	cfg := &config.AIConfig{Enabled: true, ProxyMode: config.AIProxyModeLocal, HarnessIDs: []string{ai.HarnessOpenCode, ai.HarnessCursor}}
	if err := config.SaveAIConfig(cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCODE_CONFIG_DIR", filepath.Join(t.TempDir(), "opencode"))
	plugin, err := ai.DefaultOpenCodePluginPath()
	if err != nil {
		t.Fatal(err)
	}
	cursorRoot, err := ai.DefaultCursorBootstrapPluginPath()
	if err != nil {
		t.Fatal(err)
	}
	// A Cursor plugin directory Phase does not own makes the Cursor adapter fail.
	if err := os.MkdirAll(cursorRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := installConfiguredAIHarnessAdapters(context.Background(), cfg, ai.HarnessOpenCode, source); err == nil {
		t.Fatal("the Cursor adapter did not fail")
	}
	if _, err := os.Stat(plugin); err != nil {
		t.Fatalf("the OpenCode plugin was not installed before Cursor: %v", err)
	}

	if err := os.Remove(cursorRoot); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	if err := runAIDisableForTest(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(plugin); !os.IsNotExist(err) {
		t.Fatalf("disable left the OpenCode plugin that the failed enable wrote: %v", err)
	}
}

func TestForeignOpenCodePluginIsNotRecordedForCleanup(t *testing.T) {
	_, source := isolateAISetup(t)
	plugin, err := ai.DefaultOpenCodePluginPath()
	if err != nil {
		t.Fatal(err)
	}
	foreign := []byte("export const Foreign = async () => ({})\n")
	if err := os.MkdirAll(filepath.Dir(plugin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plugin, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.AIConfig{Enabled: true, ProxyMode: config.AIProxyModeLocal, HarnessIDs: []string{ai.HarnessOpenCode}}
	if _, _, err := installConfiguredAIHarnessAdapters(context.Background(), cfg, ai.HarnessOpenCode, source); err == nil {
		t.Fatal("enable replaced a foreign OpenCode plugin")
	}
	if saved := config.LoadAIConfig(); saved != nil && len(saved.OpenCodePlugins) != 0 {
		t.Fatalf("the foreign plugin was recorded as Phase's: %v", saved.OpenCodePlugins)
	}
	if err := runAIDisableForTest(); err != nil {
		t.Fatal(err)
	}
	if payload, err := os.ReadFile(plugin); err != nil || string(payload) != string(foreign) {
		t.Fatalf("the foreign plugin was changed: %q, %v", payload, err)
	}
}
