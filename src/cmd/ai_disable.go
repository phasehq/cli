package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

var aiDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "🚫 Disable AI integrations",
	Long:  "Disable local Agent proxy sessions while retaining the selected proxy mode and default Workflow for a later re-enable.",
	RunE:  runAIDisable,
}

func init() {
	aiCmd.AddCommand(aiDisableCmd)
}

func runAIDisable(cmd *cobra.Command, args []string) error {
	if ai.IsAIAgent() {
		return fmt.Errorf("phase ai disable must be run by the user directly, not by an AI agent")
	}

	cfg := config.LoadAIConfig()
	wasEnabled := cfg != nil && cfg.Enabled
	if wasEnabled {
		cfg.Enabled = false
		if err := config.SaveAIConfig(cfg); err != nil {
			return fmt.Errorf("failed to disable AI config: %w", err)
		}
	}
	var cleanupErrors []error
	stopContext, cancel := context.WithTimeout(cmd.Context(), 3*time.Second)
	defer cancel()
	if err := stopClaudeHookRuntime(stopContext); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("stop hook-managed Phase runtime: %w", err))
	}
	// Harness shells source this file before each command; removing it makes
	// the very next command run with ambient credentials, no restart needed.
	if err := removeClaudeEnvironmentFiles(); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("remove Phase AI shell environment: %w", err))
	}
	if pluginPath, err := ai.DefaultCursorBootstrapPluginPath(); err == nil {
		_, statErr := os.Stat(filepath.Join(pluginPath, ".cursor-plugin", "plugin.json"))
		if err := ai.UninstallCursorBootstrapPlugin(pluginPath); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove Cursor bootstrap plugin: %w", err))
		} else if statErr == nil {
			fmt.Printf("   Removed Cursor bootstrap plugin: %s\n", pluginPath)
		}
	}
	if marketplacePath, err := ai.DefaultCodexBootstrapMarketplacePath(); err == nil {
		if _, statErr := os.Stat(marketplacePath); statErr == nil {
			codexExecutable, lookupErr := exec.LookPath("codex")
			if lookupErr != nil {
				cleanupErrors = append(cleanupErrors, errors.New("remove Codex bootstrap plugin: Codex CLI is unavailable"))
			} else if err := ai.UninstallCodexBootstrapPlugin(cmd.Context(), codexExecutable, marketplacePath); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("remove Codex bootstrap plugin: %w", err))
			} else {
				fmt.Printf("   Removed Codex bootstrap plugin: %s\n", marketplacePath)
			}
		}
	}
	if cfg != nil && cfg.HarnessConfigured(ai.HarnessOpenCode) {
		pluginPaths := cfg.OpenCodePlugins
		// Earlier builds did not record where the plugin went.
		if pluginPath, err := ai.DefaultOpenCodePluginPath(); err == nil && len(pluginPaths) == 0 {
			pluginPaths = []string{pluginPath}
		}
		for _, pluginPath := range pluginPaths {
			_, statErr := os.Stat(pluginPath)
			if err := ai.UninstallOpenCodePlugin(pluginPath); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("remove OpenCode Phase plugin: %w", err))
			} else if statErr == nil {
				fmt.Printf("   Removed OpenCode Phase plugin: %s\n", pluginPath)
			}
		}
	}
	if configPath, err := ai.DefaultDevinConfigPath(); err == nil && cfg != nil && cfg.HarnessConfigured(ai.HarnessDevin) {
		if _, statErr := os.Stat(configPath); statErr == nil {
			if err := ai.UninstallDevinHooks(configPath); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("remove Devin Phase hooks: %w", err))
			} else {
				fmt.Printf("   Removed Devin Phase hooks from: %s\n", configPath)
			}
		}
	}
	if pluginPath, err := ai.DefaultClaudeBootstrapPluginPath(); err == nil {
		_, statErr := os.Stat(filepath.Join(pluginPath, ".claude-plugin", "plugin.json"))
		if err := ai.UninstallClaudeBootstrapPlugin(pluginPath); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove Claude bootstrap plugin: %w", err))
		} else if statErr == nil {
			fmt.Printf("   Removed Claude bootstrap plugin: %s\n", pluginPath)
		}
	}
	// Keep the shared helper in place when an adapter could not be removed. That
	// adapter may still be active and must not be left pointing at a missing file.
	if len(cleanupErrors) == 0 {
		if err := ai.UninstallSharedHookExecutable(); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove shared Agent hook: %w", err))
		}
	}

	// Remove only unmodified Phase-owned skill files from canonical and
	// configured custom paths. Foreign files and unrelated siblings remain.
	var configuredSkillPaths []string
	if cfg != nil {
		configuredSkillPaths = cfg.ConfiguredSkillInstallPaths()
	}
	removed, err := ai.UninstallSkills(configuredSkillPaths...)
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("remove Phase AI skills: %w", err))
	}
	if len(removed) > 0 {
		for _, p := range removed {
			fmt.Printf("   Removed skill doc: %s\n", p)
		}
	}
	if len(cleanupErrors) > 0 {
		return fmt.Errorf("Phase AI was disabled, but cleanup is incomplete; rerun `phase ai disable`: %w", errors.Join(cleanupErrors...))
	}
	if cfg != nil {
		cfg.ClearHarnessInstallations()
		if err := config.SaveAIConfig(cfg); err != nil {
			return fmt.Errorf("Phase AI integrations were removed, but their local installation state could not be cleared: %w", err)
		}
	}

	if wasEnabled {
		fmt.Println(util.BoldGreen("✅ Phase AI local proxy mode disabled."))
	} else {
		fmt.Println("AI integrations were already disabled; managed runtime and hook cleanup is complete.")
	}
	return nil
}
