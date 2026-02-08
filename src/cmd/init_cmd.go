package cmd

import (
	"fmt"
	"os"
	"sort"

	"github.com/manifoldco/promptui"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "🔗 Link your project with your Phase app",
	RunE:  runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	data, err := p.Init()
	if err != nil {
		return err
	}

	if len(data.Apps) == 0 {
		return fmt.Errorf("no applications found")
	}

	// Build app choice labels
	appItems := make([]string, len(data.Apps)+1)
	for i, app := range data.Apps {
		appItems[i] = fmt.Sprintf("%s (%s)", app.Name, app.ID)
	}
	appItems[len(data.Apps)] = "Exit"

	appPrompt := promptui.Select{
		Label: "Select an App",
		Items: appItems,
	}
	appIdx, _, err := appPrompt.Run()
	if err != nil {
		return fmt.Errorf("prompt cancelled")
	}
	if appIdx == len(data.Apps) {
		return nil
	}

	selectedApp := data.Apps[appIdx]

	// Sort environments
	envSortOrder := map[string]int{"DEV": 1, "STAGING": 2, "PROD": 3}
	envKeys := make([]struct {
		idx  int
		sort int
	}, len(selectedApp.EnvironmentKeys))
	for i, ek := range selectedApp.EnvironmentKeys {
		order, ok := envSortOrder[ek.Environment.EnvType]
		if !ok {
			order = 4
		}
		envKeys[i] = struct {
			idx  int
			sort int
		}{i, order}
	}
	sort.Slice(envKeys, func(i, j int) bool {
		return envKeys[i].sort < envKeys[j].sort
	})

	// Build env choice labels
	envItems := make([]string, len(envKeys)+1)
	for i, ek := range envKeys {
		env := selectedApp.EnvironmentKeys[ek.idx]
		envItems[i] = env.Environment.Name
	}
	envItems[len(envKeys)] = "Exit"

	envPrompt := promptui.Select{
		Label: "Choose a Default Environment",
		Items: envItems,
	}
	envIdx, _, err := envPrompt.Run()
	if err != nil {
		return fmt.Errorf("prompt cancelled")
	}
	if envIdx == len(envKeys) {
		return nil
	}

	selectedEnvKey := selectedApp.EnvironmentKeys[envKeys[envIdx].idx]

	// Ask about monorepo support
	monorepoPrompt := promptui.Select{
		Label: "🍱 Monorepo support: Would you like this configuration to apply to subdirectories?",
		Items: []string{"No", "Yes"},
	}
	monorepoIdx, _, err := monorepoPrompt.Run()
	if err != nil {
		return fmt.Errorf("prompt cancelled")
	}
	monorepoSupport := monorepoIdx == 1

	// Write .phase.json
	phaseConfig := &config.PhaseJSONConfig{
		Version:         "2",
		PhaseApp:        selectedApp.Name,
		AppID:           selectedApp.ID,
		DefaultEnv:      selectedEnvKey.Environment.Name,
		EnvID:           selectedEnvKey.Environment.ID,
		MonorepoSupport: monorepoSupport,
	}

	if err := config.WritePhaseConfig(phaseConfig); err != nil {
		return fmt.Errorf("failed to write .phase.json: %w", err)
	}

	// Set file permissions
	os.Chmod(config.PhaseEnvConfig, 0600)

	fmt.Println(util.BoldGreen("✅ Initialization completed successfully."))
	return nil
}
