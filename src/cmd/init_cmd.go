package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	"github.com/phasehq/golang-sdk/v2/phase/misc"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "🔗 Link local project with Phase app",
	RunE:  runInit,
}

func init() {
	initCmd.Flags().String("app-id", "", "Application ID (skips app selection prompt)")
	initCmd.Flags().String("env", "", "Environment name (skips environment selection prompt)")
	initCmd.Flags().Bool("monorepo", false, "Enable monorepo support (skips prompt)")
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	appIDFlag, _ := cmd.Flags().GetString("app-id")
	envFlag, _ := cmd.Flags().GetString("env")
	monorepoFlag, _ := cmd.Flags().GetBool("monorepo")

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	data, err := phase.Init(p)
	if err != nil {
		return err
	}

	if len(data.Apps) == 0 {
		return fmt.Errorf("no applications found")
	}

	// Non-interactive mode: both --app-id and --env provided
	if appIDFlag != "" && envFlag != "" {
		return initNonInteractive(data, appIDFlag, envFlag, monorepoFlag)
	}

	return initInteractive(data, cmd)
}

func initNonInteractive(data *misc.AppKeyResponse, appID, envName string, monorepo bool) error {
	// Find the app by ID
	var selectedApp *misc.App
	for i, app := range data.Apps {
		if app.ID == appID {
			selectedApp = &data.Apps[i]
			break
		}
	}
	if selectedApp == nil {
		return fmt.Errorf("application with ID '%s' not found", appID)
	}

	// Find the environment by name (case-insensitive)
	var envID, resolvedEnvName string
	for _, ek := range selectedApp.EnvironmentKeys {
		if strings.EqualFold(ek.Environment.Name, envName) {
			envID = ek.Environment.ID
			resolvedEnvName = ek.Environment.Name
			break
		}
	}
	if envID == "" {
		return fmt.Errorf("environment '%s' not found in app '%s'", envName, selectedApp.Name)
	}

	return writePhaseConfig(selectedApp.Name, selectedApp.ID, resolvedEnvName, envID, monorepo)
}

func initInteractive(data *misc.AppKeyResponse, cmd *cobra.Command) error {
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

	return writePhaseConfig(selectedApp.Name, selectedApp.ID, selectedEnvKey.Environment.Name, selectedEnvKey.Environment.ID, monorepoSupport)
}

func writePhaseConfig(appName, appID, envName, envID string, monorepo bool) error {
	phaseConfig := &config.PhaseJSONConfig{
		Version:         "2",
		PhaseApp:        appName,
		AppID:           appID,
		DefaultEnv:      envName,
		EnvID:           envID,
		MonorepoSupport: monorepo,
	}

	if err := config.WritePhaseConfig(phaseConfig); err != nil {
		return fmt.Errorf("failed to write .phase.json: %w", err)
	}

	os.Chmod(config.PhaseEnvConfig, 0600)

	fmt.Println(util.BoldGreen("✅ Initialization completed successfully."))
	return nil
}
