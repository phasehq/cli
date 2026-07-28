package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/spf13/cobra"
)

var appsCmd = &cobra.Command{
	Use:   "apps",
	Short: "📱 Manage Phase apps",
}

var appsListCmd = &cobra.Command{
	Use:   "list",
	Short: "📋 List available apps and their environments",
	RunE:  runAppsList,
}

func init() {
	rootCmd.AddCommand(appsCmd)
	appsCmd.AddCommand(appsListCmd)
}

type appListEntry struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Environments []envListEntry     `json:"environments"`
}

type envListEntry struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	EnvType string `json:"env_type"`
}

func runAppsList(cmd *cobra.Command, args []string) error {
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

	entries := make([]appListEntry, len(data.Apps))
	for i, app := range data.Apps {
		envs := make([]envListEntry, len(app.EnvironmentKeys))
		for j, ek := range app.EnvironmentKeys {
			envs[j] = envListEntry{
				ID:      ek.Environment.ID,
				Name:    ek.Environment.Name,
				EnvType: ek.Environment.EnvType,
			}
		}
		entries[i] = appListEntry{
			ID:           app.ID,
			Name:         app.Name,
			Environments: envs,
		}
	}

	out, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}
	fmt.Println(string(out))
	return nil
}
