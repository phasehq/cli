package cmd

import (
	"fmt"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

var secretsImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "📩 Import secrets from a .env file",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsImport,
}

func init() {
	secretsImportCmd.Flags().String("env", "", "Environment name")
	secretsImportCmd.Flags().String("app", "", "Application name")
	secretsImportCmd.Flags().String("app-id", "", "Application ID")
	secretsImportCmd.Flags().String("path", "/", "Path for imported secrets")
	secretsCmd.AddCommand(secretsImportCmd)
}

func runSecretsImport(cmd *cobra.Command, args []string) error {
	envFile := args[0]
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")
	path, _ := cmd.Flags().GetString("path")

	// Parse env file
	pairs, err := util.ParseEnvFile(envFile)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", envFile, err)
	}

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	kvPairs := make([]phase.KeyValuePair, len(pairs))
	for i, kv := range pairs {
		kvPairs[i] = phase.KeyValuePair{Key: kv.Key, Value: kv.Value}
	}

	err = p.Create(phase.CreateOptions{
		KeyValuePairs: kvPairs,
		EnvName:       envName,
		AppName:       appName,
		AppID:         appID,
		Path:          path,
	})
	if err != nil {
		return fmt.Errorf("failed to import secrets: %w", err)
	}

	fmt.Println(util.BoldGreen(fmt.Sprintf("✅ Successfully imported and encrypted %d secrets.", len(pairs))))
	if envName == "" {
		fmt.Println("To view them please run: phase secrets list")
	} else {
		fmt.Printf("To view them please run: phase secrets list --env %s\n", envName)
	}
	return nil
}
