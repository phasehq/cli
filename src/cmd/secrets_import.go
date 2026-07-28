package cmd

import (
	"fmt"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
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
	secretsImportCmd.Flags().String("type", "", "Secret type: secret (default), sealed, or config")
	secretsCmd.AddCommand(secretsImportCmd)
}

func runSecretsImport(cmd *cobra.Command, args []string) error {
	envFile := args[0]
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")
	path, _ := cmd.Flags().GetString("path")
	secretType, _ := cmd.Flags().GetString("type")

	if err := sdk.ValidateSecretType(secretType); err != nil {
		return err
	}

	// Parse env file
	pairs, err := util.ParseEnvFile(envFile)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", envFile, err)
	}

	appName, envName, appID = phase.GetConfig(appName, envName, appID)

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	err = p.Create(sdk.CreateOptions{
		KeyValuePairs: pairs,
		EnvName:       envName,
		AppName:       appName,
		AppID:         appID,
		Path:          path,
		Type:          secretType,
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
