package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/phase"
	"github.com/spf13/cobra"
)

var secretsDeleteCmd = &cobra.Command{
	Use:   "delete [KEYS...]",
	Short: "🗑️\u200A Delete a secret",
	RunE:  runSecretsDelete,
}

func init() {
	secretsDeleteCmd.Flags().String("env", "", "Environment name")
	secretsDeleteCmd.Flags().String("app", "", "Application name")
	secretsDeleteCmd.Flags().String("app-id", "", "Application ID")
	secretsDeleteCmd.Flags().String("path", "", "Path filter")
	secretsCmd.AddCommand(secretsDeleteCmd)
}

func runSecretsDelete(cmd *cobra.Command, args []string) error {
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")
	path, _ := cmd.Flags().GetString("path")

	keysToDelete := args
	if len(keysToDelete) == 0 {
		fmt.Print("Please enter the keys to delete (separate multiple keys with a space): ")
		var input string
		fmt.Scanln(&input)
		keysToDelete = strings.Fields(input)
	}

	// Uppercase keys
	for i, k := range keysToDelete {
		keysToDelete[i] = strings.ToUpper(k)
	}

	appName, envName, appID = phase.GetConfig(appName, envName, appID)

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	keysNotFound, err := p.Delete(sdk.DeleteOptions{
		EnvName:      envName,
		AppName:      appName,
		AppID:        appID,
		KeysToDelete: keysToDelete,
		Path:         path,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(keysNotFound) > 0 {
		fmt.Fprintf(os.Stderr, "⚠️  Warning: The following keys were not found: %s\n", strings.Join(keysNotFound, ", "))
	} else {
		fmt.Println(util.BoldGreen("✅ Successfully deleted the secrets."))
	}

	listSecrets(p, envName, appName, appID, "", path, false)
	return nil
}
