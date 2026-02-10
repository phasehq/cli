package cmd

import (
	"fmt"
	"os"

	"github.com/phasehq/cli/pkg/display"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/phase"
	"github.com/spf13/cobra"
)

var secretsListCmd = &cobra.Command{
	Use:   "list",
	Short: "📇 List all the secrets",
	Long: `📇 List all the secrets

Icon legend:
  🔗  Secret references another secret in the same environment
  ⛓️   Cross-environment reference (secret from another environment)
  🏷️  Tag associated with the secret
  💬  Comment associated with the secret
  🔏  Personal secret override (visible only to you)
  ⚡️  Dynamic secret`,
	RunE: runSecretsList,
}

func init() {
	secretsListCmd.Flags().Bool("show", false, "Show decrypted secret values")
	secretsListCmd.Flags().String("env", "", "Environment name")
	secretsListCmd.Flags().String("app", "", "Application name")
	secretsListCmd.Flags().String("app-id", "", "Application ID")
	secretsListCmd.Flags().String("tags", "", "Filter by tags")
	secretsListCmd.Flags().String("path", "", "Path filter")
	secretsCmd.AddCommand(secretsListCmd)
}

// listSecrets fetches and displays secrets. Used by list, create, update, and delete commands.
func listSecrets(p *sdk.Phase, envName, appName, appID, tags, path string, show bool) {
	spinner := util.NewSpinner("Fetching secrets...")
	spinner.Start()
	secrets, err := p.Get(sdk.GetOptions{
		EnvName: envName,
		AppName: appName,
		AppID:   appID,
		Tag:     tags,
		Path:    path,
	})
	spinner.Stop()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	display.RenderSecretsTree(secrets, show)
}

func runSecretsList(cmd *cobra.Command, args []string) error {
	show, _ := cmd.Flags().GetBool("show")
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")
	tags, _ := cmd.Flags().GetString("tags")
	path, _ := cmd.Flags().GetString("path")

	appName, envName, appID = phase.GetConfig(appName, envName, appID)

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	listSecrets(p, envName, appName, appID, tags, path, show)

	fmt.Println("🔬 To view a secret, use: phase secrets get <key>")
	if !show {
		fmt.Println("🥽 To uncover the secrets, use: phase secrets list --show")
	}
	return nil
}
