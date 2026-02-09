package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/phasehq/golang-sdk/phase/network"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/spf13/cobra"
)

var dynamicSecretsListCmd = &cobra.Command{
	Use:   "list",
	Short: "📇 List dynamic secrets & metadata",
	RunE:  runDynamicSecretsList,
}

func init() {
	dynamicSecretsListCmd.Flags().String("env", "", "Environment name")
	dynamicSecretsListCmd.Flags().String("app", "", "Application name")
	dynamicSecretsListCmd.Flags().String("app-id", "", "Application ID")
	dynamicSecretsListCmd.Flags().String("path", "", "Path filter")
	dynamicSecretsCmd.AddCommand(dynamicSecretsListCmd)
}

func runDynamicSecretsList(cmd *cobra.Command, args []string) error {
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")
	path, _ := cmd.Flags().GetString("path")

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	userData, err := p.Init()
	if err != nil {
		return err
	}

	resolvedAppName, resolvedAppID, resolvedEnvName, _, _, err := phase.PhaseGetContext(userData, appName, envName, appID)
	if err != nil {
		return err
	}
	_ = resolvedAppName

	result, err := network.ListDynamicSecrets(p.TokenType, p.AppToken, p.APIHost, resolvedAppID, resolvedEnvName, path)
	if err != nil {
		return err
	}

	var formatted json.RawMessage
	if err := json.Unmarshal(result, &formatted); err != nil {
		fmt.Println(string(result))
		return nil
	}
	pretty, _ := json.MarshalIndent(formatted, "", "  ")
	fmt.Println(string(pretty))
	return nil
}
