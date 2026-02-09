package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/phasehq/golang-sdk/phase/network"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/spf13/cobra"
)

var dynamicSecretsLeaseGetCmd = &cobra.Command{
	Use:   "get <secret_id>",
	Short: "🔍 Get leases for a dynamic secret",
	Args:  cobra.ExactArgs(1),
	RunE:  runDynamicSecretsLeaseGet,
}

func init() {
	dynamicSecretsLeaseGetCmd.Flags().String("env", "", "Environment name")
	dynamicSecretsLeaseGetCmd.Flags().String("app", "", "Application name")
	dynamicSecretsLeaseGetCmd.Flags().String("app-id", "", "Application ID")
	dynamicSecretsLeaseCmd.AddCommand(dynamicSecretsLeaseGetCmd)
}

func runDynamicSecretsLeaseGet(cmd *cobra.Command, args []string) error {
	secretID := args[0]
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	userData, err := p.Init()
	if err != nil {
		return err
	}

	_, resolvedAppID, resolvedEnvName, _, _, err := phase.PhaseGetContext(userData, appName, envName, appID)
	if err != nil {
		return err
	}

	result, err := network.ListDynamicSecretLeases(p.TokenType, p.AppToken, p.APIHost, resolvedAppID, resolvedEnvName, secretID)
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
