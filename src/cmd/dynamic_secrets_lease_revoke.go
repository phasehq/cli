package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/phasehq/cli/pkg/network"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/spf13/cobra"
)

var dynamicSecretsLeaseRevokeCmd = &cobra.Command{
	Use:   "revoke <lease_id>",
	Short: "🗑️\u200A Revoke a lease",
	Args:  cobra.ExactArgs(1),
	RunE:  runDynamicSecretsLeaseRevoke,
}

func init() {
	dynamicSecretsLeaseRevokeCmd.Flags().String("env", "", "Environment name")
	dynamicSecretsLeaseRevokeCmd.Flags().String("app", "", "Application name")
	dynamicSecretsLeaseRevokeCmd.Flags().String("app-id", "", "Application ID")
	dynamicSecretsLeaseCmd.AddCommand(dynamicSecretsLeaseRevokeCmd)
}

func runDynamicSecretsLeaseRevoke(cmd *cobra.Command, args []string) error {
	leaseID := args[0]
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

	result, err := network.RevokeDynamicSecretLease(p.TokenType, p.AppToken, p.APIHost, resolvedAppID, resolvedEnvName, leaseID)
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
