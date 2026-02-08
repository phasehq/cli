package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/phasehq/cli/pkg/network"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/spf13/cobra"
)

var dynamicSecretsLeaseRenewCmd = &cobra.Command{
	Use:   "renew <lease_id> <ttl>",
	Short: "🔁 Renew a lease",
	Args:  cobra.ExactArgs(2),
	RunE:  runDynamicSecretsLeaseRenew,
}

func init() {
	dynamicSecretsLeaseRenewCmd.Flags().String("env", "", "Environment name")
	dynamicSecretsLeaseRenewCmd.Flags().String("app", "", "Application name")
	dynamicSecretsLeaseRenewCmd.Flags().String("app-id", "", "Application ID")
	dynamicSecretsLeaseCmd.AddCommand(dynamicSecretsLeaseRenewCmd)
}

func runDynamicSecretsLeaseRenew(cmd *cobra.Command, args []string) error {
	leaseID := args[0]
	ttl, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("invalid TTL value: %s", args[1])
	}

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

	result, err := network.RenewDynamicSecretLease(p.TokenType, p.AppToken, p.APIHost, resolvedAppID, resolvedEnvName, leaseID, ttl)
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
