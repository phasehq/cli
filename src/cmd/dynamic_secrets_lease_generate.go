package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/phasehq/golang-sdk/phase/network"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/spf13/cobra"
)

var dynamicSecretsLeaseGenerateCmd = &cobra.Command{
	Use:   "generate <secret_id>",
	Short: "✨ Generate a lease (create fresh dynamic secret)",
	Args:  cobra.ExactArgs(1),
	RunE:  runDynamicSecretsLeaseGenerate,
}

func init() {
	dynamicSecretsLeaseGenerateCmd.Flags().Int("lease-ttl", 0, "Lease TTL in seconds")
	dynamicSecretsLeaseGenerateCmd.Flags().String("env", "", "Environment name")
	dynamicSecretsLeaseGenerateCmd.Flags().String("app", "", "Application name")
	dynamicSecretsLeaseGenerateCmd.Flags().String("app-id", "", "Application ID")
	dynamicSecretsLeaseCmd.AddCommand(dynamicSecretsLeaseGenerateCmd)
}

func runDynamicSecretsLeaseGenerate(cmd *cobra.Command, args []string) error {
	secretID := args[0]
	leaseTTL, _ := cmd.Flags().GetInt("lease-ttl")
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	userData, err := phase.Init(p)
	if err != nil {
		return err
	}

	_, resolvedAppID, resolvedEnvName, _, _, err := phase.PhaseGetContext(userData, appName, envName, appID)
	if err != nil {
		return err
	}

	var ttlPtr *int
	if cmd.Flags().Changed("lease-ttl") {
		ttlPtr = &leaseTTL
	}

	result, err := network.CreateDynamicSecretLease(p.TokenType, p.AppToken, p.Host, resolvedAppID, resolvedEnvName, secretID, ttlPtr)
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
