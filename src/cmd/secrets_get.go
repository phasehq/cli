package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/phase"
	"github.com/spf13/cobra"
)

var secretsGetCmd = &cobra.Command{
	Use:   "get <KEY>",
	Short: "🔍 Fetch details about a secret in JSON",
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsGet,
}

func init() {
	secretsGetCmd.Flags().String("env", "", "Environment name")
	secretsGetCmd.Flags().String("app", "", "Application name")
	secretsGetCmd.Flags().String("app-id", "", "Application ID")
	secretsGetCmd.Flags().String("path", "/", "Path filter")
	secretsGetCmd.Flags().String("tags", "", "Filter by tags")
	secretsGetCmd.Flags().String("generate-leases", "true", "Generate leases for dynamic secrets")
	secretsGetCmd.Flags().Int("lease-ttl", 0, "Lease TTL in seconds")
	secretsCmd.AddCommand(secretsGetCmd)
}

func runSecretsGet(cmd *cobra.Command, args []string) error {
	key := strings.ToUpper(args[0])
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")
	path, _ := cmd.Flags().GetString("path")
	tags, _ := cmd.Flags().GetString("tags")
	generateLeases, _ := cmd.Flags().GetString("generate-leases")
	leaseTTL, _ := cmd.Flags().GetInt("lease-ttl")

	appName, envName, appID = phase.GetConfig(appName, envName, appID)

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	opts := sdk.GetOptions{
		EnvName: envName,
		AppName: appName,
		AppID:   appID,
		Keys:    []string{key},
		Tag:     tags,
		Path:    path,
		Dynamic: true,
		Lease:   util.ParseBoolFlag(generateLeases),
	}
	if cmd.Flags().Changed("lease-ttl") {
		opts.LeaseTTL = &leaseTTL
	}

	secrets, err := p.Get(opts)
	if err != nil {
		return err
	}

	var found *sdk.SecretResult
	for i, s := range secrets {
		if s.Key == key {
			found = &secrets[i]
			break
		}
	}

	if found == nil {
		return fmt.Errorf("🔍 Secret not found")
	}

	data, _ := json.MarshalIndent(found, "", "    ")
	fmt.Println(string(data))
	return nil
}
