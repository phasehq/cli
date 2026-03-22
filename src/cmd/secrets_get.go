package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
	"github.com/spf13/cobra"
)

var secretsGetCmd = &cobra.Command{
	Use:   "get <KEY> [KEY...]",
	Short: "🔍 Fetch details about one or more secrets in JSON",
	Args:  cobra.MinimumNArgs(1),
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
	keys := make([]string, len(args))
	for i, k := range args {
		keys[i] = strings.ToUpper(k)
	}

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
		Keys:    keys,
		Tag:     tags,
		Path:    path,
		Dynamic: true,
		Lease:   util.ParseBoolFlag(generateLeases),
		Raw:     true,
	}
	if cmd.Flags().Changed("lease-ttl") {
		opts.LeaseTTL = &leaseTTL
	}

	secrets, err := p.Get(opts)
	if err != nil {
		return err
	}

	// Build a lookup set for requested keys
	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}

	var results []sdk.SecretResult
	for _, s := range secrets {
		if keySet[s.Key] {
			if ai.ShouldRedact(s.Type) {
				s.Value = "[REDACTED]"
			}
			results = append(results, s)
		}
	}

	if len(results) == 0 {
		return fmt.Errorf("🔍 No matching secrets found")
	}

	// Single key: output the object directly (backwards compatible)
	if len(keys) == 1 {
		data, _ := json.MarshalIndent(results[0], "", "    ")
		fmt.Println(string(data))
		return nil
	}

	// Multiple keys: output as array
	data, _ := json.MarshalIndent(results, "", "    ")
	fmt.Println(string(data))
	return nil
}
