package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
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
	generateLeases, _ := cmd.Flags().GetString("generate-leases")
	leaseTTL, _ := cmd.Flags().GetInt("lease-ttl")

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	opts := phase.GetOptions{
		EnvName: envName,
		AppName: appName,
		AppID:   appID,
		Keys:    []string{key},
		Path:    path,
		Dynamic: true,
		Lease:   util.ParseBoolFlag(generateLeases),
	}
	if cmd.Flags().Changed("lease-ttl") {
		opts.LeaseTTL = &leaseTTL
	}

	secrets, err := p.Get(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var found *phase.SecretResult
	for i, s := range secrets {
		if s.Key == key {
			found = &secrets[i]
			break
		}
	}

	if found == nil {
		fmt.Fprintf(os.Stderr, "🔍 Secret not found\n")
		os.Exit(1)
	}

	data, _ := json.MarshalIndent(found, "", "    ")
	fmt.Println(string(data))
	return nil
}
