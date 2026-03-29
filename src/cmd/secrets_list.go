package cmd

import (
	"fmt"
	"os"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/display"
	"github.com/phasehq/cli/pkg/offline"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
	"github.com/spf13/cobra"
)

var secretsListCmd = &cobra.Command{
	Use:   "list",
	Short: "📇 List all the secrets",
	Long: `📇 List all the secrets

Icon legend:
  🔒  Sealed secret (write-only, value cannot be read back)
  🔧  Config secret (non-sensitive configuration value)
  🔗  Secret references another secret in the same environment
  🌐  Cross-environment reference (secret from another environment in the same or different application)
  🔖  Tag associated with the secret
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
	secretsListCmd.Flags().String("generate-leases", "", "Generate leases for dynamic secrets (defaults to value of --show)")
	secretsListCmd.Flags().Int("lease-ttl", 0, "Lease TTL in seconds")
	secretsCmd.AddCommand(secretsListCmd)
}

// listSecrets fetches and displays secrets. Used by list, create, update, and delete commands.
func listSecrets(p *sdk.Phase, envName, appName, appID, tags, path string, show, dynamic, lease bool, leaseTTL *int) error {
	opts := sdk.GetOptions{
		EnvName:  envName,
		AppName:  appName,
		AppID:    appID,
		Tag:      tags,
		Path:     path,
		Dynamic:  dynamic,
		Lease:    lease,
		LeaseTTL: leaseTTL,
		Raw:      true,
	}

	spinner := util.NewSpinner("Fetching secrets...")
	spinner.Start()
	secrets, err := offline.GetWithCache(p, opts, phase.GetCacheDir())
	spinner.Stop()
	if err != nil {
		return err
	}

	display.RenderSecretsTree(secrets, show)
	return nil
}

func runSecretsList(cmd *cobra.Command, args []string) error {
	show, _ := cmd.Flags().GetBool("show")
	envName, _ := cmd.Flags().GetString("env")
	appName, _ := cmd.Flags().GetString("app")
	appID, _ := cmd.Flags().GetString("app-id")
	tags, _ := cmd.Flags().GetString("tags")
	path, _ := cmd.Flags().GetString("path")
	generateLeases, _ := cmd.Flags().GetString("generate-leases")
	leaseTTL, _ := cmd.Flags().GetInt("lease-ttl")

	appName, envName, appID = phase.GetConfig(appName, envName, appID)

	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}

	// Match Python behavior: lease=show unless --generate-leases explicitly set
	var lease bool
	if cmd.Flags().Changed("generate-leases") {
		lease = util.ParseBoolFlag(generateLeases)
	} else {
		lease = show
	}
	var leaseTTLPtr *int
	if cmd.Flags().Changed("lease-ttl") {
		leaseTTLPtr = &leaseTTL
	}

	if err := listSecrets(p, envName, appName, appID, tags, path, show, true, lease, leaseTTLPtr); err != nil {
		return err
	}

	if ai.IsAIAgent() {
		fmt.Fprintf(os.Stderr, "🤖 AI mode: some values may be [REDACTED] based on secret type. To view, the user should run this command directly in their terminal.\n")
	}

	fmt.Println("🔬 To view a secret, use: phase secrets get <key>")
	if !show {
		fmt.Println("🥽 To uncover the secrets, use: phase secrets list --show")
	}
	return nil
}
