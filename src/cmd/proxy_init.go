package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/proxy"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

var proxyInitCmd = &cobra.Command{
	Use:   "init",
	Short: "🔐 Generate the proxy CA (one-time setup)",
	Long:  "Generate a per-install CA (private key in the OS keyring) and write the public CA certificate. Run once, then `phase proxy start`.",
	RunE:  runProxyInit,
}

func init() {
	proxyInitCmd.Flags().Int("ca-validity-days", 365, "CA certificate validity in days")
	proxyInitCmd.Flags().Bool("force", false, "Regenerate the CA even if one already exists")
	proxyCmd.AddCommand(proxyInitCmd)
}

func runProxyInit(cmd *cobra.Command, args []string) error {
	days, _ := cmd.Flags().GetInt("ca-validity-days")
	force, _ := cmd.Flags().GetBool("force")

	// Authenticate the operator to Phase (fails fast if not logged in).
	p, err := phase.NewPhase(true, "", "")
	if err != nil {
		return err
	}
	if err := phase.Auth(p); err != nil {
		return err
	}

	if _, err := keyring.GetProxyCAKey(); err == nil && !force {
		return fmt.Errorf("a proxy CA already exists; re-run with --force to regenerate (this invalidates the previously distributed CA)")
	}

	_, certPEM, keyPEM, err := proxy.GenerateCA(time.Duration(days) * 24 * time.Hour)
	if err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}
	if err := keyring.SetProxyCAKey(string(keyPEM)); err != nil {
		return fmt.Errorf("store CA private key in keyring: %w", err)
	}
	certPath, err := proxy.WriteCACert(certPEM)
	if err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}

	fmt.Fprintf(os.Stderr, "%s\n", util.BoldGreen("✓ Phase egress proxy initialized"))
	fmt.Fprintf(os.Stderr, "  CA private key  → OS keyring\n")
	fmt.Fprintf(os.Stderr, "  CA certificate  → %s\n\n", certPath)
	fmt.Fprintf(os.Stderr, "Next: %s\n", util.BoldWhite("phase proxy start"))
	return nil
}
