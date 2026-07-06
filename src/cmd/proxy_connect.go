package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/phasehq/cli/pkg/approval"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

var proxyConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "🔐 Approve (Touch ID) and run the egress proxy in this shell",
	Long: "Gate credential issuance on an explicit device-owner approval (Touch ID / password on macOS, " +
		"sudo elsewhere), then run the egress proxy in the FOREGROUND on a random local port and print " +
		"the routing / CA trust / dummy-credential config to paste into your running agent. The proxy " +
		"runs in this shell until you Ctrl-C — each run is its own isolated session (own port, own " +
		"credential lease), so it never collides with a previously started proxy. The agent only ever " +
		"holds dummies; live credentials stay in the proxy.",
	RunE: runProxyConnect,
}

// addProxyConnectFlags registers the flags for the connect command. Shared so the
// same command can live under both `phase proxy connect` and `phase ai serve`.
func addProxyConnectFlags(c *cobra.Command) {
	c.Flags().String("listen", "127.0.0.1:0", "Listen address (default: a random free port)")
	c.Flags().String("env", "", "Environment name")
	c.Flags().String("app", "", "Application name")
	c.Flags().String("app-id", "", "Application ID")
	c.Flags().Duration("refresh", 60*time.Second, "How often to re-fetch static secrets from Phase (0 to disable)")
	c.Flags().Bool("lockdown", false, "Egress allowlist: DENY hosts with no binding (default: pass them through)")
	c.Flags().String("log-file", "", "Where to write proxy audit logs (default ~/.phase/proxy/proxy.log; '-' = stderr)")
}

func init() {
	addProxyConnectFlags(proxyConnectCmd)
	proxyCmd.AddCommand(proxyConnectCmd)
}

func runProxyConnect(cmd *cobra.Command, args []string) error {
	listen, _ := cmd.Flags().GetString("listen")
	appName, _ := cmd.Flags().GetString("app")
	envName, _ := cmd.Flags().GetString("env")
	appID, _ := cmd.Flags().GetString("app-id")
	refresh, _ := cmd.Flags().GetDuration("refresh")
	lockdown, _ := cmd.Flags().GetBool("lockdown")
	logFile, _ := cmd.Flags().GetString("log-file")

	appName, envName, appID = phase.GetConfig(appName, envName, appID)

	// Human-in-the-loop gate BEFORE any credential/lease is minted — if the user
	// declines, nothing is fetched, issued, or printed.
	reason := fmt.Sprintf("issue %s credentials to an AI agent via the Phase egress proxy", envName)
	fmt.Fprintln(os.Stderr, "🔐 waiting for device-owner approval (check for a Touch ID / password prompt)...")
	if err := approval.Require(reason); err != nil {
		fmt.Fprintln(os.Stderr, "✗ no credentials were issued")
		return err
	}
	fmt.Fprintf(os.Stderr, "%s\n", util.BoldGreen("✓ approved by device owner"))

	// Run the proxy in THIS shell (foreground) until Ctrl-C — no background daemon,
	// so each session is self-contained and easy to stop.
	return serveProxyForeground(listen, appName, envName, appID, logFile, refresh, lockdown)
}
