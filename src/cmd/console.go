package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

var consoleCmd = &cobra.Command{
	Use:   "console",
	Short: "🖥️\u200A Open the Phase Console in your browser",
	RunE:  runConsole,
}

func init() {
	rootCmd.AddCommand(consoleCmd)
}

func runConsole(cmd *cobra.Command, args []string) error {
	user, err := config.GetDefaultUser()
	if err != nil {
		return fmt.Errorf("no user configured: %w", err)
	}

	host := user.Host
	orgName := ""
	if user.OrganizationName != nil {
		orgName = *user.OrganizationName
	}

	target := consoleURL(host, orgName, config.FindPhaseConfig(8))
	fmt.Printf("Opening %s\n", target)
	return util.OpenBrowser(target)
}

// consoleURL builds the Console page for the checkout's app and environment.
// The ids come from the checkout's .phase.json, so each is escaped as one
// path segment.
func consoleURL(host, orgName string, phaseConfig *config.PhaseJSONConfig) string {
	if phaseConfig == nil || orgName == "" {
		return host
	}
	version := 1
	if phaseConfig.Version != "" {
		if v, err := strconv.Atoi(phaseConfig.Version); err == nil {
			version = v
		}
	}
	appURL := fmt.Sprintf("%s/%s/apps/%s", host, url.PathEscape(orgName), url.PathEscape(phaseConfig.AppID))
	if version >= 2 && phaseConfig.EnvID != "" {
		return fmt.Sprintf("%s/environments/%s", appURL, url.PathEscape(phaseConfig.EnvID))
	}
	return appURL
}
