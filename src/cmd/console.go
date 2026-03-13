package cmd

import (
	"fmt"
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

	phaseConfig := config.FindPhaseConfig(8)
	if phaseConfig != nil && orgName != "" {
		version := 1
		if phaseConfig.Version != "" {
			if v, err := strconv.Atoi(phaseConfig.Version); err == nil {
				version = v
			}
		}

		if version >= 2 && phaseConfig.EnvID != "" {
			url := fmt.Sprintf("%s/%s/apps/%s/environments/%s", host, orgName, phaseConfig.AppID, phaseConfig.EnvID)
			fmt.Printf("Opening %s\n", url)
			return util.OpenBrowser(url)
		}

		url := fmt.Sprintf("%s/%s/apps/%s", host, orgName, phaseConfig.AppID)
		fmt.Printf("Opening %s\n", url)
		return util.OpenBrowser(url)
	}

	fmt.Printf("Opening %s\n", host)
	return util.OpenBrowser(host)
}
