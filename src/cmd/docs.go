package cmd

import (
	"fmt"

	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

var docsCmd = &cobra.Command{
	Use:   "docs",
	Short: "📖 Open the Phase CLI Docs in your browser",
	RunE:  runDocs,
}

func init() {
	rootCmd.AddCommand(docsCmd)
}

func runDocs(cmd *cobra.Command, args []string) error {
	url := "https://docs.phase.dev/cli/commands"
	fmt.Printf("Opening %s\n", url)
	return util.OpenBrowser(url)
}
