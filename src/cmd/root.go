package cmd

import (
	"fmt"
	"os"

	phaseerrors "github.com/phasehq/cli/pkg/errors"
	"github.com/phasehq/cli/pkg/version"
	"github.com/spf13/cobra"
)

const phaseASCii = `
             /$$
            | $$
    /$$$$$$ | $$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$
   /$$__  $$| $$__  $$ |____  $$ /$$_____/ /$$__  $$
  | $$  \ $$| $$  \ $$  /$$$$$$$|  $$$$$$ | $$$$$$$$
  | $$  | $$| $$  | $$ /$$__  $$ \____  $$| $$_____/
  | $$$$$$$/| $$  | $$|  $$$$$$$ /$$$$$$$/|  $$$$$$$
  | $$____/ |__/  |__/ \_______/|_______/  \_______/
  | $$
  |__/
`

const description = "Keep Secrets."

var rootCmd = &cobra.Command{
	Use:          "phase",
	Short:        description,
	Long:         description + "\n" + phaseASCii,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", phaseerrors.FormatSDKError(err))
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = version.Version
	rootCmd.SetVersionTemplate("{{ .Version }}\n")

	// Add emojis to built-in cobra commands
	rootCmd.InitDefaultCompletionCmd()
	if completionCmd, _, _ := rootCmd.Find([]string{"completion"}); completionCmd != nil {
		completionCmd.Short = "⌨️\u200A\u200A" + completionCmd.Short
	}
	rootCmd.InitDefaultHelpCmd()
	if helpCmd, _, _ := rootCmd.Find([]string{"help"}); helpCmd != nil {
		helpCmd.Short = "🤷\u200A" + helpCmd.Short
	}
}
