package cmd

import (
	"os"

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
	Use:   "phase",
	Short: description,
	Long:  description + "\n" + phaseASCii,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
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
