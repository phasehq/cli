package cmd

import (
	"fmt"
	"os"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

var aiDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "🚫 Disable AI integrations",
	Long:  "Remove AI configuration. The CLI will no longer apply AI-specific guardrails or redaction.",
	RunE:  runAIDisable,
}

func init() {
	aiCmd.AddCommand(aiDisableCmd)
}

func runAIDisable(cmd *cobra.Command, args []string) error {
	if ai.IsAIAgent() {
		return fmt.Errorf("phase ai disable must be run by the user directly, not by an AI agent")
	}

	if err := os.Remove(config.AIConfigPath); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("AI integrations are not currently enabled.")
			return nil
		}
		return fmt.Errorf("failed to remove AI config: %w", err)
	}

	// Remove skill docs from global AI tool directories
	removed := ai.UninstallSkill()
	if len(removed) > 0 {
		for _, p := range removed {
			fmt.Printf("   Removed skill doc: %s\n", p)
		}
	}

	fmt.Println(util.BoldGreen("✅ AI integrations disabled. AI-specific redaction and guardrails removed."))
	return nil
}
