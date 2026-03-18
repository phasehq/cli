package cmd

import (
	"fmt"

	"github.com/manifoldco/promptui"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

var aiEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable AI integrations and configure secret visibility",
	Long:  "Configure how AI tools interact with your Phase secrets. Sealed secret values are always hidden from AI regardless of settings.",
	RunE:  runAIEnable,
}

func init() {
	aiCmd.AddCommand(aiEnableCmd)
}

func runAIEnable(cmd *cobra.Command, args []string) error {
	maskPrompt := promptui.Select{
		Label: "🤖 Allow AI agents to see values of secrets and configs? (Note: Sealed secrets are always hidden regardless)",
		Items: []string{"No — mask secret values", "Yes — allow AI to read secret values (suitable for development environments)"},
	}
	maskIdx, _, err := maskPrompt.Run()
	if err != nil {
		return fmt.Errorf("prompt cancelled")
	}
	maskSecretValues := maskIdx == 0

	cfg := &config.AIConfig{
		Version:          "1",
		MaskSecretValues: maskSecretValues,
	}
	if err := config.SaveAIConfig(cfg); err != nil {
		return fmt.Errorf("failed to save AI config: %w", err)
	}

	if maskSecretValues {
		fmt.Println(util.BoldGreen("✅ AI integrations enabled. Secret values are masked from AI tools."))
	} else {
		fmt.Println(util.BoldGreen("✅ AI integrations enabled. AI tools can read secret values."))
	}
	fmt.Println("   Sealed secret values are always hidden from AI regardless of this setting.")
	return nil
}
