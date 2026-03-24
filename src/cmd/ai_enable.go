package cmd

import (
	"fmt"

	"github.com/manifoldco/promptui"
	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
)

var aiEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "🪄  Enable AI integrations and configure secret visibility",
	Long:  "Configure how AI tools interact with your Phase secrets. Sealed secret values are always hidden from AI regardless of settings.",
	RunE:  runAIEnable,
}

func init() {
	aiEnableCmd.Flags().Bool("mask", false, "Mask secret values from AI (non-interactive)")
	aiEnableCmd.Flags().Bool("no-mask", false, "Allow AI to read secret values (non-interactive)")
	aiEnableCmd.Flags().String("path", "", "Install skill doc to a specific path (non-interactive)")
	aiCmd.AddCommand(aiEnableCmd)
}

func runAIEnable(cmd *cobra.Command, args []string) error {
	if ai.IsAIAgent() {
		return fmt.Errorf("phase ai enable must be run by the user directly, not by an AI agent")
	}

	maskFlag, _ := cmd.Flags().GetBool("mask")
	noMaskFlag, _ := cmd.Flags().GetBool("no-mask")
	targetFlag, _ := cmd.Flags().GetString("path")

	// Step 1: Select where to install the skill doc
	var installPath string

	if targetFlag != "" {
		installPath = targetFlag
	} else {
		targets := ai.SkillTargets()
		items := make([]string, 0, len(targets)+1)
		for _, t := range targets {
			if t.Note != "" {
				items = append(items, fmt.Sprintf("%s (%s) → %s", t.Name, t.Note, t.Path))
			} else {
				items = append(items, fmt.Sprintf("%s → %s", t.Name, t.Path))
			}
		}
		items = append(items, "Custom path...")

		targetPrompt := promptui.Select{
			Label: "🪄  Install Phase AI skill for",
			Items: items,
		}
		targetIdx, _, err := targetPrompt.Run()
		if err != nil {
			return fmt.Errorf("prompt cancelled")
		}

		if targetIdx < len(targets) {
			installPath = targets[targetIdx].Path
		} else {
			// Custom path
			pathPrompt := promptui.Prompt{
				Label: "Enter path for skill doc",
			}
			customPath, err := pathPrompt.Run()
			if err != nil {
				return fmt.Errorf("prompt cancelled")
			}
			if customPath == "" {
				return fmt.Errorf("path cannot be empty")
			}
			installPath = customPath
		}
	}

	// Install the skill doc
	if err := ai.InstallSkillTo(installPath); err != nil {
		return fmt.Errorf("failed to install skill doc: %w", err)
	}
	fmt.Printf("🪄 Phase CLI skill (v%s) installed to: %s\n", ai.SkillVersion(), installPath)

	// Step 2: Configure secret visibility
	var maskSecretValues bool

	if maskFlag && noMaskFlag {
		return fmt.Errorf("cannot use both --mask and --no-mask")
	} else if maskFlag {
		maskSecretValues = true
	} else if noMaskFlag {
		maskSecretValues = false
	} else {
		fmt.Println()
		fmt.Println("   Secret visibility for AI agents:")
		fmt.Println("   ┌─────────────┬────────────────────┬──────────────────────────┐")
		fmt.Println("   │ Secret type │ Example            │ AI Visibility            │")
		fmt.Println("   ├─────────────┼────────────────────┼──────────────────────────┤")
		fmt.Println("   │ config      │ REDIS_PORT=6379    │ always visible           │")
		fmt.Println(util.BoldMagenta("   │ secret      │ REDIS_HOST=?.?.?.? │ 👈 mask secret value?    │"))
		fmt.Println("   │ sealed      │ REDIS_PASSWORD=███ │ never visible!           │")
		fmt.Println("   └─────────────┴────────────────────┴──────────────────────────┘")
		fmt.Println()

		maskPrompt := promptui.Select{
			Label: "🔒 Mask secret values from AI agents?",
			Items: []string{
				"Yes — mask secret values",
				"No — allow AI to read secret values (e.g. development environments)",
			},
		}
		maskIdx, _, err := maskPrompt.Run()
		if err != nil {
			return fmt.Errorf("prompt cancelled")
		}
		maskSecretValues = maskIdx == 0
	}

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
