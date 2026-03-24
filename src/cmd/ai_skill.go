package cmd

import (
	"fmt"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/spf13/cobra"
)

var aiSkillCmd = &cobra.Command{
	Use:   "skill",
	Short: "📄 Print the Phase AI skill document to stdout",
	Long:  "Dumps the raw Phase AI skill markdown to stdout. Pipe it wherever you need: a file, clipboard, or another tool's config.",
	RunE:  runAISkill,
}

func init() {
	aiCmd.AddCommand(aiSkillCmd)
}

func runAISkill(cmd *cobra.Command, args []string) error {
	fmt.Print(ai.SkillContent())
	return nil
}
