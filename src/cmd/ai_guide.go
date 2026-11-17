package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/spf13/cobra"
)

var aiGuideCmd = &cobra.Command{
	Use:   "guide [topic]",
	Short: "📖 Print a Phase AI guide for Agents",
	Long:  "Prints one topic of the Phase guidance for AI tools, or lists the topics. Works without a login or a Phase AI session.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runAIGuide,
}

func init() {
	aiCmd.AddCommand(aiGuideCmd)
}

func runAIGuide(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	if len(args) == 0 {
		_, _ = io.WriteString(out, formatAIGuideTopics())
		return nil
	}
	text, ok := ai.Guide(args[0])
	if !ok {
		return fmt.Errorf("unknown guide topic %q; run `phase ai guide` to list the topics", args[0])
	}
	_, _ = io.WriteString(out, text)
	return nil
}

func formatAIGuideTopics() string {
	topics := ai.GuideTopics()
	width := 0
	for _, topic := range topics {
		width = max(width, len(topic.Name))
	}
	var out strings.Builder
	out.WriteString("Phase AI guides. Read one with `phase ai guide <topic>`:\n\n")
	for _, topic := range topics {
		fmt.Fprintf(&out, "  %-*s  %s\n", width, topic.Name, topic.Summary)
	}
	return out.String()
}
