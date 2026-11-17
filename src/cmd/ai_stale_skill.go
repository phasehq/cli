package cmd

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/spf13/cobra"
)

var staleSkillOnce sync.Once

// staleSkillCheck is a variable so the package's tests can keep it away from
// the real home directory.
var staleSkillCheck = ai.StaleSkills

// noticeStaleSkill prints one stderr line, once per process, when a skill Phase
// installed earlier is out of date. stderr keeps stdout byte-identical for
// pipes and redirects.
func noticeStaleSkill(cmd *cobra.Command) {
	if staleSkillNoticeExcluded(cmd) {
		return
	}
	staleSkillOnce.Do(func() {
		if line := ai.StaleSkillNotice(staleSkillCheck()); line != "" {
			_, _ = fmt.Fprintln(os.Stderr, line)
		}
	})
}

// staleSkillNoticeExcluded skips the commands that update the skill or guide
// the reader, anything a harness hook runs (hidden, internal, must stay silent
// and fast), and shell completion.
func staleSkillNoticeExcluded(cmd *cobra.Command) bool {
	for current := cmd; current != nil; current = current.Parent() {
		if current.Hidden || strings.HasPrefix(current.Name(), "__") {
			return true
		}
	}
	switch strings.TrimPrefix(cmd.CommandPath(), rootCmd.Name()+" ") {
	case "ai enable", "ai disable", "ai guide", "help":
		return true
	}
	return cmd.Name() == "completion" || (cmd.Parent() != nil && cmd.Parent().Name() == "completion")
}
