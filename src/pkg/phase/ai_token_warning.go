package phase

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/phasehq/cli/pkg/ai"
)

var (
	// aiTokenWarningOutput is stderr: stdout stays byte-identical for
	// `phase secrets export > file` and pipes, and an AI harness reads stderr
	// whether or not it is a terminal.
	aiTokenWarningOutput = func() io.Writer { return os.Stderr }
	aiTokenWarningOnce   sync.Once
)

var harnessDisplayNames = map[string]string{
	"claude-code": "Claude Code",
	"cursor":      "Cursor",
	"codex":       "Codex",
	"opencode":    "OpenCode",
	"devin":       "Devin",
}

var plainHarnessName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// warnAIToolBroadToken prints one line, once per process, when an AI harness
// runs a command with a token that carries a member's or service account's
// full access. It is called only where an authenticated command resolves its
// stored or PHASE_SERVICE_TOKEN credential, so auth, help, version,
// completion and phase ai commands never reach it.
func warnAIToolBroadToken(token string) {
	var holder string
	switch {
	case strings.HasPrefix(token, "pss_user:"):
		holder = "a personal access token, which carries your full Phase access"
	case strings.HasPrefix(token, "pss_service:"):
		holder = "a service account token, which carries the service account's full Phase access"
	default:
		return
	}
	harness := ai.DetectAIAgent()
	if harness == "" {
		return
	}
	aiTokenWarningOnce.Do(func() {
		name := harnessDisplayNames[harness]
		if name == "" && plainHarnessName.MatchString(harness) {
			name = harness
		}
		if name == "" {
			name = "An AI tool"
		}
		_, _ = fmt.Fprintf(aiTokenWarningOutput(),
			"⚠️  Phase: %s is running this command with %s. AI tools should use an Agent token instead (`phase auth --mode token`), which works with `phase ai` commands only.\n",
			name, holder)
	})
}
