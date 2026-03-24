package ai

import (
	"path/filepath"
	"strings"
)

// blockedRunCommands are commands that would dump secrets injected into the environment.
// Blocked unconditionally when an AI agent is detected.
var blockedRunCommands = []string{"printenv", "env", "export", "set", "declare", "compgen"}

// IsBlockedCommand checks whether the command string contains any blocked command
// as a standalone word. Handles pipes, subshells, &&, ||, semicolons, etc.
// Returns the blocked command name and true if found.
func IsBlockedCommand(command string) (string, bool) {
	fields := strings.FieldsFunc(command, func(r rune) bool {
		return r == '|' || r == ';' || r == '&' || r == '(' || r == ')' || r == '`' || r == '\n'
	})
	for _, field := range fields {
		parts := strings.Fields(strings.TrimSpace(field))
		if len(parts) == 0 {
			continue
		}
		cmd := filepath.Base(parts[0])
		for _, blocked := range blockedRunCommands {
			if cmd == blocked {
				return blocked, true
			}
		}
	}
	return "", false
}
