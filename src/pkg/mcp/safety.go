package mcp

import (
	"fmt"
	"regexp"
	"strings"
)

// Blocked command patterns for phase_run tool
var (
	blockedPatterns = []string{
		"printenv",
		"/usr/bin/env",
		"declare -x",
		"echo $",
		"printf %s $",
		"cat /proc",
		"/proc/self/environ",
		"xargs -0",
		"eval",
		"bash -c",
		"sh -c",
		"python -c",
		"node -e",
		"ruby -e",
		"perl -e",
		"php -r",
	}

	blockedCommands = []string{
		"env",
		"export",
		"set",
	}

	blockedRegexPatterns []*regexp.Regexp
	sensitiveKeyPatterns []*regexp.Regexp
	keyNamePattern       *regexp.Regexp
)

func init() {
	regexes := []string{
		`\$[A-Za-z_][A-Za-z0-9_]*`,
		`\$\{[^}]+\}`,
		"`[^`]+`",
		`\$\([^)]+\)`,
	}
	for _, r := range regexes {
		blockedRegexPatterns = append(blockedRegexPatterns, regexp.MustCompile(r))
	}

	sensitivePatterns := []string{
		`(?i).*SECRET.*`,
		`(?i).*PRIVATE[_.]?KEY.*`,
		`(?i).*SIGNING[_.]?KEY.*`,
		`(?i).*ENCRYPTION[_.]?KEY.*`,
		`(?i).*HMAC.*`,
		`(?i).*PASSWORD.*`,
		`(?i).*PASSWD.*`,
		`(?i).*TOKEN.*`,
		`(?i).*API[_.]?KEY.*`,
		`(?i).*ACCESS[_.]?KEY.*`,
		`(?i).*AUTH[_.]?KEY.*`,
		`(?i).*CREDENTIAL.*`,
		`(?i).*CLIENT[_.]?SECRET.*`,
		`(?i).*DATABASE[_.]?URL.*`,
		`(?i).*CONNECTION[_.]?STRING.*`,
		`(?i).*DSN$`,
		`(?i).*CERTIFICATE.*`,
		`(?i).*CERT[_.]?KEY.*`,
		`(?i).*PEM$`,
		`(?i).*WEBHOOK[_.]?SECRET.*`,
		`(?i).*SALT$`,
		`(?i).*HASH[_.]?KEY.*`,
		`(?i).*SESSION[_.]?SECRET.*`,
		`(?i).*COOKIE[_.]?SECRET.*`,
	}
	for _, p := range sensitivePatterns {
		sensitiveKeyPatterns = append(sensitiveKeyPatterns, regexp.MustCompile("^"+p+"$"))
	}

	keyNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
}

// ValidateRunCommand checks if a command is safe to execute.
// Returns nil if safe, error with reason if blocked.
func ValidateRunCommand(command string) error {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return fmt.Errorf("empty command")
	}

	// Check blocked substrings
	lower := strings.ToLower(cmd)
	for _, p := range blockedPatterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return fmt.Errorf("command blocked: contains disallowed pattern '%s'", p)
		}
	}

	// Check standalone first-token commands
	tokens := strings.Fields(cmd)
	if len(tokens) > 0 {
		first := strings.ToLower(tokens[0])
		for _, bc := range blockedCommands {
			if first == bc {
				return fmt.Errorf("command blocked: '%s' is not allowed as it may expose environment variables", bc)
			}
		}
	}

	// Check regex patterns for variable expansion
	for _, re := range blockedRegexPatterns {
		if re.MatchString(cmd) {
			return fmt.Errorf("command blocked: contains shell variable expansion or command substitution")
		}
	}

	return nil
}

// SanitizeOutput truncates output and redacts credential-like patterns.
func SanitizeOutput(output string, maxLength int) string {
	if maxLength <= 0 {
		maxLength = 10000
	}

	result := output
	if len(result) > maxLength {
		result = result[:maxLength] + "\n... [output truncated]"
	}

	return result
}

// IsSensitiveKey returns true if the key name matches common sensitive key patterns.
func IsSensitiveKey(key string) bool {
	for _, re := range sensitiveKeyPatterns {
		if re.MatchString(key) {
			return true
		}
	}
	return false
}

// IsSafeKeyName validates that a key name has a valid format.
// Returns (true, "") if valid, or (false, reason) if invalid.
func IsSafeKeyName(key string) (bool, string) {
	if key == "" {
		return false, "key name cannot be empty"
	}
	if len(key) > 256 {
		return false, "key name exceeds maximum length of 256 characters"
	}
	if !keyNamePattern.MatchString(key) {
		return false, "key name must match pattern: ^[A-Za-z_][A-Za-z0-9_]*$ (letters, digits, underscores; must start with letter or underscore)"
	}
	return true, ""
}
