package util

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	sdk "github.com/phasehq/golang-sdk/v2/phase"
)

// ParseEnvFile parses a .env file
func ParseEnvFile(path string) ([]sdk.KeyValuePair, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pairs []sdk.KeyValuePair
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		idx := strings.Index(line, "=")
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		value = sanitizeValue(value)
		pairs = append(pairs, sdk.KeyValuePair{
			Key:   strings.ToUpper(key),
			Value: value,
		})
	}
	return pairs, scanner.Err()
}

func sanitizeValue(value string) string {
	if len(value) >= 2 {
		if (value[0] == '\'' && value[len(value)-1] == '\'') ||
			(value[0] == '"' && value[len(value)-1] == '"') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func GetDefaultShell() []string {
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("pwsh"); err == nil {
			_ = p
			return []string{"pwsh"}
		}
		if p, err := exec.LookPath("powershell"); err == nil {
			_ = p
			return []string{"powershell"}
		}
		return []string{"cmd"}
	}

	shell := os.Getenv("SHELL")
	if shell != "" {
		if _, err := os.Stat(shell); err == nil {
			return []string{shell}
		}
	}

	for _, sh := range []string{"/bin/zsh", "/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(sh); err == nil {
			return []string{sh}
		}
	}
	return nil
}


func ParseBoolFlag(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "false", "no", "0":
		return false
	default:
		return true
	}
}

func GetShellCommand(shellType string) ([]string, error) {
	shell := strings.ToLower(shellType)
	path, err := exec.LookPath(shell)
	if err != nil {
		return nil, fmt.Errorf("shell '%s' not found in PATH: %w", shell, err)
	}
	return []string{path}, nil
}

// ParseTokenLifetime parses a token lifetime string such as "7d", "12h", "30m", "60s"
// or "2w" into a number of seconds. Supported units are s (seconds), m (minutes),
// h (hours), d (days) and w (weeks). An empty string returns 0, meaning the token
// never expires.
func ParseTokenLifetime(lifetime string) (int64, error) {
	lifetime = strings.TrimSpace(strings.ToLower(lifetime))
	if lifetime == "" {
		return 0, nil
	}

	invalid := fmt.Errorf("invalid token lifetime %q (expected a number and a unit, e.g. 7d, 12h, 30m, 60s, 2w)", lifetime)
	if len(lifetime) < 2 {
		return 0, invalid
	}

	value, err := strconv.ParseInt(lifetime[:len(lifetime)-1], 10, 64)
	if err != nil || value < 0 {
		return 0, invalid
	}

	var perUnit int64
	switch lifetime[len(lifetime)-1] {
	case 's':
		perUnit = 1
	case 'm':
		perUnit = 60
	case 'h':
		perUnit = 3600
	case 'd':
		perUnit = 86400
	case 'w':
		perUnit = 604800
	default:
		return 0, invalid
	}

	return value * perUnit, nil
}

// ValidateURL checks that a URL has both a scheme (e.g. https) and a host (e.g. example.com).
func ValidateURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return parsed.Scheme != "" && parsed.Host != ""
}
