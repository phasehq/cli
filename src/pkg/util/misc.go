package util

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type EnvKeyValue struct {
	Key   string
	Value string
}

// Parse secrets from a .env file
func ParseEnvFile(path string) ([]EnvKeyValue, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pairs []EnvKeyValue
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
		pairs = append(pairs, EnvKeyValue{
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

func CleanSubprocessEnv() map[string]string {
	env := map[string]string{}
	for _, e := range os.Environ() {
		idx := strings.Index(e, "=")
		if idx < 0 {
			continue
		}
		key := e[:idx]
		value := e[idx+1:]
		// Remove PyInstaller library path variables
		if key == "LD_LIBRARY_PATH" || key == "DYLD_LIBRARY_PATH" {
			continue
		}
		env[key] = value
	}
	return env
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
	shellMap := map[string]string{
		"bash":       "bash",
		"zsh":        "zsh",
		"fish":       "fish",
		"sh":         "sh",
		"powershell": "powershell",
		"pwsh":       "pwsh",
		"cmd":        "cmd",
	}

	bin, ok := shellMap[strings.ToLower(shellType)]
	if !ok {
		return nil, fmt.Errorf("unsupported shell type: %s", shellType)
	}

	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, fmt.Errorf("shell '%s' not found in PATH: %w", bin, err)
	}
	return []string{path}, nil
}
