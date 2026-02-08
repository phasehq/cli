package util

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type EnvKeyValue struct {
	Key   string
	Value string
}

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

func NormalizeTag(tag string) string {
	return strings.ToLower(strings.ReplaceAll(tag, "_", " "))
}

func TagMatches(secretTags []string, userTag string) bool {
	normalizedUserTag := NormalizeTag(userTag)
	for _, tag := range secretTags {
		normalizedSecretTag := NormalizeTag(tag)
		if strings.Contains(normalizedSecretTag, normalizedUserTag) {
			return true
		}
	}
	return false
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

// GenerateRandomSecret generates a random secret of the specified type and length
func GenerateRandomSecret(randomType string, length int) (string, error) {
	if length <= 0 {
		length = 32
	}

	switch randomType {
	case "hex":
		bytes := make([]byte, length/2+1)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		return hex.EncodeToString(bytes)[:length], nil
	case "alphanumeric":
		const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		result := make([]byte, length)
		for i := range result {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
			if err != nil {
				return "", err
			}
			result[i] = chars[n.Int64()]
		}
		return string(result), nil
	case "key128":
		bytes := make([]byte, 16)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		return hex.EncodeToString(bytes), nil
	case "key256":
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		return hex.EncodeToString(bytes), nil
	case "base64":
		bytes := make([]byte, length)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		encoded := base64.StdEncoding.EncodeToString(bytes)
		if len(encoded) < length {
			return encoded, nil
		}
		return encoded[:length], nil
	case "base64url":
		bytes := make([]byte, length)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		encoded := base64.URLEncoding.EncodeToString(bytes)
		if len(encoded) < length {
			return encoded, nil
		}
		return encoded[:length], nil
	default:
		return "", fmt.Errorf("unsupported random type: %s. Supported types: hex, alphanumeric, base64, base64url, key128, key256", randomType)
	}
}
