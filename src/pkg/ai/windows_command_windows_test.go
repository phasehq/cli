//go:build windows

package ai

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// windowsTestShells runs one exact command line in each installed shell.
func windowsTestShells() map[string]func(string) (string, error) {
	shells := map[string]func(string) (string, error){
		"cmd": func(line string) (string, error) {
			command := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
			command.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd.exe /d /s /c "` + line + `"`}
			output, err := command.CombinedOutput()
			return string(output), err
		},
	}
	for _, name := range []string{"powershell", "pwsh"} {
		if path, err := exec.LookPath(name); err == nil {
			shells[name] = func(line string) (string, error) {
				output, err := exec.Command(path, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", line).CombinedOutput()
				return string(output), err
			}
		}
	}
	if bash := filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe"); func() bool { _, err := os.Stat(bash); return err == nil }() {
		shells["git-bash"] = func(line string) (string, error) {
			output, err := exec.Command(bash, "-c", line).CombinedOutput()
			return string(output), err
		}
	}
	return shells
}

// curl.exe stands in for the hook executable, from a plain and a spaced path.
func TestWindowsShellCommandRunsInEveryWindowsShell(t *testing.T) {
	system := filepath.Join(os.Getenv("SystemRoot"), "System32", "curl.exe")
	payload, err := os.ReadFile(system)
	if err != nil {
		t.Skip("curl.exe is not installed")
	}
	directory := filepath.Join(t.TempDir(), "with space")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	spaced := filepath.Join(directory, "curl.exe")
	if err := os.WriteFile(spaced, payload, 0o700); err != nil {
		t.Fatal(err)
	}
	shells := windowsTestShells()
	for _, executable := range []string{system, spaced} {
		line := WindowsShellCommand([]string{executable, "--version"})
		for name, run := range shells {
			if strings.HasPrefix(line, "& ") && name != "powershell" && name != "pwsh" {
				continue
			}
			output, err := run(line)
			if err != nil || !strings.HasPrefix(strings.TrimSpace(output), "curl ") {
				t.Errorf("%s could not run %q: %v\n%s", name, line, err, output)
			}
		}
	}
}
