//go:build windows

package cmd

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/phasehq/cli/pkg/util"
)

// windowsTestShells returns the shells a harness may run a wrapped command in
// on Windows, each running one exact command line. Missing shells are skipped.
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

// TestWindowsHarnessCommandRunsInEveryWindowsShell runs the rendered wrapper
// form, with curl.exe standing in for the hook executable, in each shell, from
// a plain path and from a path with a space.
func TestWindowsHarnessCommandRunsInEveryWindowsShell(t *testing.T) {
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
		line := windowsHarnessCommand([]string{executable, "--version"})
		for name, run := range shells {
			if strings.HasPrefix(line, "& ") && name != "powershell" && name != "pwsh" {
				// No 8.3 name on this volume: only PowerShell runs the fallback form.
				continue
			}
			output, err := run(line)
			if err != nil || !strings.HasPrefix(strings.TrimSpace(output), "curl ") {
				t.Errorf("%s could not run %q: %v\n%s", name, line, err, output)
			}
		}
	}
}

func TestExecuteHarnessShellRunsRealCurlUnderWindowsPowerShell(t *testing.T) {
	shell := util.GetDefaultShell()
	if len(shell) == 0 || (!strings.Contains(strings.ToLower(shell[0]), "powershell") && !strings.Contains(strings.ToLower(shell[0]), "pwsh")) {
		t.Skip("the default shell is not PowerShell")
	}
	var output bytes.Buffer
	err := executeHarnessShell(context.Background(), "(Get-Command curl).CommandType", os.Environ(), nil, &output, &output)
	if err != nil || strings.TrimSpace(output.String()) != "Application" {
		t.Fatalf("curl in the wrapped PowerShell = %q (err %v), want the real executable, not the Invoke-WebRequest alias", output.String(), err)
	}
}
