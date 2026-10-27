//go:build windows

package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/phasehq/cli/pkg/util"
)

func skipUnlessPowerShellDefault(t *testing.T) {
	t.Helper()
	shell := util.GetDefaultShell()
	if len(shell) == 0 || (!strings.Contains(strings.ToLower(shell[0]), "powershell") && !strings.Contains(strings.ToLower(shell[0]), "pwsh")) {
		t.Skip("the default shell is not PowerShell")
	}
}

func TestExecuteHarnessShellRunsRealCurlUnderWindowsPowerShell(t *testing.T) {
	skipUnlessPowerShellDefault(t)
	var output bytes.Buffer
	err := executeHarnessShell(context.Background(), "(Get-Command curl).CommandType", os.Environ(), nil, &output, &output)
	if err != nil || strings.TrimSpace(output.String()) != "Application" {
		t.Fatalf("curl in the wrapped PowerShell = %q (err %v), want the real executable, not the Invoke-WebRequest alias", output.String(), err)
	}
}

func TestExecuteHarnessShellKeepsTheExitStatusUnderPowerShell(t *testing.T) {
	skipUnlessPowerShellDefault(t)
	for command, want := range map[string]int{
		"cmd /c exit 7":                      7,
		`Get-Item C:\phase-missing-path`:     1,
		"cmd /c exit 7; Write-Output ok":     0,
		"Write-Output ok # trailing comment": 0,
	} {
		err := executeHarnessShell(context.Background(), command, os.Environ(), nil, io.Discard, io.Discard)
		got := 0
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			got = exitError.ExitCode()
		} else if err != nil {
			t.Fatalf("%q: %v", command, err)
		}
		if got != want {
			t.Errorf("%q exited %d, want %d", command, got, want)
		}
	}
}
