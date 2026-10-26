//go:build windows

package cmd

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/phasehq/cli/pkg/util"
)

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
