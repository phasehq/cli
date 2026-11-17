package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Commands that never resolve the stored login must stay silent even when an
// AI tool runs them with a personal access token in the environment.
func TestBroadTokenWarningSkipsCommandsThatDoNotUseTheLogin(t *testing.T) {
	for _, name := range []string{"CURSOR_AGENT", "CODEX", "OPENCODE", "AGENT"} {
		t.Setenv(name, "")
	}
	t.Setenv("CLAUDECODE", "1")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PHASE_SERVICE_TOKEN", "pss_user:v1:"+strings.Repeat("a", 64)+":"+strings.Repeat("b", 64)+":"+strings.Repeat("c", 64)+":"+strings.Repeat("d", 64))
	for _, args := range [][]string{{"--version"}, {"help"}, {"completion", "bash"}, {"ai", "--help"}, {"auth", "--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stderrPath := filepath.Join(t.TempDir(), "stderr")
			stderrFile, err := os.Create(stderrPath)
			if err != nil {
				t.Fatal(err)
			}
			original := os.Stderr
			os.Stderr = stderrFile
			var out, errOut bytes.Buffer
			rootCmd.SetOut(&out)
			rootCmd.SetErr(&errOut)
			rootCmd.SetArgs(args)
			executeErr := rootCmd.Execute()
			os.Stderr = original
			rootCmd.SetArgs(nil)
			rootCmd.SetOut(nil)
			rootCmd.SetErr(nil)
			_ = stderrFile.Close()
			if executeErr != nil {
				t.Fatal(executeErr)
			}
			written, _ := os.ReadFile(stderrPath)
			if strings.Contains(string(written)+errOut.String()+out.String(), "An Agent token gives") {
				t.Fatalf("phase %s warned about the login it does not use", strings.Join(args, " "))
			}
		})
	}
}
