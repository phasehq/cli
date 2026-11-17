package phase

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testToken(prefix string) string {
	return prefix + "v1:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 64) + ":" + strings.Repeat("d", 64)
}

// isolateHarness clears every variable the harness detector reads, so the
// result does not depend on the tool running the tests.
func isolateHarness(t *testing.T, key, value string) {
	t.Helper()
	for _, name := range []string{"CLAUDECODE", "CURSOR_AGENT", "CODEX", "OPENCODE", "AGENT"} {
		t.Setenv(name, "")
	}
	if key != "" {
		t.Setenv(key, value)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PHASE_HOST", "https://console.phase.invalid")
	aiTokenWarningOnce = sync.Once{}
	t.Cleanup(func() { aiTokenWarningOnce = sync.Once{} })
}

// captureOutput runs fn with os.Stdout and os.Stderr redirected to files and
// returns what each received.
func captureOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	directory := t.TempDir()
	outFile, err := os.Create(filepath.Join(directory, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	errFile, err := os.Create(filepath.Join(directory, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	originalOut, originalErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outFile, errFile
	func() {
		defer func() { os.Stdout, os.Stderr = originalOut, originalErr }()
		fn()
	}()
	_ = outFile.Close()
	_ = errFile.Close()
	out, _ := os.ReadFile(outFile.Name())
	errOut, _ := os.ReadFile(errFile.Name())
	return string(out), string(errOut)
}

func TestNewPhaseWarnsAIToolsAboutBroadTokensOnStderrOnce(t *testing.T) {
	for _, test := range []struct {
		name, key, value, token, harness, holder string
	}{
		{"personal", "CLAUDECODE", "1", testToken("pss_user:"), "Claude Code", "your personal access token"},
		{"service account", "AGENT", "goose", testToken("pss_service:"), "goose", "a service account token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			isolateHarness(t, test.key, test.value)
			t.Setenv("PHASE_SERVICE_TOKEN", test.token)
			stdout, stderr := captureOutput(t, func() {
				for range 3 {
					if _, err := NewPhase(true, "", ""); err != nil {
						t.Fatal(err)
					}
				}
			})
			if stdout != "" {
				t.Fatalf("the warning reached stdout: %q", stdout)
			}
			want := "Phase: tip: " + test.harness + " is using " + test.holder + ". An Agent token gives AI tools narrower access: phase auth --mode token.\n"
			if stderr != want {
				t.Fatalf("stderr = %q, want exactly one line %q", stderr, want)
			}
		})
	}
}

func TestNewPhaseDoesNotWarnOutsideAIToolsOrForOtherCredentials(t *testing.T) {
	cases := map[string]func(t *testing.T){
		"no AI tool": func(t *testing.T) {
			isolateHarness(t, "", "")
			t.Setenv("PHASE_SERVICE_TOKEN", testToken("pss_user:"))
			if _, err := NewPhase(true, "", ""); err != nil {
				t.Fatal(err)
			}
		},
		"Agent token": func(t *testing.T) {
			isolateHarness(t, "CODEX", "1")
			t.Setenv("PHASE_SERVICE_TOKEN", testToken("pss_agent:"))
			if _, err := NewPhase(true, "", ""); err == nil {
				t.Fatal("an Agent token reached the secrets API")
			}
		},
		// phase auth validates a token it was given; it never resolves the
		// stored login, so it must not warn.
		"auth validation": func(t *testing.T) {
			isolateHarness(t, "CLAUDECODE", "1")
			if _, err := NewPhase(false, testToken("pss_user:"), "https://console.phase.invalid"); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			stdout, stderr := captureOutput(t, func() { run(t) })
			if stdout != "" || stderr != "" {
				t.Fatalf("unexpected output: stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}
