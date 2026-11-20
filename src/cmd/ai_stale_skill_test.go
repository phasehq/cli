package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
)

// staleSkillHome installs an old-looking skill under a temporary HOME and
// points the notice at it, never at the real home.
func staleSkillHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	isolateHarnessHome(t, home)
	previousConfig := config.AIConfigPath
	config.AIConfigPath = filepath.Join(home, "no-ai.json")
	previousCheck := staleSkillCheck
	staleSkillCheck = ai.StaleSkills
	t.Cleanup(func() { config.AIConfigPath = previousConfig; staleSkillCheck = previousCheck })

	// A generated skill from an older build: the ownership hash ignores the
	// version value, so an older version header is still Phase's own file.
	target, _ := ai.SkillTargetByID(ai.HarnessClaudeCode)
	if err := os.MkdirAll(filepath.Dir(target.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ai.InstallSkill(target.Path, ai.HarnessClaudeCode); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(target.Path)
	if err != nil {
		t.Fatal(err)
	}
	old := strings.Replace(string(current), "phase-cli-skill-version: "+ai.SkillVersion(), "phase-cli-skill-version: 0.9.0", 1)
	if old == string(current) {
		t.Fatal("version header not found")
	}
	if err := os.WriteFile(target.Path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runCapturing(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	staleSkillOnce = sync.Once{}
	capture := func() (*os.File, func() string) {
		file, e := os.Create(filepath.Join(t.TempDir(), "out"))
		if e != nil {
			t.Fatal(e)
		}
		return file, func() string { _ = file.Close(); data, _ := os.ReadFile(file.Name()); return string(data) }
	}
	outFile, readOut := capture()
	errFile, readErr := capture()
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outFile, errFile
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs(args)
	err = rootCmd.Execute()
	os.Stdout, os.Stderr = origOut, origErr
	rootCmd.SetArgs(nil)
	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	return readOut(), readErr(), err
}

const staleNoticeText = "Phase: the Phase skill installed for Claude Code is from an older CLI. Run phase ai enable to update it.\n"

func TestStaleSkillNoticeGoesToStderrOnceAndLeavesStdoutAlone(t *testing.T) {
	staleSkillHome(t)
	stdout, stderr, err := runCapturing(t, "ai", "skill")
	if err != nil {
		t.Fatal(err)
	}
	if stderr != staleNoticeText {
		t.Fatalf("stderr = %q", stderr)
	}
	if stdout != ai.SkillContent() {
		t.Fatal("stdout changed")
	}
	// A second command in the same process does not repeat it.
	noticeStaleSkill(aiSkillCmd)
	staleSkillOnce.Do(func() {})
	if n := strings.Count(stderr, "Phase: the Phase skill"); n != 1 {
		t.Fatalf("printed %d times", n)
	}
}

func TestStaleSkillNoticeIsSilentWhenNothingIsInstalled(t *testing.T) {
	home := t.TempDir()
	isolateHarnessHome(t, home)
	previousConfig := config.AIConfigPath
	config.AIConfigPath = filepath.Join(home, "no-ai.json")
	previousCheck := staleSkillCheck
	staleSkillCheck = ai.StaleSkills
	t.Cleanup(func() { config.AIConfigPath = previousConfig; staleSkillCheck = previousCheck })
	if _, stderr, err := runCapturing(t, "ai", "skill"); err != nil || stderr != "" {
		t.Fatalf("stderr = %q err=%v", stderr, err)
	}
}

func TestStaleSkillNoticeSkipsExcludedCommands(t *testing.T) {
	staleSkillHome(t)
	for _, args := range [][]string{{"ai", "guide"}, {"completion", "bash"}, {"__complete", "ai", ""}, {"ai", "--help"}, {"--version"}, {"help"}} {
		if _, stderr, err := runCapturing(t, args...); err != nil || strings.Contains(stderr, "older CLI") {
			t.Fatalf("phase %s: stderr=%q err=%v", strings.Join(args, " "), stderr, err)
		}
	}
	// enable and disable do real work, so check the exclusion directly; the
	// hook and daemon commands are hidden internal commands.
	for _, path := range [][]string{{"ai", "enable"}, {"ai", "disable"}, {"ai", "guide"}, {"ai", "__claude-hook"}, {"ai", "__claude-event"}, {"ai", "__codex-hook"}, {"ai", "__cursor-hook"}, {"ai", "__opencode-command"}, {"ai", "__opencode-session"}, {"ai", "__harness-exec"}, {"ai", "__runtime-daemon"}, {"completion", "zsh"}} {
		command, _, err := rootCmd.Find(path)
		if err != nil || command == rootCmd {
			t.Fatalf("command %v not found: %v", path, err)
		}
		if !staleSkillNoticeExcluded(command) {
			t.Errorf("phase %s is not excluded", strings.Join(path, " "))
		}
	}
	if staleSkillNoticeExcluded(aiSkillCmd) {
		t.Error("phase ai skill must show the notice")
	}
}
