package ai

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func staleForTest(configured ...string) []StaleSkill {
	return staleSkillsAmong(SkillTargets(), configured)
}

func writeReleasedSkill(t *testing.T, path string, claude bool, body string) {
	t.Helper()
	frontmatter := releasedSkillStandardFrontmatter
	if claude {
		frontmatter = releasedSkillClaudeFrontmatter
	}
	writeTestFile(t, path, frontmatter+versionHeaderFor("2.3.3")+"\n"+body)
}

func TestStaleSkillsReportsTheReleasedSkillWithItsHarness(t *testing.T) {
	useSkillTestHome(t)
	body := useReleasedSkillFixture(t)
	claude, _ := SkillTargetByID(HarnessClaudeCode)
	writeReleasedSkill(t, claude.Path, true, body)

	stale := staleForTest()
	if len(stale) != 1 || stale[0].Harness != "Claude Code" || stale[0].Path != claude.Path {
		t.Fatalf("stale = %+v", stale)
	}
	want := "Phase: the Phase skill installed for Claude Code is from an older CLI. Run phase ai enable to update it."
	if got := StaleSkillNotice(stale); got != want {
		t.Fatalf("notice = %q", got)
	}
}

func TestStaleSkillsIgnoresCurrentEditedAndMissingFiles(t *testing.T) {
	useSkillTestHome(t)
	if stale := staleForTest(); len(stale) != 0 {
		t.Fatalf("nothing installed but stale = %+v", stale)
	}
	if StaleSkillNotice(nil) != "" {
		t.Fatal("empty result produced a notice")
	}
	claude, _ := SkillTargetByID(HarnessClaudeCode)
	cursor, _ := SkillTargetByID(HarnessCursor)
	if _, err := InstallSkill(claude.Path, HarnessClaudeCode); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallSkill(cursor.Path, HarnessCursor); err != nil {
		t.Fatal(err)
	}
	if stale := staleForTest(); len(stale) != 0 {
		t.Fatalf("current skills reported: %+v", stale)
	}
	// An edit makes the file the person's own.
	body, _ := os.ReadFile(cursor.Path)
	if err := os.WriteFile(cursor.Path, append(body, []byte("\nmy note\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if stale := staleForTest(); len(stale) != 0 {
		t.Fatalf("edited skill reported: %+v", stale)
	}
}

func TestStaleSkillsReportsFormerDirectoriesAsAnAITool(t *testing.T) {
	home := useSkillTestHome(t)
	body := useReleasedSkillFixture(t)
	writeReleasedSkill(t, filepath.Join(home, ".claude", "skills", "phase-cli-app-secrets", "SKILL.md"), true, body)
	stale := staleForTest()
	if len(stale) != 1 || stale[0].Harness != "" {
		t.Fatalf("stale = %+v", stale)
	}
	if got := StaleSkillNotice(stale); !strings.Contains(got, "installed for an AI tool is from an older CLI") {
		t.Fatalf("notice = %q", got)
	}
}

func TestStaleSkillsReportsConfiguredCustomPaths(t *testing.T) {
	home := useSkillTestHome(t)
	body := useReleasedSkillFixture(t)
	custom := filepath.Join(home, "custom", "phase-cli", "SKILL.md")
	writeReleasedSkill(t, custom, false, body)
	stale := staleForTest(custom, custom)
	if len(stale) != 1 || stale[0].Harness != "" || stale[0].Path != custom {
		t.Fatalf("stale = %+v", stale)
	}
}

func TestStaleSkillsJoinsSeveralHarnesses(t *testing.T) {
	home := useSkillTestHome(t)
	body := useReleasedSkillFixture(t)
	for _, id := range []string{HarnessClaudeCode, HarnessCursor, HarnessCodex} {
		target, _ := SkillTargetByID(id)
		writeReleasedSkill(t, target.Path, id == HarnessClaudeCode, body)
	}
	got := StaleSkillNotice(staleForTest())
	want := "Phase: the Phase skill installed for Claude Code, Cursor and Codex is from an older CLI. Run phase ai enable to update it."
	if got != want {
		t.Fatalf("notice = %q", got)
	}
	writeReleasedSkill(t, filepath.Join(home, ".cursor", "skills", "phase", "SKILL.md"), false, body)
	if got := StaleSkillNotice(staleForTest()); !strings.Contains(got, "Claude Code, Cursor, Codex and an AI tool") {
		t.Fatalf("notice = %q", got)
	}
}

func TestStaleSkillsDoesNotFollowSymlinks(t *testing.T) {
	useSkillTestHome(t)
	body := useReleasedSkillFixture(t)
	claude, _ := SkillTargetByID(HarnessClaudeCode)
	real := filepath.Join(t.TempDir(), "SKILL.md")
	writeReleasedSkill(t, real, true, body)
	if err := os.MkdirAll(filepath.Dir(claude.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, claude.Path); err != nil {
		t.Skip("symlinks unavailable")
	}
	if stale := staleForTest(); len(stale) != 0 {
		t.Fatalf("symlinked skill reported: %+v", stale)
	}
}
