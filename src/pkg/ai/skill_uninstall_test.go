package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func useSkillTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	isolateHarnessHome(t, home)
	return home
}

// isolateHarnessHome points HOME and every variable a harness uses to find its
// config at the test home, so a test never writes into a real profile.
func isolateHarnessHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, name := range []string{"XDG_CONFIG_HOME", "OPENCODE_CONFIG_DIR", "CLAUDE_CONFIG_DIR", "CLAUDE_ENV_FILE", "CODEX_HOME"} {
		t.Setenv(name, "")
	}
}

func TestUninstallSkillsRemovesOwnedFileAndPreservesSibling(t *testing.T) {
	home := useSkillTestHome(t)
	skillPath := filepath.Join(home, "custom", "phase-cli", "SKILL.md")
	if err := installSkillForTest(t, skillPath); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(filepath.Dir(skillPath), "notes.md")
	if err := os.WriteFile(sibling, []byte("user notes"), 0o600); err != nil {
		t.Fatal(err)
	}

	removed, err := UninstallSkills(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != skillPath {
		t.Fatalf("removed = %v, want [%s]", removed, skillPath)
	}
	if _, err := os.Stat(skillPath); !os.IsNotExist(err) {
		t.Fatalf("Phase skill still exists: %v", err)
	}
	if payload, err := os.ReadFile(sibling); err != nil || string(payload) != "user notes" {
		t.Fatalf("unrelated sibling changed: %q err=%v", payload, err)
	}
	if _, err := os.Stat(filepath.Dir(skillPath)); err != nil {
		t.Fatalf("non-empty parent directory was removed: %v", err)
	}
}

func TestUninstallSkillsDeduplicatesSharedPathAndRemovesEmptyParent(t *testing.T) {
	useSkillTestHome(t)
	target, found := SkillTargetByID(HarnessCodex)
	if !found {
		t.Fatal("Codex skill target is unavailable")
	}
	if err := installSkillForTest(t, target.Path); err != nil {
		t.Fatal(err)
	}

	// Codex already share this canonical target; explicit duplicates
	// must still produce one cleanup operation and one result.
	removed, err := UninstallSkills(target.Path, target.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != target.Path {
		t.Fatalf("removed shared paths = %v, want one %s", removed, target.Path)
	}
	if _, err := os.Stat(filepath.Dir(target.Path)); !os.IsNotExist(err) {
		t.Fatalf("empty Phase skill parent was not removed: %v", err)
	}
}

func TestUninstallSkillsPreservesForeignAndModifiedFiles(t *testing.T) {
	home := useSkillTestHome(t)
	foreign := filepath.Join(home, "foreign", "SKILL.md")
	modified := filepath.Join(home, "modified", "SKILL.md")
	for _, path := range []string{foreign, modified} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(foreign, []byte(versionHeader()+"\n# User-owned skill\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installSkillForTest(t, modified); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(modified)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modified, append(payload, []byte("\nUser customization\n")...), 0o600); err != nil {
		t.Fatal(err)
	}

	removed, err := UninstallSkills(foreign, modified)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("foreign or modified files were removed: %v", removed)
	}
	for _, path := range []string{foreign, modified} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("preserved file %s is missing: %v", path, err)
		}
	}
}

func TestUninstallSkillsRecognizesOlderGeneratedVersionHeader(t *testing.T) {
	home := useSkillTestHome(t)
	skillPath := filepath.Join(home, "legacy", "SKILL.md")
	if err := installSkillForTest(t, skillPath); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	legacyHeader := skillVersionHeaderPrefix + "legacy-0.0.1 -->"
	legacy := strings.Replace(string(payload), versionHeader(), legacyHeader, 1)
	if legacy == string(payload) {
		t.Fatal("test did not replace the generated version marker")
	}
	if err := os.WriteFile(skillPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	removed, err := UninstallSkills(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != skillPath {
		t.Fatalf("older generated skill was not removed: %v", removed)
	}
}

func installSkillForTest(t *testing.T, path string) error {
	t.Helper()
	_, err := InstallSkill(path, "")
	return err
}

// useReleasedSkillFixture makes a compact body stand in for the released
// application-secrets skill, whose real body this build no longer ships.
func useReleasedSkillFixture(t *testing.T) string {
	t.Helper()
	body := "# Historical Phase secrets skill\n\nExact generated fixture.\n"
	digest := sha256.Sum256([]byte(body))
	previous := releasedSkillBodyDigest
	releasedSkillBodyDigest = hex.EncodeToString(digest[:])
	t.Cleanup(func() { releasedSkillBodyDigest = previous })
	return body
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// An upgrade from the released CLI replaces its phase-cli skill in place.
func TestInstallReplacesTheReleasedSkillInPlace(t *testing.T) {
	useSkillTestHome(t)
	body := useReleasedSkillFixture(t)
	for _, harness := range []string{HarnessClaudeCode, HarnessCodex} {
		t.Run(harness, func(t *testing.T) {
			target, _ := SkillTargetByID(harness)
			frontmatter := releasedSkillStandardFrontmatter
			if harness == HarnessClaudeCode {
				frontmatter = releasedSkillClaudeFrontmatter
			}
			writeTestFile(t, target.Path, frontmatter+versionHeaderFor("0.17.0")+"\n"+body)
			result, err := InstallSkill(target.Path, harness)
			if err != nil {
				t.Fatal(err)
			}
			if result.KeptModified {
				t.Fatal("the released skill was treated as edited")
			}
			got, err := os.ReadFile(target.Path)
			if err != nil || string(got) != renderSkill(harness) {
				t.Fatalf("released skill was not replaced: err=%v", err)
			}
		})
	}
}

// A skill someone edited is kept, reported, and left alone by hook refreshes.
func TestInstallAndRefreshKeepAnEditedSkill(t *testing.T) {
	useSkillTestHome(t)
	target, _ := SkillTargetByID(HarnessClaudeCode)
	edited := claudeCodeSkill() + "\nmy own notes\n"
	writeTestFile(t, target.Path, edited)
	result, err := InstallSkill(target.Path, HarnessClaudeCode)
	if err != nil {
		t.Fatal(err)
	}
	if !result.KeptModified {
		t.Fatal("an edited skill was not reported as kept")
	}
	if err := RefreshSkill(target.Path); err != nil {
		t.Fatalf("refresh failed on an edited skill: %v", err)
	}
	if got, err := os.ReadFile(target.Path); err != nil || string(got) != edited {
		t.Fatalf("an edited skill was overwritten: err=%v", err)
	}
}

// Skills from earlier builds beside phase-cli are removed when Phase wrote
// them; an edited one stays.
func TestInstallRemovesRecognisedFormerSkills(t *testing.T) {
	useSkillTestHome(t)
	body := useReleasedSkillFixture(t)
	target, _ := SkillTargetByID(HarnessClaudeCode)
	skills := filepath.Dir(filepath.Dir(target.Path))
	writeTestFile(t, filepath.Join(skills, "phase-cli-ai-relay", "SKILL.md"), signForTest("---\nname: phase-cli-ai-relay\n---\n\n", "agent-runtime", "# earlier runtime skill\n"))
	writeTestFile(t, filepath.Join(skills, "phase-cli-app-secrets", "SKILL.md"), signForTest("", "application-secrets", "# earlier secrets skill\n"))
	writeTestFile(t, filepath.Join(skills, "phase", "SKILL.md"), strings.Replace(releasedSkillClaudeFrontmatter, "name: phase-cli", "name: phase", 1)+versionHeaderFor("0.1.0")+"\n"+body)
	editedFormer := filepath.Join(skills, "phase-secrets", "SKILL.md")
	writeTestFile(t, editedFormer, signForTest("", "application-secrets", "# earlier\n")+"edited\n")

	result, err := InstallSkill(target.Path, HarnessClaudeCode)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RemovedFormer) != 3 {
		t.Fatalf("removed = %v, want the three recognised former skills", result.RemovedFormer)
	}
	for _, directory := range []string{"phase-cli-ai-relay", "phase-cli-app-secrets", "phase"} {
		if _, err := os.Stat(filepath.Join(skills, directory)); !os.IsNotExist(err) {
			t.Fatalf("former skill directory %s remains: %v", directory, err)
		}
	}
	if _, err := os.Stat(editedFormer); err != nil {
		t.Fatalf("an edited former skill was removed: %v", err)
	}
	if got, err := os.ReadFile(target.Path); err != nil || string(got) != claudeCodeSkill() {
		t.Fatalf("phase-cli skill not installed: err=%v", err)
	}
}

func TestUninstallRemovesFormerSkillsBesideEveryTarget(t *testing.T) {
	useSkillTestHome(t)
	target, _ := SkillTargetByID(HarnessCodex)
	former := filepath.Join(filepath.Dir(filepath.Dir(target.Path)), "phase-cli-ai-relay", "SKILL.md")
	if err := installSkillForTest(t, target.Path); err != nil {
		t.Fatal(err)
	}
	// Written after the install, which would otherwise remove it already.
	writeTestFile(t, former, signForTest("", "agent-runtime", "# earlier\n"))
	removed, err := UninstallSkills()
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 {
		t.Fatalf("removed = %v, want the skill and the former skill", removed)
	}
}

func TestInstallRefusesASymlinkedSkillPath(t *testing.T) {
	home := useSkillTestHome(t)
	target := filepath.Join(home, "user-skill.md")
	writeTestFile(t, target, "user-owned\n")
	link := filepath.Join(home, "phase-cli", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallSkill(link, HarnessCodex); err == nil {
		t.Fatal("symlinked skill path was accepted")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "user-owned\n" {
		t.Fatalf("symlink target changed: %q err=%v", got, err)
	}
}

func TestCanonicalSkillPathMapsFormerDirectories(t *testing.T) {
	want := "/home/dev/.claude/skills/" + SkillName + "/SKILL.md"
	for _, directory := range append([]string{SkillName}, formerSkillDirectories...) {
		input := "/home/dev/.claude/skills/" + directory + "/SKILL.md"
		if got := CanonicalSkillPath(filepath.FromSlash(input)); got != filepath.FromSlash(want) {
			t.Fatalf("CanonicalSkillPath(%s) = %s, want %s", input, got, want)
		}
	}
	if got := CanonicalSkillPath(filepath.FromSlash("/custom/notes/SKILL.md")); got != filepath.FromSlash("/custom/notes/SKILL.md") {
		t.Fatalf("a custom path was rewritten: %s", got)
	}
}

// signForTest writes a generated skill with a former ownership kind, the way
// earlier builds signed theirs.
func signForTest(frontmatter, kind, body string) string {
	unsigned := frontmatter + versionHeader() + "\n" + body
	normalized := strings.Replace(unsigned, versionHeader(), versionHeaderFor(skillNormalizedVersion), 1)
	digest := sha256.Sum256([]byte(normalized))
	owner := skillOwnerHeaderPrefix + kind + skillOwnerHeaderHashMarker + hex.EncodeToString(digest[:]) + skillHeaderSuffix
	return frontmatter + versionHeader() + "\n" + owner + "\n" + body
}

func TestUninstallSkillsLeavesALinkedSkillDirectory(t *testing.T) {
	home := useSkillTestHome(t)
	shared := filepath.Join(home, "dotfiles", "phase-cli")
	if err := os.MkdirAll(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := installSkillForTest(t, filepath.Join(shared, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	skills := filepath.Join(home, "harness", "skills")
	if err := os.MkdirAll(skills, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(skills, "phase-cli")
	if err := os.Symlink(shared, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	removed, err := UninstallSkills(filepath.Join(link, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range removed {
		if strings.HasPrefix(path, skills) {
			t.Fatalf("uninstall removed %s through a linked directory", path)
		}
	}
	if _, err := os.Stat(filepath.Join(shared, "SKILL.md")); err != nil {
		t.Fatalf("the skill in the link target was removed: %v", err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link itself was removed: %v", err)
	}
}
