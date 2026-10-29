package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func useSkillTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func TestUninstallSkillsRemovesOwnedFileAndPreservesSibling(t *testing.T) {
	home := useSkillTestHome(t)
	skillPath := filepath.Join(home, "custom", "phase-cli", "SKILL.md")
	if err := InstallSkillTo(skillPath); err != nil {
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
	if err := InstallSkillTo(target.Path); err != nil {
		t.Fatal(err)
	}

	// Codex and Devin already share this canonical target; explicit duplicates
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
	if err := InstallSkillTo(modified); err != nil {
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
	if err := InstallSkillTo(skillPath); err != nil {
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

func TestEnableMigratesExactLegacySecretsSkillForClaudeAndCodex(t *testing.T) {
	home := useSkillTestHome(t)
	body := "# Historical Phase secrets skill\n\nExact generated fixture.\n"
	digest := sha256.Sum256([]byte(body))
	previousDigest := legacyApplicationSecretsBodyDigest
	legacyApplicationSecretsBodyDigest = hex.EncodeToString(digest[:])
	t.Cleanup(func() { legacyApplicationSecretsBodyDigest = previousDigest })

	for _, harness := range []string{HarnessClaudeCode, HarnessCodex} {
		t.Run(harness, func(t *testing.T) {
			target, ok := SkillTargetByID(harness)
			if !ok {
				t.Fatalf("missing target %s", harness)
			}
			frontmatter := legacySecretsStandardFrontmatter
			if harness == HarnessClaudeCode {
				frontmatter = legacySecretsClaudeFrontmatter
			}
			if err := os.MkdirAll(filepath.Dir(target.Path), 0o700); err != nil {
				t.Fatal(err)
			}
			legacy := frontmatter + versionHeaderFor("0.17.0") + "\n" + body
			if err := os.WriteFile(target.Path, []byte(legacy), 0o600); err != nil {
				t.Fatal(err)
			}

			result, err := InstallAgentSkillForEnable(target.Path, harness)
			if err != nil {
				t.Fatal(err)
			}
			secretsTarget, _ := SecretsSkillTargetByID(harness)
			if result.MigratedSecretsPath != secretsTarget.Path {
				t.Fatalf("migration path = %q, want %q", result.MigratedSecretsPath, secretsTarget.Path)
			}
			agentPayload, err := os.ReadFile(target.Path)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := recognizedAgentSkill(string(agentPayload)); !ok {
				t.Fatal("source was not replaced with an owned Agent skill")
			}
			secretsPayload, err := os.ReadFile(secretsTarget.Path)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := recognizedOwnedSkill(string(secretsPayload), ApplicationSecretsSkillKind); !ok {
				t.Fatal("migration destination is not an owned application-secrets skill")
			}
			if !strings.Contains(string(secretsPayload), "name: "+SecretsSkillName+"\n") {
				t.Fatalf("migrated skill did not receive the %s identity", SecretsSkillName)
			}
		})
	}
	_ = home
}

func TestEnableMigrationPreservesModifiedSourceAndDestinationConflict(t *testing.T) {
	home := useSkillTestHome(t)
	body := "# Historical Phase secrets skill\n"
	digest := sha256.Sum256([]byte(body))
	previousDigest := legacyApplicationSecretsBodyDigest
	legacyApplicationSecretsBodyDigest = hex.EncodeToString(digest[:])
	t.Cleanup(func() { legacyApplicationSecretsBodyDigest = previousDigest })

	legacy := legacySecretsStandardFrontmatter + versionHeaderFor("0.17.0") + "\n" + body
	for _, test := range []struct {
		name             string
		source           string
		destinationValue string
	}{
		{name: "modified source", source: legacy + "user edit\n"},
		{name: "occupied destination", source: legacy, destinationValue: "user-owned skill\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			agentPath := filepath.Join(home, test.name, AgentSkillName, "SKILL.md")
			secretsPath := filepath.Join(home, test.name, SecretsSkillName, "SKILL.md")
			if err := os.MkdirAll(filepath.Dir(agentPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(agentPath, []byte(test.source), 0o600); err != nil {
				t.Fatal(err)
			}
			if test.destinationValue != "" {
				if err := os.MkdirAll(filepath.Dir(secretsPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(secretsPath, []byte(test.destinationValue), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := InstallAgentSkillForEnable(agentPath, HarnessCodex); err == nil {
				t.Fatal("unsafe migration unexpectedly succeeded")
			}
			gotSource, err := os.ReadFile(agentPath)
			if err != nil || string(gotSource) != test.source {
				t.Fatalf("source changed: %q err=%v", gotSource, err)
			}
			if test.destinationValue != "" {
				gotDestination, err := os.ReadFile(secretsPath)
				if err != nil || string(gotDestination) != test.destinationValue {
					t.Fatalf("destination changed: %q err=%v", gotDestination, err)
				}
			}
		})
	}
}

func TestRefreshAndUninstallRespectSkillOwnershipKind(t *testing.T) {
	home := useSkillTestHome(t)
	agentPath := filepath.Join(home, "custom", AgentSkillName, "SKILL.md")
	secretsPath := filepath.Join(home, "custom", SecretsSkillName, "SKILL.md")
	if err := InstallSkillTo(agentPath); err != nil {
		t.Fatal(err)
	}
	if err := writeSkillAtomic(secretsPath, standardSecretsSkill()); err != nil {
		t.Fatal(err)
	}
	agentPayload, err := os.ReadFile(agentPath)
	if err != nil {
		t.Fatal(err)
	}
	modified := append(agentPayload, []byte("\nuser edit\n")...)
	if err := os.WriteFile(agentPath, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RefreshAgentSkillTo(agentPath); err == nil {
		t.Fatal("refresh accepted a modified Agent skill")
	}
	if got, err := os.ReadFile(agentPath); err != nil || string(got) != string(modified) {
		t.Fatalf("refresh changed modified skill: %q err=%v", got, err)
	}
	if err := writeSkillAtomic(agentPath, cursorSkill()); err != nil {
		t.Fatal(err)
	}
	removed, err := UninstallSkills(agentPath, secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != agentPath {
		t.Fatalf("removed = %v, want only %s", removed, agentPath)
	}
	if _, err := os.Stat(secretsPath); err != nil {
		t.Fatalf("phase-secrets was removed: %v", err)
	}
}

func TestEnablePreservesSymlinkedSkillPath(t *testing.T) {
	home := useSkillTestHome(t)
	target := filepath.Join(home, "user-skill.md")
	if err := os.WriteFile(target, []byte("user-owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "phase-cli", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallAgentSkillForEnable(link, HarnessCodex); err == nil {
		t.Fatal("symlinked skill path was accepted")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "user-owned\n" {
		t.Fatalf("symlink target changed: %q err=%v", got, err)
	}
}

func TestEnableMigratesCanonicalLegacyPhaseSibling(t *testing.T) {
	useSkillTestHome(t)
	body := "# Historical Phase secrets skill\n"
	digest := sha256.Sum256([]byte(body))
	previousDigest := legacyApplicationSecretsBodyDigest
	legacyApplicationSecretsBodyDigest = hex.EncodeToString(digest[:])
	t.Cleanup(func() { legacyApplicationSecretsBodyDigest = previousDigest })

	agentTarget, _ := SkillTargetByID(HarnessClaudeCode)
	legacyPath := filepath.Join(filepath.Dir(filepath.Dir(agentTarget.Path)), "phase", "SKILL.md")
	legacyFrontmatter := strings.Replace(legacySecretsClaudeFrontmatter, "name: phase-cli", "name: phase", 1)
	legacy := legacyFrontmatter + versionHeaderFor("0.17.0") + "\n" + body
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InstallAgentSkillForEnable(agentTarget.Path, HarnessClaudeCode)
	if err != nil {
		t.Fatal(err)
	}
	secretsTarget, _ := SecretsSkillTargetByID(HarnessClaudeCode)
	if result.MigratedSecretsPath != secretsTarget.Path {
		t.Fatalf("migration path = %q, want %q", result.MigratedSecretsPath, secretsTarget.Path)
	}
	if _, err := os.Lstat(legacyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact migrated phase skill remains: %v", err)
	}
	if payload, err := os.ReadFile(secretsTarget.Path); err != nil {
		t.Fatal(err)
	} else if _, owned := recognizedOwnedSkill(string(payload), ApplicationSecretsSkillKind); !owned {
		t.Fatal("phase-secrets destination is not owned")
	}
	if payload, err := os.ReadFile(agentTarget.Path); err != nil {
		t.Fatal(err)
	} else if _, owned := recognizedAgentSkill(string(payload)); !owned {
		t.Fatal("Agent skill was not installed")
	}
}

func TestEnablePreservesModifiedCanonicalLegacyPhaseSibling(t *testing.T) {
	useSkillTestHome(t)
	agentTarget, _ := SkillTargetByID(HarnessCodex)
	legacyPath := filepath.Join(filepath.Dir(filepath.Dir(agentTarget.Path)), "phase", "SKILL.md")
	modified := "user-customized phase skill\n"
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, []byte(modified), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallAgentSkillForEnable(agentTarget.Path, HarnessCodex); err == nil {
		t.Fatal("modified canonical phase skill was accepted")
	}
	if got, err := os.ReadFile(legacyPath); err != nil || string(got) != modified {
		t.Fatalf("modified phase skill changed: %q err=%v", got, err)
	}
	if _, err := os.Lstat(agentTarget.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Agent skill was written after migration failure: %v", err)
	}
}

func TestEnableRefreshesExistingOwnedPhaseSecretsSibling(t *testing.T) {
	useSkillTestHome(t)
	agentTarget, _ := SkillTargetByID(HarnessCodex)
	secretsTarget, _ := SecretsSkillTargetByID(HarnessCodex)
	stale := renderOwnedSkill(secretsStandardFrontmatter, ApplicationSecretsSkillKind, "# stale generated body\n")
	if err := writeSkillAtomic(secretsTarget.Path, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallAgentSkillForEnable(agentTarget.Path, HarnessCodex); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(secretsTarget.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != standardSecretsSkill() {
		t.Fatal("owned phase-secrets sibling was not refreshed")
	}
}

func TestEnablePreservesModifiedPhaseSecretsSiblingWithoutMigration(t *testing.T) {
	useSkillTestHome(t)
	agentTarget, _ := SkillTargetByID(HarnessClaudeCode)
	secretsTarget, _ := SecretsSkillTargetByID(HarnessClaudeCode)
	modified := claudeSecretsSkill() + "\nuser customization\n"
	if err := writeSkillAtomic(secretsTarget.Path, modified); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallAgentSkillForEnable(agentTarget.Path, HarnessClaudeCode); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(secretsTarget.Path)
	if err != nil || string(got) != modified {
		t.Fatalf("modified phase-secrets sibling changed: %q err=%v", got, err)
	}
	if _, err := os.Stat(agentTarget.Path); err != nil {
		t.Fatalf("Agent skill was not installed: %v", err)
	}
}

func TestEnableMigratesReleasedPhaseCliSkillIntoNewLayout(t *testing.T) {
	useSkillTestHome(t)
	body := "# Historical Phase secrets skill\n"
	digest := sha256.Sum256([]byte(body))
	previousDigest := legacyApplicationSecretsBodyDigest
	legacyApplicationSecretsBodyDigest = hex.EncodeToString(digest[:])
	t.Cleanup(func() { legacyApplicationSecretsBodyDigest = previousDigest })

	for _, harness := range []string{HarnessClaudeCode, HarnessCodex} {
		t.Run(harness, func(t *testing.T) {
			agentTarget, _ := SkillTargetByID(harness)
			secretsTarget, _ := SecretsSkillTargetByID(harness)
			skillsDirectory := filepath.Dir(filepath.Dir(agentTarget.Path))
			// The released CLI installed the application-secrets guide here.
			releasedPath := filepath.Join(skillsDirectory, "phase-cli", "SKILL.md")
			frontmatter := legacySecretsStandardFrontmatter
			if harness == HarnessClaudeCode {
				frontmatter = legacySecretsClaudeFrontmatter
			}
			if err := os.MkdirAll(filepath.Dir(releasedPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(releasedPath, []byte(frontmatter+versionHeaderFor("2.3.0")+"\n"+body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := CanonicalAgentSkillPath(releasedPath); got != agentTarget.Path {
				t.Fatalf("CanonicalAgentSkillPath(%s) = %s, want %s", releasedPath, got, agentTarget.Path)
			}
			result, err := InstallAgentSkillForEnable(agentTarget.Path, harness)
			if err != nil {
				t.Fatal(err)
			}
			if result.MigratedSecretsPath != secretsTarget.Path {
				t.Fatalf("migration path = %q, want %q", result.MigratedSecretsPath, secretsTarget.Path)
			}
			if _, err := os.Lstat(releasedPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("released phase-cli skill remains beside the new layout: %v", err)
			}
			if _, err := os.Lstat(filepath.Dir(releasedPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("empty phase-cli directory remains: %v", err)
			}
			secretsPayload, err := os.ReadFile(secretsTarget.Path)
			if err != nil {
				t.Fatal(err)
			}
			if _, owned := recognizedOwnedSkill(string(secretsPayload), ApplicationSecretsSkillKind); !owned || !strings.Contains(string(secretsPayload), "name: "+SecretsSkillName+"\n") {
				t.Fatalf("application-secrets skill was not installed under %s", SecretsSkillName)
			}
			agentPayload, err := os.ReadFile(agentTarget.Path)
			if err != nil {
				t.Fatal(err)
			}
			if _, owned := recognizedAgentSkill(string(agentPayload)); !owned || !strings.Contains(string(agentPayload), "name: "+AgentSkillName+"\n") {
				t.Fatalf("Agent skill was not installed under %s", AgentSkillName)
			}
		})
	}
}

func TestEnableMigratesDevelopmentBuildLayout(t *testing.T) {
	useSkillTestHome(t)
	agentTarget, _ := SkillTargetByID(HarnessClaudeCode)
	secretsTarget, _ := SecretsSkillTargetByID(HarnessClaudeCode)
	skillsDirectory := filepath.Dir(filepath.Dir(agentTarget.Path))
	// Development builds wrote the runtime skill under phase-cli/ and the
	// application-secrets skill under phase-secrets/.
	devAgentPath := filepath.Join(skillsDirectory, "phase-cli", "SKILL.md")
	devSecretsPath := filepath.Join(skillsDirectory, "phase-secrets", "SKILL.md")
	if err := writeSkillAtomic(devAgentPath, renderOwnedSkill(strings.Replace(agentClaudeFrontmatter, "name: "+AgentSkillName, "name: phase-cli", 1), AgentRuntimeSkillKind, "# old runtime body\n")); err != nil {
		t.Fatal(err)
	}
	if err := writeSkillAtomic(devSecretsPath, renderOwnedSkill(strings.Replace(secretsClaudeFrontmatter, "name: "+SecretsSkillName, "name: phase-secrets", 1), ApplicationSecretsSkillKind, "# old secrets body\n")); err != nil {
		t.Fatal(err)
	}
	result, err := InstallAgentSkillForEnable(agentTarget.Path, HarnessClaudeCode)
	if err != nil {
		t.Fatal(err)
	}
	if result.MigratedSecretsPath != secretsTarget.Path {
		t.Fatalf("migration path = %q, want %q", result.MigratedSecretsPath, secretsTarget.Path)
	}
	for _, stale := range []string{devAgentPath, devSecretsPath} {
		if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("development-build skill remains at %s: %v", stale, err)
		}
	}
	if got, err := os.ReadFile(secretsTarget.Path); err != nil || string(got) != claudeSecretsSkill() {
		t.Fatalf("application-secrets skill was not renamed in place: err=%v", err)
	}
	if got, err := os.ReadFile(agentTarget.Path); err != nil || string(got) != claudeCodeSkill() {
		t.Fatalf("Agent skill was not installed under the new name: err=%v", err)
	}
}

func TestEnableLeavesCustomizedPhaseCliSkillAloneAndInstallsBothSkills(t *testing.T) {
	useSkillTestHome(t)
	agentTarget, _ := SkillTargetByID(HarnessCodex)
	secretsTarget, _ := SecretsSkillTargetByID(HarnessCodex)
	customized := filepath.Join(filepath.Dir(filepath.Dir(agentTarget.Path)), "phase-cli", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(customized), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(customized, []byte("# my own phase notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := InstallAgentSkillForEnable(agentTarget.Path, HarnessCodex)
	if err != nil {
		t.Fatal(err)
	}
	if result.MigratedSecretsPath != "" {
		t.Fatalf("customized skill was reported as migrated: %q", result.MigratedSecretsPath)
	}
	if got, err := os.ReadFile(customized); err != nil || string(got) != "# my own phase notes\n" {
		t.Fatalf("customized phase-cli skill changed: %q err=%v", got, err)
	}
	// A fresh enable installs both skills even when nothing was migrated.
	if got, err := os.ReadFile(secretsTarget.Path); err != nil || string(got) != standardSecretsSkill() {
		t.Fatalf("application-secrets skill missing after a fresh enable: err=%v", err)
	}
	if got, err := os.ReadFile(agentTarget.Path); err != nil || string(got) != cursorSkill() {
		t.Fatalf("Agent skill missing after a fresh enable: err=%v", err)
	}
	// Hooks never create the application-secrets skill on their own.
	if err := os.Remove(secretsTarget.Path); err != nil {
		t.Fatal(err)
	}
	if err := InstallSkillTo(agentTarget.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(secretsTarget.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hook refresh created the application-secrets skill: %v", err)
	}
}

func TestCanonicalAgentSkillPathMapsEarlierLayouts(t *testing.T) {
	for input, want := range map[string]string{
		"/home/dev/.claude/skills/phase-cli/SKILL.md":              "/home/dev/.claude/skills/" + AgentSkillName + "/SKILL.md",
		"/home/dev/.claude/skills/phase/SKILL.md":                  "/home/dev/.claude/skills/" + AgentSkillName + "/SKILL.md",
		"/home/dev/.claude/skills/phase-secrets/SKILL.md":          "/home/dev/.claude/skills/" + AgentSkillName + "/SKILL.md",
		"/home/dev/.claude/skills/" + AgentSkillName + "/SKILL.md": "/home/dev/.claude/skills/" + AgentSkillName + "/SKILL.md",
		"/home/dev/custom/notes.md":                                "/home/dev/custom/notes.md",
		"/home/dev/.claude/skills/other/SKILL.md":                  "/home/dev/.claude/skills/other/SKILL.md",
	} {
		if got := CanonicalAgentSkillPath(filepath.FromSlash(input)); got != filepath.FromSlash(want) {
			t.Fatalf("CanonicalAgentSkillPath(%s) = %s, want %s", input, got, want)
		}
	}
}
