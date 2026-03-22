package ai

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/phasehq/cli/pkg/version"
)

//go:embed PHASE.md
var skillContent string

// SkillTarget represents an AI tool that can receive the skill doc.
type SkillTarget struct {
	Name string // Display name
	Path string // Absolute file path
	Note string // Extra context shown in dropdown
}

// SkillVersion returns the skill doc version (matches CLI version).
func SkillVersion() string {
	return version.Version
}

// versionHeader returns the version comment used to detect installed skill docs.
func versionHeader() string {
	return fmt.Sprintf("<!-- phase-cli-skill-version: %s -->", SkillVersion())
}

// SkillContent returns the full skill doc with version header (plain markdown).
func SkillContent() string {
	return versionHeader() + "\n" + skillContent
}

// claudeCodeSkill wraps the skill content with Claude Code SKILL.md frontmatter.
func claudeCodeSkill() string {
	return fmt.Sprintf(`---
name: phase-cli
description: |
  Phase CLI — secrets and environment variable management.
  Use when: managing secrets, environment variables, sealed secrets,
  dynamic credentials, secret rotation, importing .env files,
  running apps with injected secrets, phase run, phase init, phase auth.
user-invocable: true
---

%s
%s`, versionHeader(), skillContent)
}

// cursorSkill wraps the skill content with Cursor's SKILL.md frontmatter.
func cursorSkill() string {
	return fmt.Sprintf(`---
name: phase-cli
description: |
  Phase CLI — secrets and environment variable management.
  Use when: managing secrets, environment variables, sealed secrets,
  dynamic credentials, secret rotation, importing .env files,
  running apps with injected secrets, phase run, phase init, phase auth.
---

%s
%s`, versionHeader(), skillContent)
}

// SkillTargets returns the list of known AI tool skill paths for the current platform.
func SkillTargets() []SkillTarget {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	return []SkillTarget{
		// Claude Code: ~/.claude/skills/phase-cli/SKILL.md — user-invocable via /phase-cli
		{Name: "Claude Code", Path: filepath.Join(home, ".claude", "skills", "phase-cli", "SKILL.md"), Note: "global"},
		// Cursor: ~/.cursor/skills/phase-cli/SKILL.md — auto-discovered, also reads ~/.claude/skills/ and ~/.agents/skills/
		{Name: "Cursor", Path: filepath.Join(home, ".cursor", "skills", "phase-cli", "SKILL.md"), Note: "global"},
		// VS Code Copilot: ~/.copilot/skills/phase-cli/SKILL.md — also reads ~/.claude/skills/ and ~/.agents/skills/
		{Name: "VS Code Copilot", Path: filepath.Join(home, ".copilot", "skills", "phase-cli", "SKILL.md"), Note: "global"},
		// Codex: ~/.agents/skills/phase-cli/SKILL.md — user-level, also read by Cursor/Copilot/OpenCode as fallback
		{Name: "Codex", Path: filepath.Join(home, ".agents", "skills", "phase-cli", "SKILL.md"), Note: "global"},
		// OpenCode: ~/.config/opencode/skills/phase-cli/SKILL.md — also reads ~/.claude/skills/ and ~/.agents/skills/
		{Name: "OpenCode", Path: filepath.Join(home, ".config", "opencode", "skills", "phase-cli", "SKILL.md"), Note: "global"},
	}
}

// InstallSkillTo writes the skill doc to a specific path.
// Detects the target agent by path and applies the appropriate frontmatter.
func InstallSkillTo(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	var content string

	switch {
	case strings.Contains(path, ".claude") || strings.Contains(path, ".copilot"):
		// Claude Code / VS Code Copilot: includes user-invocable frontmatter
		content = claudeCodeSkill()
	default:
		// Cursor / Codex / OpenCode / custom: standard SKILL.md frontmatter
		content = cursorSkill()
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write skill doc: %w", err)
	}
	return nil
}

// UninstallSkill removes the skill doc from all known skill directories.
func UninstallSkill() []string {
	targets := SkillTargets()
	var removed []string
	for _, t := range targets {
		// Remove the entire skill directory (e.g. ~/.claude/skills/phase-cli/)
		skillDir := filepath.Dir(t.Path)
		if err := os.RemoveAll(skillDir); err == nil {
			removed = append(removed, skillDir)
		}
	}
	return removed
}
