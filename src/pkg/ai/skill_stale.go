package ai

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/phasehq/cli/pkg/config"
)

// StaleSkill is a skill file Phase wrote that this CLI would no longer write
// as it is.
type StaleSkill struct {
	Path string
	// Harness is the display name of the tool the path belongs to, or empty
	// for a custom path or a former skill directory.
	Harness string
}

// StaleSkills reports Phase-owned skill files on disk that differ from what
// this CLI would install there. It is read-only and uses the same recognition
// as enable and uninstall, so a file someone edited is never reported. Any
// failure to look yields no result: the notice is a courtesy, not a check.
func StaleSkills() []StaleSkill {
	targets := SkillTargets()
	if len(targets) == 0 {
		return nil
	}
	return staleSkillsAmong(targets, config.LoadAIConfig().ConfiguredSkillInstallPaths())
}

func staleSkillsAmong(targets []SkillTarget, configured []string) []StaleSkill {
	type candidate struct {
		path, harness string
		former        bool
	}
	var candidates []candidate
	for _, target := range targets {
		candidates = append(candidates, candidate{path: target.Path, harness: target.Name})
		for _, directory := range formerSkillDirectories {
			candidates = append(candidates, candidate{
				path:   filepath.Join(filepath.Dir(filepath.Dir(target.Path)), directory, "SKILL.md"),
				former: true,
			})
		}
	}
	for _, path := range configured {
		if absolute, err := filepath.Abs(path); err == nil {
			candidates = append(candidates, candidate{path: absolute, former: CanonicalSkillPath(absolute) != absolute})
		}
	}

	seen := make(map[string]struct{}, len(candidates))
	var stale []StaleSkill
	for _, entry := range candidates {
		path := filepath.Clean(entry.path)
		if _, done := seen[path]; done {
			continue
		}
		seen[path] = struct{}{}
		// Lstat-based: a symlink or oversized file is not a skill Phase wrote.
		payload, _, err := readBoundedRegularFile(path)
		if err != nil {
			continue
		}
		variant, owned := recognizedPhaseSkill(string(payload))
		if !owned {
			continue
		}
		harness := entry.harness
		if !entry.former {
			id := inferredHarness(path)
			if id == "" {
				id = harnessForVariant(variant)
			}
			if string(payload) == renderSkill(id) {
				continue
			}
			if target, ok := SkillTargetByPath(path); ok {
				harness = target.Name
			}
		}
		stale = append(stale, StaleSkill{Path: path, Harness: harness})
	}
	return stale
}

// StaleSkillNotice is the one line printed when stale is not empty, or "".
func StaleSkillNotice(stale []StaleSkill) string {
	if len(stale) == 0 {
		return ""
	}
	var names []string
	generic := false
	for _, skill := range stale {
		switch {
		case skill.Harness == "":
			generic = true
		case !containsString(names, skill.Harness):
			names = append(names, skill.Harness)
		}
	}
	if generic {
		names = append(names, "an AI tool")
	}
	list := strings.Join(names, ", ")
	if len(names) > 1 {
		list = strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
	return fmt.Sprintf("Phase: the Phase skill installed for %s is from an older CLI. Run phase ai enable to update it.", list)
}

func containsString(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}
