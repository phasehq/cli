package ai

import "testing"

func TestSkillTargetsHaveStableUniqueHarnessIDs(t *testing.T) {
	seen := make(map[string]bool)
	for _, target := range SkillTargets() {
		if target.ID == "" {
			t.Fatalf("target %q has no stable harness ID", target.Name)
		}
		if seen[target.ID] {
			t.Fatalf("duplicate harness ID %q", target.ID)
		}
		seen[target.ID] = true
		resolved, ok := SkillTargetByID(target.ID)
		if !ok || resolved.ID != target.ID || resolved.Path != target.Path {
			t.Fatalf("target %q did not resolve by ID: %#v, %v", target.ID, resolved, ok)
		}
	}
	for _, required := range []string{HarnessClaudeCode, HarnessCursor, HarnessCodex, HarnessDevin, HarnessOpenCode} {
		if !seen[required] {
			t.Fatalf("missing harness target %q", required)
		}
	}
}
