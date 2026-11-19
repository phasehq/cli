package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/phasehq/cli/pkg/ai"
)

// The guides are read by Agents that may have no session and no login, so the
// command touches neither.
func TestAIGuideListsTopicsAndPrintsOne(t *testing.T) {
	isolateHarnessHome(t, t.TempDir())
	var out bytes.Buffer
	aiGuideCmd.SetOut(&out)
	if err := runAIGuide(aiGuideCmd, nil); err != nil {
		t.Fatal(err)
	}
	for _, topic := range ai.GuideTopics() {
		if !strings.Contains(out.String(), topic.Name) {
			t.Fatalf("topic list is missing %s:\n%s", topic.Name, out.String())
		}
	}
	out.Reset()
	if err := runAIGuide(aiGuideCmd, []string{"app-secrets"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "# App secrets") {
		t.Fatalf("unexpected guide:\n%s", out.String())
	}
	if err := runAIGuide(aiGuideCmd, []string{"unknown"}); err == nil {
		t.Fatal("an unknown topic was accepted")
	}
}
