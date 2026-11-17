package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/util"
)

func TestResolveAIEnableCATrust(t *testing.T) {
	tests := []struct {
		name        string
		flagChanged bool
		flagValue   bool
		interactive bool
		toolMissing bool
		promptValue bool
		wantTrust   bool
		wantPrompt  bool
	}{
		{name: "interactive defaults through prompt", interactive: true, promptValue: true, wantTrust: true, wantPrompt: true},
		{name: "interactive decline", interactive: true, promptValue: false, wantPrompt: true},
		{name: "noninteractive does not mutate trust", interactive: false},
		{name: "explicit noninteractive opt in", flagChanged: true, flagValue: true, wantTrust: true},
		{name: "explicit decline suppresses prompt", flagChanged: true, interactive: true},
		// A stock Linux install has no certutil: the offer is skipped, the
		// user is never asked, and enable continues.
		{name: "missing tool skips the prompt", interactive: true, toolMissing: true, promptValue: true},
		// An explicit opt-in still asks for trust; the caller then fails with
		// the install hint instead of silently skipping.
		{name: "missing tool keeps an explicit opt in", flagChanged: true, flagValue: true, toolMissing: true, wantTrust: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			promptCalls := 0
			trust, prompted, err := resolveAIEnableCATrust(test.flagChanged, test.flagValue, test.interactive, !test.toolMissing, func() (bool, error) {
				promptCalls++
				return test.promptValue, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if trust != test.wantTrust || prompted != test.wantPrompt {
				t.Fatalf("trust=%v prompted=%v, want trust=%v prompted=%v", trust, prompted, test.wantTrust, test.wantPrompt)
			}
			wantCalls := 0
			if test.wantPrompt {
				wantCalls = 1
			}
			if promptCalls != wantCalls {
				t.Fatalf("prompt calls=%d, want %d", promptCalls, wantCalls)
			}
		})
	}
}

func TestResolveAIEnableCATrustPropagatesPromptFailure(t *testing.T) {
	want := errors.New("prompt failed")
	_, prompted, err := resolveAIEnableCATrust(false, false, true, true, func() (bool, error) {
		return false, want
	})
	if !prompted || !errors.Is(err, want) {
		t.Fatalf("prompted=%v err=%v", prompted, err)
	}
}

func TestInstallConfiguredAIHarnessAdaptersRefreshesEveryHelper(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	installed, _, err := installConfiguredAIHarnessAdapters(
		context.Background(),
		&config.AIConfig{HarnessIDs: []string{ai.HarnessClaudeCode, ai.HarnessCursor}},
		ai.HarnessCursor,
		source,
	)
	if err != nil {
		t.Fatal(err)
	}
	if installed[ai.HarnessClaudeCode] == "" || installed[ai.HarnessCursor] == "" {
		t.Fatalf("missing adapter installation results: %v", installed)
	}

	name := "phase-hook-v1"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	claudeRoot, err := ai.DefaultClaudeBootstrapPluginPath()
	if err != nil {
		t.Fatal(err)
	}
	cursorRoot, err := ai.DefaultCursorBootstrapPluginPath()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(home, ".phase", "ai", "bin", name)
	got, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("shared helper %s was not refreshed from the current executable", helper)
	}
	legacyName := "phase-hook"
	if runtime.GOOS == "windows" {
		legacyName += ".exe"
	}
	for _, legacy := range []string{filepath.Join(claudeRoot, "bin", legacyName), filepath.Join(cursorRoot, "bin", legacyName)} {
		if _, err := os.Stat(legacy); !os.IsNotExist(err) {
			t.Fatalf("legacy per-harness helper remains at %s: %v", legacy, err)
		}
	}
}

func TestCodexHookReviewRequiredWhenExistingAdapterIsRefreshed(t *testing.T) {
	// The newly selected harness can be Cursor while the additive installer
	// refreshes a previously configured Codex helper in the same pass.
	installations := map[string]string{
		ai.HarnessCursor: "Cursor automatic Phase bootstrap installed",
		ai.HarnessCodex:  "Codex automatic Phase bootstrap installed",
	}
	if !codexHookReviewRequired(installations) {
		t.Fatal("refreshed Codex adapter did not trigger hook-trust guidance")
	}
	if codexHookReviewRequired(map[string]string{ai.HarnessCursor: installations[ai.HarnessCursor]}) {
		t.Fatal("Codex hook-trust guidance appeared without a Codex refresh")
	}
}

func TestInstallConfiguredAIHarnessAdaptersDoNotNeedCodexForAnotherHarness(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", t.TempDir())
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Codex was enabled earlier, and Cursor is added where codex is not on PATH.
	cfg := &config.AIConfig{HarnessIDs: []string{ai.HarnessCodex, ai.HarnessCursor}}
	installed, skipped, err := installConfiguredAIHarnessAdapters(context.Background(), cfg, ai.HarnessCursor, source)
	if err != nil {
		t.Fatalf("adding Cursor failed because the Codex CLI is missing: %v", err)
	}
	if installed[ai.HarnessCursor] == "" || installed[ai.HarnessCodex] != "" || skipped[ai.HarnessCodex] == "" {
		t.Fatalf("installed=%v skipped=%v", installed, skipped)
	}
	if _, _, err := installConfiguredAIHarnessAdapters(context.Background(), cfg, ai.HarnessCodex, source); err == nil || !strings.Contains(err.Error(), "PATH") {
		t.Fatalf("enabling Codex itself must still require its CLI, got %v", err)
	}
	// Once the Codex adapter is up to date, adding Cursor leaves it alone.
	root, err := ai.DefaultCodexBootstrapMarketplacePath()
	if err != nil {
		t.Fatal(err)
	}
	helper, err := ai.DefaultSharedHookExecutablePath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ai.InstallCodexBootstrapPlugin(root, helper); err != nil {
		t.Fatal(err)
	}
	if installed, skipped, err := installConfiguredAIHarnessAdapters(context.Background(), cfg, ai.HarnessCursor, source); err != nil || len(skipped) != 0 || installed[ai.HarnessCodex] != "" {
		t.Fatalf("an up-to-date Codex adapter was touched or reported: installed=%v skipped=%v err=%v", installed, skipped, err)
	}
}

func TestFormatAIEnableSummaryEndsWithTheFinalStep(t *testing.T) {
	agent := &config.UserConfig{PrincipalType: config.PrincipalAgent}
	cfg := &config.AIConfig{Enabled: true}
	for _, test := range []struct {
		harness, open, restart string
	}{
		{ai.HarnessClaudeCode, "open Claude Code (desktop or CLI)", "Restart Claude Code only if it does not pick up Phase."},
		{ai.HarnessCursor, "open a new Agent chat in Cursor", "Reload the Cursor window only if it does not pick up Phase."},
		{ai.HarnessCodex, "start a new task in Codex (desktop or CLI)", "Restart Codex only if it does not pick up Phase."},
		{ai.HarnessOpenCode, "start a new OpenCode session", "Restart OpenCode only if it does not pick up Phase."},
		{ai.HarnessCopilot, "start a new Copilot chat in VS Code", "Reload VS Code only if Copilot does not pick up the Phase skill."},
	} {
		t.Run(test.harness, func(t *testing.T) {
			target, _ := ai.SkillTargetByID(test.harness)
			summary := formatAIEnableSummary(target, cfg, agent, nil, nil)
			want := "\n" + util.BoldGreen("✅ Phase AI enabled for "+target.Name) + "\n"
			if test.harness == ai.HarnessCodex {
				want += "\n" + util.Bold("Before Codex can use Phase:") + "\n" +
					"   1. Open the Codex CLI, run /hooks, and trust every hook from " + ai.CodexBootstrapPluginName + "@" + ai.CodexBootstrapMarketplaceName + ".\n"
			}
			want += "\n" + util.Bold("👉 Final step: "+test.open+" and say:") + "\n" +
				"   \"Set up an AWS connection using Phase and run get caller identity\"\n" +
				"   " + test.restart + "\n"
			if summary != want {
				t.Fatalf("summary:\n%s\nwant:\n%s", summary, want)
			}
		})
	}
	for _, removed := range []string{"Local proxy", "secret values", "Workflow: scoped", "Add another harness", "Fully quit"} {
		claude, _ := ai.SkillTargetByID(ai.HarnessClaudeCode)
		if summary := formatAIEnableSummary(claude, cfg, agent, nil, nil); strings.Contains(summary, removed) {
			t.Fatalf("summary still says %q:\n%s", removed, summary)
		}
	}

	claude, _ := ai.SkillTargetByID(ai.HarnessClaudeCode)
	user := &config.UserConfig{PrincipalType: "user"}
	summary := formatAIEnableSummary(claude, cfg, user, map[string]string{ai.HarnessCodex: "refreshed"}, nil)
	for _, required := range []string{"Before Claude Code can use Phase:", "   1. Set a default Workflow with `phase ai enable --workflow <id>`.", "⚠️  Codex: its Phase hook was refreshed too."} {
		if !strings.Contains(summary, required) {
			t.Fatalf("Claude summary missing %q:\n%s", required, summary)
		}
	}
	if !strings.HasSuffix(summary, "Restart Claude Code only if it does not pick up Phase.\n") {
		t.Fatalf("the final step must be last:\n%s", summary)
	}
	if summary := formatAIEnableSummary(claude, &config.AIConfig{Enabled: true, DefaultWorkflowID: "wf-123"}, user, nil, nil); strings.Contains(summary, "Workflow") {
		t.Fatalf("a configured Workflow needs no step:\n%s", summary)
	}
	custom := formatAIEnableSummary(ai.SkillTarget{}, cfg, agent, nil, nil)
	if !strings.Contains(custom, "✅ Phase AI enabled\n") || !strings.Contains(custom, "phase ai run -- <agent>") {
		t.Fatalf("custom-path summary:\n%s", custom)
	}
}

func TestFormatAIEnableSummaryReportsASkippedCodexRefresh(t *testing.T) {
	cursor, _ := ai.SkillTargetByID(ai.HarnessCursor)
	summary := formatAIEnableSummary(cursor, &config.AIConfig{Enabled: true}, nil,
		map[string]string{ai.HarnessCursor: "Cursor Phase discovery adapter installed"},
		map[string]string{ai.HarnessCodex: "the Codex CLI is not on PATH"})
	if !strings.Contains(summary, "⚠️  Codex: its Phase plugin is out of date and was not refreshed, because the Codex CLI is not on PATH.") ||
		!strings.Contains(summary, "`phase ai enable --harness codex`") || strings.Contains(summary, "refreshed too") {
		t.Fatalf("a skipped Codex refresh must be reported, without asking to re-trust hooks that did not change:\n%s", summary)
	}
}

func TestTrustAttemptPossibleOnlyWhenADialogCanAppear(t *testing.T) {
	for _, test := range []struct {
		flagChanged, flagValue, interactive, want bool
	}{
		{true, true, false, true}, {true, false, true, false}, {false, false, true, true}, {false, false, false, false},
	} {
		if got := trustAttemptPossible(test.flagChanged, test.flagValue, test.interactive); got != test.want {
			t.Fatalf("trustAttemptPossible(%v, %v, %v) = %v", test.flagChanged, test.flagValue, test.interactive, got)
		}
	}
}
