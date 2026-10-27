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
		[]string{ai.HarnessClaudeCode, ai.HarnessCursor},
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

func TestInstallConfiguredAIHarnessAdaptersSkipsCodexWithoutItsCLIUnlessSelected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", t.TempDir())
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Codex was enabled earlier, and Cursor is added where codex is not on PATH.
	harnesses := []string{ai.HarnessCodex, ai.HarnessCursor}
	installed, skipped, err := installConfiguredAIHarnessAdapters(context.Background(), harnesses, ai.HarnessCursor, source)
	if err != nil {
		t.Fatalf("adding Cursor failed because the Codex CLI is missing: %v", err)
	}
	if installed[ai.HarnessCursor] == "" || installed[ai.HarnessCodex] != "" || skipped[ai.HarnessCodex] == "" {
		t.Fatalf("installed=%v skipped=%v", installed, skipped)
	}
	if _, _, err := installConfiguredAIHarnessAdapters(context.Background(), harnesses, ai.HarnessCodex, source); err == nil || !strings.Contains(err.Error(), "PATH") {
		t.Fatalf("enabling Codex itself must still require its CLI, got %v", err)
	}
}

func TestAIEnableHarnessRestartMessagesRepeatOriginalPrompt(t *testing.T) {
	tests := []struct {
		harness string
		name    string
	}{
		{harness: ai.HarnessClaudeCode, name: "Claude"},
		{harness: ai.HarnessCursor, name: "Cursor"},
		{harness: ai.HarnessCodex, name: "Codex"},
		{harness: ai.HarnessOpenCode, name: "OpenCode"},
		{harness: ai.HarnessDevin, name: "Devin"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := aiEnableHarnessRestartMessage(test.harness)
			for _, required := range []string{test.name, "start a new", "repeat the original prompt"} {
				if !strings.Contains(message, required) {
					t.Fatalf("restart guidance %q is missing %q", message, required)
				}
			}
			if !strings.Contains(strings.ToLower(message), "restart") || strings.Contains(message, "phase ai enable") {
				t.Fatalf("unexpected restart guidance: %q", message)
			}
		})
	}
	if message := aiEnableHarnessRestartMessage(ai.HarnessCopilot); message != "" {
		t.Fatalf("skill-only Copilot unexpectedly received lifecycle restart guidance: %q", message)
	}
}

func TestFormatAIEnableSummaryEndsWithNextSteps(t *testing.T) {
	codex, _ := ai.SkillTargetByID(ai.HarnessCodex)
	cfg := &config.AIConfig{Enabled: true, MaskSecretValues: true}
	agent := &config.UserConfig{PrincipalType: config.PrincipalAgent}
	summary := formatAIEnableSummary(codex, cfg, agent, map[string]string{ai.HarnessCodex: "Codex Phase discovery adapter installed: phase-ai-bootstrap@phase-cli-local"}, nil)
	if !strings.HasPrefix(summary, "\n") {
		t.Fatalf("summary must be separated from the install log:\n%s", summary)
	}
	for _, required := range []string{
		"✅ Phase AI enabled for Codex", "secret values masked", "Workflow: scoped by your Agent-token login.",
		"👉 Before Codex can use Phase:", "1. Open the Codex CLI, run /hooks, and trust every hook from " + ai.CodexBootstrapPluginName + "@" + ai.CodexBootstrapMarketplaceName + ".",
		"2. " + aiEnableHarnessRestartMessage(ai.HarnessCodex), "ordinary shell commands stay ambient",
		"Add another harness with `phase ai enable --harness <name>`",
	} {
		if !strings.Contains(summary, required) {
			t.Fatalf("summary missing %q:\n%s", required, summary)
		}
	}
	if strings.Contains(summary, "⚠️") {
		t.Fatalf("the selected harness's own hook review must not repeat as a warning:\n%s", summary)
	}
	if nextSteps := strings.Index(summary, "👉"); nextSteps < strings.Index(summary, "✅") || strings.Count(summary, "\n\n") < 2 {
		t.Fatalf("next steps must come last, in their own block:\n%s", summary)
	}

	claude, _ := ai.SkillTargetByID(ai.HarnessClaudeCode)
	user := &config.UserConfig{PrincipalType: "user"}
	summary = formatAIEnableSummary(claude, &config.AIConfig{Enabled: true}, user, map[string]string{ai.HarnessCodex: "refreshed"}, nil)
	for _, required := range []string{
		"AI tools can read secret values", "No default Workflow yet", "👉 Before Claude Code can use Phase:",
		"   " + aiEnableHarnessRestartMessage(ai.HarnessClaudeCode) + "\n", "automatically while the proxy runs",
		"⚠️  Codex: its Phase hook was refreshed too.",
	} {
		if !strings.Contains(summary, required) {
			t.Fatalf("Claude summary missing %q:\n%s", required, summary)
		}
	}
	if strings.Contains(summary, "1. ") {
		t.Fatalf("a single step must not be numbered:\n%s", summary)
	}
	summary = formatAIEnableSummary(claude, &config.AIConfig{Enabled: true, DefaultWorkflowID: "wf-123"}, nil, nil, nil)
	if !strings.Contains(summary, "Default Workflow: wf-123") {
		t.Fatalf("default Workflow missing:\n%s", summary)
	}
	custom := formatAIEnableSummary(ai.SkillTarget{}, cfg, nil, nil, nil)
	if !strings.Contains(custom, "✅ Phase AI enabled\n") || !strings.Contains(custom, "phase ai run -- <agent>") || strings.Contains(custom, "Add another harness") {
		t.Fatalf("custom-path summary:\n%s", custom)
	}
	copilot, _ := ai.SkillTargetByID(ai.HarnessCopilot)
	if summary := formatAIEnableSummary(copilot, cfg, nil, nil, nil); !strings.Contains(summary, "phase ai exec -- <command>") {
		t.Fatalf("Copilot summary must point at phase ai exec:\n%s", summary)
	}
	t.Logf("codex summary:%s", formatAIEnableSummary(codex, cfg, agent, nil, nil))
}

func TestFormatAIEnableSummaryReportsASkippedCodexRefresh(t *testing.T) {
	cursor, _ := ai.SkillTargetByID(ai.HarnessCursor)
	summary := formatAIEnableSummary(cursor, &config.AIConfig{Enabled: true}, nil,
		map[string]string{ai.HarnessCursor: "Cursor Phase discovery adapter installed"},
		map[string]string{ai.HarnessCodex: "the Codex CLI is not on PATH"})
	if !strings.Contains(summary, "⚠️  Codex: its Phase plugin was not refreshed, because the Codex CLI is not on PATH.") ||
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
