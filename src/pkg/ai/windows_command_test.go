package ai

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func withShortPathName(t *testing.T, resolve func(string) (string, error)) {
	t.Helper()
	original := shortPathName
	shortPathName = resolve
	t.Cleanup(func() { shortPathName = original })
}

func TestWindowsShellCommandRunsEverywhereOrFallsBack(t *testing.T) {
	arguments := []string{`C:\Users\dev\.phase\ai\bin\phase-hook-v1.exe`, "ai", "__codex-event", "guard"}
	withShortPathName(t, func(string) (string, error) { return "", errors.New("not needed") })
	// PowerShell, cmd and Git Bash all run an unquoted forward-slash path.
	if got, want := WindowsShellCommand(arguments), "C:/Users/dev/.phase/ai/bin/phase-hook-v1.exe ai __codex-event guard"; got != want {
		t.Fatalf("plain path command = %q, want %q", got, want)
	}
	spaced := append([]string{`C:\Users\First Last\.phase\ai\bin\phase-hook-v1.exe`}, arguments[1:]...)
	withShortPathName(t, func(path string) (string, error) {
		if path != spaced[0] {
			t.Fatalf("short name requested for %q", path)
		}
		return `C:\Users\FIRSTL~1\.phase\ai\bin\PHASE-~1.EXE`, nil
	})
	if got, want := WindowsShellCommand(spaced), "C:/Users/FIRSTL~1/.phase/ai/bin/PHASE-~1.EXE ai __codex-event guard"; got != want {
		t.Fatalf("spaced path command = %q, want %q", got, want)
	}
	withShortPathName(t, func(string) (string, error) { return "", errors.New("8.3 names are disabled") })
	quoted := append([]string{`C:\Users\O'Brien Smith\.phase\ai\bin\phase-hook-v1.exe`}, arguments[1:]...)
	if got, want := WindowsShellCommand(quoted), `& 'C:\Users\O''Brien Smith\.phase\ai\bin\phase-hook-v1.exe' 'ai' '__codex-event' 'guard'`; got != want {
		t.Fatalf("fallback command = %q, want %q", got, want)
	}
}

func TestCodexWindowsHookCommandsAvoidALeadingQuotedPath(t *testing.T) {
	withShortPathName(t, func(string) (string, error) { return "", errors.New("not needed") })
	command := codexPluginCommand(`C:\Users\dev\.phase\ai\bin\phase-hook-v1.exe`, true, "ai", "__codex-event", "guard")
	// Codex runs commandWindows in a Windows shell; PowerShell cannot run a
	// command line that starts with a quoted path.
	if strings.HasPrefix(command, `"`) || command != "C:/Users/dev/.phase/ai/bin/phase-hook-v1.exe ai __codex-event guard" {
		t.Fatalf("Codex commandWindows = %q", command)
	}
}

func TestDevinRecognizesEveryWindowsSpellingOfTheHelper(t *testing.T) {
	withShortPathName(t, func(string) (string, error) { return "", errors.New("8.3 names are disabled") })
	helper := `C:\Users\dev\.phase\ai\bin\phase-hook-v1.exe`
	group := func(command string) json.RawMessage {
		payload, err := json.Marshal(devinHookGroup{Matcher: "exec", Hooks: []devinHookHandler{{Type: "command", Command: command, Timeout: 45}}})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	hooks := map[string][]json.RawMessage{"PreToolUse": {
		group(`"C:\Users\dev\.phase\ai\bin\phase-hook-v1.exe" "ai" "__devin-event" "guard"`),
		group("C:/Users/dev/.phase/ai/bin/phase-hook-v1.exe ai __devin-event guard"),
		group("node C:/Users/dev/hooks/audit.js"),
	}}
	removePhaseDevinGroups(hooks, windowsExecutableForms(helper)...)
	if len(hooks["PreToolUse"]) != 1 || !strings.Contains(string(hooks["PreToolUse"][0]), "audit.js") {
		t.Fatalf("Phase groups from earlier and current builds must both be removed, and only them: %s", hooks["PreToolUse"])
	}
}
