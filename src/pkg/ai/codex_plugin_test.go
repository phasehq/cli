package ai

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestInstallCodexBootstrapPluginBuildsPortableMarketplace(t *testing.T) {
	parent := t.TempDir()
	t.Setenv("HOME", parent)
	t.Setenv("USERPROFILE", parent)
	root := filepath.Join(parent, "Phase's Codex Marketplace")
	firstExecutable := filepath.Join(parent, "Phase CLI", "phase")
	if err := os.MkdirAll(filepath.Dir(firstExecutable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstExecutable, []byte("first-phase-binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	shared, err := InstallSharedHookExecutable(firstExecutable)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InstallCodexBootstrapPlugin(root, shared.ExecutablePath); err != nil {
		t.Fatal(err)
	}
	first, err := InstallCodexBootstrapPlugin(root, shared.ExecutablePath)
	if err != nil {
		t.Fatal(err)
	}
	if first.MarketplaceRoot != root || first.PluginRoot != filepath.Join(root, "plugins", CodexBootstrapPluginName) ||
		first.Selector != codexPluginSelector() {
		t.Fatalf("unexpected installation: %#v", first)
	}
	if first.PluginVersion != HarnessAdapterProtocolVersion {
		t.Fatalf("unexpected plugin version %q", first.PluginVersion)
	}
	manifestPath := filepath.Join(first.PluginRoot, ".codex-plugin", "plugin.json")
	manifestPayload, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var rawManifest map[string]json.RawMessage
	if err := json.Unmarshal(manifestPayload, &rawManifest); err != nil {
		t.Fatal(err)
	}
	if _, ok := rawManifest["hooks"]; ok {
		t.Fatal("plugin manifest should use default hooks/hooks.json discovery")
	}
	var manifest codexPluginManifest
	if err := json.Unmarshal(manifestPayload, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Name != CodexBootstrapPluginName || manifest.Version != first.PluginVersion ||
		manifest.Author.Name != "Phase" || manifest.Interface.DisplayName != "Phase AI" {
		t.Fatalf("unexpected plugin manifest: %#v", manifest)
	}

	hooksPayload, err := os.ReadFile(filepath.Join(first.PluginRoot, "hooks", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var hooks codexHookFile
	if err := json.Unmarshal(hooksPayload, &hooks); err != nil {
		t.Fatal(err)
	}
	assertCodexHook := func(event, matcher string, args ...string) codexHookHandler {
		t.Helper()
		groups := hooks.Hooks[event]
		if len(groups) != 1 || groups[0].Matcher != matcher || len(groups[0].Hooks) != 1 {
			t.Fatalf("unexpected %s hook: %#v", event, groups)
		}
		hook := groups[0].Hooks[0]
		if hook.Command != codexPluginCommand(shared.ExecutablePath, false, args...) || hook.CommandWindows != codexPluginCommand(shared.ExecutablePath, true, args...) {
			t.Fatalf("unexpected %s commands: %#v", event, hook)
		}
		if strings.Contains(hook.Command, root) || strings.Contains(hook.CommandWindows, root) {
			t.Fatalf("%s embeds the source marketplace path: %#v", event, hook)
		}
		return hook
	}
	start := assertCodexHook("SessionStart", "startup|resume|clear|compact", "ai", "__codex-hook")
	if start.Timeout != 45 || start.AdditionalContextLimit != 1200 {
		t.Fatalf("unexpected SessionStart limits: %#v", start)
	}
	guard := assertCodexHook("PreToolUse", "Bash", "ai", "__codex-event", "guard")
	if guard.Timeout != 45 {
		t.Fatalf("unexpected guard timeout: %#v", guard)
	}
	assertCodexHook("UserPromptSubmit", "", "ai", "__codex-event", "heartbeat")
	assertCodexHook("SessionEnd", "other", "ai", "__codex-event", "session-end")
	// Codex's hook review dialog shows the status message as the hook's name;
	// an unnamed hook reads as "Hook 3" and looks like a leftover.
	for event, matchers := range hooks.Hooks {
		for _, matcher := range matchers {
			for _, hook := range matcher.Hooks {
				if strings.TrimSpace(hook.StatusMessage) == "" {
					t.Fatalf("%s hook has no status message: %#v", event, hook)
				}
			}
		}
	}

	installedExecutable := shared.ExecutablePath
	if payload, err := os.ReadFile(installedExecutable); err != nil {
		t.Fatal(err)
	} else if string(payload) != "first-phase-binary" {
		t.Fatalf("unexpected copied executable: %q", payload)
	}
	for _, path := range []string{manifestPath, filepath.Join(first.PluginRoot, "hooks", "hooks.json"), codexMarketplaceManifestPath(root)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", path, info.Mode().Perm())
		}
	}
	if info, err := os.Stat(installedExecutable); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("hook executable mode = %o, want 700", info.Mode().Perm())
	}

	document, entries, err := readCodexMarketplace(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || marketplaceEntryName(entries[0]) != CodexBootstrapPluginName {
		t.Fatalf("unexpected marketplace entries: %#v", entries)
	}
	if _, ok := document["interface"]; !ok {
		t.Fatal("marketplace presentation is missing")
	}

	secondExecutable := filepath.Join(parent, "new-bin", "phase")
	if err := os.MkdirAll(filepath.Dir(secondExecutable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondExecutable, []byte("second-phase-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallSharedHookExecutable(secondExecutable); err != nil {
		t.Fatal(err)
	}
	second, err := InstallCodexBootstrapPlugin(root, installedExecutable)
	if err != nil {
		t.Fatal(err)
	}
	if second.PluginVersion != first.PluginVersion {
		t.Fatal("stable adapter protocol changed with the helper implementation")
	}
	if payload, err := os.ReadFile(installedExecutable); err != nil {
		t.Fatal(err)
	} else if string(payload) != "second-phase-binary" {
		t.Fatalf("stable Codex hook executable was not refreshed: %q", payload)
	}
}

func TestInstallCodexBootstrapPluginPreservesUnrelatedMarketplaceDataAndRepairsPartialInstall(t *testing.T) {
	root, executable := installCodexTestPlugin(t)
	document, entries, err := readCodexMarketplace(root)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := json.RawMessage(`{"name":"unrelated","source":{"source":"local","path":"./plugins/unrelated"},"custom":true}`)
	entries = append(entries, unrelated)
	plugins, _ := json.Marshal(entries)
	document["plugins"] = plugins
	document["customTopLevel"] = json.RawMessage(`{"preserve":"me"}`)
	if err := writeJSONFile(codexMarketplaceManifestPath(root), document, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "plugins", CodexBootstrapPluginName, ".codex-plugin", "plugin.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallCodexBootstrapPlugin(root, executable); err != nil {
		t.Fatal(err)
	}
	document, entries, err = readCodexMarketplace(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || marketplaceEntryName(entries[0]) != CodexBootstrapPluginName || marketplaceEntryName(entries[1]) != "unrelated" {
		t.Fatalf("marketplace entries were not safely upserted: %#v", entries)
	}
	if _, ok := document["customTopLevel"]; !ok {
		t.Fatal("unrelated top-level marketplace data was removed")
	}
}

func TestActivateCodexBootstrapPluginUsesOfficialIdempotentCommands(t *testing.T) {
	root, _ := installCodexTestPlugin(t)
	var calls [][]string
	runner := func(_ context.Context, executable string, arguments ...string) ([]byte, error) {
		calls = append(calls, append([]string{executable}, arguments...))
		switch strings.Join(arguments, " ") {
		case "plugin marketplace list --json":
			return []byte(`{"marketplaces":[]}`), nil
		case "plugin marketplace add " + root + " --json", "plugin add " + codexPluginSelector() + " --json":
			return []byte(`{}`), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}
	if err := activateCodexBootstrapPlugin(context.Background(), "/path/to/codex", root, runner); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"/path/to/codex", "plugin", "marketplace", "list", "--json"},
		{"/path/to/codex", "plugin", "marketplace", "add", root, "--json"},
		{"/path/to/codex", "plugin", "add", codexPluginSelector(), "--json"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("commands = %#v, want %#v", calls, want)
	}

	calls = nil
	runner = func(_ context.Context, executable string, arguments ...string) ([]byte, error) {
		calls = append(calls, append([]string{executable}, arguments...))
		if strings.Join(arguments, " ") == "plugin marketplace list --json" {
			payload, _ := json.Marshal(codexMarketplaceList{Marketplaces: []codexMarketplaceInfo{{Name: CodexBootstrapMarketplaceName, Root: root}}})
			return payload, nil
		}
		if strings.Join(arguments, " ") == "plugin add "+codexPluginSelector()+" --json" {
			return []byte(`{}`), nil
		}
		return nil, errors.New("unexpected command")
	}
	if err := activateCodexBootstrapPlugin(context.Background(), "codex", root, runner); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || strings.Contains(strings.Join(calls[1], " "), "marketplace add") {
		t.Fatalf("configured marketplace was added again: %#v", calls)
	}
}

func TestActivateCodexBootstrapPluginRejectsMarketplaceNameCollision(t *testing.T) {
	root, _ := installCodexTestPlugin(t)
	runner := func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		if strings.Join(arguments, " ") != "plugin marketplace list --json" {
			t.Fatalf("unexpected command: %#v", arguments)
		}
		payload, _ := json.Marshal(codexMarketplaceList{Marketplaces: []codexMarketplaceInfo{{Name: CodexBootstrapMarketplaceName, Root: filepath.Join(t.TempDir(), "someone-else")}}})
		return payload, nil
	}
	if err := activateCodexBootstrapPlugin(context.Background(), "codex", root, runner); err == nil || !strings.Contains(err.Error(), "already points") {
		t.Fatalf("expected marketplace collision, got %v", err)
	}
}

func TestUninstallCodexBootstrapPluginRemovesOnlyPhaseOwnedState(t *testing.T) {
	root, _ := installCodexTestPlugin(t)
	unrelatedFile := filepath.Join(root, "keep-me.txt")
	if err := os.WriteFile(unrelatedFile, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	runner := func(_ context.Context, executable string, arguments ...string) ([]byte, error) {
		calls = append(calls, append([]string{executable}, arguments...))
		switch strings.Join(arguments, " ") {
		case "plugin marketplace list --json":
			payload, _ := json.Marshal(codexMarketplaceList{Marketplaces: []codexMarketplaceInfo{{Name: CodexBootstrapMarketplaceName, Root: root}}})
			return payload, nil
		case "plugin list --json":
			payload, _ := json.Marshal(codexPluginList{Installed: []codexInstalledPlugin{{PluginID: codexPluginSelector(), Installed: true}}})
			return payload, nil
		case "plugin remove " + codexPluginSelector() + " --json", "plugin marketplace remove " + CodexBootstrapMarketplaceName + " --json":
			return []byte(`{}`), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}
	if err := uninstallCodexBootstrapPlugin(context.Background(), "codex", root, runner); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(unrelatedFile); err != nil {
		t.Fatalf("unrelated file was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "plugins", CodexBootstrapPluginName)); !os.IsNotExist(err) {
		t.Fatalf("Phase plugin source remains: %v", err)
	}
	for _, command := range []string{"plugin remove " + codexPluginSelector(), "plugin marketplace remove " + CodexBootstrapMarketplaceName} {
		if !callsContain(calls, command) {
			t.Fatalf("missing %q in calls %#v", command, calls)
		}
	}
	calls = nil
	if err := uninstallCodexBootstrapPlugin(context.Background(), "codex", root, runner); err != nil {
		t.Fatalf("idempotent uninstall failed: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("idempotent uninstall invoked Codex: %#v", calls)
	}
}

func TestUninstallCodexBootstrapPluginPreservesUnrelatedMarketplaceEntries(t *testing.T) {
	root, _ := installCodexTestPlugin(t)
	document, entries, err := readCodexMarketplace(root)
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, json.RawMessage(`{"name":"other","source":{"source":"local","path":"./plugins/other"}}`))
	plugins, _ := json.Marshal(entries)
	document["plugins"] = plugins
	if err := writeJSONFile(codexMarketplaceManifestPath(root), document, 0o600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	runner := func(_ context.Context, executable string, arguments ...string) ([]byte, error) {
		calls = append(calls, append([]string{executable}, arguments...))
		switch strings.Join(arguments, " ") {
		case "plugin marketplace list --json":
			payload, _ := json.Marshal(codexMarketplaceList{Marketplaces: []codexMarketplaceInfo{{Name: CodexBootstrapMarketplaceName, Root: root}}})
			return payload, nil
		case "plugin list --json":
			return []byte(`{"installed":[]}`), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}
	if err := uninstallCodexBootstrapPlugin(context.Background(), "codex", root, runner); err != nil {
		t.Fatal(err)
	}
	if callsContain(calls, "marketplace remove") {
		t.Fatalf("shared marketplace registration was removed: %#v", calls)
	}
	_, remaining, err := readCodexMarketplace(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || marketplaceEntryName(remaining[0]) != "other" {
		t.Fatalf("unrelated marketplace entry was not preserved: %#v", remaining)
	}
	if err := uninstallCodexBootstrapPlugin(context.Background(), "codex", root, runner); err != nil {
		t.Fatalf("second uninstall should be a no-op: %v", err)
	}
}

func TestCodexBootstrapPluginRefusesUnownedPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-phase")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "user-file"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(t.TempDir(), "phase")
	if err := os.WriteFile(executable, []byte("phase"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallCodexBootstrapPlugin(root, executable); err == nil || !strings.Contains(err.Error(), "refusing to claim") {
		t.Fatalf("non-empty path was claimed: %v", err)
	}
	if err := uninstallCodexBootstrapPlugin(context.Background(), "codex", root, func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("Codex should not run for an unowned empty state")
		return nil, nil
	}); err != nil {
		t.Fatalf("unowned path without Phase artifacts should be ignored: %v", err)
	}
}

func TestCodexBootstrapPluginCurrentMatchesWhatInstallWrites(t *testing.T) {
	root, executable := installCodexTestPlugin(t)
	if !CodexBootstrapPluginCurrent(root, executable) {
		t.Fatal("the plugin InstallCodexBootstrapPlugin just wrote is not current")
	}
	if CodexBootstrapPluginCurrent(root, executable+"-moved") {
		t.Fatal("hooks that run another helper path are current")
	}
	if CodexBootstrapPluginCurrent(filepath.Join(root, "missing"), executable) {
		t.Fatal("a missing plugin is current")
	}
}

func installCodexTestPlugin(t *testing.T) (string, string) {
	t.Helper()
	parent := t.TempDir()
	root := filepath.Join(parent, "codex-marketplace")
	executable := filepath.Join(parent, "phase")
	if err := os.WriteFile(executable, []byte("phase-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallCodexBootstrapPlugin(root, executable); err != nil {
		t.Fatal(err)
	}
	return root, executable
}

func callsContain(calls [][]string, fragment string) bool {
	for _, call := range calls {
		if strings.Contains(strings.Join(call, " "), fragment) {
			return true
		}
	}
	return false
}
