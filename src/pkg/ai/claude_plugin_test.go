package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCopyClaudeHookExecutablePreservesSourceModTimeAcrossHarnessCopies(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "phase")
	if err := os.WriteFile(source, []byte("same-phase-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, time.August, 10, 8, 0, 0, 123456000, time.UTC)
	if err := os.Chtimes(source, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	sourceInfo, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}

	var installedTimes []time.Time
	for _, name := range []string{"claude-hook", "codex-hook"} {
		destination := filepath.Join(directory, name)
		if err := copyClaudeHookExecutable(source, destination); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(destination)
		if err != nil {
			t.Fatal(err)
		}
		if !info.ModTime().Equal(sourceInfo.ModTime()) {
			t.Fatalf("%s mtime = %s, want source mtime %s", name, info.ModTime(), sourceInfo.ModTime())
		}
		installedTimes = append(installedTimes, info.ModTime())
	}
	if !installedTimes[0].Equal(installedTimes[1]) {
		t.Fatalf("concurrent harness copies have different mtimes: %s and %s", installedTimes[0], installedTimes[1])
	}
}

func TestInstallClaudeBootstrapPluginUsesExecFormAndIsIdempotent(t *testing.T) {
	parent := t.TempDir()
	t.Setenv("HOME", parent)
	t.Setenv("USERPROFILE", parent)
	root := filepath.Join(parent, ClaudeBootstrapPluginName)
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
	if err := InstallClaudeBootstrapPlugin(root, shared.ExecutablePath); err != nil {
		t.Fatal(err)
	}
	installedExecutable := shared.ExecutablePath
	manifestPayload, err := os.ReadFile(filepath.Join(root, ".claude-plugin", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest claudePluginManifest
	if err := json.Unmarshal(manifestPayload, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Name != ClaudeBootstrapPluginName || manifest.Version != HarnessAdapterProtocolVersion || manifest.Author.Name != "Phase" ||
		manifest.Schema != "https://json.schemastore.org/claude-code-plugin-manifest.json" {
		t.Fatalf("unexpected plugin manifest: %#v", manifest)
	}

	readHooks := func() claudeHookFile {
		t.Helper()
		payload, err := os.ReadFile(filepath.Join(root, "hooks", "hooks.json"))
		if err != nil {
			t.Fatal(err)
		}
		var hooks claudeHookFile
		if err := json.Unmarshal(payload, &hooks); err != nil {
			t.Fatal(err)
		}
		return hooks
	}
	readHook := func() claudeHookHandler {
		t.Helper()
		groups := readHooks().Hooks["SessionStart"]
		if len(groups) != 1 || groups[0].Matcher != "startup|resume|clear|compact|fork" || len(groups[0].Hooks) != 1 {
			t.Fatalf("unexpected SessionStart hook: %#v", groups)
		}
		return groups[0].Hooks[0]
	}
	hook := readHook()
	if hook.Command != installedExecutable || len(hook.Args) != 2 || hook.Args[0] != "ai" || hook.Args[1] != "__claude-hook" {
		t.Fatalf("unexpected exec-form hook: %#v", hook)
	}
	hooks := readHooks()
	if guard, present := hooks.Hooks["PreToolUse"]; present {
		t.Fatalf("transparent mode must not run a per-command hook: %#v", guard)
	}
	if _, present := hooks.Hooks["FileChanged"]; present {
		t.Fatalf("credential recovery must not depend on FileChanged: %#v", hooks.Hooks["FileChanged"])
	}
	for event, action := range map[string]string{"UserPromptSubmit": "heartbeat", "SessionEnd": "session-end"} {
		groups := hooks.Hooks[event]
		if len(groups) != 1 || len(groups[0].Hooks) != 1 || len(groups[0].Hooks[0].Args) != 3 || groups[0].Hooks[0].Args[2] != action {
			t.Fatalf("unexpected %s hook: %#v", event, groups)
		}
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
	if err := InstallClaudeBootstrapPlugin(root, installedExecutable); err != nil {
		t.Fatal(err)
	}
	if hook = readHook(); hook.Command != installedExecutable {
		t.Fatalf("reinstalled hook command = %q, want %q", hook.Command, installedExecutable)
	}
	installedPayload, err := os.ReadFile(installedExecutable)
	if err != nil {
		t.Fatal(err)
	}
	if string(installedPayload) != "second-phase-binary" {
		t.Fatalf("stable hook executable was not refreshed: %q", installedPayload)
	}
	for _, path := range []string{
		filepath.Join(root, ".claude-plugin", "plugin.json"),
		filepath.Join(root, "hooks", "hooks.json"),
	} {
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
}

func TestUninstallClaudeBootstrapPluginRemovesOnlyOwnedPlugin(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, ClaudeBootstrapPluginName)
	executable := filepath.Join(parent, "phase")
	if err := os.WriteFile(executable, []byte("phase-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := InstallClaudeBootstrapPlugin(root, executable); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(parent, "unrelated")
	if err := os.MkdirAll(unrelated, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := UninstallClaudeBootstrapPlugin(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("Phase plugin still exists: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated directory was touched: %v", err)
	}
	if err := UninstallClaudeBootstrapPlugin(unrelated); err == nil {
		t.Fatal("unexpected plugin path was accepted")
	}
}
