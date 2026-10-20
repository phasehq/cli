package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultCursorBootstrapPluginPathUsesOfficialUserLocalDirectory(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	path, err := DefaultCursorBootstrapPluginPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".cursor", "plugins", "local", CursorBootstrapPluginName)
	if path != want {
		t.Fatalf("Cursor plugin path = %q, want %q", path, want)
	}
}

func TestInstallCursorBootstrapPluginIsIdempotentAndPreservesUnrelatedFiles(t *testing.T) {
	parent := t.TempDir()
	t.Setenv("HOME", parent)
	t.Setenv("USERPROFILE", parent)
	root := filepath.Join(parent, CursorBootstrapPluginName)
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
	if err := InstallCursorBootstrapPlugin(root, shared.ExecutablePath); err != nil {
		t.Fatal(err)
	}
	if err := InstallCursorBootstrapPlugin(root, shared.ExecutablePath); err != nil {
		t.Fatal(err)
	}
	manifestPayload, err := os.ReadFile(filepath.Join(root, ".cursor-plugin", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest cursorPluginManifest
	if err := json.Unmarshal(manifestPayload, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Name != CursorBootstrapPluginName || manifest.Author.Name != "Phase" || manifest.Version != HarnessAdapterProtocolVersion || manifest.Hooks != "./hooks/hooks.json" {
		t.Fatalf("unexpected plugin manifest: %#v", manifest)
	}
	markerPayload, err := os.ReadFile(filepath.Join(root, ".phase-owned.json"))
	if err != nil {
		t.Fatal(err)
	}
	var marker cursorPluginMarker
	if json.Unmarshal(markerPayload, &marker) != nil || marker.AdapterProtocol != HarnessAdapterProtocolVersion {
		t.Fatalf("unexpected Cursor adapter marker: %#v", marker)
	}

	readHooks := func() cursorHookFile {
		t.Helper()
		payload, err := os.ReadFile(filepath.Join(root, "hooks", "hooks.json"))
		if err != nil {
			t.Fatal(err)
		}
		var hooks cursorHookFile
		if err := json.Unmarshal(payload, &hooks); err != nil {
			t.Fatal(err)
		}
		return hooks
	}
	hooks := readHooks()
	if hooks.Version != 1 {
		t.Fatalf("hook schema version = %d, want 1", hooks.Version)
	}
	assertHook := func(event, action string, timeout int) cursorHookHandler {
		t.Helper()
		handlers := hooks.Hooks[event]
		if len(handlers) != 1 {
			t.Fatalf("unexpected %s hooks: %#v", event, handlers)
		}
		hook := handlers[0]
		wantCommand := cursorHookCommand(shared.ExecutablePath, strings.Fields(action)...)
		if hook.Type != "command" || hook.Timeout != timeout || hook.Command != wantCommand {
			t.Fatalf("unexpected %s hook: %#v", event, hook)
		}
		return hook
	}
	assertHook("sessionStart", "ai __cursor-hook", 45)
	guard := assertHook("preToolUse", "ai __cursor-event guard", 45)
	if guard.Matcher != "Shell" || guard.FailClosed {
		t.Fatalf("Cursor Shell guard must fail open so silent ordinary commands are never blocked: %#v", guard)
	}
	assertHook("beforeSubmitPrompt", "ai __cursor-event heartbeat", 3)
	assertHook("sessionEnd", "ai __cursor-event session-end", 1)

	unrelatedPath := filepath.Join(root, "keep-me.txt")
	if err := os.WriteFile(unrelatedPath, []byte("user-owned"), 0o600); err != nil {
		t.Fatal(err)
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
	if err := InstallCursorBootstrapPlugin(root, shared.ExecutablePath); err != nil {
		t.Fatal(err)
	}
	installedExecutable := shared.ExecutablePath
	installedPayload, err := os.ReadFile(installedExecutable)
	if err != nil {
		t.Fatal(err)
	}
	if string(installedPayload) != "second-phase-binary" {
		t.Fatalf("stable hook executable was not refreshed: %q", installedPayload)
	}
	if payload, err := os.ReadFile(unrelatedPath); err != nil || string(payload) != "user-owned" {
		t.Fatalf("unrelated plugin file was changed: payload=%q err=%v", payload, err)
	}

	for _, path := range []string{
		filepath.Join(root, ".cursor-plugin", "plugin.json"),
		filepath.Join(root, "hooks", "hooks.json"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", path, info.Mode().Perm())
		}
	}
	if info, err := os.Stat(installedExecutable); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("hook executable mode = %o, want 700", info.Mode().Perm())
	}
}

func TestInstallCursorBootstrapPluginRejectsRelativeExecutable(t *testing.T) {
	root := filepath.Join(t.TempDir(), CursorBootstrapPluginName)
	if err := InstallCursorBootstrapPlugin(root, "phase"); err == nil {
		t.Fatal("relative Phase executable was accepted")
	}
}

func TestUninstallCursorBootstrapPluginRemovesOnlyOwnedPlugin(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, CursorBootstrapPluginName)
	executable := filepath.Join(parent, "phase")
	if err := os.WriteFile(executable, []byte("phase-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := InstallCursorBootstrapPlugin(root, executable); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(parent, "unrelated")
	if err := os.MkdirAll(unrelated, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := UninstallCursorBootstrapPlugin(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("Phase Cursor plugin still exists: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated directory was touched: %v", err)
	}
	if err := UninstallCursorBootstrapPlugin(unrelated); err == nil {
		t.Fatal("unexpected plugin path was accepted")
	}

	foreign := filepath.Join(parent, CursorBootstrapPluginName)
	if err := os.MkdirAll(filepath.Join(foreign, ".cursor-plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, ".cursor-plugin", "plugin.json"), []byte(`{"name":"other"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := UninstallCursorBootstrapPlugin(foreign); err == nil {
		t.Fatal("foreign plugin manifest was accepted")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign plugin was touched: %v", err)
	}
}

func TestCursorPluginRejectsForeignRootAndPreservesUnknownOwnedFiles(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, CursorBootstrapPluginName)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "foreign.txt")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(parent, "phase")
	if err := os.WriteFile(executable, []byte("phase"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := InstallCursorBootstrapPlugin(root, executable); err == nil {
		t.Fatal("foreign Cursor plugin root was overwritten")
	}

	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if err := InstallCursorBootstrapPlugin(root, executable); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := UninstallCursorBootstrapPlugin(root); err != nil {
		t.Fatal(err)
	}
	if payload, err := os.ReadFile(foreign); err != nil || string(payload) != "keep" {
		t.Fatalf("unknown file in owned Cursor root was removed: %q, %v", payload, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".cursor-plugin", "plugin.json")); !os.IsNotExist(err) {
		t.Fatalf("Phase Cursor manifest remains after uninstall: %v", err)
	}
}
