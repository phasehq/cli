package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHarnessPluginIdentitiesShareStableV1Name(t *testing.T) {
	for harness, name := range map[string]string{
		"claude":   ClaudeBootstrapPluginName,
		"cursor":   CursorBootstrapPluginName,
		"codex":    CodexBootstrapPluginName,
		"opencode": OpenCodePluginName,
	} {
		if name != "phase-ai-bootstrap" {
			t.Fatalf("%s plugin name = %q, want phase-ai-bootstrap", harness, name)
		}
	}
	if HarnessAdapterProtocolVersion != "1.0.0" || HelperIPCProtocolVersion != "1.0.0" {
		t.Fatalf("unexpected v1 protocols: adapter=%s helper=%s", HarnessAdapterProtocolVersion, HelperIPCProtocolVersion)
	}
}

func TestInstallSharedHookExecutableUsesStableV1PathAndDigestMetadata(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	source := filepath.Join(home, "build", "phase")
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("first-phase-binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	first, err := InstallSharedHookExecutable(source)
	if err != nil {
		t.Fatal(err)
	}
	name := "phase-hook-v1"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	wantPath := filepath.Join(home, ".phase", "ai", "bin", name)
	if first.ExecutablePath != wantPath || first.MetadataPath != wantPath+".metadata.json" || !first.Changed {
		t.Fatalf("unexpected shared hook installation: %#v", first)
	}
	if payload, err := os.ReadFile(first.ExecutablePath); err != nil || string(payload) != "first-phase-binary" {
		t.Fatalf("unexpected shared helper: %q, %v", payload, err)
	}
	var metadata sharedHookMetadata
	if payload, err := os.ReadFile(first.MetadataPath); err != nil || json.Unmarshal(payload, &metadata) != nil {
		t.Fatalf("read shared hook metadata: %q, %v", payload, err)
	}
	if metadata.SchemaVersion != 1 || metadata.Owner != "phase-cli" ||
		metadata.AdapterProtocol != HarnessAdapterProtocolVersion || metadata.HelperProtocol != HelperIPCProtocolVersion ||
		metadata.SHA256 != first.Digest {
		t.Fatalf("unexpected shared hook metadata: %#v", metadata)
	}
	second, err := InstallSharedHookExecutable(source)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed || second.RepairedDrift || second.Digest != first.Digest {
		t.Fatalf("unchanged helper was treated as changed: %#v", second)
	}

	if err := os.WriteFile(source, []byte("second-phase-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	third, err := InstallSharedHookExecutable(source)
	if err != nil {
		t.Fatal(err)
	}
	if !third.Changed || third.Digest == first.Digest {
		t.Fatalf("updated helper was not detected: %#v", third)
	}
	if payload, err := os.ReadFile(third.ExecutablePath); err != nil || string(payload) != "second-phase-binary" {
		t.Fatalf("shared helper was not refreshed: %q, %v", payload, err)
	}
}

func TestInstallSharedHookExecutableRepairsOwnedDriftAndRejectsUnownedFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	source := filepath.Join(home, "phase")
	if err := os.WriteFile(source, []byte("expected"), 0o700); err != nil {
		t.Fatal(err)
	}
	installed, err := InstallSharedHookExecutable(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed.ExecutablePath, []byte("drifted"), 0o700); err != nil {
		t.Fatal(err)
	}
	repaired, err := InstallSharedHookExecutable(source)
	if err != nil {
		t.Fatal(err)
	}
	if !repaired.Changed || !repaired.RepairedDrift {
		t.Fatalf("owned drift was not reported: %#v", repaired)
	}

	if err := UninstallSharedHookExecutable(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(installed.ExecutablePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed.ExecutablePath, []byte("foreign"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallSharedHookExecutable(source); err == nil {
		t.Fatal("unowned shared helper was overwritten")
	}
}
