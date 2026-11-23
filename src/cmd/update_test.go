package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/phasehq/cli/pkg/ai"
)

func TestRefreshSharedAIHookAfterUpdateDoesNotInstallOrRewriteAdapters(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	first := filepath.Join(home, "phase-first")
	second := filepath.Join(home, "phase-second")
	if err := os.WriteFile(first, []byte("first"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("second"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := refreshSharedAIHookAfterUpdate(first); err != nil {
		t.Fatal(err)
	}
	hookPath, err := ai.DefaultSharedHookExecutablePath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Fatalf("CLI update created an unconfigured shared hook: %v", err)
	}

	installed, err := ai.InstallSharedHookExecutable(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := refreshSharedAIHookAfterUpdate(second); err != nil {
		t.Fatal(err)
	}
	if payload, err := os.ReadFile(installed.ExecutablePath); err != nil || string(payload) != "second" {
		t.Fatalf("shared helper was not refreshed: %q, %v", payload, err)
	}
}
