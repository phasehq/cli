package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/pkg/config"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

func TestAIStatusCommandIsRegistered(t *testing.T) {
	command, _, err := aiCmd.Find([]string{"status"})
	if err != nil || command == nil || command.Name() != "status" || command.Hidden {
		t.Fatalf("phase ai status is not registered: command=%v err=%v", command, err)
	}
}

func TestRenderAIStatusReportsSetupRuntimeAndCA(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	originalAIConfig := config.AIConfigPath
	config.AIConfigPath = filepath.Join(t.TempDir(), "ai.json")
	t.Cleanup(func() { config.AIConfigPath = originalAIConfig })
	originalConfig := config.ConfigFilePath
	config.ConfigFilePath = filepath.Join(t.TempDir(), "config.json")
	t.Cleanup(func() { config.ConfigFilePath = originalConfig })

	disabled := renderAIStatus(context.Background())
	if !strings.Contains(disabled, "Phase AI:    disabled") || !strings.Contains(disabled, "Login:       none") || !strings.Contains(disabled, "not created yet") {
		t.Fatalf("disabled status:\n%s", disabled)
	}

	if err := config.SaveAIConfig(&config.AIConfig{Enabled: true, ProxyMode: config.AIProxyModeLocal, HarnessIDs: []string{"claude-code", "opencode"}, DefaultWorkflowID: "wf-123", SkillInstallPaths: []string{"/home/dev/.claude/skills/phase-cli-ai-relay/SKILL.md"}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.ConfigFilePath, []byte(`{"default-user":"u1","phase-users":[{"host":"https://console.example.test","id":"u1","email":"dev@example.test"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: "generation-one", RuntimeFingerprint: "binding-one",
		PID: os.Getpid(), StartedAt: time.Now().UTC().Add(-90 * time.Minute), ProxyURL: "http://phase:capability@127.0.0.1:1",
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	connections := []aiproxy.EndpointConnection{{ConnectionID: "aws-1", Name: "aws-prod", ServiceType: "aws", Protocol: "http"}, {ConnectionID: "pg-1", ServiceType: "postgres", Protocol: "postgres"}}
	if err := writeClaudeEnvironment(directory, os.Getpid(), "generation-one", state.StartedAt, testClaudeEnvironmentPlan(), connections, true); err != nil {
		t.Fatal(err)
	}
	_, certPEM, _, err := phaseproxy.GenerateCA(60 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ca.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	status := renderAIStatus(context.Background())
	for _, required := range []string{
		"Phase AI:    enabled, local proxy", "Harnesses:   claude-code, opencode", "Login:       dev@example.test @ https://console.example.test",
		"Workflow:    wf-123", "Proxy:       running (pid", "up 1h30m", "Connections: aws-prod (aws)", "             pg-1 (postgres)",
		"Environment: " + claudeEnvironmentPath(directory) + " (proxy routing active)", "CA:          " + filepath.Join(directory, "ca.pem") + ", expires " + time.Now().UTC().Add(60*24*time.Hour).Format("2006-01-02"),
		"Skills:      /home/dev/.claude/skills/phase-cli-ai-relay/SKILL.md",
	} {
		if !strings.Contains(status, required) {
			t.Fatalf("status missing %q:\n%s", required, status)
		}
	}
	for _, forbidden := range []string{"capability", "AKIADECOY", "pg-decoy"} {
		if strings.Contains(status, forbidden) {
			t.Fatalf("status leaked %q:\n%s", forbidden, status)
		}
	}

	if err := os.Remove(filepath.Join(directory, claudeRuntimeStateFile)); err != nil {
		t.Fatal(err)
	}
	stopped := renderAIStatus(context.Background())
	if !strings.Contains(stopped, "Proxy:       not running") {
		t.Fatalf("stopped status:\n%s", stopped)
	}
}

func TestFormatStatusDuration(t *testing.T) {
	for value, want := range map[time.Duration]string{
		5 * time.Minute: "5m", 90 * time.Minute: "1h30m", 49 * time.Hour: "2d1h",
	} {
		if got := formatStatusDuration(value); got != want {
			t.Fatalf("formatStatusDuration(%s) = %q, want %q", value, got, want)
		}
	}
}
