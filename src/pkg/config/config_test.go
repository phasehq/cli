package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeConfig writes a Config as config.json into dir and returns the path.
func writeConfig(t *testing.T, dir string, cfg Config) string {
	t.Helper()
	path := filepath.Join(dir, "config.json")
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// overrideConfigPath swaps ConfigFilePath for the duration of the test.
func overrideConfigPath(t *testing.T, path string) {
	t.Helper()
	original := ConfigFilePath
	ConfigFilePath = path
	t.Cleanup(func() { ConfigFilePath = original })
}

func TestGetDefaultUserHost_PHASEHOSTTakesPrecedence(t *testing.T) {
	t.Setenv("PHASE_HOST", "https://override.example.com")

	host, err := GetDefaultUserHost()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "https://override.example.com" {
		t.Fatalf("got %s, want PHASE_HOST value", host)
	}
}

func TestGetDefaultUserHost_PHASEHOSTOverridesServiceToken(t *testing.T) {
	t.Setenv("PHASE_HOST", "https://override.example.com")
	t.Setenv("PHASE_SERVICE_TOKEN", "pss_service:v1:sometoken")

	host, err := GetDefaultUserHost()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "https://override.example.com" {
		t.Fatalf("got %s, want PHASE_HOST to win over service token", host)
	}
}

func TestGetDefaultUserHost_PHASEHOSTOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	overrideConfigPath(t, writeConfig(t, dir, Config{
		DefaultUser: "user-123",
		PhaseUsers:  []UserConfig{{ID: "user-123", Host: "https://self-hosted.example.com"}},
	}))
	t.Setenv("PHASE_HOST", "https://override.example.com")

	host, err := GetDefaultUserHost()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "https://override.example.com" {
		t.Fatalf("got %s, want PHASE_HOST to win over config.json", host)
	}
}

func TestGetDefaultUserHost_ServiceTokenDefaultsToCloud(t *testing.T) {
	t.Setenv("PHASE_HOST", "")
	t.Setenv("PHASE_SERVICE_TOKEN", "pss_service:v1:sometoken")

	host, err := GetDefaultUserHost()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != PhaseCloudAPIHost {
		t.Fatalf("got %s, want cloud host for service token with no PHASE_HOST", host)
	}
}

func TestGetDefaultUserHost_FromConfig(t *testing.T) {
	dir := t.TempDir()
	overrideConfigPath(t, writeConfig(t, dir, Config{
		DefaultUser: "user-123",
		PhaseUsers:  []UserConfig{{ID: "user-123", Host: "https://self-hosted.example.com"}},
	}))
	t.Setenv("PHASE_HOST", "")
	t.Setenv("PHASE_SERVICE_TOKEN", "")

	host, err := GetDefaultUserHost()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "https://self-hosted.example.com" {
		t.Fatalf("got %s, want host from config.json", host)
	}
}

func TestGetDefaultUserHost_NoConfigNoToken(t *testing.T) {
	overrideConfigPath(t, "/nonexistent/path/config.json")
	t.Setenv("PHASE_HOST", "")
	t.Setenv("PHASE_SERVICE_TOKEN", "")

	_, err := GetDefaultUserHost()
	if err == nil {
		t.Fatal("expected error when no config and no token, got nil")
	}
}

func TestGetDefaultUserHost_ConfigMissingDefaultUser(t *testing.T) {
	dir := t.TempDir()
	overrideConfigPath(t, writeConfig(t, dir, Config{
		DefaultUser: "user-999",
		PhaseUsers:  []UserConfig{{ID: "user-123", Host: "https://self-hosted.example.com"}},
	}))
	t.Setenv("PHASE_HOST", "")
	t.Setenv("PHASE_SERVICE_TOKEN", "")

	_, err := GetDefaultUserHost()
	if err == nil {
		t.Fatal("expected error when default user not found in config, got nil")
	}
}
