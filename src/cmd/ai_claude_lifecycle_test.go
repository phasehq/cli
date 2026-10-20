package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeLifecycleLogAcceptsOnlyBoundedAllowlistedRecords(t *testing.T) {
	directory := t.TempDir()
	const sensitive = "phase_runtime_sensitive-capability"
	appendClaudeLifecycleEvent(directory, "session_recycle", sensitive)
	appendClaudeLifecycleEvent(directory, sensitive, "environment_changed")
	appendClaudeLifecycleEvent(directory, "session_recycle", "environment_changed")

	path := filepath.Join(directory, claudeLifecycleLogFile)
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(sensitive)) {
		t.Fatalf("lifecycle log persisted non-allowlisted material: %s", payload)
	}
	lines := strings.Split(strings.TrimSpace(string(payload)), "\n")
	if len(lines) != 1 {
		t.Fatalf("lifecycle log records = %d, want 1: %s", len(lines), payload)
	}
	var record claudeLifecycleRecord
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	if record.Event != "session_recycle" || record.Reason != "environment_changed" || record.Time.IsZero() {
		t.Fatalf("lifecycle record = %#v", record)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("lifecycle log mode = %o, want 600", info.Mode().Perm())
	}
}

func TestClaudeLifecycleLogRotatesBeforeExceedingBound(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, claudeLifecycleLogFile)
	filler := bytes.Repeat([]byte("x"), claudeLifecycleLogMaxBytes-1)
	if err := os.WriteFile(path, filler, 0o600); err != nil {
		t.Fatal(err)
	}
	appendClaudeLifecycleEvent(directory, "session_ready", "recycled")

	rotated, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Size() != int64(len(filler)) {
		t.Fatalf("rotated lifecycle log size = %d, want %d", rotated.Size(), len(filler))
	}
	current, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if current.Size() <= 0 || current.Size() > claudeLifecycleLogMaxBytes {
		t.Fatalf("current lifecycle log size = %d", current.Size())
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record claudeLifecycleRecord
	if err := json.Unmarshal(bytes.TrimSpace(payload), &record); err != nil {
		t.Fatalf("rotated lifecycle log did not start with one complete record: %v (%q)", err, payload)
	}
	if record.Event != "session_ready" || record.Reason != "recycled" {
		t.Fatalf("post-rotation lifecycle record = %#v", record)
	}
}
