package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
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

func TestLastClaudeSessionRefreshReadsTheLatestRecycle(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 10, 22, 11, 20, 0, 0, time.UTC)
	write := func(records ...claudeLifecycleRecord) {
		var out []byte
		for _, record := range records {
			line, _ := json.Marshal(record)
			out = append(out, append(line, '\n')...)
		}
		if err := os.WriteFile(filepath.Join(directory, claudeLifecycleLogFile), out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	at := func(seconds int) time.Time { return now.Add(-time.Duration(seconds) * time.Second) }

	if refreshed, _ := lastClaudeSessionRefresh(directory, now, claudeRefreshNoticeWindow); !refreshed.IsZero() {
		t.Fatal("a missing log must not report a refresh")
	}
	write(
		claudeLifecycleRecord{Time: at(600), Event: "daemon_started"},
		claudeLifecycleRecord{Time: at(599), Event: "session_ready", Reason: "initial"},
	)
	if refreshed, _ := lastClaudeSessionRefresh(directory, now, claudeRefreshNoticeWindow); !refreshed.IsZero() {
		t.Fatal("an initial session is not a refresh")
	}
	write(
		claudeLifecycleRecord{Time: at(600), Event: "daemon_started"},
		claudeLifecycleRecord{Time: at(599), Event: "session_ready", Reason: "initial"},
		claudeLifecycleRecord{Time: at(40), Event: "session_recycle", Reason: "environment_changed"},
		claudeLifecycleRecord{Time: at(39), Event: "session_ready", Reason: "recycled"},
	)
	refreshed, reason := lastClaudeSessionRefresh(directory, now, claudeRefreshNoticeWindow)
	if !refreshed.Equal(at(39)) || reason != "environment_changed" {
		t.Fatalf("refresh = %v %q", refreshed, reason)
	}
	if notice := claudeSessionRefreshNotice(refreshed, reason); !strings.Contains(notice, "11:19:21Z") || !strings.Contains(notice, "changed in the Console") || !strings.Contains(notice, "keep working") {
		t.Fatalf("notice = %q", notice)
	}
	if refreshed, _ := lastClaudeSessionRefresh(directory, now, 30*time.Second); !refreshed.IsZero() {
		t.Fatal("a recycle outside the window must not be reported")
	}
	write(
		claudeLifecycleRecord{Time: at(40), Event: "session_recycle", Reason: "hard_expiry"},
		claudeLifecycleRecord{Time: at(39), Event: "session_ready", Reason: "recycled"},
		claudeLifecycleRecord{Time: at(10), Event: "daemon_stopped", Reason: "shutdown"},
		claudeLifecycleRecord{Time: at(5), Event: "daemon_started"},
		claudeLifecycleRecord{Time: at(4), Event: "session_ready", Reason: "initial"},
	)
	if refreshed, _ := lastClaudeSessionRefresh(directory, now, claudeRefreshNoticeWindow); !refreshed.IsZero() {
		t.Fatal("a recycle before a daemon restart must not be reported")
	}
	write(
		claudeLifecycleRecord{Time: at(40), Event: "session_recycle", Reason: "hard_expiry"},
		claudeLifecycleRecord{Time: at(39), Event: "session_ready", Reason: "recycled"},
	)
	refreshed, reason = lastClaudeSessionRefresh(directory, now, claudeRefreshNoticeWindow)
	if refreshed.IsZero() || reason != "hard_expiry" || !strings.Contains(claudeSessionRefreshNotice(refreshed, reason), "renewed at") {
		t.Fatalf("expiry refresh = %v %q", refreshed, reason)
	}
	if claudeSessionRefreshNotice(time.Time{}, "") != "" {
		t.Fatal("no refresh must add no notice")
	}
}
