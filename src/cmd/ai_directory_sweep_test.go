package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/pkg/ai"
)

const sweepLiveGeneration = "0123456789abcdef0123456789abcdef"

// writeLiveSweepRuntime publishes a runtime owned by this test process, so its
// generation is live for the lease and failure checks.
func writeLiveSweepRuntime(t *testing.T, directory string) {
	t.Helper()
	now := time.Now().UTC()
	state := claudeRuntimeState{
		Version: claudeRuntimeStateVersion, Generation: sweepLiveGeneration, RuntimeFingerprint: "binding-one",
		PID: os.Getpid(), StartedAt: now, ProxyURL: "http://phase:capability@127.0.0.1:9543",
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, claudeRuntimeLockFile), claudeRuntimeLock{
		Version: claudeRuntimeStateVersion, Generation: sweepLiveGeneration, PID: os.Getpid(), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

func directoryNames(t *testing.T, directory string) []string {
	t.Helper()
	var names []string
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != directory {
			relative, _ := filepath.Rel(directory, path)
			names = append(names, relative)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	return names
}

func TestManySessionsLeaveTheAIDirectoryAtItsBaseline(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	writeLiveSweepRuntime(t, directory)
	cycle := func(index int) {
		sessionID := fmt.Sprintf("session-%d", index)
		if err := registerHarnessLease(ai.HarnessCursor, sessionID, time.Now().UTC().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		touchClaudeSessionLease(harnessLeaseID(ai.HarnessCursor, sessionID))
		release, err := holdHarnessCommandLease(ai.HarnessCodex)
		if err != nil {
			t.Fatal(err)
		}
		if active, err := hasActiveClaudeSessionLease(directory, sweepLiveGeneration, time.Now()); err != nil || !active {
			t.Fatalf("live session not counted: %v %v", active, err)
		}
		release()
		if err := removeClaudeSessionLease(harnessLeaseID(ai.HarnessCursor, sessionID)); err != nil {
			t.Fatal(err)
		}
	}
	cycle(0)
	baseline := directoryNames(t, directory)
	for index := 1; index <= 40; index++ {
		cycle(index)
	}
	if after := directoryNames(t, directory); !slices.Equal(after, baseline) {
		t.Fatalf("sessions left files behind:\nbaseline %v\nafter    %v", baseline, after)
	}
	for _, name := range baseline {
		if strings.HasPrefix(name, claudeSessionLeasePrefix) && name != claudeLeaseRegistryName+claudeLeaseLockSuffix {
			t.Fatalf("per-session file %s outlived its session", name)
		}
	}
}

func TestSweepRemovesLeftoversAndKeepsLiveAndUnknownFiles(t *testing.T) {
	directory := withClaudeHookRuntimeDirectory(t)
	writeLiveSweepRuntime(t, directory)
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	old := time.Now().Add(-2 * time.Hour)
	age := func(path string) {
		t.Helper()
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}

	// A live session, and a lease left by a daemon that is gone.
	if err := registerHarnessLease(ai.HarnessCursor, "live-session", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	livePath, _ := claudeSessionLeasePath(directory, harnessLeaseID(ai.HarnessCursor, "live-session"))
	stalePath, _ := claudeSessionLeasePath(directory, harnessLeaseID(ai.HarnessCursor, "ended-session"))
	if err := writeOwnerOnlyJSON(stalePath, claudeSessionLease{
		Version: claudeRuntimeStateVersion, Generation: "fedcba9876543210fedcba9876543210", UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	removed := []string{
		stalePath,
		stalePath + claudeLeaseLockSuffix,
		livePath + claudeLeaseLockSuffix,
		write("ca-key.pem", "-----BEGIN EC PRIVATE KEY-----\n"),
		write(".phase-ca-123", "partial"),
		write("java-truststore.p12", "p12"),
		write("runtime-java-truststore.p12", "p12"),
		write("phase-ca.pem", "certificate"),
		write("claude-runtime-fedcba9876543210fedcba9876543210.error.json", `{}`),
		write("phase-hook-v1", "binary"),
		write("phase-hook-v1.metadata.json", `{"owner":"phase-cli"}`),
	}
	write(filepath.Base(stalePath)+claudeLeaseLockSuffix, "")
	write(filepath.Base(livePath)+claudeLeaseLockSuffix, "")
	if runtime.GOOS == "windows" {
		removed = slices.DeleteFunc(removed, func(path string) bool { return strings.HasSuffix(path, claudeLeaseLockSuffix) })
		removed = slices.DeleteFunc(removed, func(path string) bool { return strings.HasSuffix(path, "phase-hook-v1") })
	}
	staleTemporary := write(".phase-runtime-old", "partial")
	age(staleTemporary)
	removed = append(removed, staleTemporary)
	emptySpool := filepath.Join(directory, eventSpoolDirectory, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err := os.MkdirAll(emptySpool, 0o700); err != nil {
		t.Fatal(err)
	}
	age(emptySpool)
	removed = append(removed, emptySpool)

	kept := []string{
		livePath,
		write("notes.txt", "not Phase's"),
		write("claude-runtime-"+sweepLiveGeneration+".error.json", `{}`),
		write(".phase-runtime-fresh", "in progress"),
		write(filepath.Join(eventSpoolDirectory, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "event.json"), `{}`),
	}
	freshSpool := filepath.Join(directory, eventSpoolDirectory, "cccccccccccccccccccccccccccccccc")
	if err := os.MkdirAll(freshSpool, 0o700); err != nil {
		t.Fatal(err)
	}
	kept = append(kept, freshSpool)
	outside := filepath.Join(t.TempDir(), "outside.p12")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Remove(filepath.Join(directory, "java-truststore.p12")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(directory, "java-truststore.p12")); err != nil {
			t.Fatal(err)
		}
		removed = slices.DeleteFunc(removed, func(path string) bool { return filepath.Base(path) == "java-truststore.p12" })
		kept = append(kept, filepath.Join(directory, "java-truststore.p12"), outside)
	}

	if err := sweepAIDirectory(directory, true); err != nil {
		t.Fatal(err)
	}
	for _, path := range removed {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("sweep kept %s", path)
		}
	}
	for _, path := range kept {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("sweep removed %s: %v", path, err)
		}
	}
	if payload, _ := os.ReadFile(outside); string(payload) != "keep" {
		t.Error("sweep followed a symlink")
	}
}

func TestSweepLeavesALockFileSomeoneHolds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("lock files stay in place on Windows")
	}
	directory := withClaudeHookRuntimeDirectory(t)
	logPath := filepath.Join(directory, claudeLifecycleLogFile)
	if err := os.WriteFile(logPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	held, acquired, err := tryLockClaudeLeaseFile(logPath + claudeLeaseLockSuffix)
	if err != nil || !acquired {
		t.Fatalf("lock: %v %v", acquired, err)
	}
	if err := removeAIRuntimeLeftovers(directory); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{logPath, logPath + claudeLeaseLockSuffix} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("a held lock's files were removed: %s", path)
		}
	}
	_ = unlockClaudeLeaseFile(held)
	if err := removeAIRuntimeLeftovers(directory); err != nil {
		t.Fatal(err)
	}
	if names := directoryNames(t, directory); len(names) != 0 {
		t.Fatalf("disable leftovers remain: %v", names)
	}
}
