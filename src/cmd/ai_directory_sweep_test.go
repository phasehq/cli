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
	state := hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: sweepLiveGeneration, RuntimeFingerprint: "binding-one",
		PID: os.Getpid(), StartedAt: now, ProxyURL: "http://phase:capability@127.0.0.1:9543",
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeStateFile), state); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerOnlyJSON(filepath.Join(directory, hookRuntimeLockFile), hookRuntimeLock{
		Version: hookRuntimeStateVersion, Generation: sweepLiveGeneration, PID: os.Getpid(), CreatedAt: now,
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
	directory := withHookRuntimeDirectory(t)
	writeLiveSweepRuntime(t, directory)
	cycle := func(index int) {
		sessionID := fmt.Sprintf("session-%d", index)
		if err := registerHarnessLease(ai.HarnessCursor, sessionID, time.Now().UTC().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		touchSessionLease(harnessLeaseID(ai.HarnessCursor, sessionID))
		release, err := holdHarnessCommandLease(ai.HarnessCodex)
		if err != nil {
			t.Fatal(err)
		}
		if active, err := hasActiveSessionLease(directory, sweepLiveGeneration, time.Now()); err != nil || !active {
			t.Fatalf("live session not counted: %v %v", active, err)
		}
		release()
		if err := removeSessionLease(harnessLeaseID(ai.HarnessCursor, sessionID)); err != nil {
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
		if strings.HasPrefix(name, sessionLeasePrefix) && name != leaseRegistryName+leaseLockSuffix {
			t.Fatalf("per-session file %s outlived its session", name)
		}
	}
}

func TestSweepRemovesLeftoversAndKeepsLiveAndUnknownFiles(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
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
	livePath, _ := sessionLeasePath(directory, harnessLeaseID(ai.HarnessCursor, "live-session"))
	stalePath, _ := sessionLeasePath(directory, harnessLeaseID(ai.HarnessCursor, "ended-session"))
	if err := writeOwnerOnlyJSON(stalePath, sessionLease{
		Version: hookRuntimeStateVersion, Generation: "fedcba9876543210fedcba9876543210", UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	former := "claude-session-" + strings.Repeat("ab", 16) + ".lease.json"
	removed := []string{
		stalePath,
		write("ca-key.pem", "-----BEGIN EC PRIVATE KEY-----\n"),
		write(".phase-ca-123", "partial"),
		write("java-truststore.p12", "p12"),
		write("runtime-java-truststore.p12", "p12"),
		write("phase-ca.pem", "certificate"),
		write("runtime-fedcba9876543210fedcba9876543210.error.json", `{}`),
		// Names earlier builds wrote.
		write("claude-runtime-fedcba9876543210fedcba9876543210.error.json", `{}`),
		write("claude-runtime.json", `{}`),
		write("claude-runtime.log", "{}\n"),
		write("claude-session-leases.registry", ""),
		write(former, `{}`),
		write(former+leaseLockSuffix, ""),
		write("claude-runtime.lock", `{}`),
	}
	if runtime.GOOS == "windows" {
		removed = slices.DeleteFunc(removed, func(path string) bool { return strings.HasSuffix(path, ".lock") })
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

	// Only enable and disable remove the earlier top-level helper.
	formerHelper := "phase-hook-v1"
	if runtime.GOOS == "windows" {
		formerHelper += ".exe"
	}
	formerHook := []string{write(formerHelper, "binary"), write(formerHelper+".metadata.json", `{"owner":"phase-cli"}`)}
	kept := []string{
		formerHook[0], formerHook[1],
		livePath,
		write("notes.txt", "not Phase's"),
		write("runtime-"+sweepLiveGeneration+".error.json", `{}`),
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

	if err := sweepAIDirectory(directory, false); err != nil {
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

// The earlier top-level helper goes only when enable or disable asks, and only
// when its metadata says Phase owns it.
func TestSweepRemovesTheFormerTopLevelHelperOnlyWhenAskedAndOwned(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	name := "phase-hook-v1"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	helper, metadata := filepath.Join(directory, name), filepath.Join(directory, name+".metadata.json")
	write := func(owner string) {
		t.Helper()
		if err := os.WriteFile(helper, []byte("binary"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(metadata, []byte(`{"owner":"`+owner+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(path string) bool { _, err := os.Lstat(path); return err == nil }

	write("someone-else")
	if err := sweepAIDirectory(directory, true); err != nil {
		t.Fatal(err)
	}
	if !exists(helper) || !exists(metadata) {
		t.Fatal("a helper Phase does not own was removed")
	}
	write("phase-cli")
	if err := sweepAIDirectory(directory, false); err != nil {
		t.Fatal(err)
	}
	if !exists(helper) || !exists(metadata) {
		t.Fatal("a sweep enable or disable did not ask for removed the helper")
	}
	if err := sweepAIDirectory(directory, true); err != nil {
		t.Fatal(err)
	}
	if exists(helper) || exists(metadata) {
		t.Fatal("enable or disable kept the helper Phase owns")
	}
}

// A daemon of an earlier build that cannot be stopped keeps its state file,
// so it can still be found, and the failure is reported.
func TestSweepKeepsTheStateOfAnEarlierDaemonItCouldNotStop(t *testing.T) {
	directory := withHookRuntimeDirectory(t)
	statePath := filepath.Join(directory, formerRuntimeState)
	state := hookRuntimeState{
		Version: hookRuntimeStateVersion, Generation: sweepLiveGeneration, RuntimeFingerprint: "former",
		PID: os.Getpid(), StartedAt: time.Now().UTC(), ProxyURL: "http://phase:capability@127.0.0.1:1",
	}
	if err := writeOwnerOnlyJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	err := sweepAIDirectory(directory, false)
	if err == nil || !strings.Contains(err.Error(), "earlier build") {
		t.Fatalf("sweep = %v", err)
	}
	if _, err := os.Lstat(statePath); err != nil {
		t.Fatalf("the state file of a daemon still running was removed: %v", err)
	}
}

func TestSweepLeavesALockFileSomeoneHolds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("lock files stay in place on Windows")
	}
	directory := withHookRuntimeDirectory(t)
	logPath := filepath.Join(directory, lifecycleLogFile)
	if err := os.WriteFile(logPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	held, acquired, err := tryLockLeaseFile(logPath + leaseLockSuffix)
	if err != nil || !acquired {
		t.Fatalf("lock: %v %v", acquired, err)
	}
	if err := removeAIRuntimeLeftovers(directory); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{logPath, logPath + leaseLockSuffix} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("a held lock's files were removed: %s", path)
		}
	}
	_ = unlockLeaseFile(held)
	if err := removeAIRuntimeLeftovers(directory); err != nil {
		t.Fatal(err)
	}
	if names := directoryNames(t, directory); len(names) != 0 {
		t.Fatalf("disable leftovers remain: %v", names)
	}
}
