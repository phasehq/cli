package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// Everything Phase AI writes under ~/.phase. The sweep below removes only the
// names in this table, and only where the table says they are leftovers.
//
//	Path (under ~/.phase)                        Written by                        Why                                             Removed
//	ai.json                                      phase ai enable/disable           enabled bit, Workflow, installed harnesses      never (disable keeps it, enabled=false)
//	ai/ca.pem                                    CA store (enable, proxy start)    public CA certificate(s)                        kept; replaced on renewal
//	ai/ca-bundle.pem                             CA store                          CA certificate(s) + system roots, base bundle   kept; replaced with ca.pem
//	ai/ca.lock                                   CA store                          serializes CA load and publication              kept
//	ai/runtime-ca-bundle.pem                     every proxy start                 trust bundle child processes are pointed at     kept: live phase ai run children may read it
//	ai/env.sh, env.json, env-status.json         hook daemon                       environment harness shells and plugins load     phase ai disable
//	ai/claude-runtime.json                       hook daemon                       running daemon's PID, generation, proxy URL     daemon exit
//	ai/claude-runtime.lock                       hooks starting the daemon         daemon ownership                                daemon exit
//	ai/claude-runtime-<generation>.error.json    hook daemon                       why a daemon failed, for hooks and status       read by the waiting hook, or sweep
//	ai/claude-session-<id>.lease.json            hooks, phase ai exec              keeps the daemon alive for a session/command    session or command end, daemon exit, sweep
//	ai/claude-runtime.log, .log.1                hooks and daemon                  lifecycle log, rotated at 1 MiB (2 MiB max)     phase ai disable
//	ai/claude-runtime.setup.lock                 phase ai enable, hooks            keeps hooks from starting during setup          phase ai disable
//	ai/*.mutation.lock (runtime lock, lease       hooks and daemon                  OS locks for the files above; one per name,     phase ai disable
//	  registry, log)                                                               none per session
//	ai/event-spool/<session>/<event>.json        proxy                             denial/error audit events not yet delivered     on delivery; folder when drained or by sweep when empty
//	ai/bin/phase-hook-v1, .metadata.json         phase ai enable                   stable helper every harness adapter runs        phase ai disable
//	ai/codex-marketplace/                        phase ai enable --harness codex   Codex plugin marketplace                        phase ai disable
//	ai/.phase-runtime-*, .phase-ca-*             atomic writers                    temporary files                                 by the writer; leftovers by sweep
//
// Earlier layouts the sweep also removes: claude-session-*.lease.json.mutation.lock
// (one lock per session), ca-key.pem (plaintext CA key), java-truststore.p12,
// runtime-java-truststore.p12, phase-ca.pem, and a top-level phase-hook-v1 with
// its metadata from before the helper moved into bin/.

const (
	aiSweepTemporaryAge = time.Hour
	aiSweepSpoolAge     = 10 * time.Minute
	eventSpoolDirectory = "event-spool"
)

var (
	sessionLeaseLockPattern = regexp.MustCompile(`^claude-session-[0-9a-f]{32}\.lease\.json\.mutation\.lock$`)
	runtimeFailurePattern   = regexp.MustCompile(`^claude-runtime-([0-9a-f]{32})\.error\.json$`)
	spoolSessionPattern     = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// sweepAIDirectory removes leftovers from ~/.phase/ai: leases whose session or
// daemon is gone, per-session lock files, empty event-spool folders, failure
// records of other daemons, stale temporary files and files from earlier
// layouts. It touches only names in the inventory above, directly inside the
// directory (and event-spool), never follows symlinks, and is safe beside live
// sessions: leases are judged under the lease registry lock, CA files under
// the CA lock, lock files are removed only while held, and spool folders only
// when empty and idle. legacyHook also removes a top-level shared hook from
// the earlier layout; only enable and disable pass it, since an adapter that
// enable has not rewritten may still run that file.
func sweepAIDirectory(directory string, legacyHook bool) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("Phase AI directory is not a directory")
	}
	var errs []error
	if err := phaseproxy.SweepCAFiles(directory); err != nil {
		errs = append(errs, err)
	}
	live := liveClaudeRuntimeGeneration(directory)
	if _, _, err := activeClaudeLeases(directory, live, time.Now()); err != nil {
		errs = append(errs, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	now := time.Now()
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(directory, name)
		if !entry.Type().IsRegular() {
			continue
		}
		switch {
		case sessionLeaseLockPattern.MatchString(name):
			errs = append(errs, removeHeldLockFile(path))
		case runtimeFailurePattern.MatchString(name):
			if live == "" || runtimeFailurePattern.FindStringSubmatch(name)[1] != live {
				errs = append(errs, removeIfExists(path))
			}
		case strings.HasPrefix(name, ".phase-runtime-"):
			if fileInfo, err := entry.Info(); err == nil && now.Sub(fileInfo.ModTime()) > aiSweepTemporaryAge {
				errs = append(errs, removeIfExists(path))
			}
		}
	}
	errs = append(errs, sweepEventSpool(filepath.Join(directory, eventSpoolDirectory), now))
	if legacyHook {
		errs = append(errs, removeLegacySharedHook(directory))
	}
	return errors.Join(errs...)
}

// liveClaudeRuntimeGeneration is the generation of a daemon whose process is
// alive, or "" when none is running.
func liveClaudeRuntimeGeneration(directory string) string {
	if lock, err := readClaudeRuntimeLock(filepath.Join(directory, claudeRuntimeLockFile)); err == nil &&
		lock.Generation != "" && lock.PID > 0 && processIsAlive(lock.PID) {
		return lock.Generation
	}
	if state, err := readClaudeRuntimeState(filepath.Join(directory, claudeRuntimeStateFile)); err == nil &&
		state.Generation != "" && state.PID > 0 && processIsAlive(state.PID) {
		return state.Generation
	}
	return ""
}

// sweepEventSpool removes session folders that are empty and have not changed
// for a while. os.Remove refuses a folder that holds anything, so undelivered
// events are never deleted, and a proxy that loses its empty folder to the
// sweep makes it again before its next write.
func sweepEventSpool(spool string, now time.Time) error {
	info, err := os.Lstat(spool)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() {
		return err
	}
	entries, err := os.ReadDir(spool)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !spoolSessionPattern.MatchString(entry.Name()) {
			continue
		}
		folderInfo, err := entry.Info()
		if err != nil || now.Sub(folderInfo.ModTime()) < aiSweepSpoolAge {
			continue
		}
		_ = os.Remove(filepath.Join(spool, entry.Name()))
	}
	_ = os.Remove(spool)
	return nil
}

// removeLegacySharedHook removes the shared helper earlier builds installed
// directly in ~/.phase/ai, only when its metadata says Phase owns it.
func removeLegacySharedHook(directory string) error {
	name := "phase-hook-v1"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	executable := filepath.Join(directory, name)
	metadataPath := executable + ".metadata.json"
	info, err := os.Lstat(metadataPath)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	payload, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil
	}
	var metadata struct {
		Owner string `json:"owner"`
	}
	if json.Unmarshal(payload, &metadata) != nil || metadata.Owner != "phase-cli" {
		return nil
	}
	if info, err := os.Lstat(executable); err == nil && !info.Mode().IsRegular() {
		return nil
	}
	return errors.Join(removeIfExists(executable), removeIfExists(metadataPath))
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// removeAIRuntimeLeftovers is what phase ai disable removes once the hook
// daemon has stopped: the lifecycle log and the fixed lock files, which are
// only useful while Phase AI is enabled. The CA and the trust bundles stay.
func removeAIRuntimeLeftovers(directory string) error {
	logPath := filepath.Join(directory, claudeLifecycleLogFile)
	return errors.Join(
		removeHeldLockFile(logPath+claudeLeaseLockSuffix, logPath, logPath+".1"),
		removeHeldLockFile(filepath.Join(directory, claudeLeaseRegistryName+claudeLeaseLockSuffix)),
		removeHeldLockFile(filepath.Join(directory, claudeRuntimeLockFile+claudeLeaseLockSuffix)),
		removeHeldLockFile(filepath.Join(directory, claudeSetupLockFile)),
	)
}

// sweepAIDirectoryQuietly runs the sweep where a failure must not stop the
// command that triggered it.
func sweepAIDirectoryQuietly(ctx context.Context, legacyHook bool) {
	if ctx != nil && ctx.Err() != nil {
		return
	}
	directory, err := claudeHookRuntimeDir()
	if err != nil {
		return
	}
	_ = sweepAIDirectory(directory, legacyHook)
}
