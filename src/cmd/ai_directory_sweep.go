package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
//	ai/runtime.json                              hook daemon                       running daemon's PID, generation, proxy URL     daemon exit
//	ai/runtime.lock                              hooks starting the daemon         daemon ownership                                daemon exit
//	ai/runtime-<generation>.error.json           hook daemon                       why a daemon failed, for hooks and status       read by the waiting hook, or sweep
//	ai/session-<id>.lease.json                   hooks, phase ai exec              keeps the daemon alive for a session/command    session or command end, daemon exit, sweep
//	ai/runtime.log, .log.1                       hooks and daemon                  lifecycle log, rotated at 1 MiB (2 MiB max)     phase ai disable
//	ai/runtime.setup.lock                        phase ai enable, hooks            keeps hooks from starting during setup          phase ai disable
//	ai/*.mutation.lock (runtime lock, lease       hooks and daemon                  OS locks for the files above; one per name,     phase ai disable
//	  registry, log)                                                               none per session
//	ai/event-spool/<session>/<event>.json        proxy                             denial/error audit events not yet delivered     on delivery; folder when drained or by sweep when empty
//	ai/bin/phase-hook-v1, .metadata.json         phase ai enable                   stable helper every harness adapter runs        phase ai disable
//	ai/codex-marketplace/                        phase ai enable --harness codex   Codex plugin marketplace                        phase ai disable
//	ai/.phase-runtime-*, .phase-ca-*             atomic writers                    temporary files                                 by the writer; leftovers by sweep
//
// Names earlier builds wrote are in formerAINames and formerAIPatterns, the
// one place that knows about them. Obsolete CA files (ca-key.pem, a plaintext
// key, and the Java trust stores) are removed by phaseproxy.SweepCAFiles under
// the CA lock.

const (
	aiSweepTemporaryAge = time.Hour
	aiSweepSpoolAge     = 10 * time.Minute
	eventSpoolDirectory = "event-spool"
	formerRuntimeState  = "claude-runtime.json"
)

// formerAINames are files earlier builds wrote directly in ~/.phase/ai: the
// runtime files before they lost their claude- prefix, and the shared helper
// from before it moved into bin/.
var formerAINames = []string{
	formerRuntimeState,
	"claude-runtime.lock",
	"claude-runtime.lock" + leaseLockSuffix,
	"claude-runtime.setup.lock",
	"claude-runtime.log",
	"claude-runtime.log.1",
	"claude-runtime.log" + leaseLockSuffix,
	"claude-session-leases.registry",
	"claude-session-leases.registry" + leaseLockSuffix,
	"phase-hook-v1",
	"phase-hook-v1.metadata.json",
	"phase-hook-v1.exe",
	"phase-hook-v1.exe.metadata.json",
}

// formerAIPatterns are per-session and per-generation files of earlier builds,
// including the per-session lock files they kept.
var formerAIPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^claude-session-[0-9a-f]{32}\.lease\.json(\.mutation\.lock)?$`),
	regexp.MustCompile(`^claude-runtime-[0-9a-f]{32}\.error\.json$`),
}

var (
	runtimeFailurePattern = regexp.MustCompile(`^runtime-([0-9a-f]{32})\.error\.json$`)
	spoolSessionPattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// sweepAIDirectory removes leftovers from ~/.phase/ai: leases whose session or
// daemon is gone, empty event-spool folders, failure records of other daemons,
// stale temporary files and the names earlier builds wrote. It touches only
// names in the inventory above, directly inside the directory (and
// event-spool), never follows symlinks, and is safe beside live sessions:
// leases are judged under the lease registry lock, CA files under the CA lock,
// lock files are removed only while held, and spool folders only when empty
// and idle.
func sweepAIDirectory(directory string) error {
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
	live := liveHookRuntimeGeneration(directory)
	if _, _, err := activeSessionLeases(directory, live, time.Now()); err != nil {
		errs = append(errs, err)
	}
	if err := stopFormerRuntime(directory); err != nil {
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
		case formerAIName(name):
			if strings.HasSuffix(name, ".lock") {
				errs = append(errs, removeHeldLockFile(path))
			} else {
				errs = append(errs, removeIfExists(path))
			}
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
	return errors.Join(errs...)
}

func formerAIName(name string) bool {
	if slices.Contains(formerAINames, name) {
		return true
	}
	return slices.ContainsFunc(formerAIPatterns, func(pattern *regexp.Regexp) bool { return pattern.MatchString(name) })
}

// stopFormerRuntime stops a daemon an earlier build started under its former
// state file. It holds the proxy port, so the current runtime could not start
// beside it.
func stopFormerRuntime(directory string) error {
	state, err := readHookRuntimeState(filepath.Join(directory, formerRuntimeState))
	if err != nil || state.PID <= 0 || !processIsAlive(state.PID) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := requestHookRuntimeShutdown(ctx, state.ProxyURL); err != nil {
		return fmt.Errorf("stop the Phase AI runtime of an earlier build: %w", err)
	}
	return waitForRuntimeProcessExit(ctx, state.PID, 2*time.Second)
}

// liveHookRuntimeGeneration is the generation of a daemon whose process is
// alive, or "" when none is running.
func liveHookRuntimeGeneration(directory string) string {
	if lock, err := readHookRuntimeLock(filepath.Join(directory, hookRuntimeLockFile)); err == nil &&
		lock.Generation != "" && lock.PID > 0 && processIsAlive(lock.PID) {
		return lock.Generation
	}
	if state, err := readHookRuntimeState(filepath.Join(directory, hookRuntimeStateFile)); err == nil &&
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
	logPath := filepath.Join(directory, lifecycleLogFile)
	return errors.Join(
		removeHeldLockFile(logPath+leaseLockSuffix, logPath, logPath+".1"),
		removeHeldLockFile(filepath.Join(directory, leaseRegistryName+leaseLockSuffix)),
		removeHeldLockFile(filepath.Join(directory, hookRuntimeLockFile+leaseLockSuffix)),
		removeHeldLockFile(filepath.Join(directory, hookSetupLockFile)),
	)
}

// sweepAIDirectoryQuietly runs the sweep where a failure must not stop the
// command that triggered it.
func sweepAIDirectoryQuietly(ctx context.Context) {
	if ctx != nil && ctx.Err() != nil {
		return
	}
	directory, err := hookRuntimeDir()
	if err != nil {
		return
	}
	_ = sweepAIDirectory(directory)
}
