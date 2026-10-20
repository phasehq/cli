package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

var errClaudeRuntimeAuthenticationRequired = errors.New("Phase AI authentication is invalid or no longer active")

type claudeLifecycleRecord struct {
	Time   time.Time `json:"time"`
	Event  string    `json:"event"`
	Reason string    `json:"reason,omitempty"`
}

func validClaudeLifecycleRecord(event, reason string) bool {
	switch event {
	case "daemon_started", "session_ready":
		return reason == "" || reason == "initial" || reason == "recycled"
	case "daemon_rejected":
		return reason == "ownership"
	case "session_recycle":
		return reason == "environment_changed" || reason == "hard_expiry"
	case "session_retry":
		return reason == "backend_unavailable"
	case "startup_failed":
		return reason == "authentication" || reason == "fingerprint" || reason == "runtime" || reason == "state_publish"
	case "daemon_stopped":
		return reason == "shutdown" || reason == "fatal"
	default:
		return false
	}
}

// appendClaudeLifecycleEvent writes only allowlisted, non-sensitive lifecycle
// codes. It deliberately never accepts an error string, identifier, path,
// fingerprint, session value, or proxy URL. Diagnostics are best effort and
// cannot block the credential boundary from starting or stopping.
func appendClaudeLifecycleEvent(directory, event, reason string) {
	if !validClaudeLifecycleRecord(event, reason) {
		return
	}
	payload, err := json.Marshal(claudeLifecycleRecord{
		Time: time.Now().UTC(), Event: event, Reason: reason,
	})
	if err != nil {
		return
	}
	payload = append(payload, '\n')
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	path := filepath.Join(directory, claudeLifecycleLogFile)
	_ = withClaudeLeaseMutationLock(ctx, path, func() error {
		if info, statErr := os.Lstat(path); statErr == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("Phase AI lifecycle log must be a regular non-symlink file")
			}
			if info.Size()+int64(len(payload)) > claudeLifecycleLogMaxBytes {
				rotated := path + ".1"
				if rotatedInfo, rotatedErr := os.Lstat(rotated); rotatedErr == nil {
					if !rotatedInfo.Mode().IsRegular() || rotatedInfo.Mode()&os.ModeSymlink != 0 {
						return errors.New("Phase AI rotated lifecycle log must be a regular non-symlink file")
					}
					if err := os.Remove(rotated); err != nil {
						return err
					}
				} else if !errors.Is(rotatedErr, os.ErrNotExist) {
					return rotatedErr
				}
				if err := os.Rename(path, rotated); err != nil {
					return err
				}
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		file, err := openClaudeEnvironmentFile(path)
		if err != nil {
			return err
		}
		defer file.Close()
		if err := file.Chmod(0o600); err != nil {
			return err
		}
		if _, err := file.Write(payload); err != nil {
			return err
		}
		return file.Sync()
	})
}

func writeClaudeRuntimeFailure(path, generation, reason string) {
	if !validClaudeLifecycleRecord("startup_failed", reason) {
		reason = "runtime"
	}
	_ = writeOwnerOnlyJSON(path, claudeRuntimeFailure{Generation: generation, Reason: reason})
}

func claudeRuntimeFailureMessage(reason string) string {
	switch reason {
	case "authentication":
		return errClaudeRuntimeAuthenticationRequired.Error()
	case "fingerprint":
		return "Phase AI runtime identity could not be verified"
	case "state_publish":
		return "Phase AI runtime state could not be published"
	default:
		return "Phase AI runtime could not start"
	}
}

func claudeRuntimeFailureError(reason string) error {
	if reason == "authentication" {
		return errClaudeRuntimeAuthenticationRequired
	}
	return errors.New(claudeRuntimeFailureMessage(reason))
}
