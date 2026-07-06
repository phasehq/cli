//go:build (darwin && !cgo) || (!darwin && !windows)

package approval

import (
	"fmt"
	"os"
	"os/exec"
)

// Require blocks until the user re-authenticates via sudo, which runs the OS PAM
// stack (so pam_tid / pam_u2f / pam_fprintd apply if configured). `sudo -k` first
// so a cached timestamp can never silently approve — the user must actually
// satisfy the prompt. Used on Linux/BSD, and on macOS builds without cgo (where
// the native Touch ID path in approval_darwin.go isn't compiled in).
func Require(reason string) error {
	_ = exec.Command("sudo", "-k").Run()
	c := exec.Command("sudo", "-p", fmt.Sprintf("Phase approval — %s\n[sudo] password for %%p: ", reason), "true")
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("approval not granted: %w", err)
	}
	return nil
}
