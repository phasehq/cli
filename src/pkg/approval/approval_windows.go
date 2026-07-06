//go:build windows

package approval

import "fmt"

// Require is not yet implemented on Windows. The sensible primitive is Windows
// Hello via WinRT Windows.Security.Credentials.UI.UserConsentVerifier
// (RequestVerificationAsync), which prompts for PIN / fingerprint / face and
// works without a TTY. Until that is wired up we fail CLOSED — never silently
// approve a sensitive action just because the platform can't prompt.
func Require(reason string) error {
	return fmt.Errorf("device-owner approval is not yet supported on Windows (reason: %q); Windows Hello support is planned", reason)
}
