// Package approval gates a sensitive action behind explicit, interactive
// device-owner consent. It is deliberately generic and reusable: any command
// that should require a human's physical approval — issuing proxy credentials,
// listing production secrets, revealing a value, deleting an app — calls Require
// with a short, human-readable reason describing what is being approved.
//
//	if err := approval.Require("list secrets in production"); err != nil {
//	    return err // user declined or approval is unavailable
//	}
//
// Require blocks until the device owner approves, and returns an error if the
// request is denied or the platform can't prompt. It is implemented per-platform
// (build-tagged) with the strongest primitive available:
//
//   - macOS (cgo builds): Touch ID / Apple Watch / password via LocalAuthentication.
//   - Linux / BSD:        sudo, which runs the OS PAM stack — so pam_tid,
//     pam_u2f, or pam_fprintd apply automatically if the user configured them.
//   - Windows:            not yet implemented — planned via Windows Hello
//     (WinRT UserConsentVerifier). Fails closed until then.
//
// The prompt is a system/OS interaction, not a terminal prompt, so it works even
// when the caller has no controlling TTY (e.g. an agent-invoked shell). Callers
// should treat a non-nil error as "not approved" and abort the sensitive action.
package approval
