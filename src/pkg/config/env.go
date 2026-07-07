package config

import (
	"os"
	"strings"

	"github.com/phasehq/golang-sdk/v2/phase/misc"
)

// ConfigureSSLVerification reads the PHASE_VERIFY_SSL environment variable and
// disables TLS certificate verification in the SDK when it is set to "false"
// (case-insensitive). Any other value — or the variable being unset — keeps
// verification enabled. This mirrors the Python CLI's behavior
// (os.environ.get("PHASE_VERIFY_SSL", "True").lower() != "false") and makes
// the hint shown in SSL error messages ("You may set PHASE_VERIFY_SSL=False
// to bypass this check") actually work.
//
// It must run before any SDK network call: the SDK caches its HTTP client on
// first use, so changes to misc.VerifySSL after that have no effect.
func ConfigureSSLVerification() {
	if strings.EqualFold(os.Getenv("PHASE_VERIFY_SSL"), "false") {
		misc.VerifySSL = false
	}
}