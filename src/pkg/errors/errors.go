package errors

import (
	"errors"
	"fmt"

	"github.com/phasehq/golang-sdk/v2/phase/network"
)

// FormatSDKError wraps SDK errors with user-facing presentation (emoji, hints).
// Non-SDK errors pass through unchanged.
func FormatSDKError(err error) string {
	var netErr *network.NetworkError
	if errors.As(err, &netErr) {
		const offlineHint = ". Set PHASE_OFFLINE=1 to use cached data if available."
		switch netErr.Kind {
		case "dns":
			return fmt.Sprintf("🗿 Network error: Could not resolve host '%s'%s", netErr.Host, offlineHint)
		case "connection":
			return "🗿 Network error: Could not connect to the Phase host" + offlineHint
		case "timeout":
			return "🗿 Network error: Request timed out" + offlineHint
		default:
			return fmt.Sprintf("🗿 Network error: %s%s", netErr.Detail, offlineHint)
		}
	}

	var sslErr *network.SSLError
	if errors.As(err, &sslErr) {
		return fmt.Sprintf("🗿 SSL error: %s. You may set PHASE_VERIFY_SSL=False to bypass this check", sslErr.Detail)
	}

	var authErr *network.AuthorizationError
	if errors.As(err, &authErr) {
		if authErr.Detail != "" {
			return fmt.Sprintf("🚫 Not authorized: %s", authErr.Detail)
		}
		return "🚫 Not authorized. Token may be expired or revoked"
	}

	var rateLimitErr *network.RateLimitError
	if errors.As(err, &rateLimitErr) {
		return "⏳ Rate limit exceeded. Please try again later"
	}

	var apiErr *network.APIError
	if errors.As(err, &apiErr) {
		if apiErr.Detail != "" {
			return fmt.Sprintf("🗿 Request failed (HTTP %d): %s", apiErr.StatusCode, apiErr.Detail)
		}
		return fmt.Sprintf("🗿 Request failed with status code %d", apiErr.StatusCode)
	}

	return err.Error()
}
