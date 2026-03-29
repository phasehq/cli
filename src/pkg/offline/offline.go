package offline

import (
	"os"
	"path/filepath"
	"strings"
)

// CacheDir returns the offline cache directory for a given account ID.
func CacheDir(secretsDir, accountID string) string {
	return filepath.Join(secretsDir, "offline", accountID)
}

// IsOffline returns true if PHASE_OFFLINE is set to "1" or "true".
func IsOffline() bool {
	v := os.Getenv("PHASE_OFFLINE")
	return v == "1" || strings.EqualFold(v, "true")
}
