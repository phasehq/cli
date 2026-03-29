package offline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sdk "github.com/phasehq/golang-sdk/v2/phase"
	"github.com/phasehq/golang-sdk/v2/phase/network"
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

// cacheKey builds a deterministic filename for cached secrets.
// Uses sha256 of "envName|appName|appID|path" so filenames are filesystem-safe.
func cacheKey(envName, appName, appID, path string) string {
	if path == "" {
		path = "/"
	}
	raw := fmt.Sprintf("%s|%s|%s|%s", envName, appName, appID, path)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// secretsCachePath returns the path for cached secrets JSON.
func secretsCachePath(cacheDir, envName, appName, appID, path string) string {
	return filepath.Join(cacheDir, "secrets", cacheKey(envName, appName, appID, path)+".json")
}

// SaveSecrets caches decrypted secret results to disk.
func SaveSecrets(cacheDir, envName, appName, appID, path string, secrets []sdk.SecretResult) error {
	// Filter out dynamic secrets — they contain time-bound lease data
	var toCache []sdk.SecretResult
	for _, s := range secrets {
		if !s.IsDynamic {
			toCache = append(toCache, s)
		}
	}

	data, err := json.MarshalIndent(toCache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secrets for cache: %w", err)
	}

	fp := secretsCachePath(cacheDir, envName, appName, appID, path)
	if err := os.MkdirAll(filepath.Dir(fp), 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Atomic write: temp file + rename
	tmp := fp + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("failed to write cache temp file: %w", err)
	}
	if err := os.Rename(tmp, fp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("failed to rename cache file: %w", err)
	}
	return nil
}

// LoadSecrets reads cached secret results from disk.
func LoadSecrets(cacheDir, envName, appName, appID, path string) ([]sdk.SecretResult, error) {
	fp := secretsCachePath(cacheDir, envName, appName, appID, path)
	data, err := os.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("no cached secrets found for this environment and path: %w", err)
	}

	var secrets []sdk.SecretResult
	if err := json.Unmarshal(data, &secrets); err != nil {
		return nil, fmt.Errorf("failed to decode cached secrets: %w", err)
	}
	return secrets, nil
}

// IsNetworkError returns true if the error is a network or SSL error
// (i.e., the server is unreachable, not an auth/API error).
func IsNetworkError(err error) bool {
	var netErr *network.NetworkError
	var sslErr *network.SSLError
	return errors.As(err, &netErr) || errors.As(err, &sslErr)
}

// GetWithCache wraps p.Get() with offline caching logic.
// On success: caches results, returns them.
// On network failure: falls back to cache if available.
// When PHASE_OFFLINE=1: skips network entirely, serves from cache.
func GetWithCache(p *sdk.Phase, opts sdk.GetOptions, cacheDir string) ([]sdk.SecretResult, error) {
	if IsOffline() {
		secrets, err := LoadSecrets(cacheDir, opts.EnvName, opts.AppName, opts.AppID, opts.Path)
		if err != nil {
			return nil, fmt.Errorf("offline mode: %w", err)
		}
		// Warn about dynamic secrets that won't be available
		if opts.Dynamic {
			fmt.Fprintf(os.Stderr, "⚠ Offline mode: dynamic secrets require network access and are not available from cache\n")
		}
		return filterByKeys(secrets, opts.Keys), nil
	}

	// Online: try network
	secrets, err := p.Get(opts)
	if err != nil {
		if IsNetworkError(err) {
			// Try cache fallback
			cached, cacheErr := LoadSecrets(cacheDir, opts.EnvName, opts.AppName, opts.AppID, opts.Path)
			if cacheErr == nil {
				fmt.Fprintf(os.Stderr, "⚠ Network unavailable, using cached secrets. Set PHASE_OFFLINE=1 to skip network attempts\n")
				return filterByKeys(cached, opts.Keys), nil
			}
			// No cache available — return original network error with offline hint
			return nil, fmt.Errorf("%w\n\nHint: if you have previously fetched secrets, set PHASE_OFFLINE=1 to use cached data", err)
		}
		return nil, err
	}

	// Cache on success (best-effort, don't fail the operation)
	_ = SaveSecrets(cacheDir, opts.EnvName, opts.AppName, opts.AppID, opts.Path, secrets)

	return secrets, nil
}

// filterByKeys filters results to only include the specified keys.
// If keys is empty, returns all results.
func filterByKeys(secrets []sdk.SecretResult, keys []string) []sdk.SecretResult {
	if len(keys) == 0 {
		return secrets
	}
	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}
	var filtered []sdk.SecretResult
	for _, s := range secrets {
		if keySet[s.Key] {
			filtered = append(filtered, s)
		}
	}
	return filtered
}
