package phase

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	sdk "github.com/phasehq/golang-sdk/v2/phase"
)

// userDataJSON is a minimal AppKeyResponse as served by
// GET {host}/service/secrets/tokens/ and cached at {cacheDir}/userdata.json.
const userDataJSON = `{
	"apps": [
		{
			"id": "8e977d18-3fdc-45a5-91a9-3e6a9e5b3f11",
			"name": "my-app",
			"environment_keys": [
				{"environment": {"id": "env-1", "name": "Development"}},
				{"environment": {"id": "env-2", "name": "Production"}}
			]
		}
	]
}`

func userDataServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/service/secrets/tokens/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(userDataJSON))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The core promise of the empty-fetch label fix: partial, case-insensitive
// selectors resolve to the canonical names from the account's app list.
func TestResolveNamesResolvesViaNetworkWhenNoCache(t *testing.T) {
	t.Setenv("PHASE_OFFLINE", "")
	srv := userDataServer(t)
	p := &sdk.Phase{Host: srv.URL}

	app, env := resolveNames(p, "my", "dev", "", "")
	if app != "my-app" || env != "Development" {
		t.Fatalf("selector resolution: got %q/%q want %q/%q", app, env, "my-app", "Development")
	}

	app, env = resolveNames(p, "", "prod", "8e977d18-3fdc-45a5-91a9-3e6a9e5b3f11", "")
	if app != "my-app" || env != "Production" {
		t.Fatalf("app-id resolution: got %q/%q want %q/%q", app, env, "my-app", "Production")
	}
}

// The SDK refreshes {cacheDir}/userdata.json on every successful online fetch,
// so by the time labels are resolved the cache satisfies the lookup without a
// second request. The reachable server must stay untouched — a network-first
// implementation would reintroduce the duplicate user-data fetch.
func TestResolveNamesPrefersCache(t *testing.T) {
	t.Setenv("PHASE_OFFLINE", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "userdata.json"), []byte(userDataJSON), 0600); err != nil {
		t.Fatalf("write cache: %v", err)
	}
	var contacted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted.Store(true)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	app, env := resolveNames(&sdk.Phase{Host: srv.URL}, "my", "dev", "", dir)
	if contacted.Load() {
		t.Fatal("cache was populated — the network must not be contacted")
	}
	if app != "my-app" || env != "Development" {
		t.Fatalf("cache resolution: got %q/%q want %q/%q", app, env, "my-app", "Development")
	}
}

// Offline mode must never touch the network: with no cache available the
// labels degrade to the selectors, with the app ID standing in for a missing
// app name so nothing renders blank.
func TestResolveNamesOfflineSkipsNetwork(t *testing.T) {
	t.Setenv("PHASE_OFFLINE", "1")
	var contacted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted.Store(true)
	}))
	t.Cleanup(srv.Close)

	app, env := resolveNames(&sdk.Phase{Host: srv.URL}, "", "Development", "8e977d18-3fdc-45a5-91a9-3e6a9e5b3f11", "")
	if contacted.Load() {
		t.Fatal("offline mode must not make network requests")
	}
	if app != "8e977d18-3fdc-45a5-91a9-3e6a9e5b3f11" || env != "Development" {
		t.Fatalf("offline fallback: got %q/%q, want app ID and selector env", app, env)
	}
}

// When the lookup fails online (unreachable host) the app ID substitutes for a
// missing app name — the label must never be blank in the .phase.json flow,
// where only the app ID is known.
func TestResolveNamesFallsBackToAppIDOnLookupFailure(t *testing.T) {
	t.Setenv("PHASE_OFFLINE", "")

	// The zero-value client has no host, so the request fails before any I/O.
	app, env := resolveNames(&sdk.Phase{}, "", "Development", "8e977d18-3fdc-45a5-91a9-3e6a9e5b3f11", "")
	if app != "8e977d18-3fdc-45a5-91a9-3e6a9e5b3f11" || env != "Development" {
		t.Fatalf("failure fallback: got %q/%q, want app ID and selector env", app, env)
	}
}
