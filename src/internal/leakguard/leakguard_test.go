package leakguard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
)

func withEnvironment(t *testing.T, values map[string]string) {
	t.Helper()
	previous := Environment
	Environment = func(key string) string { return values[key] }
	keyMu.Lock()
	cachedKey, keyProxy = nil, ""
	keyMu.Unlock()
	t.Cleanup(func() {
		Environment = previous
		keyMu.Lock()
		cachedKey, keyProxy = nil, ""
		keyMu.Unlock()
	})
}

// fakeProxy answers the two control routes the way the Phase proxy does, as
// an HTTP proxy that receives absolute-form requests for phase.invalid.
type fakeProxy struct {
	mu        sync.Mutex
	key       *censor.Key
	keyCalls  int
	posts     int
	sizes     []int
	entries   []*censor.Entries
	bodies    [][]byte
	keyStatus int
	full      bool
}

func newFakeProxy(t *testing.T) (*fakeProxy, *httptest.Server) {
	t.Helper()
	key, err := censor.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeProxy{key: key}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("phase:capability")) || r.URL.Host != "phase.invalid" {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/inventory/key":
			fake.keyCalls++
			if fake.keyStatus != 0 {
				w.WriteHeader(fake.keyStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(remoteapi.InventoryKeyResponse{SchemaVersion: 1, Key: base64.StdEncoding.EncodeToString(key.Bytes()), Format: censor.EntriesVersion})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/inventory":
			body, _ := io.ReadAll(r.Body)
			fake.posts++
			if fake.full {
				w.WriteHeader(http.StatusInsufficientStorage)
				_, _ = w.Write([]byte(`{"error":{"code":"leak_inventory_full","message":"full"}}`))
				return
			}
			fake.sizes = append(fake.sizes, len(body))
			fake.bodies = append(fake.bodies, body)
			var request remoteapi.InventoryRequest
			if json.Unmarshal(body, &request) != nil || len(body) > 4<<20 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			answer := remoteapi.InventoryResponse{SchemaVersion: 1}
			for _, raw := range request.Entries {
				entry, err := censor.ParseEntries(raw)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				fake.entries = append(fake.entries, entry)
				if entry.Protected() {
					answer.Added++
				} else {
					answer.Unprotected++
				}
			}
			_ = json.NewEncoder(w).Encode(answer)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return fake, server
}

func sessionEnvironment(server *httptest.Server) map[string]string {
	proxy := strings.Replace(server.URL, "http://", "http://phase:capability@", 1)
	return map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": proxy}
}

func TestOutsideASessionNothingHappens(t *testing.T) {
	fake, server := newFakeProxy(t)
	for _, environment := range []map[string]string{
		{},
		{"HTTPS_PROXY": strings.Replace(server.URL, "http://", "http://phase:capability@", 1)},
		{"PHASE_AI_ENABLED": "1"},
	} {
		withEnvironment(t, environment)
		if Active() {
			t.Fatalf("%v counts as a session", environment)
		}
		if _, err := Register(context.Background(), []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_0123456789abcdefghij"}}); err != nil {
			t.Fatal(err)
		}
	}
	if fake.keyCalls != 0 || fake.posts != 0 {
		t.Fatal("a call was made outside a session")
	}
}

func TestConfigValuesAreNotRegisteredAndCostNothing(t *testing.T) {
	fake, server := newFakeProxy(t)
	withEnvironment(t, sessionEnvironment(server))
	if _, err := Register(context.Background(), []Value{{Type: "config", ID: "x", Value: "debug-level-config-value-0001"}, {Type: "secret", ID: "y", Value: "  "}}); err != nil {
		t.Fatal(err)
	}
	if fake.keyCalls != 0 || fake.posts != 0 {
		t.Fatal("config values were registered")
	}
}

func TestRegisterSendsKeyedHashesOnlyAndFetchesTheKeyOnce(t *testing.T) {
	fake, server := newFakeProxy(t)
	withEnvironment(t, sessionEnvironment(server))
	value := "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"
	for i := 0; i < 2; i++ {
		result, err := Register(context.Background(), []Value{
			{Type: "secret", ID: "secret-uuid-1", Value: value},
			{Type: "Sealed", ID: "DATABASE URL", Value: "postgres://u:Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3@db:5432/app"},
			{Type: "dynamic", ID: "lease-1", Value: "abc"},
		})
		if err != nil || result.Added != 2 || result.Unprotected != 1 {
			t.Fatalf("register: %+v %v", result, err)
		}
	}
	if fake.keyCalls != 1 {
		t.Fatalf("the key was fetched %d times", fake.keyCalls)
	}
	for _, body := range fake.bodies {
		if strings.Contains(string(body), value) || strings.Contains(string(body), "Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3") ||
			strings.Contains(string(body), base64.StdEncoding.EncodeToString([]byte(value))) {
			t.Fatal("a registration carries a value")
		}
	}
	placeholders := map[string]bool{}
	for _, entry := range fake.entries {
		placeholders[entry.Placeholder()] = true
	}
	if !placeholders["ph:secret:secret-uuid-1"] || !placeholders["ph:sealed:"+PlaceholderID("DATABASE URL")] || !placeholders["ph:dynamic:lease-1"] {
		t.Fatalf("placeholders: %v", placeholders)
	}
	// The index the proxy builds from them finds the value.
	index, _ := censor.NewIndex(fake.key, censor.IndexOptions{})
	for _, entry := range fake.entries {
		if err := index.Add(entry); err != nil {
			t.Fatal(err)
		}
	}
	out, report, err := index.RewriteJSON([]byte(`{"messages":["`+value+`"]}`), censor.ScanOptions{})
	if err != nil || !report.Changed || strings.Contains(string(out), value) {
		t.Fatalf("the registered value is not found: %s", out)
	}
}

func TestLargeRegistrationsAreSplitUnderTheProxyLimit(t *testing.T) {
	fake, server := newFakeProxy(t)
	withEnvironment(t, sessionEnvironment(server))
	previous := maxBatchBytes
	maxBatchBytes = 300 << 10
	t.Cleanup(func() { maxBatchBytes = previous })
	var values []Value
	for i := 0; i < 6; i++ {
		raw := make([]byte, 3<<10)
		_, _ = rand.Read(raw)
		values = append(values, Value{Type: "secret", ID: "big-" + string(rune('a'+i)), Value: base64.StdEncoding.EncodeToString(raw)[:4<<10]})
	}
	result, err := Register(context.Background(), values)
	if err != nil || result.Added != 6 {
		t.Fatalf("register: %+v %v", result, err)
	}
	if fake.posts < 2 {
		t.Fatalf("%d posts for %d large values", fake.posts, len(values))
	}
	for _, size := range fake.sizes {
		if size > maxBatchBytes+maxBatchBytes/4 {
			t.Fatalf("a registration of %d bytes is over the batch limit", size)
		}
	}
}

func TestRegisterFailsFastWhenTheProxyIsDown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	withEnvironment(t, map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": "http://phase:capability@" + address})
	started := time.Now()
	if _, err := Register(context.Background(), []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}}); err == nil {
		t.Fatal("a registration with no proxy succeeded")
	}
	if elapsed := time.Since(started); elapsed > 2*Timeout {
		t.Fatalf("a failed registration took %v", elapsed)
	}

	// A proxy that refuses the key, or one off this machine, fails too.
	fake, server := newFakeProxy(t)
	fake.keyStatus = http.StatusServiceUnavailable
	withEnvironment(t, sessionEnvironment(server))
	if _, err := Register(context.Background(), []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}}); err == nil {
		t.Fatal("a refused key request succeeded")
	}
	withEnvironment(t, map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": "http://phase:capability@proxy.example.com:9543"})
	if _, err := Register(context.Background(), []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}}); err == nil {
		t.Fatal("a remote proxy was used")
	}
}

func TestPlaceholderIDNeverHoldsAnythingButTheName(t *testing.T) {
	if PlaceholderID("DATABASE_URL") != "DATABASE_URL" {
		t.Fatal("a key name that fits is used as it is")
	}
	id := PlaceholderID("DATABASE URL/with spaces")
	if !identifier.MatchString(id) || strings.Contains(id, " ") {
		t.Fatalf("id %q", id)
	}
	if PlaceholderID("DATABASE URL/with spaces") != id {
		t.Fatal("the id is not deterministic")
	}
}

// A full inventory is its own error: the proxy answered, so nothing may say
// it could not be reached.
func TestAFullInventoryIsNotAnUnreachableProxy(t *testing.T) {
	fake, server := newFakeProxy(t)
	fake.full = true
	withEnvironment(t, sessionEnvironment(server))
	_, err := Register(context.Background(), []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}})
	if !errors.Is(err, ErrInventoryFull) {
		t.Fatalf("a full inventory came back as %v", err)
	}
}
