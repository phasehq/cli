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
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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
	mu       sync.Mutex
	key      *censor.Key
	keyCalls int
	posts    int
	sizes    []int
	entries  []*censor.Entries
	bodies   [][]byte
	// kinds holds what each registration said of its ids, entry by entry.
	kinds     [][]string
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
			if json.Unmarshal(body, &request) != nil || len(body) > 4<<20 || len(request.IDKinds) != len(request.Entries) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fake.kinds = append(fake.kinds, request.IDKinds)
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

// A session whose environment kept the marker and lost the proxy, as after a
// filter that strips proxy variables, is a session that cannot protect what
// it hands out, not a shell outside any session: the registration fails as it
// does when the session's proxy is down. Another source's proxy is still
// used when there is one.
func TestASessionMarkerWithNoProxyIsABrokenSession(t *testing.T) {
	withEnvironment(t, map[string]string{"PHASE_AI_ENABLED": "1"})
	value := []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_0123456789abcdefghij"}}
	proxy, found := Locate()
	if !found || !proxy.InSession() || proxy.URL != "" {
		t.Fatalf("a session with no proxy in its environment was located as %+v, found %t", proxy, found)
	}
	if _, err := proxy.Register(context.Background(), value); !errors.Is(err, ErrNotListening) {
		t.Fatalf("registering with a session that names no proxy: %v", err)
	}
	if _, err := Register(context.Background(), value); !errors.Is(err, ErrNotListening) {
		t.Fatalf("registering in a session that names no proxy: %v", err)
	}

	machine, server := newFakeProxy(t)
	withSource(t, Source{Name: "runtime", Find: func() (string, bool) { return capabilityURL(server), true }})
	if proxy, found := Locate(); !found || proxy.Source != "runtime" {
		t.Fatalf("a proxy another source finds was passed over: %+v, found %t", proxy, found)
	}
	if result, err := Register(context.Background(), value); err != nil || result.Added != 1 || machine.posts != 1 {
		t.Fatalf("registering with the proxy another source found: %+v %v", result, err)
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
	// Nothing listens there: that is its own error, since it means no proxy
	// runs rather than a proxy that failed. It costs one dial, which is over
	// at once where the system refuses at once and after the dial timeout
	// where it is slow to, as Windows can be, and never the registration's
	// whole time.
	if _, err := Register(context.Background(), []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}}); !errors.Is(err, ErrNotListening) {
		t.Fatalf("a registration with nothing listening came back as %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*Timeout {
		t.Fatalf("a failed registration took %v", elapsed)
	}

	// A proxy that refuses the key, or one off this machine, fails too, and
	// neither is a proxy that is not running.
	fake, server := newFakeProxy(t)
	fake.keyStatus = http.StatusServiceUnavailable
	withEnvironment(t, sessionEnvironment(server))
	if _, err := Register(context.Background(), []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}}); err == nil || errors.Is(err, ErrNotListening) {
		t.Fatalf("a refused key request: %v", err)
	}
	withEnvironment(t, map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": "http://phase:capability@proxy.example.com:9543"})
	if _, err := Register(context.Background(), []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}}); err == nil || errors.Is(err, ErrNotListening) {
		t.Fatalf("a remote proxy: %v", err)
	}
	// A proxy that goes away between the key and the values is not running
	// either.
	fake, server = newFakeProxy(t)
	withEnvironment(t, sessionEnvironment(server))
	if _, err := Register(context.Background(), []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}}); err != nil || fake.keyCalls != 1 {
		t.Fatalf("the first registration: %v", err)
	}
	server.Close()
	if _, err := Register(context.Background(), []Value{{Type: "secret", ID: "y", Value: "sk_" + "live_Z9yX8wV7uT6sR5qP4oN3mL2kJ1iH0gF"}}); !errors.Is(err, ErrNotListening) {
		t.Fatalf("a registration with a proxy that went away came back as %v", err)
	}
}

// A proxy that accepts the connection and does not answer in time is a proxy
// that failed, not one that is not running.
func TestAProxyThatDoesNotAnswerIsNotAProxyThatIsNotRunning(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	held := make(chan net.Conn, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			held <- conn
		}
	}()
	defer func() {
		for {
			select {
			case conn := <-held:
				_ = conn.Close()
			default:
				return
			}
		}
	}()
	withEnvironment(t, map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": "http://phase:capability@" + listener.Addr().String()})
	started := time.Now()
	_, err = Register(context.Background(), []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}})
	if err == nil || errors.Is(err, ErrNotListening) {
		t.Fatalf("a proxy that did not answer: %v", err)
	}
	if elapsed := time.Since(started); elapsed < Timeout/2 || elapsed > 3*Timeout {
		t.Fatalf("a proxy that did not answer was waited for %v", elapsed)
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

// withSource adds a source for the length of a test.
func withSource(t *testing.T, source Source) {
	t.Helper()
	sourcesMu.Lock()
	previous := sources
	sourcesMu.Unlock()
	AddSource(source)
	t.Cleanup(func() {
		sourcesMu.Lock()
		sources = previous
		sourcesMu.Unlock()
	})
}

func capabilityURL(server *httptest.Server) string {
	return strings.Replace(server.URL, "http://", "http://phase:capability@", 1)
}

// A proxy is looked for in order: the session's own environment first, then
// whatever else was added. The first that finds one is registered with.
func TestSourcesAreTriedInOrder(t *testing.T) {
	session, sessionServer := newFakeProxy(t)
	machine, machineServer := newFakeProxy(t)
	later, laterServer := newFakeProxy(t)
	value := []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}}
	machineRuns := true
	asked := 0
	withSource(t, Source{Name: "runtime", Find: func() (string, bool) { asked++; return capabilityURL(machineServer), machineRuns }})
	withSource(t, Source{Name: "later", Find: func() (string, bool) { return capabilityURL(laterServer), true }})
	// A source without a name or a way to look is not kept.
	sourcesMu.RLock()
	before := len(sources)
	sourcesMu.RUnlock()
	AddSource(Source{Name: "", Find: func() (string, bool) { return capabilityURL(laterServer), true }})
	AddSource(Source{Name: "nothing"})
	sourcesMu.RLock()
	if len(sources) != before || sources[0].Name != SourceSession {
		t.Fatalf("the sources: %d, first %q", len(sources), sources[0].Name)
	}
	sourcesMu.RUnlock()

	// Inside a session the session's own proxy is used, and nothing else is
	// even asked.
	withEnvironment(t, sessionEnvironment(sessionServer))
	found, ok := Locate()
	if !ok || !found.InSession() || found.Source != SourceSession || asked != 0 {
		t.Fatalf("inside a session: %+v %v, %d other sources asked", found, ok, asked)
	}
	if result, err := Register(context.Background(), value); err != nil || result.Added != 1 || session.posts != 1 || machine.posts != 0 {
		t.Fatalf("inside a session: %+v %v", result, err)
	}

	// With no proxy in the environment, the next source that finds one.
	withEnvironment(t, map[string]string{})
	found, ok = Locate()
	if !ok || found.InSession() || found.Source != "runtime" || found.URL != capabilityURL(machineServer) {
		t.Fatalf("outside a session: %+v %v", found, ok)
	}
	if result, err := Register(context.Background(), value); err != nil || result.Added != 1 || machine.posts != 1 || machine.keyCalls != 1 || session.posts != 1 {
		t.Fatalf("outside a session: %+v %v", result, err)
	}
	// And the one after it when that one finds nothing.
	machineRuns = false
	if found, ok = Locate(); !ok || found.Source != "later" {
		t.Fatalf("after the first found nothing: %+v %v", found, ok)
	}
	if result, err := Register(context.Background(), value); err != nil || result.Added != 1 || later.posts != 1 || machine.posts != 1 {
		t.Fatalf("after the first found nothing: %+v %v", result, err)
	}
}

// When no source finds a proxy nothing is registered and nothing is called.
func TestNoProxyFoundCostsNothing(t *testing.T) {
	fake, _ := newFakeProxy(t)
	withEnvironment(t, map[string]string{})
	withSource(t, Source{Name: "runtime", Find: func() (string, bool) { return "", false }})
	// A source that says it found a proxy and names none found none.
	withSource(t, Source{Name: "empty", Find: func() (string, bool) { return "", true }})
	if found, ok := Locate(); ok {
		t.Fatalf("a proxy was found: %+v", found)
	}
	result, err := Register(context.Background(), []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}})
	if err != nil || result != (Result{}) || fake.keyCalls != 0 || fake.posts != 0 {
		t.Fatalf("with no proxy: %+v %v", result, err)
	}
}

// A registration says of each id whether it is a secret's key name, in step
// with its entries however they are split.
func TestRegistrationSaysWhatEachIDIs(t *testing.T) {
	fake, server := newFakeProxy(t)
	withEnvironment(t, sessionEnvironment(server))
	previous := maxBatchBytes
	maxBatchBytes = 40 << 10
	t.Cleanup(func() { maxBatchBytes = previous })
	var values []Value
	for i := 0; i < 8; i++ {
		raw := make([]byte, 600)
		_, _ = rand.Read(raw)
		values = append(values, Value{Type: "secret", ID: "value-" + string(rune('a'+i)), KeyName: i%3 == 0, Value: base64.StdEncoding.EncodeToString(raw)})
	}
	// A value that cannot be protected still says what its id is.
	values = append(values, Value{Type: "secret", ID: "LOG LEVEL", KeyName: true, Value: "abc"})
	result, err := Register(context.Background(), values)
	if err != nil || result.Added != 8 || result.Unprotected != 1 {
		t.Fatalf("register: %+v %v", result, err)
	}
	if fake.posts < 2 {
		t.Fatalf("%d posts: the registration was not split", fake.posts)
	}
	wanted := map[string]string{}
	for _, value := range values {
		kind := remoteapi.InventoryIDPhase
		if value.KeyName {
			kind = remoteapi.InventoryIDKeyName
		}
		wanted[PlaceholderID(value.ID)] = kind
	}
	said := map[string]string{}
	index := 0
	for _, kinds := range fake.kinds {
		for _, kind := range kinds {
			said[fake.entries[index].ID] = kind
			index++
		}
	}
	if len(said) != len(values) || index != len(fake.entries) {
		t.Fatalf("%d ids were described for %d values", len(said), len(values))
	}
	for id, kind := range wanted {
		if said[id] != kind {
			t.Errorf("%s was registered as %q, want %q", id, said[id], kind)
		}
	}
	for _, body := range fake.bodies {
		if !strings.Contains(string(body), `"idKinds":["`) {
			t.Fatalf("a registration does not say what its ids are: %.80s", body)
		}
	}
}

// closedProxy is the URL of a proxy nothing listens at.
func closedProxy(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return "http://phase:capability@" + address
}

// restartingSource is a source whose proxy is away for a while: it is found
// at found, which the test changes, and says it is restarting while it is.
type restartingSource struct {
	mu         sync.Mutex
	found      string
	restarting bool
	asked      int
}

func (s *restartingSource) set(found string, restarting bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.found, s.restarting = found, restarting
}

// timesAsked is how often the source was asked whether it is restarting.
func (s *restartingSource) timesAsked() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked
}

func (s *restartingSource) source() Source {
	return Source{
		Name: "runtime",
		Find: func() (string, bool) {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.found, s.found != ""
		},
		Restarting: func() bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.asked++
			return s.restarting
		},
	}
}

// A proxy that is restarting takes no registration for a moment: it is
// starting, or between two sessions with its listener closed. A value handed
// out then would never reach the inventory it comes back with, so the
// registration waits for it, for Timeout in all.
func TestARegistrationWaitsForAProxyThatIsRestarting(t *testing.T) {
	value := []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}}
	for name, start := range map[string]func(t *testing.T) string{
		// Its source does not find it yet.
		"not found yet": func(*testing.T) string { return "" },
		// Its source still points at it, and nothing listens there.
		"found where nothing listens": closedProxy,
	} {
		t.Run(name+", back in time", func(t *testing.T) {
			fake, server := newFakeProxy(t)
			withEnvironment(t, map[string]string{})
			away := &restartingSource{found: start(t), restarting: true}
			withSource(t, away.source())
			found, ok := Locate()
			if !ok || found.InSession() || found.Source != "runtime" {
				t.Fatalf("a proxy that is restarting was not found: %+v %v", found, ok)
			}
			go func() {
				time.Sleep(150 * time.Millisecond)
				away.set(capabilityURL(server), true)
			}()
			started := time.Now()
			result, err := Register(context.Background(), value)
			if elapsed := time.Since(started); err != nil || result.Added != 1 || fake.posts != 1 || elapsed < 100*time.Millisecond || elapsed > Timeout+500*time.Millisecond {
				t.Fatalf("a registration with a proxy back after 150ms: %+v %v after %v", result, err, elapsed)
			}
		})
		t.Run(name+", not back in time", func(t *testing.T) {
			withEnvironment(t, map[string]string{})
			away := &restartingSource{found: start(t), restarting: true}
			withSource(t, away.source())
			started := time.Now()
			result, err := Register(context.Background(), value)
			elapsed := time.Since(started)
			// Its own error: a proxy runs, and the values are not protected.
			if !errors.Is(err, ErrRestarting) || errors.Is(err, ErrNotListening) || result != (Result{}) {
				t.Fatalf("a registration with a proxy that stayed away: %+v %v", result, err)
			}
			if elapsed < Timeout*8/10 || elapsed > 2*Timeout {
				t.Fatalf("a proxy that is restarting was waited for %v, not about %v", elapsed, Timeout)
			}
		})
		t.Run(name+", gone for good", func(t *testing.T) {
			withEnvironment(t, map[string]string{})
			away := &restartingSource{found: start(t), restarting: true}
			withSource(t, away.source())
			proxy, ok := Locate()
			if !ok {
				t.Fatal("a proxy that is restarting was not found")
			}
			// Its process ends while it is waited for: no proxy runs.
			go func() {
				time.Sleep(100 * time.Millisecond)
				away.set("", false)
			}()
			started := time.Now()
			_, err := proxy.Register(context.Background(), value)
			if elapsed := time.Since(started); !errors.Is(err, ErrNotListening) || elapsed > Timeout*8/10 {
				t.Fatalf("a proxy that went away for good: %v after %v", err, elapsed)
			}
		})
	}

	// A source that does not say its proxy is restarting is not waited for,
	// and is not even asked when there is nothing to register. Not waited for
	// is one dial: that is at most the dial timeout, where the system takes
	// its time to refuse, and well short of the wait.
	oneDial := dialTimeout + Timeout/2
	withEnvironment(t, map[string]string{})
	gone := &restartingSource{found: closedProxy(t)}
	withSource(t, gone.source())
	started := time.Now()
	if _, err := Register(context.Background(), value); !errors.Is(err, ErrNotListening) || time.Since(started) > oneDial {
		t.Fatalf("a proxy that is not running: %v after %v", err, time.Since(started))
	}
	gone.set(closedProxy(t), true)
	proxy, _ := Locate()
	asked := gone.timesAsked()
	if result, err := proxy.Register(context.Background(), []Value{{Type: "config", ID: "LOG_LEVEL", Value: "debug-level-value"}}); err != nil || result != (Result{}) || gone.timesAsked() != asked {
		t.Fatalf("a registration of nothing: %+v %v, the source was asked %d times", result, err, gone.timesAsked()-asked)
	}
	// The wait ends with the command's own context. With nothing to dial
	// that is the wait's own error.
	gone.set("", true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started = time.Now()
	if _, err := Register(ctx, value); !errors.Is(err, ErrRestarting) || time.Since(started) > Timeout/2 {
		t.Fatalf("a wait whose context ended: %v after %v", err, time.Since(started))
	}
	// With an address nothing listens at, the context may end the dial
	// before the system has refused it, which is no refusal: whatever the
	// error, it is never that no proxy runs, and it comes with the context.
	gone.set(closedProxy(t), true)
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started = time.Now()
	if _, err := Register(ctx, value); err == nil || errors.Is(err, ErrNotListening) || time.Since(started) > Timeout/2 {
		t.Fatalf("a wait whose context ended while it dialled: %v after %v", err, time.Since(started))
	}
	// A session's own proxy says nothing of the kind: nothing listening there
	// fails after one dial, as before, and no other source is asked about it.
	withEnvironment(t, map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": closedProxy(t)})
	asked = gone.timesAsked()
	started = time.Now()
	if _, err := Register(context.Background(), value); !errors.Is(err, ErrNotListening) || time.Since(started) > oneDial || gone.timesAsked() != asked {
		t.Fatalf("a session whose proxy is gone: %v after %v, another source asked %d times", err, time.Since(started), gone.timesAsked()-asked)
	}
}

// withDialTimeout sets how long a registration's connection may take to be
// made, for the length of a test.
func withDialTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()
	previous := dialTimeout
	dialTimeout = timeout
	t.Cleanup(func() { dialTimeout = previous })
}

// A connection to the proxy's address that is not made in time means nothing
// listens there, as a refused one does: the address is a loopback one, and
// that is how a port nothing listens on shows where the system is slow to
// refuse. Here the dial is given no time at all, so the error is the dialer's
// own for a dial that did not complete, on every system, although a proxy
// listens.
func TestADialThatRunsOutOfTimeIsNothingListening(t *testing.T) {
	value := []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}}
	fake, server := newFakeProxy(t)
	withDialTimeout(t, -time.Second)
	// A proxy found outside the session's environment: stale state, to the
	// command that asked.
	withEnvironment(t, map[string]string{})
	withSource(t, Source{Name: "runtime", Find: func() (string, bool) { return capabilityURL(server), true }})
	if _, err := Register(context.Background(), value); !errors.Is(err, ErrNotListening) {
		t.Fatalf("a dial that ran out of time, outside a session: %v", err)
	}
	// Inside a session the error is the same; it is the command that treats
	// it as a failure there.
	withEnvironment(t, sessionEnvironment(server))
	if _, err := Register(context.Background(), value); !errors.Is(err, ErrNotListening) {
		t.Fatalf("a dial that ran out of time, inside a session: %v", err)
	}
	if fake.keyCalls != 0 || fake.posts != 0 {
		t.Fatalf("the proxy was reached %d times by a dial given no time", fake.keyCalls+fake.posts)
	}
	// Given time, the same registration goes through: only the dial failed.
	dialTimeout = 5 * time.Second
	if result, err := Register(context.Background(), value); err != nil || result.Added != 1 {
		t.Fatalf("the same registration with time to dial: %+v %v", result, err)
	}

	// Only a dial that timed out is told so: not a call that timed out once
	// the connection stood, not a dial that failed some other way, and not a
	// dial that was cancelled.
	timedOut := &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	for name, c := range map[string]struct {
		err  error
		want bool
	}{
		"a dial that timed out, as the client reports it": {&url.Error{Op: "Get", URL: "http://phase.invalid/v1/inventory/key", Err: &net.OpError{Op: "proxyconnect", Net: "tcp", Err: timedOut}}, true},
		"a dial that timed out":                           {timedOut, true},
		"a read that timed out":                           {&url.Error{Op: "Get", URL: "http://phase.invalid/", Err: &net.OpError{Op: "read", Net: "tcp", Err: context.DeadlineExceeded}}, false},
		"a call that outlived its context":                {&url.Error{Op: "Get", URL: "http://phase.invalid/", Err: context.DeadlineExceeded}, false},
		"a dial that was cancelled":                       {&net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled}, false},
		"a dial that failed for another reason":           {&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("no route to host")}, false},
		"no error":                                        {nil, false},
	} {
		if got := dialTimedOut(c.err); got != c.want {
			t.Errorf("%s: timed out in the dial = %v", name, got)
		}
		if listening := !errors.Is(unanswered(c.err), ErrNotListening); c.err != nil && listening == c.want {
			t.Errorf("%s: taken for nothing listening = %v", name, !listening)
		}
	}
}

// slowRefusals makes a connection to an address nothing listens at fail the
// way it does where the system is slow to refuse, on any system: the refusal
// arrives delay after the dial began, so a dial given less time than that
// runs out of it instead. Every error it returns is the dialer's own.
func slowRefusals(t *testing.T, delay time.Duration) {
	t.Helper()
	previous := controlClient
	controlClient = func(rawProxyURL string, dial, timeout time.Duration) (*http.Client, error) {
		client, err := previous(rawProxyURL, dial, timeout)
		if err != nil {
			return nil, err
		}
		client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			began := time.Now()
			conn, err := (&net.Dialer{Timeout: dial}).DialContext(ctx, network, address)
			if err == nil || !connectionRefused(err) {
				return conn, err
			}
			inTime := dial <= 0 || dial >= delay
			wait := delay
			if !inTime {
				wait = dial
			}
			select {
			case <-ctx.Done():
				return (&net.Dialer{}).DialContext(ctx, network, address)
			case <-time.After(wait - time.Since(began)):
			}
			if inTime {
				return nil, err
			}
			return (&net.Dialer{Timeout: -time.Second}).DialContext(ctx, network, address)
		}
		return client, nil
	}
	t.Cleanup(func() { controlClient = previous })
}

// Where the system takes two seconds to refuse a connection to a port
// nothing listens on, a registration does not wait for the refusal. Stale
// state costs one dial timeout, well under a second, and the wait for a
// proxy that is restarting still ends on time, although each dial it makes
// meanwhile takes its whole timeout.
func TestASlowRefusalIsNotWaitedFor(t *testing.T) {
	value := []Value{{Type: "secret", ID: "x", Value: "sk_" + "live_Q7tZ2mK9pL4vX8rN1wB6yC3dF5hJ0aS"}}
	slowRefusals(t, 2*time.Second)
	if dialTimeout >= Timeout/2 {
		t.Fatalf("the dial timeout is %v: stale state would cost half the registration's time or more", dialTimeout)
	}
	// What one dial that runs out of time costs, with room for a slow machine
	// and still well under the second a refusal would take.
	oneDial := dialTimeout + Timeout/2

	t.Run("stale state costs one dial", func(t *testing.T) {
		// No proxy runs, and it takes one dial to know.
		withEnvironment(t, map[string]string{})
		withSource(t, (&restartingSource{found: closedProxy(t)}).source())
		started := time.Now()
		_, err := Register(context.Background(), value)
		if elapsed := time.Since(started); !errors.Is(err, ErrNotListening) || elapsed < dialTimeout*8/10 || elapsed > oneDial {
			t.Fatalf("stale state: %v after %v, want nothing listening after about %v", err, elapsed, dialTimeout)
		}
		// A session whose proxy is gone: the same error as soon.
		withEnvironment(t, map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": closedProxy(t)})
		started = time.Now()
		_, err = Register(context.Background(), value)
		if elapsed := time.Since(started); !errors.Is(err, ErrNotListening) || elapsed > oneDial {
			t.Fatalf("a session whose proxy is gone: %v after %v", err, elapsed)
		}
	})

	t.Run("a proxy that stays away is waited for no longer", func(t *testing.T) {
		// The wait is Timeout in all, the dials included.
		withEnvironment(t, map[string]string{})
		withSource(t, (&restartingSource{found: closedProxy(t), restarting: true}).source())
		started := time.Now()
		_, err := Register(context.Background(), value)
		if elapsed := time.Since(started); !errors.Is(err, ErrRestarting) || elapsed < Timeout*8/10 || elapsed > Timeout+Timeout/4 {
			t.Fatalf("a proxy that stayed away: %v after %v, want a wait of about %v", err, elapsed, Timeout)
		}
	})

	// Here a dial takes more than half the wait, so the second one is cut
	// short where the wait ends: a wait that let it run, or that began
	// counting after the first, would end late. And a dial cut short says
	// nothing of what listens there. The source stops saying its proxy is
	// restarting once that dial is made, as when the proxy came back, or went
	// for good, in that moment: the answer is still that the proxy was not
	// back in time, never that none runs.
	t.Run("the last dial of the wait is cut short", func(t *testing.T) {
		withEnvironment(t, map[string]string{})
		withDialTimeout(t, 600*time.Millisecond)
		var cutShort atomic.Bool
		slow := controlClient
		controlClient = func(rawProxyURL string, dial, timeout time.Duration) (*http.Client, error) {
			if dial < dialTimeout {
				cutShort.Store(true)
			}
			return slow(rawProxyURL, dial, timeout)
		}
		t.Cleanup(func() { controlClient = slow })
		address := closedProxy(t)
		withSource(t, Source{
			Name:       "runtime",
			Find:       func() (string, bool) { return address, true },
			Restarting: func() bool { return !cutShort.Load() },
		})
		started := time.Now()
		_, err := Register(context.Background(), value)
		elapsed := time.Since(started)
		if !cutShort.Load() {
			t.Fatalf("no dial was cut short in a wait of %v with dials of %v: %v after %v", Timeout, dialTimeout, err, elapsed)
		}
		if !errors.Is(err, ErrRestarting) || elapsed < Timeout*8/10 || elapsed > Timeout+Timeout/4 {
			t.Fatalf("a wait whose last dial was cut short: %v after %v, want a proxy not back after about %v", err, elapsed, Timeout)
		}
	})

	t.Run("a proxy back after the first dial is registered with", func(t *testing.T) {
		fake, server := newFakeProxy(t)
		withEnvironment(t, map[string]string{})
		away := &restartingSource{found: closedProxy(t), restarting: true}
		withSource(t, away.source())
		back := dialTimeout + 50*time.Millisecond
		go func() {
			time.Sleep(back)
			away.set(capabilityURL(server), true)
		}()
		started := time.Now()
		result, err := Register(context.Background(), value)
		if elapsed := time.Since(started); err != nil || result.Added != 1 || fake.posts != 1 || elapsed > Timeout+Timeout/4 {
			t.Fatalf("a proxy back after the first dial: %+v %v after %v", result, err, elapsed)
		}
	})

	t.Run("a refusal within the dial's time is still a refusal", func(t *testing.T) {
		withEnvironment(t, map[string]string{})
		withDialTimeout(t, 400*time.Millisecond)
		slowRefusals(t, 100*time.Millisecond)
		withSource(t, (&restartingSource{found: closedProxy(t)}).source())
		started := time.Now()
		_, err := Register(context.Background(), value)
		if elapsed := time.Since(started); !errors.Is(err, ErrNotListening) || elapsed > dialTimeout+Timeout/2 {
			t.Fatalf("a refusal after 100ms: %v after %v", err, elapsed)
		}
	})
}
