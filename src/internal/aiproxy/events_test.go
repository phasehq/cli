package aiproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
)

func TestDenialAuditSpoolRetriesAcrossProxyRestart(t *testing.T) {
	var unavailable atomic.Bool
	unavailable.Store(true)
	var calls atomic.Int32
	var mu sync.Mutex
	var eventIDs []string
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch agentapi.EventBatchRequest
		_ = json.Unmarshal(body, &batch)
		mu.Lock()
		for _, event := range batch.Events {
			eventIDs = append(eventIDs, event.EventID)
		}
		mu.Unlock()
		calls.Add(1)
		if unavailable.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"code":"temporary","message":"retry","retryable":true,"details":{}}}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"schemaVersion":1,"accepted":1,"duplicates":0}`))
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	spoolDirectory := t.TempDir()
	event := agentapi.Event{
		EventID: "event-durable-denial", CreatedAt: time.Now().UTC(), GrantID: "grant-1",
		EventType: "request", Protocol: "http", Method: http.MethodGet, Host: "api.example.test",
		ProxyDecision: "block", Outcome: "denied", Reason: "matched_connection_route",
	}

	stateOne, err := newRuntimeStateWithCapability(emptyProxySession(t, client, "spool-capability"), "spool-runtime-capability")
	if err != nil {
		t.Fatal(err)
	}
	bufferOne, err := newEventBuffer(stateOne, 10*time.Millisecond, spoolDirectory, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	bufferOne.Emit(event)
	waitForAtomic(t, &calls, 1)
	bufferOne.Stop()
	stateOne.destroy()

	files := spoolJSONFiles(t, spoolDirectory)
	if len(files) != 1 {
		t.Fatalf("durable spool files=%d, want 1", len(files))
	}
	info, err := os.Stat(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("spool mode=%#o, want 0600", info.Mode().Perm())
	}
	payload, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if stringContainsAny(string(payload), "spool-capability", durableTestToken()) {
		t.Fatalf("spool leaked credential: %s", payload)
	}

	unavailable.Store(false)
	stateTwo, err := newRuntimeStateWithCapability(emptyProxySession(t, client, "spool-capability"), "spool-runtime-capability")
	if err != nil {
		t.Fatal(err)
	}
	bufferTwo, err := newEventBuffer(stateTwo, 10*time.Millisecond, spoolDirectory, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	waitForAtomic(t, &calls, 2)
	bufferTwo.Stop()
	stateTwo.destroy()
	if files := spoolJSONFiles(t, spoolDirectory); len(files) != 0 {
		t.Fatalf("delivered spool retained %d files", len(files))
	}
	mu.Lock()
	defer mu.Unlock()
	seen := 0
	for _, id := range eventIDs {
		if id == event.EventID {
			seen++
		}
	}
	if seen < 2 {
		t.Fatalf("event ID was not replayed idempotently: %v", eventIDs)
	}
}

func TestLockdownUnboundCONNECTEmitsDurableEventWithPort(t *testing.T) {
	const (
		backendCapability = "backend-connect-capability"
		runtimeCapability = "runtime-connect-capability"
	)
	batches := make(chan agentapi.EventBatchRequest, 1)
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch agentapi.EventBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode event batch: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		batches <- batch
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"schemaVersion":1,"accepted":1,"duplicates":0}`))
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(emptyProxySession(t, client, backendCapability), runtimeCapability)
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	spoolDirectory := t.TempDir()
	events, err := newEventBuffer(state, time.Hour, spoolDirectory, 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	proxy := &httpProxy{state: state, lockdown: true, events: events}
	request := httptest.NewRequest(http.MethodConnect, "http://proxy.invalid", nil)
	request.Host = "ssmmessages.eu-central-1.amazonaws.com:8443"
	setProxyCapability(request, runtimeCapability)
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("CONNECT status=%d body=%s", response.Code, response.Body.String())
	}
	if files := spoolJSONFiles(t, spoolDirectory); len(files) != 1 {
		t.Fatalf("durable CONNECT denial spool files=%d, want 1", len(files))
	}
	if err := events.Stop(); err != nil {
		t.Fatal(err)
	}

	select {
	case batch := <-batches:
		if len(batch.Events) != 1 {
			t.Fatalf("events=%d, want 1", len(batch.Events))
		}
		event := batch.Events[0]
		if event.Method != http.MethodConnect || event.Host != "ssmmessages.eu-central-1.amazonaws.com" || event.Port != 8443 {
			t.Fatalf("CONNECT destination event=%+v", event)
		}
		if event.ProxyDecision != "block" || event.Outcome != "denied" || event.Reason != "lockdown_unbound_host" || event.StatusCode != http.StatusForbidden {
			t.Fatalf("CONNECT denial event=%+v", event)
		}
		encoded, marshalErr := json.Marshal(batch)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if stringContainsAny(string(encoded), backendCapability, runtimeCapability, durableTestToken()) {
			t.Fatalf("CONNECT denial event leaked credentials: %s", encoded)
		}
	case <-time.After(time.Second):
		t.Fatal("CONNECT denial event was not shipped")
	}
	if files := spoolJSONFiles(t, spoolDirectory); len(files) != 0 {
		t.Fatalf("acknowledged CONNECT denial retained %d spool files", len(files))
	}
}

func TestSafeEventDetailPreservesRedactedAWSSigV4Failure(t *testing.T) {
	const failure = "missing_authorization"
	detail := safeEventDetail(map[string]any{"aws_sigv4_failure": failure}, nil)
	if got := detail["aws_sigv4_failure"]; got != failure {
		t.Fatalf("AWS SigV4 failure detail=%v", detail)
	}
	for _, unsafe := range []string{failure + "\nsecret", strings.Repeat("x", 65)} {
		if detail := safeEventDetail(map[string]any{"aws_sigv4_failure": unsafe}, nil); len(detail) != 0 {
			t.Fatalf("unsafe AWS SigV4 failure detail survived: %v", detail)
		}
	}
	if detail := safeEventDetail(map[string]any{"aws_sigv4_failure": failure}, []string{failure}); len(detail) != 0 {
		t.Fatalf("credential-shaped AWS SigV4 failure detail survived: %v", detail)
	}
}

func waitForAtomic(t *testing.T, value *atomic.Int32, minimum int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for value.Load() < minimum && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if value.Load() < minimum {
		t.Fatalf("calls=%d, want at least %d", value.Load(), minimum)
	}
}

func spoolJSONFiles(t *testing.T, root string) []string {
	t.Helper()
	var result []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && filepath.Ext(path) == ".json" {
			result = append(result, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func stringContainsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if candidate != "" && len(candidate) <= len(value) {
			for index := 0; index+len(candidate) <= len(value); index++ {
				if value[index:index+len(candidate)] == candidate {
					return true
				}
			}
		}
	}
	return false
}

func TestUnauthenticatedRequestFieldsAreRedactedInsteadOfStoppingTheRelay(t *testing.T) {
	var mu sync.Mutex
	var received []agentapi.Event
	var calls atomic.Int32
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch agentapi.EventBatchRequest
		_ = json.Unmarshal(body, &batch)
		mu.Lock()
		received = append(received, batch.Events...)
		mu.Unlock()
		calls.Add(1)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"schemaVersion":1,"accepted":1,"duplicates":0}`))
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state, err := newRuntimeStateWithCapability(emptyProxySession(t, client, "spool-capability"), "spool-runtime-capability")
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	buffer, err := newEventBuffer(state, 10*time.Millisecond, t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer buffer.Stop()

	// Anyone can send a request without a capability; its path and authority
	// are theirs to choose, and a credential-shaped value there must neither
	// be recorded nor take the relay down.
	buffer.Emit(agentapi.Event{
		EventID: "event-auth-deny", CreatedAt: time.Now().UTC(), EventType: "request", Protocol: "http",
		Method: "G\x00ET", Host: "psx_sess_forged_host", Path: "/AKIA0123456789ABCDEF/spool-capability",
		ProxyDecision: "auth_deny", Outcome: "denied", Reason: "invalid_runtime_capability",
	})
	waitForAtomic(t, &calls, 1)
	select {
	case err := <-state.fatal:
		t.Fatalf("an unauthenticated request stopped the relay: %v", err)
	default:
	}
	mu.Lock()
	defer mu.Unlock()
	// A durable event may be re-sent from the spool on a later tick before its
	// acknowledgement lands; delivery is idempotent by EventID, so every copy
	// must carry the redacted fields and none the original ones.
	delivered := 0
	for _, event := range received {
		if event.EventID != "event-auth-deny" {
			t.Fatalf("unexpected event delivered: %+v", event)
		}
		delivered++
		if event.Method != "UNKNOWN" || event.Host != "redacted.invalid" || event.Path != "/redacted" || event.ProxyDecision != "auth_deny" {
			t.Fatalf("request fields were not redacted: %+v", event)
		}
	}
	if delivered == 0 {
		t.Fatal("the denial was not delivered")
	}
}

func TestRedactRequestFieldsMirrorsConsoleFieldRules(t *testing.T) {
	secrets := []string{"live-secret-value"}
	long := strings.Repeat("a", 513)
	for name, tc := range map[string]struct {
		in   agentapi.Event
		want agentapi.Event
	}{
		"clean request is untouched": {
			in:   agentapi.Event{Method: "GET", Host: "api.example.test", Path: "/repos/o/r"},
			want: agentapi.Event{Method: "GET", Host: "api.example.test", Path: "/repos/o/r"},
		},
		"token method characters and length": {
			in:   agentapi.Event{Method: "GET!", Host: "api.example.test", Path: "/"},
			want: agentapi.Event{Method: "UNKNOWN", Host: "api.example.test", Path: "/"},
		},
		"over-long method": {
			in:   agentapi.Event{Method: strings.Repeat("M", 33), Host: "api.example.test", Path: "/"},
			want: agentapi.Event{Method: "UNKNOWN", Host: "api.example.test", Path: "/"},
		},
		"empty method and host": {
			in:   agentapi.Event{Method: "", Host: "", Path: "/"},
			want: agentapi.Event{Method: "UNKNOWN", Host: "redacted.invalid", Path: "/"},
		},
		"over-long host and control character": {
			in:   agentapi.Event{Method: "GET", Host: long, Path: "/a\x01b"},
			want: agentapi.Event{Method: "UNKNOWN"[:0] + "GET", Host: "redacted.invalid", Path: "/redacted"},
		},
		"credential-shaped and secret-bearing fields": {
			in:   agentapi.Event{Method: "GET", Host: "psx_sess_forged", Path: "/AKIA0123456789ABCDEF/live-secret-value"},
			want: agentapi.Event{Method: "GET", Host: "redacted.invalid", Path: "/redacted"},
		},
		"over-long path": {
			in:   agentapi.Event{Method: "GET", Host: "api.example.test", Path: "/" + strings.Repeat("p", 4096)},
			want: agentapi.Event{Method: "GET", Host: "api.example.test", Path: "/redacted"},
		},
	} {
		event := tc.in
		redactRequestFields(&event, secrets)
		if event.Method != tc.want.Method || event.Host != tc.want.Host || event.Path != tc.want.Path {
			t.Fatalf("%s: got method=%q host=%q path=%q, want method=%q host=%q path=%q", name, event.Method, event.Host, event.Path, tc.want.Method, tc.want.Host, tc.want.Path)
		}
	}
}
