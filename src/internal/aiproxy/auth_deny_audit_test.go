package aiproxy

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
)

// Anyone who can reach the listener can send a request without a capability.
// The denial it produces is durable, so its request-derived fields must pass
// Console's validation however the client shaped them; otherwise the refused
// batch would block every later one until the spool filled and the relay
// stopped.
func TestUnauthenticatedRequestsProduceDenialsConsoleAccepts(t *testing.T) {
	identifier := regexp.MustCompile(`^[A-Za-z0-9._:/-]+$`)
	control := regexp.MustCompile(`[\x00-\x1f\x7f]`)
	var accepted, rejected atomic.Int32
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch agentapi.EventBatchRequest
		_ = json.Unmarshal(body, &batch)
		for _, event := range batch.Events {
			// Console's rules for the request-derived fields.
			if event.Method == "" || len(event.Method) > 32 || !identifier.MatchString(event.Method) ||
				event.Host == "" || len(event.Host) > 512 || control.MatchString(event.Host) ||
				len(event.Path) > 4096 {
				rejected.Add(1)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"code":"invalid_agent_event_batch","message":"invalid","retryable":false,"details":{}}}`))
				return
			}
		}
		accepted.Add(int32(len(batch.Events)))
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
	events, err := newEventBuffer(state, 10*time.Millisecond, t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Stop()
	proxy := httptest.NewServer(&httpProxy{state: state, events: events})
	defer proxy.Close()

	requests := []string{
		"GET http://api.example.test/ HTTP/1.0\r\n\r\n",
		"GET! http://api.example.test/ HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
		strings.Repeat("M", 33) + " http://api.example.test/ HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + strings.Repeat("h", 513) + "\r\n\r\n",
		"GET http://api.example.test/AKIA0123456789ABCDEF HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
	}
	for _, raw := range requests {
		connection, dialErr := net.Dial("tcp", proxy.Listener.Addr().String())
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		if _, writeErr := connection.Write([]byte(raw)); writeErr != nil {
			t.Fatal(writeErr)
		}
		status, readErr := bufio.NewReader(connection).ReadString('\n')
		_ = connection.Close()
		if readErr != nil || !strings.Contains(status, "407") {
			t.Fatalf("request %q: status %q err %v", raw, status, readErr)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for accepted.Load() < int32(len(requests)) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := accepted.Load(); got != int32(len(requests)) {
		t.Fatalf("Console accepted %d denials, want %d (rejected batches: %d)", got, len(requests), rejected.Load())
	}
	if rejected.Load() != 0 {
		t.Fatalf("Console rejected %d batches", rejected.Load())
	}
	select {
	case fatal := <-state.fatal:
		t.Fatalf("unauthenticated requests stopped the relay: %v", fatal)
	default:
	}
}
