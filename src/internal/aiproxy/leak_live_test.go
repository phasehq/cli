package aiproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/pkg/censor"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// The live leak proxy: the proxy's leak protection on a loopback address, for
// a person to point a real AI tool at. It is the real HTTP proxy, leak guard,
// host table, event pipeline and upstream transport, with a throwaway CA whose
// key never leaves memory, a session that exists only in this process and a
// stand-in for the Console that prints the events it is sent. It needs no
// Phase login, no Console, no keychain and nothing under ~/.phase, and it
// runs nothing itself: whoever starts it runs the tool.
//
//	PHASE_LIVE_LEAK_PROXY   loopback address to listen on, for example 127.0.0.1:18444 (required; the test is skipped without it)
//	PHASE_LIVE_LEAK_VALUES  file of values to protect, one per line (optional); they are registered as live-1, live-2, ...
//	PHASE_LIVE_LEAK_STOP    file whose appearance stops the proxy (optional); it stops after 10 minutes either way
//	PHASE_LIVE_LEAK_TRACE   set to 1 to also print each CONNECT, each upstream dial and events that are not leak events
//	PHASE_AI_LEAK_PROTECTION censor (default), observe or off, as for the real proxy
//
//	go test ./internal/aiproxy -run '^TestLiveLeakProxy$' -count=1 -v -timeout 11m
//
// It prints the CA file, the proxy URL to give the tool, and then one line per
// leak protection event: its type, outcome, reason, host, path, counts and
// placeholders. Nothing it prints holds content of a request or a value.
const (
	liveProxyEnvironmentKey  = "PHASE_LIVE_LEAK_PROXY"
	liveValuesEnvironmentKey = "PHASE_LIVE_LEAK_VALUES"
	liveStopEnvironmentKey   = "PHASE_LIVE_LEAK_STOP"
	liveTraceEnvironmentKey  = "PHASE_LIVE_LEAK_TRACE"
	liveProxyLifetime        = 10 * time.Minute
)

// liveOutput writes whole lines, one writer at a time.
type liveOutput struct {
	mu sync.Mutex
	w  io.Writer
}

func (o *liveOutput) line(format string, arguments ...any) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = fmt.Fprintf(o.w, format+"\n", arguments...)
}

// liveEventLine describes one event without anything a request carried: the
// fields the proxy wrote, the counts, the rule labels and the placeholders.
func liveEventLine(event agentapi.Event) string {
	var line strings.Builder
	fmt.Fprintf(&line, "event type=%s outcome=%s reason=%s host=%s path=%s method=%s protocol=%s decision=%s",
		event.EventType, event.Outcome, event.Reason, event.Host, event.Path, event.Method, event.Protocol, event.ProxyDecision)
	if event.StatusCode != 0 {
		fmt.Fprintf(&line, " status=%d", event.StatusCode)
	}
	names := make([]string, 0, len(event.Detail))
	for name := range event.Detail {
		if name != "placeholders" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&line, " %s=%v", name, event.Detail[name])
	}
	if placeholders, ok := event.Detail["placeholders"]; ok {
		fmt.Fprintf(&line, " placeholders=%v", placeholders)
	}
	return line.String()
}

// liveValues reads the values to protect. They are indexed as the CLI indexes
// what it hands out, and never printed.
func liveValues(t *testing.T, guard *leakGuard, path string) (registered, unprotected int) {
	t.Helper()
	if path == "" {
		return 0, 0
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("%s: the file of values could not be opened", liveValuesEnvironmentKey)
	}
	defer file.Close()
	var entries []*censor.Entries
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		value := strings.TrimRight(scanner.Text(), "\r")
		if value == "" {
			continue
		}
		entry, err := censor.IndexValue(guard.key, "secret", fmt.Sprintf("live-%d", len(entries)+1), value)
		if err != nil {
			t.Fatalf("value %d could not be indexed", len(entries)+1)
		}
		entries = append(entries, entry)
	}
	if scanner.Err() != nil {
		t.Fatalf("%s: the file of values could not be read", liveValuesEnvironmentKey)
	}
	registered, unprotected, err = guard.add(entries)
	if err != nil {
		t.Fatalf("the values could not be registered: %v", err)
	}
	return registered, unprotected
}

func TestLiveLeakProxy(t *testing.T) {
	address := os.Getenv(liveProxyEnvironmentKey)
	if address == "" {
		t.Skipf("set %s to a loopback address, for example 127.0.0.1:18444, to run the live leak proxy", liveProxyEnvironmentKey)
	}
	if host, _, err := net.SplitHostPort(address); err != nil || !phaseproxy.IsLoopbackHost(host) {
		t.Fatalf("%s must be a loopback address with a port, for example 127.0.0.1:18444", liveProxyEnvironmentKey)
	}
	output := &liveOutput{w: os.Stdout}
	trace := os.Getenv(liveTraceEnvironmentKey) == "1"

	// A CA for this run only. Its key stays in this process; the certificate
	// is what the tool has to trust.
	authority, certificate, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(t.TempDir(), "phase-live-ca.pem")
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}

	guard, err := newLeakGuardFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	registered, unprotected := liveValues(t, guard, os.Getenv(liveValuesEnvironmentKey))

	// The Console's place is taken by a listener in this process that prints
	// the leak protection events the proxy ships, once each.
	var printed sync.Map
	var lines atomic.Int64
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/events/") {
			http.NotFound(w, r)
			return
		}
		var batch agentapi.EventBatchRequest
		if json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&batch) == nil {
			for _, event := range batch.Events {
				if _, again := printed.LoadOrStore(event.EventID, true); again || (event.EventType != leakEventType && !trace) {
					continue
				}
				lines.Add(1)
				output.line("%s", liveEventLine(event))
			}
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}

	// A session with no Connections: every host is one no Connection covers,
	// so the hosts of the table are read for leak protection and the rest are
	// tunnelled untouched.
	capability := make([]byte, 16)
	if _, err := rand.Read(capability); err != nil {
		t.Fatal(err)
	}
	state := selectionState(t)
	state.runtimeCapability = agentapi.SensitiveString("live_" + hex.EncodeToString(capability))
	state.expiresAt = time.Now().Add(liveProxyLifetime + time.Hour)
	state.hints = &hintLog{}
	state.client = client
	events, err := newEventBuffer(state, 250*time.Millisecond, t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The engine's own transport and dialer: requests leave as they do from a
	// real session.
	dial := defaultUpstreamDialer().DialContext
	if trace {
		plain := dial
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := plain(ctx, network, address)
			output.line("dial %s ok=%v", address, err == nil)
			return conn, err
		}
	}
	transport := defaultUpstreamTransport()
	defer transport.CloseIdleConnections()
	proxy := &httpProxy{
		state: state, ca: authority, transport: transport, dial: dial, events: events, leak: guard,
		control: &controlHandler{state: state, leak: guard}, lifecycle: ctx,
	}
	var handler http.Handler = proxy
	if trace {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				output.line("connect %s", r.Host)
			}
			proxy.ServeHTTP(w, r)
		})
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("listen on %s: %v", address, err)
	}
	if !listenerIsLoopback(listener) {
		_ = listener.Close()
		t.Fatal("the live leak proxy would listen on an address that is not loopback")
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = server.Serve(listener)
	}()

	// The test binary's own time limit comes first when it is the shorter.
	stopAt := time.Now().Add(liveProxyLifetime)
	if deadline, limited := t.Deadline(); limited && deadline.Add(-10*time.Second).Before(stopAt) {
		stopAt = deadline.Add(-10 * time.Second)
	}
	stopPath := os.Getenv(liveStopEnvironmentKey)
	proxyURL := &url.URL{Scheme: "http", User: url.UserPassword("phase", state.runtimeCapability.Reveal()), Host: listener.Addr().String()}
	status := guard.status()
	var copied []string
	for _, harness := range guard.hosts {
		for _, rule := range harness.Hosts {
			if rule.MirrorHello {
				copied = append(copied, rule.Host)
			}
		}
	}
	output.line("ca: %s", certificatePath)
	output.line("proxy: %s", proxyURL)
	output.line("mode: %s; %d values registered, %d too short or plain to protect", status.Mode, registered, unprotected)
	output.line("inspected: %s", strings.Join(status.InspectedHosts, ", "))
	output.line("re-sent with a copy of the client's hello: %s", strings.Join(copied, ", "))
	output.line("not inspected: %s", strings.Join(status.UnreadHosts, ", "))
	if stopPath != "" {
		output.line("stops when %s appears, or at %s", stopPath, stopAt.Format(time.TimeOnly))
	} else {
		output.line("stops at %s", stopAt.Format(time.TimeOnly))
	}
	output.line("tool: HTTPS_PROXY=<proxy> and NODE_EXTRA_CA_CERTS=<ca> (Bun, Node); the tool keeps its own roots for every other host")

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for running := true; running; {
		<-ticker.C
		if time.Now().After(stopAt) {
			running = false
		} else if stopPath != "" {
			if _, err := os.Stat(stopPath); err == nil {
				running = false
			}
		}
	}

	cancel()
	_ = server.Close()
	proxy.CloseHijacked()
	<-served
	if err := events.Stop(); err != nil {
		output.line("events: %v", err)
	}
	status = guard.status()
	output.line("stopped: %d events printed; not inspected at the end: %s", lines.Load(), strings.Join(status.UnreadHosts, ", "))
}

// What the live proxy prints of an event is what the event holds: nothing a
// request carried.
func TestLiveEventLineHoldsNoContent(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	registerLeakValues(t, guard, map[string]string{"live-1": leakSecretOne})
	proxy := &httpProxy{leak: guard}
	match := guard.inspects("opencode.ai", 443)
	scan := guard.newScan(match, "http", censor.ScanOptions{})
	body := []byte(`{"messages":[{"role":"user","content":"the key is ` + leakSecretOne + `"}]}`)
	if guard.scanPayload(scan, body, "body") == nil {
		t.Fatal("the value was not found")
	}
	scan.changed, scan.listed = true, scan.placeholders
	request := httptest.NewRequest(http.MethodPost, "https://opencode.ai/zen/v1/chat/completions", nil)
	event := proxy.leakEvent(nil, request, "opencode.ai", 443, scan, "allow", outcomeCensored, leakReasonFound, 0, time.Now())
	event.Detail = safeEventDetail(event.Detail, nil)
	line := liveEventLine(event)
	want := "event type=leak_protection outcome=censored reason=secret_in_request host=opencode.ai path=/zen/v1/chat/completions method=POST protocol=http decision=allow harness=opencode inventoryHits=1 mode=censor placeholderCount=1 where=body placeholders=ph:secret:live-1"
	if line != want || strings.Contains(line, leakSecretOne) {
		t.Fatalf("the line for an event:\n%s\n%s", line, want)
	}
}
