package aiproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/censortest"
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
//	PHASE_LIVE_LEAK_PROXY    loopback address to listen on, for example 127.0.0.1:18444 (required; the test is skipped without it)
//	PHASE_LIVE_LEAK_MANIFEST file holding a JSON list of {"id": "...", "type": "secret" or "sealed", "value": "..."} (optional; other
//	                         members are ignored). Each value is registered under its type and id, so it is replaced by ph:<type>:<id>
//	PHASE_LIVE_LEAK_VALUES   file of values to protect, one per line (optional); they are registered as live-1, live-2, ...
//	PHASE_LIVE_LEAK_MODE     censor (default) or observe; unset, PHASE_AI_LEAK_PROTECTION is read as by the real proxy
//	PHASE_LIVE_LEAK_STOP     file whose appearance stops the proxy (optional); it stops after 10 minutes either way
//	PHASE_LIVE_LEAK_TRACE    set to 1 to also print each CONNECT, each upstream dial and events that are not leak events
//
//	go test ./internal/aiproxy -run '^TestLiveLeakProxy$' -count=1 -v -timeout 11m
//
// It prints the CA file, the proxy URL to give the tool, the ids of the values
// that are too short or plain to protect (unprotected: ...), and then:
//
//   - one line per leak protection event: its type, outcome, reason, host,
//     path, counts and placeholders;
//   - one line per request body, and per WebSocket text message from the
//     client, that the proxy read on an inspected host;
//   - one line per message of a Connect stream (Cursor's agent sends its whole
//     session as one) in which a registered value was sent, or the proxy
//     found anything, or that it could not read. The other messages of a
//     stream, of which there are very many, are only counted;
//   - a summary when it stops.
//
// A request line is a measurement:
//
//	request host=... path=... conversation=true|false bytes=... replaced=... seen=... missed=... expected_missed=... protocol=http|http2|websocket micros=...
//
// The values of the manifest and of the values file are looked for, by a
// verifier that shares no code with the matcher, in what the client sent
// (seen) and in exactly what goes on to the provider after inspection,
// decoded (missed): a compressed body, and a compressed message of a stream,
// is inflated first. A value that cannot be protected is listed under
// expected_missed instead. bytes is the size of what goes on, decoded,
// replaced the distinct placeholders put into it, and micros the time the
// proxy spent inspecting it. blocked=true ends the line of one that was
// stopped, and unread=<reason> that of one the proxy could not read.
//
// The summary counts the bodies and messages read (a message counts as a
// request with a body), those on conversation paths, those rewritten and
// blocked, the ids seen and missed, the hits, what was left unread and which
// pass-through windows opened, by reason, and gives the median and the
// longest inspection. Its last line counts the messages of Connect streams,
// and how many of them got a line.
//
// For Cursor's command-line agent (Node: it takes the proxy and the CA from
// its environment), with the proxy and the CA file this prints:
//
//	HTTPS_PROXY=<proxy> NODE_EXTRA_CA_CERTS=<ca> cursor-agent
//
// Its unary calls go to api2.cursor.sh over HTTP/1.1 and its stream to a
// host named agentn.<region>.api5.cursor.sh over HTTP/2; both are read. In
// what goes on to Cursor a value is overwritten by its placeholder padded
// with '*' to the value's length, so bytes does not change there.
//
// What gets no request line: a request with no body, a body sent on a path of
// a listed host that the proxy does not read (chatgpt.com outside
// /backend-api/), and anything on a connection that was passed through
// unread, which the summary counts. A body too large to hold gets a line with
// bytes=0 and unread=body_over_limit: it went on as it came and was not
// measured.
//
// Nothing it prints holds content of a request or a value: ids, counts,
// hosts and paths only.
const (
	liveProxyEnvironmentKey    = "PHASE_LIVE_LEAK_PROXY"
	liveManifestEnvironmentKey = "PHASE_LIVE_LEAK_MANIFEST"
	liveValuesEnvironmentKey   = "PHASE_LIVE_LEAK_VALUES"
	liveModeEnvironmentKey     = "PHASE_LIVE_LEAK_MODE"
	liveStopEnvironmentKey     = "PHASE_LIVE_LEAK_STOP"
	liveTraceEnvironmentKey    = "PHASE_LIVE_LEAK_TRACE"
	liveProxyLifetime          = 10 * time.Minute
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

// liveValue is one value to protect and to look for.
type liveValue struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

var liveIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// liveRegister indexes values as the CLI indexes what it hands out and adds
// them to the proxy's inventory, each under its type and id; the ids are
// treated as the Console's own, so events name them. It returns what the
// verifier is to look for, and the ids of the values that are too short or
// plain to protect: those are expected to get through. Nothing of a value is
// ever printed.
func liveRegister(t *testing.T, guard *leakGuard, values []liveValue) (entries []censortest.Entry, unprotected []string) {
	t.Helper()
	indexed := make([]*censor.Entries, 0, len(values))
	ids := map[string]bool{}
	for _, value := range values {
		// The lines name a value by its id alone.
		if ids[value.ID] {
			t.Fatalf("the id %s names two values", value.ID)
		}
		ids[value.ID] = true
		entry, err := censor.IndexValue(guard.key, value.Type, value.ID, value.Value)
		if err != nil {
			t.Fatalf("the value %s could not be indexed", value.ID)
		}
		indexed = append(indexed, entry)
		expect := ""
		if !entry.Protected() {
			expect = "too_short"
			unprotected = append(unprotected, value.ID)
		}
		entries = append(entries, censortest.Entry{ID: value.ID, Type: value.Type, Value: value.Value, Expect: expect})
	}
	if _, _, err := guard.add(indexed, nil); err != nil {
		t.Fatalf("the values could not be registered: %v", err)
	}
	sort.Strings(unprotected)
	return entries, unprotected
}

// parseLiveManifest reads a manifest: a JSON list of values with their ids
// and types. Members it does not know are ignored. An error names an entry by
// its position or its id, never by anything of its value.
func parseLiveManifest(content []byte) ([]liveValue, error) {
	var values []liveValue
	if json.Unmarshal(content, &values) != nil {
		return nil, errors.New(`the manifest is not a JSON list of {"id", "type", "value"}`)
	}
	seen := map[string]bool{}
	for index, value := range values {
		switch {
		case !liveIdentifier.MatchString(value.ID):
			return nil, fmt.Errorf("entry %d has no id of 1 to 64 letters, digits, '_', '.' or '-'", index)
		case value.Type != "secret" && value.Type != "sealed":
			return nil, fmt.Errorf("the type of %s must be secret or sealed", value.ID)
		case strings.TrimSpace(value.Value) == "":
			return nil, fmt.Errorf("%s has no value", value.ID)
		case seen[value.ID]:
			return nil, fmt.Errorf("the id %s appears twice", value.ID)
		}
		seen[value.ID] = true
	}
	return values, nil
}

// liveManifest reads the manifest file, when there is one.
func liveManifest(t *testing.T, path string) []liveValue {
	t.Helper()
	if path == "" {
		return nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: the manifest could not be read", liveManifestEnvironmentKey)
	}
	values, err := parseLiveManifest(content)
	if err != nil {
		t.Fatalf("%s: %v", liveManifestEnvironmentKey, err)
	}
	return values
}

// liveValues reads the file of values, one per line. They are named live-1,
// live-2 and so on.
func liveValues(t *testing.T, path string) []liveValue {
	t.Helper()
	if path == "" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("%s: the file of values could not be opened", liveValuesEnvironmentKey)
	}
	defer file.Close()
	var values []liveValue
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		value := strings.TrimRight(scanner.Text(), "\r")
		if value == "" {
			continue
		}
		values = append(values, liveValue{ID: fmt.Sprintf("live-%d", len(values)+1), Type: "secret", Value: value})
	}
	if scanner.Err() != nil {
		t.Fatalf("%s: the file of values could not be read", liveValuesEnvironmentKey)
	}
	return values
}

// liveMeter measures what leak protection let through. The proxy tells it of
// every body and text message it read (httpProxy.observe); it looks for the
// registered values, with the independent verifier, in what the client sent
// and in what goes on to the provider, and prints one line for each. It holds
// plaintext, as the fixture tests do. Nothing it prints does: ids, counts,
// hosts and paths only.
//
// The verifier is slow next to the proxy, so the checking runs on a goroutine
// of its own and the proxy only hands the bytes over. Neither side changes
// them afterwards.
type liveMeter struct {
	output   *liveOutput
	guard    *leakGuard
	verifier *censortest.Verifier

	gate   sync.RWMutex
	closed bool
	queue  chan leakObservation
	done   chan struct{}

	mu             sync.Mutex
	requests       int // bodies and text messages the proxy read
	messages       int // those of them that were WebSocket messages
	streamed       int // those of them that were messages of a Connect stream
	streamedListed int // and of those, the ones that got a line
	conversations  int
	rewritten      int
	blocked        int
	seen           map[string]bool
	missed         map[string]bool
	expectedMissed map[string]bool
	inventory      int
	redactions     int
	alerts         int
	signed         int
	unread         map[string]int
	windows        map[string]int
	took           []time.Duration
}

func newLiveMeter(output *liveOutput, guard *leakGuard, entries []censortest.Entry) *liveMeter {
	meter := &liveMeter{
		output: output, guard: guard, verifier: censortest.NewVerifier(entries),
		queue: make(chan leakObservation, 64), done: make(chan struct{}),
		seen: map[string]bool{}, missed: map[string]bool{}, expectedMissed: map[string]bool{},
		unread: map[string]int{}, windows: map[string]int{},
	}
	go func() {
		defer close(meter.done)
		for observation := range meter.queue {
			meter.measure(observation)
		}
	}()
	return meter
}

// observe is what the proxy calls. It only queues: the proxy waits for
// nothing but room in the queue.
func (m *liveMeter) observe(observation leakObservation) {
	m.gate.RLock()
	defer m.gate.RUnlock()
	if !m.closed {
		m.queue <- observation
	}
}

// finish waits for everything observed so far to be measured and printed.
// What the proxy observes afterwards is dropped.
func (m *liveMeter) finish() {
	m.gate.Lock()
	if !m.closed {
		m.closed = true
		close(m.queue)
	}
	m.gate.Unlock()
	<-m.done
}

// found returns the ids of the values present in payload: those a scan is
// meant to remove, and those too short or plain to protect.
func (m *liveMeter) found(payload []byte) (ids, expected []string) {
	if len(payload) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	for _, miss := range m.verifier.Check(payload) {
		if seen[miss.ID] {
			continue
		}
		seen[miss.ID] = true
		if miss.Expected {
			expected = append(expected, miss.ID)
		} else {
			ids = append(ids, miss.ID)
		}
	}
	sort.Strings(ids)
	sort.Strings(expected)
	return ids, expected
}

var liveHostName = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)

// printable returns a host and a path that are safe to print: a path that
// holds a value, or anything a matcher finds, is not repeated.
func (m *liveMeter) printable(host, path string) (string, string) {
	if !liveHostName.MatchString(host) {
		host = "invalid"
	}
	ids, expected := m.found([]byte(path))
	if len(ids)+len(expected) > 0 || len(m.guard.index.Find([]byte(path))) > 0 || containsControlCharacter(path) || strings.ContainsAny(path, " \t") {
		path = "/redacted"
	}
	if len(path) > 256 {
		path = path[:256]
	}
	return host, path
}

func (m *liveMeter) measure(observation leakObservation) {
	if observation.scan == nil {
		m.mu.Lock()
		if observation.connection != "" {
			m.unread[observation.connection]++
		}
		if observation.window != "" {
			m.windows[observation.window]++
		}
		m.mu.Unlock()
		return
	}
	scan := observation.scan
	seen, seenExpected := m.found(observation.original)
	missed, expected := seen, seenExpected
	// The same bytes go on when nothing was replaced; only other bytes need
	// another look.
	if observation.blocked || len(observation.forwarded) == 0 {
		missed, expected = nil, nil
	} else if len(observation.original) == 0 || &observation.forwarded[0] != &observation.original[0] || len(observation.forwarded) != len(observation.original) {
		missed, expected = m.found(observation.forwarded)
	}
	allSeen := append(append([]string(nil), seen...), seenExpected...)
	sort.Strings(allSeen)
	// Every pattern rule applies on a conversation path and only there.
	conversation := scan.opts.Rules == nil
	// A stream sends a message for every step of a session. Those with
	// nothing in them are counted; one gets a line when a value was sent in
	// it, the proxy found something in it, or it was not read.
	listed := !observation.streamed || len(allSeen) > 0 || scan.found() || scan.unread != "" || observation.blocked
	if listed {
		host, path := m.printable(observation.host, observation.path)
		m.output.line("%s", liveRequestLine(host, path, conversation, len(observation.forwarded), scan.replaced(), allSeen, missed, expected,
			scan.protocol, observation.took, observation.blocked, scan.unread))
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++
	if scan.protocol == "websocket" {
		m.messages++
	}
	if observation.streamed {
		m.streamed++
		if listed {
			m.streamedListed++
		}
	}
	if conversation {
		m.conversations++
	}
	if scan.changed {
		m.rewritten++
	}
	if observation.blocked {
		m.blocked++
	}
	for _, id := range allSeen {
		m.seen[id] = true
	}
	for _, id := range missed {
		m.missed[id] = true
	}
	for _, id := range expected {
		m.expectedMissed[id] = true
	}
	m.inventory += scan.inventory
	m.redactions += scan.redacted
	m.alerts += scan.alerts
	m.signed += scan.left
	if scan.unread != "" {
		m.unread[scan.unread]++
	}
	if observation.original != nil {
		m.took = append(m.took, observation.took)
	}
}

// liveRequestLine is the line for one body or message the proxy read: where
// it went, how much of it goes on, how many distinct placeholders were put
// into it, which registered values the client sent (seen) and which are
// still in what goes on (missed, or expected_missed for a value that cannot
// be protected). It is made of ids and counts alone.
func liveRequestLine(host, path string, conversation bool, size, replaced int, seen, missed, expected []string, protocol string, took time.Duration, blocked bool, unread string) string {
	line := fmt.Sprintf("request host=%s path=%s conversation=%t bytes=%d replaced=%d seen=%s missed=%s expected_missed=%s protocol=%s micros=%d",
		host, path, conversation, size, replaced, strings.Join(seen, ","), strings.Join(missed, ","), strings.Join(expected, ","), protocol, took.Microseconds())
	if blocked {
		line += " blocked=true"
	}
	if unread != "" {
		line += " unread=" + unread
	}
	return line
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func liveCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "none"
	}
	reasons := make([]string, 0, len(counts))
	for reason := range counts {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	parts := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		parts = append(parts, fmt.Sprintf("%s=%d", reason, counts[reason]))
	}
	return strings.Join(parts, " ")
}

// summary is what the run measured, in the same terms as the lines.
func (m *liveMeter) summary() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	took := append([]time.Duration(nil), m.took...)
	sort.Slice(took, func(i, j int) bool { return took[i] < took[j] })
	var median, longest time.Duration
	if len(took) > 0 {
		median, longest = took[len(took)/2], took[len(took)-1]
	}
	seen, missed, expected := sortedKeys(m.seen), sortedKeys(m.missed), sortedKeys(m.expectedMissed)
	return []string{
		fmt.Sprintf("summary requests_with_body=%d conversation_requests=%d requests_rewritten=%d requests_blocked=%d websocket_messages=%d",
			m.requests, m.conversations, m.rewritten, m.blocked, m.messages),
		fmt.Sprintf("summary ids_seen=%d seen=%s", len(seen), strings.Join(seen, ",")),
		fmt.Sprintf("summary ids_missed=%d missed=%s", len(missed), strings.Join(missed, ",")),
		fmt.Sprintf("summary ids_expected_missed=%d expected_missed=%s", len(expected), strings.Join(expected, ",")),
		fmt.Sprintf("summary inventory_hits=%d rule_hits=%d rule_redactions=%d rule_alerts=%d signed_findings=%d",
			m.inventory, m.redactions+m.alerts, m.redactions, m.alerts, m.signed),
		"summary unread " + liveCounts(m.unread),
		"summary bypass " + liveCounts(m.windows),
		fmt.Sprintf("summary inspect_micros p50=%d max=%d inspected=%d", median.Microseconds(), longest.Microseconds(), len(took)),
		fmt.Sprintf("summary stream_messages=%d listed=%d", m.streamed, m.streamedListed),
	}
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

	var guard *leakGuard
	switch mode := os.Getenv(liveModeEnvironmentKey); mode {
	case "":
		guard, err = newLeakGuardFromEnvironment()
	case leakModeCensor, leakModeObserve:
		guard, err = newLeakGuard(mode)
	default:
		t.Fatalf("%s must be censor or observe", liveModeEnvironmentKey)
	}
	if err != nil {
		t.Fatal(err)
	}
	values := append(liveManifest(t, os.Getenv(liveManifestEnvironmentKey)), liveValues(t, os.Getenv(liveValuesEnvironmentKey))...)
	entries, unprotected := liveRegister(t, guard, values)
	meter := newLiveMeter(output, guard, entries)

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
		control: &controlHandler{state: state, leak: guard}, lifecycle: ctx, observe: meter.observe,
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
	output.line("mode: %s; %d values registered, %d too short or plain to protect", status.Mode, len(entries)-len(unprotected), len(unprotected))
	if len(values) > 0 {
		output.line("unprotected: %s", strings.Join(unprotected, ","))
	}
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
	meter.finish()
	for _, line := range meter.summary() {
		output.line("%s", line)
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
	match := guard.inspects(envFlow, "opencode.ai", 443)
	scan := guard.newScan(match, "http", censor.ScanOptions{})
	body := []byte(`{"messages":[{"role":"user","content":"the key is ` + leakSecretOne + `"}]}`)
	if guard.readPayload(scan, body, "body") == nil {
		t.Fatal("the value was not found")
	}
	scan.changed, scan.listed = true, scan.placeholders
	request := httptest.NewRequest(http.MethodPost, "https://opencode.ai/zen/v1/chat/completions", nil)
	event := proxy.leakEvent(nil, request, "opencode.ai", 443, scan, "allow", outcomeCensored, leakReasonFound, 0, time.Now())
	event.Detail = safeEventDetail(event.Detail, nil)
	line := liveEventLine(event)
	want := "event type=leak_protection outcome=censored reason=secret_in_request host=opencode.ai path=/zen/v1/chat/completions method=POST protocol=http decision=allow capture=proxy harness=opencode inventoryHits=1 mode=censor placeholderCount=1 replacedCount=1 severity=medium where=body placeholders=ph:secret:live-1"
	if line != want || strings.Contains(line, leakSecretOne) {
		t.Fatalf("the line for an event:\n%s\n%s", line, want)
	}

	// The same holds for everything else the harness prints: the measurement
	// lines, the summary and the events of requests of every kind, with
	// values replaced, blocked, left unread and let through.
	for _, mode := range []string{leakModeCensor, leakModeObserve} {
		printed, values := liveScenario(t, mode)
		if len(printed) < 12 {
			t.Fatalf("%s: the harness printed %d lines", mode, len(printed))
		}
		everything := strings.Join(printed, "\n")
		var entries []censortest.Entry
		for _, value := range values {
			entries = append(entries, censortest.Entry{ID: value.ID, Value: value.Value})
			if strings.Contains(everything, value.Value) {
				t.Fatalf("%s: what the harness printed holds the value of %s", mode, value.ID)
			}
		}
		// Not whole, not in part and not encoded: the verifier that looks for
		// the values in requests finds none of them in the output.
		if found := censortest.NewVerifier(entries).Check([]byte(everything)); len(found) != 0 {
			t.Fatalf("%s: what the harness printed holds %+v", mode, found)
		}
		for _, fragment := range []string{liveFragment, "the key is", "hunter2", "postgres://"} {
			if strings.Contains(everything, fragment) {
				t.Fatalf("%s: what the harness printed holds request content: %q", mode, fragment)
			}
		}
		for _, line := range printed {
			if strings.ContainsAny(line, "\n\r\x00") || len(line) > 1024 {
				t.Fatalf("%s: a line of %d characters", mode, len(line))
			}
		}
	}
}

// liveFragment is a piece of leakSecretOne long enough to matter to the
// verifier and placed so that the matcher cannot be sure of it: it holds no
// whole chunk of the value.
var liveFragment = leakSecretOne[5:19]

// liveScenario sends requests of every kind through a proxy with the meter
// attached, the way the live harness attaches it, and returns everything the
// harness prints for them: the measurement lines, the summary, and the event
// lines. The manifest goes through a file, as it does for the harness.
func liveScenario(t *testing.T, mode string) (printed []string, values []liveValue) {
	t.Helper()
	rig := newLeakRig(t, mode)
	manifest := filepath.Join(t.TempDir(), "manifest.json")
	written, _ := json.Marshal([]map[string]any{
		{"id": "stripe-key", "type": "secret", "value": leakSecretOne, "where": ".env", "expect": "hit"},
		{"id": "database-url", "type": "sealed", "value": leakSecretTwo, "where": "config/database.yml"},
		// Too short to protect: it is expected to get through.
		{"id": "admin-pin", "type": "secret", "value": "hunter2!"},
	})
	if err := os.WriteFile(manifest, written, 0o600); err != nil {
		t.Fatal(err)
	}
	values = liveManifest(t, manifest)
	entries, unprotected := liveRegister(t, rig.guard, values)
	if len(values) != 3 || len(entries) != 3 || !reflect.DeepEqual(unprotected, []string{"admin-pin"}) {
		t.Fatalf("the manifest: %d values, unprotected %v", len(values), unprotected)
	}
	output := &lockedBuffer{}
	meter := newLiveMeter(&liveOutput{w: output}, rig.guard, entries)
	rig.proxy.observe = meter.observe
	client := rig.client(rig.phaseRoots)
	messages := "https://api.anthropic.com/v1/messages"

	// A conversation with all three values in it.
	postMessages(t, client, messages, anthropicBody("the key is "+leakSecretOne+" and "+leakSecretTwo+" and the pin hunter2!"), "")
	// A gzip body off the conversation paths.
	postMessages(t, client, "https://api.anthropic.com/api/event_logging/batch", gzipBytes(t, []byte(`{"events":[{"value":"`+leakSecretOne+`"}]}`)), "gzip")
	// A piece of a value the matcher cannot be sure of.
	postMessages(t, client, messages, anthropicBody("it ends in "+liveFragment), "")
	// A body in an encoding the proxy does not undo, with nothing in it.
	request, _ := http.NewRequest(http.MethodPost, messages, strings.NewReader("not brotli, and nothing known"))
	request.Header.Set("Content-Encoding", "br")
	doRequest(t, client, request)
	// A value in bytes that cannot be rewritten.
	request, _ = http.NewRequest(http.MethodPost, messages, bytes.NewReader(append([]byte{0xff, 0x00, 0xfe}, leakSecretOne...)))
	request.Header.Set("Content-Type", "application/octet-stream")
	doRequest(t, client, request)
	// A WebSocket text message.
	peer := rig.openWebSocket(t, "chatgpt.com", codexSocketPath)
	peer.send(t, clientFrame(true, wsOpText, []byte(`{"type":"response.create","input":"`+leakSecretTwo+`"}`)))
	if _, open := peer.received(t); !open {
		t.Fatal("the WebSocket ended")
	}
	// A connection the proxy could not read at all.
	tap := rig.connect(t, mirrorHost)
	_, _ = tap.Write([]byte("EHLO not-a-tls-client.example\r\n"))
	_ = tap.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.Copy(io.Discard, tap)
	// A client that refuses the proxy's certificate twice.
	for refusals := 1; refusals <= 2; refusals++ {
		refused, _ := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/models", nil)
		if _, err := rig.client(rig.providerRoots).Do(refused); err == nil {
			t.Fatal("a client that does not trust Phase completed TLS with the proxy")
		}
		for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			key := refusalKey(rig.guard, hostKey("api.openai.com"))
			rig.guard.handshakes.mu.Lock()
			state := rig.guard.handshakes.hosts[key]
			counted := state != nil && state.failures >= refusals
			rig.guard.handshakes.mu.Unlock()
			if counted {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("refusal %d was not counted", refusals)
			}
		}
	}

	events := rig.leakEventsNow()
	meter.finish()
	printed = strings.Split(strings.TrimRight(string(output.bytes()), "\n"), "\n")
	printed = append(printed, meter.summary()...)
	for _, event := range events {
		printed = append(printed, liveEventLine(event))
	}
	return printed, values
}

var liveVaryingNumbers = regexp.MustCompile(`\b(micros|bytes|p50|max)=[0-9]+`)

// liveNormalised replaces the numbers that differ from run to run.
func liveNormalised(lines []string) []string {
	normalised := make([]string, 0, len(lines))
	for _, line := range lines {
		normalised = append(normalised, liveVaryingNumbers.ReplaceAllString(line, "$1=N"))
	}
	return normalised
}

// The lines are the measurement: which registered values the client sent,
// and which are still in what goes on to the provider.
func TestLiveMeterMeasuresWhatStillLeaves(t *testing.T) {
	censored, _ := liveScenario(t, leakModeCensor)
	want := []string{
		"request host=api.anthropic.com path=/v1/messages conversation=true bytes=N replaced=2 seen=admin-pin,database-url,stripe-key missed= expected_missed=admin-pin protocol=http micros=N",
		"request host=api.anthropic.com path=/api/event_logging/batch conversation=false bytes=N replaced=1 seen=stripe-key missed= expected_missed= protocol=http micros=N",
		// The piece of a value got through, and the line says so.
		"request host=api.anthropic.com path=/v1/messages conversation=true bytes=N replaced=0 seen=stripe-key missed=stripe-key expected_missed= protocol=http micros=N",
		"request host=api.anthropic.com path=/v1/messages conversation=true bytes=N replaced=0 seen= missed= expected_missed= protocol=http micros=N unread=body_undecodable",
		// Blocked: nothing goes on, so nothing is missed.
		"request host=api.anthropic.com path=/v1/messages conversation=true bytes=N replaced=0 seen=stripe-key missed= expected_missed= protocol=http micros=N blocked=true",
		"request host=chatgpt.com path=/backend-api/codex/responses conversation=true bytes=N replaced=1 seen=database-url missed= expected_missed= protocol=websocket micros=N",
		"summary requests_with_body=6 conversation_requests=5 requests_rewritten=3 requests_blocked=1 websocket_messages=1",
		"summary ids_seen=3 seen=admin-pin,database-url,stripe-key",
		"summary ids_missed=1 missed=stripe-key",
		"summary ids_expected_missed=1 expected_missed=admin-pin",
		"summary inventory_hits=5 rule_hits=0 rule_redactions=0 rule_alerts=0 signed_findings=0",
		"summary unread body_undecodable=1 hello_unreadable=1",
		"summary bypass tls_refused=1",
		"summary inspect_micros p50=N max=N inspected=6",
	}
	if got := liveNormalised(censored); len(got) < len(want) || !reflect.DeepEqual(got[:len(want)], want) {
		t.Fatalf("censor mode:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The blocked body is the one line whose bytes are nothing.
	for index, line := range censored[:6] {
		if blocked := strings.HasSuffix(line, " blocked=true"); strings.Contains(line, " bytes=0 ") != blocked {
			t.Fatalf("line %d: %s", index, line)
		}
	}

	// In observe mode nothing is replaced or blocked, so everything the
	// client sent goes on.
	observed, _ := liveScenario(t, leakModeObserve)
	want = []string{
		"request host=api.anthropic.com path=/v1/messages conversation=true bytes=N replaced=0 seen=admin-pin,database-url,stripe-key missed=database-url,stripe-key expected_missed=admin-pin protocol=http micros=N",
		"request host=api.anthropic.com path=/api/event_logging/batch conversation=false bytes=N replaced=0 seen=stripe-key missed=stripe-key expected_missed= protocol=http micros=N",
		"request host=api.anthropic.com path=/v1/messages conversation=true bytes=N replaced=0 seen=stripe-key missed=stripe-key expected_missed= protocol=http micros=N",
		"request host=api.anthropic.com path=/v1/messages conversation=true bytes=N replaced=0 seen= missed= expected_missed= protocol=http micros=N unread=body_undecodable",
		"request host=api.anthropic.com path=/v1/messages conversation=true bytes=N replaced=0 seen=stripe-key missed=stripe-key expected_missed= protocol=http micros=N",
		"request host=chatgpt.com path=/backend-api/codex/responses conversation=true bytes=N replaced=0 seen=database-url missed=database-url expected_missed= protocol=websocket micros=N",
		"summary requests_with_body=6 conversation_requests=5 requests_rewritten=0 requests_blocked=0 websocket_messages=1",
		"summary ids_seen=3 seen=admin-pin,database-url,stripe-key",
		"summary ids_missed=2 missed=database-url,stripe-key",
		"summary ids_expected_missed=1 expected_missed=admin-pin",
		"summary inventory_hits=5 rule_hits=0 rule_redactions=0 rule_alerts=0 signed_findings=0",
		"summary unread body_undecodable=1 hello_unreadable=1",
		"summary bypass tls_refused=1",
		"summary inspect_micros p50=N max=N inspected=6",
	}
	if got := liveNormalised(observed); len(got) < len(want) || !reflect.DeepEqual(got[:len(want)], want) {
		t.Fatalf("observe mode:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A manifest the harness cannot use is refused, by a message that names an
// entry by its position or its id and holds nothing of a value.
func TestLiveManifestIsCheckedBeforeAnythingIsRegistered(t *testing.T) {
	good := `[{"id":"stripe-key","type":"secret","value":"` + leakSecretOne + `","where":".env","expect":"hit","note":{"any":"thing"}},{"id":"db.url_1","type":"sealed","value":"` + leakSecretTwo + `"}]`
	values, err := parseLiveManifest([]byte(good))
	if err != nil || !reflect.DeepEqual(values, []liveValue{{ID: "stripe-key", Type: "secret", Value: leakSecretOne}, {ID: "db.url_1", Type: "sealed", Value: leakSecretTwo}}) {
		t.Fatalf("a manifest with members the harness does not know: %v", err)
	}
	if values, err := parseLiveManifest([]byte(`[]`)); err != nil || len(values) != 0 {
		t.Fatalf("an empty manifest: %v", err)
	}
	for name, manifest := range map[string]string{
		"not a list":         `{"id":"a","type":"secret","value":"` + leakSecretOne + `"}`,
		"not JSON":           `id=a value=` + leakSecretOne,
		"no id":              `[{"type":"secret","value":"` + leakSecretOne + `"}]`,
		"an id with a space": `[{"id":"a b","type":"secret","value":"` + leakSecretOne + `"}]`,
		"the value as an id": `[{"id":"` + leakSecretOne + `!","type":"secret","value":"` + leakSecretOne + `"}]`,
		"another type":       `[{"id":"a","type":"config","value":"` + leakSecretOne + `"}]`,
		"no type":            `[{"id":"a","value":"` + leakSecretOne + `"}]`,
		"no value":           `[{"id":"a","type":"secret","value":" "}]`,
		"an id twice":        `[{"id":"a","type":"secret","value":"` + leakSecretOne + `"},{"id":"a","type":"sealed","value":"` + leakSecretTwo + `"}]`,
	} {
		values, err := parseLiveManifest([]byte(manifest))
		if err == nil || values != nil {
			t.Errorf("%s: the manifest was accepted", name)
			continue
		}
		if strings.Contains(err.Error(), leakSecretOne) || strings.Contains(err.Error(), leakSecretTwo) || strings.Contains(err.Error(), liveFragment) {
			t.Errorf("%s: the refusal holds a value: %v", name, err)
		}
	}
}

// A path that holds a value, or anything else a line must not carry, is not
// repeated in it, and a host that is no host name is not printed. Told after
// it finished, the meter prints nothing.
func TestLiveLinesNeverRepeatAPathThatHoldsAValue(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	entries, _ := liveRegister(t, guard, []liveValue{{ID: "stripe-key", Type: "secret", Value: leakSecretOne}})
	output := &lockedBuffer{}
	meter := newLiveMeter(&liveOutput{w: output}, guard, entries)
	match := guard.inspects(envFlow, "api.anthropic.com", 443)
	for _, path := range []string{"/v1/files/" + leakSecretOne, "/v1/files/" + liveFragment, "/v1/a path", "/v1/" + phaseServiceToken()} {
		meter.observe(leakObservation{scan: guard.newScan(match, "http", guard.scanOptionsFor(match, path)), host: "api.anthropic.com", path: path, original: []byte("{}"), forwarded: []byte("{}")})
	}
	meter.observe(leakObservation{scan: guard.newScan(match, "http", censor.ScanOptions{}), host: "evil host\nrequest host=x", path: "/v1/messages", original: []byte("{}"), forwarded: []byte("{}")})
	meter.finish()
	// Told after it finished, it neither prints nor waits.
	meter.observe(leakObservation{scan: guard.newScan(match, "http", censor.ScanOptions{}), host: "api.anthropic.com", path: "/v1/late"})
	lines := strings.Split(strings.TrimRight(string(output.bytes()), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("%d lines:\n%s", len(lines), output.bytes())
	}
	for index, line := range lines[:4] {
		if !strings.HasPrefix(line, "request host=api.anthropic.com path=/redacted conversation=") {
			t.Fatalf("line %d repeats its path: %s", index, line)
		}
	}
	if !strings.HasPrefix(lines[4], "request host=invalid path=/v1/messages ") {
		t.Fatalf("a host that is no host name was printed: %s", lines[4])
	}
}
