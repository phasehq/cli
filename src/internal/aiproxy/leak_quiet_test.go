package aiproxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/pkg/censor"
)

// leakEventsNow returns the leak events shipped so far, after giving the
// buffer time to flush. A spooled event can be shipped again before the
// spool learns it was delivered; the Console keeps one per ID, and so does
// this.
func (r *leakRig) leakEventsNow() []agentapi.Event {
	time.Sleep(150 * time.Millisecond)
	r.mu.Lock()
	defer r.mu.Unlock()
	var events []agentapi.Event
	seen := map[string]bool{}
	for _, event := range r.shipped {
		if event.EventType == leakEventType && !seen[event.EventID] {
			seen[event.EventID] = true
			events = append(events, event)
		}
	}
	return events
}

func doRequest(t *testing.T, client *http.Client, request *http.Request) int {
	t.Helper()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return response.StatusCode
}

// An identity value that was registered and is sent by the harness in a
// header of every model request is reported once and never blocks.
func TestLeakHeadersAreReportedOnceAndNeverBlock(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	organisation := "org-Q7tZ2mK9pL4vX8rN1wB6yC3d"
	registerLeakValues(t, rig.guard, map[string]string{"OPENAI_ORG_ID": organisation})
	client := rig.client(rig.phaseRoots)
	for i := 0; i < 3; i++ {
		request, _ := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses", strings.NewReader(`{"model":"gpt","input":"hello there friend"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer sk-harness")
		request.Header.Set("OpenAI-Organization", organisation)
		if status := doRequest(t, client, request); status != http.StatusOK {
			t.Fatalf("request %d: %d", i, status)
		}
		if got := rig.lastReceived().header.Get("OpenAI-Organization"); got != organisation {
			t.Fatal("the header was changed")
		}
	}
	events := rig.leakEventsNow()
	if len(events) != 1 {
		t.Fatalf("%d events for one header value sent three times", len(events))
	}
	if event := events[0]; event.Outcome != outcomeReported || event.ProxyDecision != "allow" || event.Detail["where"] != "header" ||
		event.Detail["placeholders"] != "ph:secret:OPENAI_ORG_ID" {
		t.Fatalf("event: %+v", event)
	}
}

// The URL of a request without a body is read too, and blocks; a clean one
// goes out with no event. Headers of a request without a body are not read.
func TestLeakURLIsReadWithoutABody(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.client(rig.phaseRoots)
	request, _ := http.NewRequest(http.MethodGet, "https://api.anthropic.com/v1/models?k="+leakSecretOne, nil)
	if status := doRequest(t, client, request); status != http.StatusForbidden || rig.receivedCount() != 0 {
		t.Fatalf("a value in the URL of a GET was not blocked: %d", status)
	}
	request, _ = http.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/wham/tasks/list?limit=20", nil)
	request.Header.Set("X-Note", leakSecretOne)
	if status := doRequest(t, client, request); status != http.StatusOK || rig.lastReceived().header.Get("X-Note") != leakSecretOne {
		t.Fatalf("a clean GET: %d", status)
	}
	events := rig.leakEventsNow()
	if len(events) != 1 || events[0].ProxyDecision != "block" || events[0].Method != http.MethodGet || events[0].Detail["where"] != "url" {
		t.Fatalf("events: %+v", events)
	}
}

// A request without a body costs the URL scan and nothing more.
func TestLeakRequestWithoutABodyCostsOnlyTheScan(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	registerLeakValues(t, guard, map[string]string{"stripe": leakSecretOne})
	p := &httpProxy{leak: guard}
	request := httptest.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/wham/tasks/list?limit=20&task_filter=current", nil)
	upstream := request.Clone(request.Context())
	upstream.Body = nil
	match := guard.inspects("chatgpt.com", 443)
	opts := guard.scanOptionsFor(match, request.URL.Path)
	target := []byte(request.URL.RequestURI())
	scanOnly := testing.AllocsPerRun(200, func() { guard.index.FindWith(target, opts) })
	inspect := testing.AllocsPerRun(200, func() {
		if p.inspectForLeaks(request, upstream, nil, "chatgpt.com", 443, time.Time{}) != nil {
			t.Fatal("a clean request was stopped")
		}
	})
	if inspect > scanOnly {
		t.Fatalf("a request without a body allocates %v times, the scan alone %v", inspect, scanOnly)
	}
}

// Events are sent for what is new: the history every request repeats is
// reported once, alerts alone are not reported, and an outcome says what
// happened.
func TestLeakEventsAreQuietAndSayWhatHappened(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne, "db": leakSecretTwo})
	client := rig.client(rig.phaseRoots)
	target := "https://api.anthropic.com/v1/messages"

	// A JWT with no keyword near it is only an alert: nothing changes, no event.
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	alertOnly := anthropicBody("here is the value " + jwt)
	postMessages(t, client, target, alertOnly, "")
	if !bytes.Equal(rig.lastReceived().body, alertOnly) {
		t.Fatal("an alert changed the body")
	}
	if events := rig.leakEventsNow(); len(events) != 0 {
		t.Fatalf("an alert alone was reported: %+v", events)
	}

	// The same value in three requests: one event.
	first := anthropicBody("key " + leakSecretOne)
	for i := 0; i < 3; i++ {
		postMessages(t, client, target, first, "")
		if bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) {
			t.Fatal("the value went out")
		}
	}
	events := rig.leakEventsNow()
	if len(events) != 1 || events[0].Outcome != outcomeCensored || events[0].Detail["placeholders"] != "ph:secret:stripe" {
		t.Fatalf("events: %+v", events)
	}
	// A request that adds a value names only the new one, with the total.
	postMessages(t, client, target, anthropicBody("key "+leakSecretOne+" and "+leakSecretTwo), "")
	events = rig.leakEventsNow()
	if len(events) != 2 || events[1].Detail["placeholders"] != "ph:secret:db" || events[1].Detail["placeholderCount"] != float64(2) {
		t.Fatalf("events: %+v", events)
	}
	for _, event := range events {
		if durableAuditEvent(event) {
			t.Fatalf("a censored request is spooled durably: %+v", event)
		}
	}
}

// Once a host's reported set is full, new placeholders there are reported at
// most once a minute.
func TestReportedPlaceholdersAreBounded(t *testing.T) {
	log := newPlaceholderLog()
	now := time.Now()
	log.now = func() time.Time { return now }
	for i := 0; i < maxReportedPlaceholders; i++ {
		if fresh := log.fresh("api.anthropic.com", []string{fmt.Sprintf("ph:secret:%d", i)}); len(fresh) != 1 {
			t.Fatalf("placeholder %d was not fresh", i)
		}
	}
	if fresh := log.fresh("api.anthropic.com", []string{"ph:secret:0"}); len(fresh) != 0 {
		t.Fatal("a reported placeholder was reported again")
	}
	if fresh := log.fresh("api.anthropic.com", []string{"ph:secret:over-a"}); len(fresh) != 1 {
		t.Fatal("the first placeholder past the bound was not reported")
	}
	if fresh := log.fresh("api.anthropic.com", []string{"ph:secret:over-b"}); len(fresh) != 0 {
		t.Fatal("past the bound, a second report came within the minute")
	}
	if fresh := log.fresh("api.openai.com", []string{"ph:secret:over-b"}); len(fresh) != 1 {
		t.Fatal("another host was affected")
	}
	now = now.Add(reportedOverflowPeriod)
	if fresh := log.fresh("api.anthropic.com", []string{"ph:secret:over-b"}); len(fresh) != 1 {
		t.Fatal("past the bound, nothing was reported after a minute")
	}
	if len(log.hosts["api.anthropic.com"].seen) != maxReportedPlaceholders {
		t.Fatal("the reported set grew past its bound")
	}
}

// A Console that is down while thousands of requests are censored never
// makes the session unavailable: those events are not spooled durably.
func TestLeakFindingsNeverStopTheSessionWhenTheConsoleIsDown(t *testing.T) {
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := selectionState(t)
	state.hints = &hintLog{}
	state.client = client
	// A spool far too small for thousands of events.
	events, err := newEventBuffer(state, time.Millisecond, t.TempDir(), 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Stop()
	guard := newTestLeakGuard(t, leakModeCensor)
	p := &httpProxy{events: events, leak: guard}
	request := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	for i := 0; i < 5000; i++ {
		scan := guard.newScan(guard.hosts.lookup("api.anthropic.com"), "http", censor.ScanOptions{})
		scan.addFinding(censor.Finding{Kind: "inventory", Placeholder: fmt.Sprintf("ph:secret:v%d", i), Action: "redact"}, "body")
		scan.changed = true
		p.emitLeakEvent(nil, request, "api.anthropic.com", 443, scan, 0, time.Now())
	}
	time.Sleep(50 * time.Millisecond)
	if err := state.availability(); err != nil {
		t.Fatalf("the session became unavailable: %v", err)
	}
}

// Only a client that refuses the certificate counts toward a pass-through
// window. A CONNECT that sends bytes that are not TLS, or closes at once,
// says nothing about the certificate, and any process could send one.
func TestLeakBareConnectsNeverOpenAWindow(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	host := "api.anthropic.com"
	connect := func(send []byte) {
		t.Helper()
		raw, err := net.Dial("tcp", rig.proxyURL.Host)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		authorization := base64.StdEncoding.EncodeToString([]byte("phase:runtime-test"))
		_, _ = fmt.Fprintf(raw, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: Basic %s\r\n\r\n", host, host, authorization)
		response, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: http.MethodConnect})
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT: %v", err)
		}
		if send != nil {
			_, _ = raw.Write(send)
			_ = raw.SetReadDeadline(time.Now().Add(time.Second))
			_, _ = io.Copy(io.Discard, raw)
		}
	}
	for i := 0; i < 2; i++ {
		connect([]byte("garbage-not-tls\r\n\r\n"))
		connect(nil)
	}
	time.Sleep(100 * time.Millisecond)
	rig.guard.handshakes.mu.Lock()
	counted := rig.guard.handshakes.hosts[host]
	rig.guard.handshakes.mu.Unlock()
	if counted != nil || rig.guard.handshakes.bypassed(host) {
		t.Fatalf("bare CONNECTs counted toward a window: %+v", counted)
	}
	original := anthropicBody("key " + leakSecretOne)
	postMessages(t, rig.client(rig.phaseRoots), "https://"+host+"/v1/messages", original, "")
	if bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) {
		t.Fatal("the host was not read")
	}
}

// Off the conversation paths only indexed values and Phase's own tokens are
// looked for: a pattern rule there could break the harness's login or
// telemetry, which carry tokens of their own.
func TestLeakPatternRulesRunOnlyOnConversationPaths(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	phaseToken := "pss_service:v2:" + strings.Repeat("a1b2c3d4", 8) + ":" + strings.Repeat("e5f6a7b8", 8) + ":" + strings.Repeat("c9d0e1f2", 8) + ":" + strings.Repeat("a3b4c5d6", 8)
	body := []byte(`{"events":[{"note":"bearer ` + jwt + `","value":"` + leakSecretOne + `","phase":"` + phaseToken + `"}]}`)
	client := rig.client(rig.phaseRoots)

	postMessages(t, client, "https://api.anthropic.com/api/event_logging/batch", body, "")
	telemetry := rig.lastReceived().body
	if !bytes.Contains(telemetry, []byte(jwt)) {
		t.Fatal("a pattern rule ran on a telemetry path")
	}
	if bytes.Contains(telemetry, []byte(leakSecretOne)) || bytes.Contains(telemetry, []byte(phaseToken)) {
		t.Fatalf("an indexed value or a Phase token went out on a telemetry path: %s", telemetry)
	}

	postMessages(t, client, "https://api.anthropic.com/v1/messages", body, "")
	if conversation := rig.lastReceived().body; bytes.Contains(conversation, []byte(jwt)) {
		t.Fatal("the pattern rules did not run on the conversation path")
	}
}

// A raw deflate body goes back as raw deflate.
func TestLeakRawDeflateStaysRaw(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	var buffer bytes.Buffer
	writer, _ := flate.NewWriter(&buffer, flate.BestSpeed)
	_, _ = writer.Write(anthropicBody("key " + leakSecretOne))
	_ = writer.Close()
	postMessages(t, rig.client(rig.phaseRoots), "https://api.anthropic.com/v1/messages", buffer.Bytes(), "deflate")
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(rig.lastReceived().body)))
	if err != nil || bytes.Contains(inflated, []byte(leakSecretOne)) || !bytes.Contains(inflated, []byte("ph:secret:stripe")) {
		t.Fatalf("the body did not go out as raw deflate with the value replaced: %v", err)
	}
}

func TestLeakConversationPathsOfTheTable(t *testing.T) {
	cases := []struct {
		host, path   string
		conversation bool
	}{
		{"api.anthropic.com", "/v1/messages", true},
		{"api.anthropic.com", "/v1/messages/count_tokens", true},
		{"api.anthropic.com", "/api/event_logging/batch", false},
		{"api.anthropic.com", "/v1/oauth/token", false},
		{"chatgpt.com", "/backend-api/codex/responses", true},
		{"chatgpt.com", "/backend-api/wham/tasks/list", false},
		{"api.openai.com", "/v1/responses", true},
		{"api.openai.com", "/v1/chat/completions", true},
		{"api.openai.com", "/v1/completions", true},
		{"api.openai.com", "/v1/models", false},
		{"openrouter.ai", "/api/v1/chat/completions", true},
		{"openrouter.ai", "/api/v1/responses", true},
		{"openrouter.ai", "/api/v1/completions", true},
		{"openrouter.ai", "/api/v1/auth/key", false},
	}
	for _, c := range cases {
		if got := defaultLeakHosts.lookup(c.host).conversation(c.path); got != c.conversation {
			t.Errorf("%s%s conversation = %v, want %v", c.host, c.path, got, c.conversation)
		}
	}
}
