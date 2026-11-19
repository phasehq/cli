package aiproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// The tests of who is calling: a host is read for the flows the table lists
// it for, whichever way the connection reached the proxy.

func tunnelFlow(tool string) FlowContext { return FlowContext{Capture: CaptureTunnel, Tool: tool} }

func proxyFlow(tool string) FlowContext { return FlowContext{Capture: CaptureProxy, Tool: tool} }

func TestLeakLookupFollowsTheFlow(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	cases := []struct {
		name    string
		flow    FlowContext
		host    string
		harness string // "" means the host is not read for the flow
	}{
		// The tool is known: only that tool's entries, however it was captured.
		{"opencode calls Anthropic through a tunnel", tunnelFlow("opencode"), "api.anthropic.com", "opencode"},
		{"opencode calls Anthropic through the proxy environment", proxyFlow("opencode"), "api.anthropic.com", "opencode"},
		{"opencode calls OpenAI", tunnelFlow("opencode"), "api.openai.com", "opencode"},
		{"opencode calls its hosted models", tunnelFlow("opencode"), "opencode.ai", "opencode"},
		{"claude calls Anthropic", tunnelFlow("claude"), "api.anthropic.com", "claude"},
		{"claude's processes on another tool's host", tunnelFlow("claude"), "api.openai.com", ""},
		{"claude's processes on another tool's host, proxy environment", proxyFlow("claude"), "chatgpt.com", ""},
		{"codex calls OpenAI", proxyFlow("codex"), "api.openai.com", "codex"},
		{"codex's processes on Anthropic", tunnelFlow("codex"), "api.anthropic.com", ""},
		{"cursor's host is listed and not read", tunnelFlow("cursor"), "api2.cursor.sh", ""},
		{"a tool with no entries", tunnelFlow("goose"), "api.anthropic.com", ""},
		// The tool is not known and the client was given the proxy through
		// its environment: the first entry that names the host, as before.
		{"unknown, proxy environment, Anthropic", proxyFlow(""), "api.anthropic.com", "claude"},
		{"unknown, proxy environment, OpenAI", proxyFlow(""), "api.openai.com", "codex"},
		{"unknown, proxy environment, OpenCode", proxyFlow(""), "opencode.ai", "opencode"},
		{"the zero flow is such a client", FlowContext{}, "api.anthropic.com", "claude"},
		// The tool is not known and a tunnel captured the flow: never read.
		{"unknown, tunnel, Anthropic", tunnelFlow(""), "api.anthropic.com", ""},
		{"unknown, tunnel, OpenAI", tunnelFlow(""), "api.openai.com", ""},
		{"unknown, tunnel, OpenCode", tunnelFlow(""), "opencode.ai", ""},
	}
	for _, c := range cases {
		match := guard.inspects(c.flow, c.host, 443)
		switch {
		case c.harness == "" && match != nil:
			t.Errorf("%s: %s is read as %s", c.name, c.host, match.harness)
		case c.harness != "" && (match == nil || match.harness != c.harness):
			t.Errorf("%s: %s is read as %+v, want %s", c.name, c.host, match, c.harness)
		case match != nil:
			// What is remembered about the host is kept under the flow's own
			// tool, and the event says how the flow was captured.
			if match.key != (leakStateKey{tool: c.flow.Tool, host: c.host}) || match.flow.Capture != c.flow.capture() {
				t.Errorf("%s: kept under %+v, captured by %q", c.name, match.key, match.flow.Capture)
			}
		}
		// The answer is the same the second time, from what was remembered.
		if again := guard.inspects(c.flow, c.host, 443); (again == nil) != (match == nil) {
			t.Errorf("%s: a second look disagrees", c.name)
		}
	}
	// A tunnel flow from an unknown program is not read even after the same
	// host was looked up for a client of the proxy environment.
	if guard.inspects(proxyFlow(""), "chatgpt.com", 443) == nil || guard.inspects(tunnelFlow(""), "chatgpt.com", 443) != nil {
		t.Fatal("what was remembered for one flow answered for another")
	}
	// Off the table's port nothing is read for any flow.
	if guard.inspects(tunnelFlow("opencode"), "api.anthropic.com", 8443) != nil {
		t.Fatal("a port other than 443 is read")
	}
}

// A provider's API has one rule, listed under each tool that calls it.
func TestOpenCodeListsTheProvidersItCallsWithTheSameRules(t *testing.T) {
	for _, host := range []string{"api.anthropic.com", "api.openai.com"} {
		first := defaultLeakHosts.lookup(host)
		own := defaultLeakHosts.lookupTool("opencode", host)
		if first == nil || own == nil || first.harness == "opencode" || own.harness != "opencode" {
			t.Fatalf("%s: listed first under %+v and for opencode as %+v", host, first, own)
		}
		if !reflect.DeepEqual(first.rule, own.rule) || !own.inspected() || len(own.rule.ConversationPaths) == 0 {
			t.Fatalf("%s: opencode's rule %+v is not the rule of %s, %+v", host, own.rule, first.harness, first.rule)
		}
	}
	// Each host is named once in status, however many tools list it.
	names := defaultLeakHosts.hostNames("", leakTreatmentInspect)
	for i, name := range names {
		if i > 0 && names[i-1] == name {
			t.Fatalf("%s is named twice: %v", name, names)
		}
	}
	if got := defaultLeakHosts.hostNames("opencode", leakTreatmentInspect); !reflect.DeepEqual(got, []string{"api.anthropic.com", "api.openai.com", "opencode.ai", "openrouter.ai"}) {
		t.Fatalf("opencode's hosts: %v", got)
	}
	// A harness label names its tool; anything else names none.
	for label, tool := range map[string]string{
		"claude": "claude", "claude-code": "claude", "Claude-Code ": "claude", "codex": "codex", "opencode": "opencode",
		"cursor": "cursor", "cursor-agent": "cursor", "goose": "", "amp": "", "my-launcher": "", "": "",
	} {
		if got := defaultLeakHosts.toolFor(label); got != tool {
			t.Errorf("label %q names %q, want %q", label, got, tool)
		}
	}
}

func TestFlowNotesAreUsedOnceExpireAndAreBounded(t *testing.T) {
	notes := newFlowNotes()
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	notes.now = func() time.Time { return now }
	flow := tunnelFlow("opencode")

	if err := notes.note("127.0.0.1:50001", flow); err != nil {
		t.Fatal(err)
	}
	if _, noted := notes.take("127.0.0.1:50002"); noted {
		t.Fatal("another address took the note")
	}
	if got, noted := notes.take("127.0.0.1:50001"); !noted || got != flow {
		t.Fatalf("the note was not found: %+v %v", got, noted)
	}
	if _, noted := notes.take("127.0.0.1:50001"); noted {
		t.Fatal("a note was used twice")
	}

	// A note waits about ten seconds for its CONNECT and no longer.
	if err := notes.note("127.0.0.1:50003", flow); err != nil {
		t.Fatal(err)
	}
	now = now.Add(flowNoteLifetime - time.Second)
	if err := notes.note("127.0.0.1:50004", flow); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, noted := notes.take("127.0.0.1:50003"); noted {
		t.Fatal("a note outlived its ten seconds")
	}
	if _, noted := notes.take("127.0.0.1:50004"); !noted {
		t.Fatal("a note that had not expired was dropped")
	}

	// The loopback address is the same however it is written.
	if err := notes.note("[::ffff:127.0.0.1]:50005", tunnelFlow(" OpenCode ")); err != nil {
		t.Fatal(err)
	}
	if got, noted := notes.take("127.0.0.1:50005"); !noted || got.Tool != "opencode" {
		t.Fatalf("a mapped loopback address is another address: %+v %v", got, noted)
	}
	if err := notes.note("[::1]:50006", proxyFlow("")); err != nil {
		t.Fatal(err)
	}
	if got, noted := notes.take("[::1]:50006"); !noted || got != proxyFlow("") {
		t.Fatalf("the IPv6 loopback address: %+v %v", got, noted)
	}

	// What is not a loopback address and port, or not a flow, is refused.
	for name, c := range map[string]struct {
		address string
		flow    FlowContext
	}{
		"an address off this machine": {"192.0.2.10:50007", flow},
		"no port":                     {"127.0.0.1", flow},
		"port zero":                   {"127.0.0.1:0", flow},
		"a host name":                 {"localhost:50007", flow},
		"no capture":                  {"127.0.0.1:50007", FlowContext{Tool: "claude"}},
		"an unknown capture":          {"127.0.0.1:50007", FlowContext{Capture: "header", Tool: "claude"}},
		"a tool that is no id":        {"127.0.0.1:50007", tunnelFlow("claude code; rm")},
		"a tool too long to be an id": {"127.0.0.1:50007", tunnelFlow(strings.Repeat("a", 33))},
	} {
		if err := notes.note(c.address, c.flow); err == nil {
			t.Errorf("%s was noted", name)
		}
	}
	if len(notes.notes) != 0 {
		t.Fatalf("%d notes are left", len(notes.notes))
	}

	// The notes are bounded. A full set drops what has expired, never what
	// still waits, and says so when it cannot keep a new one.
	for i := 0; i < maxFlowNotes; i++ {
		if err := notes.note(fmt.Sprintf("127.0.0.1:%d", 10000+i), flow); err != nil {
			t.Fatalf("note %d: %v", i, err)
		}
	}
	if err := notes.note("127.0.0.1:9999", flow); err == nil {
		t.Fatal("a note was kept past the bound")
	}
	if _, noted := notes.take("127.0.0.1:10000"); !noted {
		t.Fatal("a note that was waiting was dropped for a new one")
	}
	// Noting an address again takes no room.
	if err := notes.note("127.0.0.1:10001", proxyFlow("claude")); err != nil {
		t.Fatal(err)
	}
	if err := notes.note("127.0.0.1:9999", flow); err != nil {
		t.Fatalf("a freed place was not used: %v", err)
	}
	now = now.Add(flowNoteLifetime)
	if err := notes.note("127.0.0.1:9998", flow); err != nil {
		t.Fatalf("expired notes kept the set full: %v", err)
	}
	if len(notes.notes) != 1 {
		t.Fatalf("%d notes are kept after all but one expired", len(notes.notes))
	}
}

// connectAs opens a tunnel to host through the proxy the way a capture layer
// does: it notes the flow for the address its connection comes from, then
// sends the CONNECT, here with any extra header lines. A nil flow notes
// nothing, as a client of the proxy environment does.
func (r *leakRig) connectAs(t *testing.T, host string, flow *FlowContext, headers ...string) net.Conn {
	t.Helper()
	raw, err := net.Dial("tcp", r.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	if flow != nil {
		if err := r.proxy.flows.note(raw.LocalAddr().String(), *flow); err != nil {
			t.Fatal(err)
		}
	}
	password, _ := r.proxyURL.User.Password()
	authorization := base64.StdEncoding.EncodeToString([]byte(r.proxyURL.User.Username() + ":" + password))
	request := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: Basic %s\r\n", host, host, authorization)
	for _, header := range headers {
		request += header + "\r\n"
	}
	if _, err := raw.Write([]byte(request + "\r\n")); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s: %v %v", host, response, err)
	}
	return raw
}

// sendAs sends one model request over such a tunnel and reports whether the
// proxy read it: a client that is read completes TLS with Phase's certificate
// and its value arrives replaced; one that is left alone completes TLS with
// the provider's own and its body arrives as it was sent.
func (r *leakRig) sendAs(t *testing.T, host, path string, flow *FlowContext, headers ...string) (read bool) {
	t.Helper()
	raw := r.connectAs(t, host, flow, headers...)
	conn := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: r.bothRoots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("TLS with %s: %v", host, err)
	}
	_, phaseErr := conn.ConnectionState().PeerCertificates[0].Verify(x509.VerifyOptions{Roots: r.phaseRoots, DNSName: host})
	body := anthropicBody("the key is " + leakSecretOne)
	request := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", path, host, len(body), body)
	if response, _ := exchange(t, conn, bufio.NewReader(conn), request); response.StatusCode != http.StatusOK {
		t.Fatalf("%s: status %d", host, response.StatusCode)
	}
	_ = conn.Close()
	received := r.lastReceived()
	replaced := !bytes.Contains(received.body, []byte(leakSecretOne)) && bytes.Contains(received.body, []byte("ph:secret:stripe"))
	if untouched := bytes.Equal(received.body, body); replaced == untouched || replaced != (phaseErr == nil) {
		t.Fatalf("%s: answered by Phase = %v, value replaced = %v, body untouched = %v", host, phaseErr == nil, replaced, untouched)
	}
	return replaced
}

// OpenCode's own processes are read on api.anthropic.com, while another
// program's traffic to the same host through the tunnel passes untouched.
func TestTunnelFlowsAreReadForTheirOwnToolOnly(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.flows = newFlowNotes()
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	const host, path = "api.anthropic.com", "/v1/messages"
	opencode, unknown, claude := tunnelFlow("opencode"), tunnelFlow(""), tunnelFlow("claude")

	if !rig.sendAs(t, host, path, &opencode) {
		t.Fatal("OpenCode's flow to api.anthropic.com was not read")
	}
	if rig.sendAs(t, host, path, &unknown) {
		t.Fatal("a tunnel flow from an unknown program was read")
	}
	// Neither is a tool's flow to a host listed for other tools only.
	if rig.sendAs(t, "api.openai.com", "/v1/responses", &claude) {
		t.Fatal("Claude's flow to api.openai.com was read")
	}
	if !rig.sendAs(t, host, path, &claude) {
		t.Fatal("Claude's flow to api.anthropic.com was not read")
	}
	// A client that was given the proxy through its environment is read as
	// before, whatever it is.
	if !rig.sendAs(t, host, path, nil) || !rig.sendAs(t, "api.openai.com", "/v1/responses", nil) {
		t.Fatal("a client of the proxy environment was not read")
	}

	// Each tool's first sight of the value is its own event, and each says
	// whose flow it was and how it was captured.
	type seen struct{ harness, capture, host string }
	var events []seen
	for _, event := range rig.leakEventsNow() {
		if event.Outcome != outcomeCensored || event.Detail["placeholders"] != "ph:secret:stripe" {
			t.Fatalf("event: %+v", event)
		}
		events = append(events, seen{fmt.Sprint(event.Detail["harness"]), fmt.Sprint(event.Detail["capture"]), event.Host})
	}
	want := []seen{
		{"opencode", CaptureTunnel, host},
		{"claude", CaptureTunnel, host},
		// The tool is not known here: it is inferred from the host.
		{"claude", CaptureProxy, host},
		{"codex", CaptureProxy, "api.openai.com"},
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events: %+v\nwant:   %+v", events, want)
	}
}

// Nothing a client sends says whose flow it is: only a note left by code in
// this process does, and the CONNECT it was left for uses it up.
func TestFlowCannotBeSetByAHeaderAndIsUsedOnce(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.flows = newFlowNotes()
	// This proxy was started for Claude: without a note, a connection is
	// Claude's and api.openai.com is not read.
	rig.proxy.tool = "claude"
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	spoof := []string{
		"X-Phase-Tool: codex", "X-Phase-Flow: tunnel", "X-Phase-Capture: tunnel", "X-Phase-Harness: codex",
		"Phase-Flow-Context: capture=tunnel; tool=codex", "Forwarded: for=127.0.0.1;by=tunnel", "X-Forwarded-For: 127.0.0.1",
		"User-Agent: codex_cli_rs/1.0", "Proxy-Connection: tunnel",
	}
	if rig.sendAs(t, "api.openai.com", "/v1/responses", nil, spoof...) {
		t.Fatal("a header made the proxy read a host of another tool")
	}
	// Nor can a header take a flow out of reading.
	if !rig.sendAs(t, "api.anthropic.com", "/v1/messages", nil, "X-Phase-Tool: ", "X-Phase-Capture: tunnel", "X-Phase-Flow: capture=tunnel") {
		t.Fatal("a header kept the proxy from reading its own tool's host")
	}
	// A user name is not a tool either: it selects a Connection and no more.
	selecting := *rig.proxyURL
	selecting.User = url.UserPassword("phase.codex", "runtime-test")
	transport := &http.Transport{Proxy: http.ProxyURL(&selecting), TLSClientConfig: &tls.Config{RootCAs: rig.bothRoots}}
	t.Cleanup(transport.CloseIdleConnections)
	if _, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get("https://api.openai.com/v1/models"); err == nil {
		t.Fatal("a proxy user name that selects no Connection was accepted")
	}

	// A note is for one CONNECT: the connection that left it is Codex's, and
	// the next connection, from another address, is Claude's again.
	codex := tunnelFlow("codex")
	if !rig.sendAs(t, "api.openai.com", "/v1/responses", &codex) {
		t.Fatal("the noted flow was not read as its tool")
	}
	if len(rig.proxy.flows.notes) != 0 {
		t.Fatal("the note outlived its CONNECT")
	}
	if rig.sendAs(t, "api.openai.com", "/v1/responses", nil) {
		t.Fatal("a later connection inherited the note")
	}
	// A CONNECT the proxy refuses uses its note up too.
	raw, err := net.Dial("tcp", rig.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := rig.proxy.flows.note(raw.LocalAddr().String(), codex); err != nil {
		t.Fatal(err)
	}
	authorization := base64.StdEncoding.EncodeToString([]byte("phase:runtime-test"))
	_, _ = fmt.Fprintf(raw, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: Basic %s\r\n\r\n", ManifestHost, ManifestHost, authorization)
	if response, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: http.MethodConnect}); err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("CONNECT to the reserved host: %v %v", response, err)
	}
	if len(rig.proxy.flows.notes) != 0 {
		t.Fatal("a refused CONNECT left its note behind")
	}
}

// A proxy started for one tool reads that tool's hosts for the clients it was
// given to, and says so in status.
func TestAProxyStartedForOneToolReadsThatToolsHosts(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.tool, rig.proxy.control.tool = "opencode", "opencode"
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	if !rig.sendAs(t, "api.anthropic.com", "/v1/messages", nil) || !rig.sendAs(t, "openrouter.ai", "/api/v1/chat/completions", nil) {
		t.Fatal("OpenCode's hosts were not read")
	}
	if rig.sendAs(t, "chatgpt.com", "/backend-api/codex/responses", nil) {
		t.Fatal("a host of another tool was read")
	}
	for _, event := range rig.leakEventsNow() {
		if event.Detail["harness"] != "opencode" || event.Detail["capture"] != CaptureProxy {
			t.Fatalf("event: %+v", event)
		}
	}
	recorder := controlCall(rig.proxy, http.MethodGet, "/v1/status", "", nil)
	var status remoteapi.StatusResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &status) != nil || status.LeakProtection == nil {
		t.Fatalf("status: %d %s", recorder.Code, recorder.Body.String())
	}
	if got := status.LeakProtection.InspectedHosts; !reflect.DeepEqual(got, []string{"api.anthropic.com", "api.openai.com", "opencode.ai", "openrouter.ai"}) {
		t.Fatalf("inspected: %v", got)
	}
	if got := status.LeakProtection.UnreadHosts; !reflect.DeepEqual(got, []string{"*.cursor.sh", "chatgpt.com", "cursor.sh"}) {
		t.Fatalf("not inspected: %v", got)
	}
	// A proxy that serves whatever reaches it lists every tool's hosts.
	if all := rig.guard.status(""); !containsString(all.InspectedHosts, "chatgpt.com") || !reflect.DeepEqual(all.UnreadHosts, []string{"*.cursor.sh", "cursor.sh"}) {
		t.Fatalf("status of a proxy for every tool: %+v", all)
	}
}

// One tool's refused handshakes open a window for that tool on that host and
// for nothing else.
func TestRefusedHandshakesOpenAWindowForOneToolOnly(t *testing.T) {
	tracker := newHandshakeTracker()
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	tracker.now = func() time.Time { return now }
	const host = "api.anthropic.com"
	opencode, claude, unknown := leakStateKey{tool: "opencode", host: host}, leakStateKey{tool: "claude", host: host}, hostKey(host)
	tracker.note(opencode, false)
	// A refusal by another tool is not the second in a row.
	if window := tracker.note(claude, false); window != 0 || tracker.bypassed(opencode) || tracker.bypassed(claude) {
		t.Fatal("two tools' refusals were counted together")
	}
	if window := tracker.note(opencode, false); window != handshakeBypassFirst {
		t.Fatalf("a tool's second refusal opened a window of %v", window)
	}
	if !tracker.bypassed(opencode) || tracker.bypassed(claude) || tracker.bypassed(unknown) || tracker.bypassed(leakStateKey{tool: "opencode", host: "api.openai.com"}) {
		t.Fatal("the window is not for one tool on one host")
	}
	// Another tool's success does not close it.
	tracker.note(claude, true)
	if !tracker.bypassed(opencode) {
		t.Fatal("another tool's handshake closed the window")
	}
	if hosts := tracker.bypassedHosts(); !reflect.DeepEqual(hosts, []string{host}) {
		t.Fatalf("hosts in a window: %v", hosts)
	}
	tracker.note(opencode, true)
	if tracker.bypassed(opencode) {
		t.Fatal("the tool's own handshake did not close the window")
	}
}

func TestAToolsWindowLeavesOtherToolsRead(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.flows = newFlowNotes()
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	const host, path = "api.anthropic.com", "/v1/messages"
	opencode, claude := tunnelFlow("opencode"), tunnelFlow("claude")
	key := leakStateKey{tool: "opencode", host: host}
	for want := 1; want <= 2; want++ {
		// OpenCode's client does not trust Phase and says so.
		raw := rig.connectAs(t, host, &opencode)
		if err := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: rig.providerRoots}).Handshake(); err == nil {
			t.Fatal("a client that does not trust Phase completed TLS with the proxy")
		}
		_ = raw.Close()
		for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			rig.guard.handshakes.mu.Lock()
			state := rig.guard.handshakes.hosts[key]
			counted := state != nil && state.failures >= want
			rig.guard.handshakes.mu.Unlock()
			if counted {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("refusal %d was not counted for the tool", want)
			}
		}
	}
	if !rig.guard.handshakes.bypassed(key) || rig.guard.handshakes.bypassed(hostKey(host)) || rig.guard.handshakes.bypassed(leakStateKey{tool: "claude", host: host}) {
		t.Fatal("the window is not OpenCode's alone")
	}
	// Inside the window OpenCode is passed through; Claude, and a client of
	// the proxy environment, are still read on the same host.
	if rig.sendAs(t, host, path, &opencode) {
		t.Fatal("OpenCode was read inside its window")
	}
	if !rig.sendAs(t, host, path, &claude) || !rig.sendAs(t, host, path, nil) {
		t.Fatal("another tool was passed through by OpenCode's window")
	}
	var window []agentapi.Event
	for _, event := range rig.leakEventsNow() {
		if event.Outcome == outcomeBypass {
			window = append(window, event)
		}
	}
	if len(window) != 1 || window[0].Reason != leakReasonTLSRefused || window[0].Detail["harness"] != "opencode" ||
		window[0].Detail["capture"] != CaptureTunnel || window[0].Detail["windowSeconds"] != float64(20) || window[0].Detail["severity"] != nil {
		t.Fatalf("window events: %+v", window)
	}
}

// What a capture layer is given to decide with, without a copy of the table.
func TestEngineTellsACaptureLayerWhatToHandOver(t *testing.T) {
	t.Setenv(LeakProtectionEnvironmentKey, "")
	engine := New()
	for _, c := range []struct {
		tool, host string
		read       bool
	}{
		{"opencode", "api.anthropic.com", true},
		{"opencode", "API.Anthropic.com.", true},
		{"OpenCode", "opencode.ai", true},
		{"claude", "api.anthropic.com", true},
		{"codex", "chatgpt.com", true},
		{"claude", "api.openai.com", false},
		{"codex", "api.anthropic.com", false},
		{"cursor", "api2.cursor.sh", false},
		{"", "api.anthropic.com", false},
		{"goose", "api.anthropic.com", false},
		{"not an id", "api.anthropic.com", false},
		{"claude", "example.com", false},
	} {
		if got := engine.ShouldRead(c.tool, c.host); got != c.read {
			t.Errorf("ShouldRead(%q, %q) = %v", c.tool, c.host, got)
		}
	}
	want := []ReadHost{{Host: "openrouter.ai"}, {Host: "opencode.ai"}, {Host: "api.anthropic.com"}, {Host: "api.openai.com"}}
	if got := engine.ReadHosts("opencode"); !reflect.DeepEqual(got, want) {
		t.Fatalf("OpenCode's hosts: %+v", got)
	}
	if got := engine.ReadHosts("claude"); !reflect.DeepEqual(got, []ReadHost{{Host: "api.anthropic.com"}}) {
		t.Fatalf("Claude's hosts: %+v", got)
	}
	for _, tool := range []string{"cursor", "", "goose"} {
		if got := engine.ReadHosts(tool); len(got) != 0 {
			t.Errorf("hosts read for %q: %+v", tool, got)
		}
	}
	// With leak protection off there is nothing to hand over.
	t.Setenv(LeakProtectionEnvironmentKey, "off")
	off := New()
	if off.ShouldRead("claude", "api.anthropic.com") || len(off.ReadHosts("claude")) != 0 {
		t.Fatal("a capture layer is told to hand flows to a proxy that reads nothing")
	}
	// A note is kept for the engine's proxy whenever it starts, and an
	// invalid one is refused.
	if err := engine.NoteFlow("127.0.0.1:50100", tunnelFlow("claude")); err != nil {
		t.Fatal(err)
	}
	if got, noted := engine.flowNotes().take("127.0.0.1:50100"); !noted || got != tunnelFlow("claude") {
		t.Fatalf("the engine's note: %+v %v", got, noted)
	}
	if err := engine.NoteFlow("192.0.2.1:50100", tunnelFlow("claude")); err == nil {
		t.Fatal("a flow was noted for an address off this machine")
	}
	var zero Engine
	if err := zero.NoteFlow("127.0.0.1:50101", proxyFlow("")); err != nil {
		t.Fatalf("a zero engine keeps no notes: %v", err)
	}
}

// The harness a session was started for reaches the proxy: its own clients
// are that tool's, a flow a capture layer noted through the engine is
// whatever the note says, and status names the hosts read.
func TestEngineServesTheToolOfItsSession(t *testing.T) {
	t.Setenv(LeakProtectionEnvironmentKey, "")
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{}")) }))
	defer provider.Close()
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"schemaVersion":1,"accepted":1,"duplicates":0}`))
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := emptyProxySession(t, client, "psx_sess_test_capability_0123456789")
	_, certPEM, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	session.CAPaths = phaseproxy.CAPaths{Certificate: filepath.Join(directory, "ca.pem"), Bundle: filepath.Join(directory, "bundle.pem")}
	for _, path := range []string{session.CAPaths.Certificate, session.CAPaths.Bundle} {
		if err := os.WriteFile(path, certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// What phase ai run -- claude resolves.
	session.HarnessLabel = "claude-code"

	engine := New()
	engine.ListenAddress = unusedTestListenAddresses(t, "127.0.0.1")[0]
	engine.RefreshInterval = time.Hour
	engine.EventSpoolDirectory = t.TempDir()
	engine.Transport = provider.Client().Transport
	providerAddress := provider.Listener.Addr().String()
	engine.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, providerAddress)
	}
	started := make(chan Endpoints, 1)
	engine.OnStarted = func(endpoints Endpoints) { started <- endpoints }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Serve(ctx, session) }()
	var endpoints Endpoints
	select {
	case endpoints = <-started:
	case err := <-done:
		t.Fatalf("the engine stopped before it started: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the engine did not start")
	}
	var stop sync.Once
	stopEngine := func() {
		stop.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("the engine did not stop")
			}
		})
	}
	defer stopEngine()
	proxyURL, _ := url.Parse(endpoints.ProxyURL.Reveal())
	password, _ := proxyURL.User.Password()
	authorization := base64.StdEncoding.EncodeToString([]byte("phase:" + password))

	// readBy reports whether a CONNECT to host is answered with Phase's
	// certificate (read) or the provider's own (left alone).
	readBy := func(host string, flow *FlowContext) bool {
		t.Helper()
		raw, err := net.Dial("tcp", endpoints.ProxyAddress)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		if flow != nil {
			if err := engine.NoteFlow(raw.LocalAddr().String(), *flow); err != nil {
				t.Fatal(err)
			}
		}
		_, _ = fmt.Fprintf(raw, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: Basic %s\r\n\r\n", host, host, authorization)
		if response, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: http.MethodConnect}); err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT %s: %v %v", host, response, err)
		}
		conn := tls.Client(raw, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		if err := conn.Handshake(); err != nil {
			t.Fatalf("TLS with %s: %v", host, err)
		}
		return !conn.ConnectionState().PeerCertificates[0].Equal(provider.Certificate())
	}
	codex, unknown := tunnelFlow("codex"), tunnelFlow("")
	if !readBy("api.anthropic.com", nil) {
		t.Fatal("the session's own tool was not read on its host")
	}
	if readBy("api.openai.com", nil) {
		t.Fatal("a host of another tool was read for the session's tool")
	}
	if !readBy("api.openai.com", &codex) {
		t.Fatal("a flow noted through the engine was not read as its tool")
	}
	if readBy("api.anthropic.com", &unknown) {
		t.Fatal("a tunnel flow from an unknown program was read")
	}

	request, _ := http.NewRequest(http.MethodGet, phaseproxy.ControlURL+"/v1/status", nil)
	response, err := (&http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var status remoteapi.StatusResponse
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil || status.LeakProtection == nil {
		t.Fatalf("status: %v", err)
	}
	if got := status.LeakProtection.InspectedHosts; !reflect.DeepEqual(got, []string{"api.anthropic.com"}) {
		t.Fatalf("a proxy started for Claude says it inspects %v", got)
	}
}

// A host a Connection covers is terminated for the Connection whatever the
// flow, and its credential is injected; the body is read only for the flows
// the table lists the host for.
func TestAConnectionsHostIsReadForItsFlowOnly(t *testing.T) {
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-custom", 1,
		customConnectionPayload(customDecoyToken, customLiveToken)), "runtime-custom")
	defer state.destroy()
	guard := newTestLeakGuard(t, leakModeCensor)
	guard.hosts = leakHostTable{{Harness: "test", Hosts: []leakHostRule{{Host: "api.example.test", Treatment: leakTreatmentInspect}}}}
	registerLeakValues(t, guard, map[string]string{"one": leakSecretOne})
	upstream := &recordingUpstream{}
	proxy := &httpProxy{state: state, transport: upstream, leak: guard}
	body := `{"messages":[{"role":"user","content":"the key is ` + leakSecretOne + `"}]}`
	replaced := strings.Replace(body, leakSecretOne, "ph:secret:one", 1)
	for name, c := range map[string]struct {
		flow FlowContext
		read bool
	}{
		"an unknown program through a tunnel": {tunnelFlow(""), false},
		"another tool through a tunnel":       {tunnelFlow("claude"), false},
		"the listed tool through a tunnel":    {tunnelFlow("test"), true},
		"the listed tool, proxy environment":  {proxyFlow("test"), true},
		"another tool, proxy environment":     {proxyFlow("claude"), false},
		"a client of the proxy environment":   {proxyFlow(""), true},
	} {
		request, _ := http.NewRequest(http.MethodPost, "https://api.example.test/v1/items", strings.NewReader(body))
		result := proxy.process(request, &tunnelAuthentication{flow: c.flow})
		if result.response != nil && result.response.Body != nil {
			result.response.Body.Close()
		}
		if result.failure != nil {
			t.Fatalf("%s: the request was refused: %+v", name, result.failure)
		}
		sent := upstream.last.Load()
		if sent.Header.Get("Authorization") != "Bearer "+customLiveToken {
			t.Fatalf("%s: the Connection's credential was not injected", name)
		}
		forwarded, _ := io.ReadAll(sent.Body)
		if want := map[bool]string{true: replaced, false: body}[c.read]; string(forwarded) != want {
			t.Errorf("%s: the forwarded body is %q", name, forwarded)
		}
	}
	// A request outside any tunnel is the proxy's own client's.
	proxy.tool = "claude"
	request, _ := http.NewRequest(http.MethodPost, "https://api.example.test/v1/items", strings.NewReader(body))
	if result := processThrough(proxy, request); result.failure != nil {
		t.Fatalf("the request was refused: %+v", result.failure)
	}
	if forwarded, _ := io.ReadAll(upstream.last.Load().Body); string(forwarded) != body {
		t.Fatalf("a proxy started for another tool read the body: %q", forwarded)
	}
}
