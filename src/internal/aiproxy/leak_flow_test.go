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
	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// The tests of who is calling. Behind the environment proxy any listed host
// is read and the tool only names the flow; a tunnel's flow is read on the
// hosts listed for its own tool and nowhere else.

func tunnelFlow(tool string) FlowContext { return FlowContext{Capture: CaptureTunnel, Tool: tool} }

func proxyFlow(tool string) FlowContext { return FlowContext{Capture: CaptureProxy, Tool: tool} }

func TestLeakLookupFollowsTheFlow(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	cases := []struct {
		name    string
		flow    FlowContext
		host    string
		harness string // what the flow is named as; "" means the host is not read for it
	}{
		// A tunnel's flow from a known tool: only that tool's entries.
		{"opencode calls Anthropic through a tunnel", tunnelFlow("opencode"), "api.anthropic.com", "opencode"},
		{"opencode calls OpenAI through a tunnel", tunnelFlow("opencode"), "api.openai.com", "opencode"},
		{"opencode calls its hosted models through a tunnel", tunnelFlow("opencode"), "opencode.ai", "opencode"},
		{"claude calls Anthropic through a tunnel", tunnelFlow("claude"), "api.anthropic.com", "claude"},
		{"claude's processes on another tool's host, tunnel", tunnelFlow("claude"), "api.openai.com", ""},
		{"codex's processes on Anthropic, tunnel", tunnelFlow("codex"), "api.anthropic.com", ""},
		{"cursor's host is listed and not read, tunnel", tunnelFlow("cursor"), "api2.cursor.sh", ""},
		{"a tool with no entries, tunnel", tunnelFlow("goose"), "api.anthropic.com", ""},
		// A tunnel's flow from a program that is not a listed tool: never read.
		{"unknown, tunnel, Anthropic", tunnelFlow(""), "api.anthropic.com", ""},
		{"unknown, tunnel, OpenAI", tunnelFlow(""), "api.openai.com", ""},
		{"unknown, tunnel, OpenCode", tunnelFlow(""), "opencode.ai", ""},
		// A client that was given the proxy through its environment: any
		// listed host is read, whichever tool the proxy serves, as before. A
		// tool started inside another tool's session is read like its host.
		{"unknown, proxy environment, Anthropic", proxyFlow(""), "api.anthropic.com", "claude"},
		{"unknown, proxy environment, OpenAI", proxyFlow(""), "api.openai.com", "codex"},
		{"unknown, proxy environment, OpenCode", proxyFlow(""), "opencode.ai", "opencode"},
		{"the zero flow is such a client", FlowContext{}, "api.anthropic.com", "claude"},
		{"codex run inside claude's session", proxyFlow("claude"), "chatgpt.com", "codex"},
		{"codex run inside claude's session, OpenAI", proxyFlow("claude"), "api.openai.com", "codex"},
		{"claude run inside codex's session", proxyFlow("codex"), "api.anthropic.com", "claude"},
		{"opencode's hosted models inside claude's session", proxyFlow("claude"), "opencode.ai", "opencode"},
		{"a tool with no entries, proxy environment", proxyFlow("goose"), "api.anthropic.com", "claude"},
		// The tool the proxy serves names the flow where its own list holds
		// the host, and decides nothing else.
		{"claude's own host in claude's session", proxyFlow("claude"), "api.anthropic.com", "claude"},
		{"codex's own host in codex's session", proxyFlow("codex"), "api.openai.com", "codex"},
		{"opencode's session calls Anthropic", proxyFlow("opencode"), "api.anthropic.com", "opencode"},
		{"opencode's session calls OpenAI", proxyFlow("opencode"), "api.openai.com", "opencode"},
		{"opencode's session, a host of codex's alone", proxyFlow("opencode"), "chatgpt.com", "codex"},
		// A host listed as not read is not read in any session.
		{"cursor's host in claude's session", proxyFlow("claude"), "api2.cursor.sh", ""},
		{"cursor's host in cursor's session", proxyFlow("cursor"), "api2.cursor.sh", ""},
		{"a host outside the table", proxyFlow("claude"), "example.com", ""},
	}
	for _, c := range cases {
		match := guard.inspects(c.flow, c.host, 443)
		switch {
		case c.harness == "" && match != nil:
			t.Errorf("%s: %s is read as %s", c.name, c.host, match.harness)
		case c.harness != "" && (match == nil || match.harness != c.harness):
			t.Errorf("%s: %s is read as %+v, want %s", c.name, c.host, match, c.harness)
		case match != nil:
			// What is remembered about the host is kept under the tool the
			// flow is named as, and the event says how it was captured.
			if match.key != (leakStateKey{tool: c.harness, host: c.host}) || match.flow.Capture != c.flow.capture() || match.flow.Tool != c.flow.Tool {
				t.Errorf("%s: kept under %+v, flow %+v", c.name, match.key, match.flow)
			}
		}
		// The answer is the same the second time, from what was remembered.
		if again := guard.inspects(c.flow, c.host, 443); again != match {
			t.Errorf("%s: a second look disagrees", c.name)
		}
	}
	// What is read for a client of the proxy environment is what was read
	// before flows were told apart: the same hosts, the same rules.
	for _, harness := range defaultLeakHosts {
		for _, rule := range harness.Hosts {
			want := defaultLeakHosts.lookup(rule.Host)
			for _, tool := range []string{"", "claude", "codex", "opencode", "cursor", "goose"} {
				got := guard.inspects(proxyFlow(tool), rule.Host, 443)
				if (got != nil) != want.inspected() || (got != nil && !reflect.DeepEqual(got.rule, want.rule)) {
					t.Errorf("%s in a session for %q: read as %+v, before as %+v", rule.Host, tool, got, want)
				}
			}
		}
	}
	// A tunnel flow from an unknown program is not read even after the same
	// host was looked up for a client of the proxy environment.
	if guard.inspects(proxyFlow(""), "chatgpt.com", 443) == nil || guard.inspects(tunnelFlow(""), "chatgpt.com", 443) != nil {
		t.Fatal("what was remembered for one flow answered for another")
	}
	// Off the table's port nothing is read for any flow.
	if guard.inspects(tunnelFlow("opencode"), "api.anthropic.com", 8443) != nil || guard.inspects(proxyFlow("claude"), "api.anthropic.com", 8443) != nil {
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
	names := defaultLeakHosts.hostNames(leakTreatmentInspect)
	if !reflect.DeepEqual(names, []string{"api.anthropic.com", "api.openai.com", "chatgpt.com", "opencode.ai", "openrouter.ai"}) {
		t.Fatalf("the inspected hosts: %v", names)
	}
	var own []string
	for _, rule := range defaultLeakHosts.rulesOf("opencode") {
		own = append(own, rule.Host)
	}
	if !reflect.DeepEqual(own, []string{"openrouter.ai", "opencode.ai", "api.anthropic.com", "api.openai.com"}) {
		t.Fatalf("opencode's hosts: %v", own)
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

// seenLeakEvent is what an event says of the flow it is about.
type seenLeakEvent struct{ harness, capture, host string }

func (r *leakRig) seenLeakEvents(t *testing.T) []seenLeakEvent {
	t.Helper()
	var seen []seenLeakEvent
	for _, event := range r.leakEventsNow() {
		if event.Outcome != outcomeCensored || event.Detail["placeholders"] != "ph:secret:stripe" {
			t.Fatalf("event: %+v", event)
		}
		seen = append(seen, seenLeakEvent{fmt.Sprint(event.Detail["harness"]), fmt.Sprint(event.Detail["capture"]), event.Host})
	}
	return seen
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
		t.Fatal("Claude's flow to api.openai.com was read through the tunnel")
	}
	if !rig.sendAs(t, host, path, &claude) {
		t.Fatal("Claude's flow to api.anthropic.com was not read")
	}
	// A client that was given the proxy through its environment is read as
	// before, whatever it is and whatever host of the table it calls.
	if !rig.sendAs(t, host, path, nil) || !rig.sendAs(t, "api.openai.com", "/v1/responses", nil) {
		t.Fatal("a client of the proxy environment was not read")
	}

	// Each tool's first sight of the value on a host is its own event, and
	// each says whose flow it was and how it was captured. The client of the
	// proxy environment on api.anthropic.com is named claude, from the host:
	// that tool and host have reported the value already.
	want := []seenLeakEvent{
		{"opencode", CaptureTunnel, host},
		{"claude", CaptureTunnel, host},
		{"codex", CaptureProxy, "api.openai.com"},
	}
	if got := rig.seenLeakEvents(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("events: %+v\nwant:   %+v", got, want)
	}
}

// Nothing a client sends says whose flow it is: only a note left by code in
// this process does, and the CONNECT it was left for uses it up.
func TestFlowCannotBeSetByAHeaderAndIsUsedOnce(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.flows = newFlowNotes()
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	const host, path = "api.anthropic.com", "/v1/messages"
	unknown, codex := tunnelFlow(""), tunnelFlow("codex")

	// A tunnel's flow from an unknown program is not read, and no header on
	// its CONNECT names a tool for it.
	claims := []string{
		"X-Phase-Tool: claude", "X-Phase-Flow: proxy", "X-Phase-Capture: proxy", "X-Phase-Harness: claude",
		"Phase-Flow-Context: capture=proxy; tool=claude", "Forwarded: for=127.0.0.1;by=proxy", "X-Forwarded-For: 127.0.0.1",
		"User-Agent: claude-cli/2.0", "Proxy-Connection: keep-alive",
	}
	if rig.sendAs(t, host, path, &unknown, claims...) {
		t.Fatal("a header made the proxy read a tunnel flow from an unknown program")
	}
	// Nor does a header make a tunnel flow of a client that sent no note.
	hides := []string{"X-Phase-Tool: ", "X-Phase-Capture: tunnel", "X-Phase-Flow: capture=tunnel", "Phase-Flow-Context: capture=tunnel; tool="}
	if !rig.sendAs(t, host, path, nil, hides...) {
		t.Fatal("a header kept the proxy from reading a client of the proxy environment")
	}
	if got := rig.seenLeakEvents(t); !reflect.DeepEqual(got, []seenLeakEvent{{"claude", CaptureProxy, host}}) {
		t.Fatalf("events: %+v", got)
	}
	// A user name is not a tool either: it selects a Connection and no more.
	selecting := *rig.proxyURL
	selecting.User = url.UserPassword("phase.codex", "runtime-test")
	transport := &http.Transport{Proxy: http.ProxyURL(&selecting), TLSClientConfig: &tls.Config{RootCAs: rig.bothRoots}}
	t.Cleanup(transport.CloseIdleConnections)
	if _, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get("https://api.openai.com/v1/models"); err == nil {
		t.Fatal("a proxy user name that selects no Connection was accepted")
	}

	// A note is for one CONNECT. The connection that left it is Codex's flow
	// through the tunnel: not read on Anthropic's host, read on its own.
	if rig.sendAs(t, host, path, &codex) {
		t.Fatal("the noted flow was read on a host of another tool")
	}
	if len(rig.proxy.flows.notes) != 0 {
		t.Fatal("the note outlived its CONNECT")
	}
	// The next connection, from another address, is a client of the proxy
	// environment again.
	if !rig.sendAs(t, host, path, nil) {
		t.Fatal("a later connection inherited the note")
	}
	if !rig.sendAs(t, "api.openai.com", "/v1/responses", &codex) {
		t.Fatal("the noted flow was not read on its own tool's host")
	}
	if got := rig.seenLeakEvents(t); len(got) != 2 || got[1] != (seenLeakEvent{"codex", CaptureTunnel, "api.openai.com"}) {
		t.Fatalf("events: %+v", got)
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

// A proxy started for one tool still reads every listed host for the clients
// it was given to: a tool started inside another tool's session sends
// conversation content through the same proxy. The tool only names the flow
// where its own list holds the host.
func TestAProxyStartedForOneToolStillReadsEveryListedHost(t *testing.T) {
	for tool, labels := range map[string]map[string]string{
		// OpenCode's own list holds Anthropic's API; chatgpt.com is Codex's.
		"opencode": {"api.anthropic.com": "opencode", "openrouter.ai": "opencode", "chatgpt.com": "codex", "api.openai.com": "opencode"},
		// Codex run from a Claude Code shell, and the reverse.
		"claude": {"api.anthropic.com": "claude", "openrouter.ai": "opencode", "chatgpt.com": "codex", "api.openai.com": "codex"},
		"codex":  {"api.anthropic.com": "claude", "openrouter.ai": "opencode", "chatgpt.com": "codex", "api.openai.com": "codex"},
		// A proxy that serves whatever reaches it.
		"": {"api.anthropic.com": "claude", "openrouter.ai": "opencode", "chatgpt.com": "codex", "api.openai.com": "codex"},
	} {
		t.Run("a session for "+tool, func(t *testing.T) {
			rig := newLeakRig(t, leakModeCensor)
			rig.proxy.tool = tool
			registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
			paths := map[string]string{
				"api.anthropic.com": "/v1/messages", "openrouter.ai": "/api/v1/chat/completions",
				"chatgpt.com": "/backend-api/codex/responses", "api.openai.com": "/v1/responses",
			}
			for host, path := range paths {
				if !rig.sendAs(t, host, path, nil) {
					t.Fatalf("%s was not read", host)
				}
			}
			named := map[string]string{}
			for _, event := range rig.seenLeakEvents(t) {
				if event.capture != CaptureProxy {
					t.Fatalf("event: %+v", event)
				}
				named[event.host] = event.harness
			}
			if !reflect.DeepEqual(named, labels) {
				t.Fatalf("the flows were named %v, want %v", named, labels)
			}
			// Status names every inspected host, whichever tool the session is for.
			recorder := controlCall(rig.proxy, http.MethodGet, "/v1/status", "", nil)
			var status remoteapi.StatusResponse
			if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &status) != nil || status.LeakProtection == nil {
				t.Fatalf("status: %d %s", recorder.Code, recorder.Body.String())
			}
			if got := status.LeakProtection.InspectedHosts; !reflect.DeepEqual(got, []string{"api.anthropic.com", "api.openai.com", "chatgpt.com", "opencode.ai", "openrouter.ai"}) {
				t.Fatalf("inspected: %v", got)
			}
			if got := status.LeakProtection.UnreadHosts; !reflect.DeepEqual(got, []string{"*.cursor.sh", "cursor.sh"}) {
				t.Fatalf("not inspected: %v", got)
			}
		})
	}
}

// One tool's refused handshakes open a window for that tool on that host and
// for nothing else.
func TestRefusedHandshakesOpenAWindowForOneToolOnly(t *testing.T) {
	tracker := newHandshakeTracker()
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	tracker.now = func() time.Time { return now }
	const host = "api.anthropic.com"
	opencode, claude, codex := leakStateKey{tool: "opencode", host: host}, leakStateKey{tool: "claude", host: host}, leakStateKey{tool: "codex", host: host}
	tracker.note(opencode, false)
	// A refusal by another tool is not the second in a row.
	if window := tracker.note(claude, false); window != 0 || tracker.bypassed(opencode) || tracker.bypassed(claude) {
		t.Fatal("two tools' refusals were counted together")
	}
	if window := tracker.note(opencode, false); window != handshakeBypassFirst {
		t.Fatalf("a tool's second refusal opened a window of %v", window)
	}
	if !tracker.bypassed(opencode) || tracker.bypassed(claude) || tracker.bypassed(codex) || tracker.bypassed(leakStateKey{tool: "opencode", host: "api.openai.com"}) {
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

// A proxy's own clients are remembered under the tool they are named as, as
// a tunnel's flows are: in a session started for OpenCode a refused
// certificate on api.anthropic.com is OpenCode's, and Claude's flows to the
// same host are still read.
func TestAWindowIsKeptUnderTheToolTheFlowIsNamedAs(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.flows = newFlowNotes()
	rig.proxy.tool = "opencode"
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	const host, path = "api.anthropic.com", "/v1/messages"
	key := leakStateKey{tool: "opencode", host: host}
	for want := 1; want <= 2; want++ {
		raw := rig.connectAs(t, host, nil)
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
				t.Fatalf("refusal %d was not counted under the session's tool", want)
			}
		}
	}
	if !rig.guard.handshakes.bypassed(key) || rig.guard.handshakes.bypassed(leakStateKey{tool: "claude", host: host}) {
		t.Fatal("the window is not kept under the tool the session's clients are named as")
	}
	claude := tunnelFlow("claude")
	if rig.sendAs(t, host, path, nil) {
		t.Fatal("the session's own client was read inside its window")
	}
	if !rig.sendAs(t, host, path, &claude) {
		t.Fatal("Claude's flow was passed through by a window of the session's tool")
	}
	// A host the session's tool does not list is named after the host, and
	// has no window.
	if !rig.sendAs(t, "chatgpt.com", "/backend-api/codex/responses", nil) {
		t.Fatal("another tool's host was not read in the session")
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

// The harness a session was started for reaches the proxy as a name for its
// own clients: every listed host is read for them, an event names the
// session's tool where that tool's list holds the host, and status lists
// every inspected host. A flow a capture layer noted through the engine is
// whatever the note says.
func TestEngineNamesItsClientsAfterTheToolOfItsSession(t *testing.T) {
	t.Setenv(LeakProtectionEnvironmentKey, "")
	providerCA, providerPEM, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	providerRoots := x509.NewCertPool()
	providerRoots.AppendCertsFromPEM(providerPEM)
	var received sync.Map // host -> the last body it was sent
	provider := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received.Store(r.Host, body)
		_, _ = w.Write([]byte("{}"))
	}))
	provider.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return providerCA.CertificateForHost(hello.ServerName)
	}}
	provider.StartTLS()
	defer provider.Close()

	var eventsMu sync.Mutex
	var shipped []agentapi.Event
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/events/") {
			var batch agentapi.EventBatchRequest
			_ = json.NewDecoder(r.Body).Decode(&batch)
			eventsMu.Lock()
			shipped = append(shipped, batch.Events...)
			eventsMu.Unlock()
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"schemaVersion":1,"accepted":1,"duplicates":0}`))
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := emptyProxySession(t, client, "psx_sess_test_capability_0123456789")
	phaseCA, phasePEM, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	session.CA = phaseCA
	phaseRoots := x509.NewCertPool()
	phaseRoots.AppendCertsFromPEM(phasePEM)
	directory := t.TempDir()
	session.CAPaths = phaseproxy.CAPaths{Certificate: filepath.Join(directory, "ca.pem"), Bundle: filepath.Join(directory, "bundle.pem")}
	for _, path := range []string{session.CAPaths.Certificate, session.CAPaths.Bundle} {
		if err := os.WriteFile(path, phasePEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// What phase ai run -- opencode resolves.
	session.HarnessLabel = "opencode"

	engine := New()
	engine.ListenAddress = unusedTestListenAddresses(t, "127.0.0.1")[0]
	engine.RefreshInterval = time.Hour
	engine.EventFlushInterval = 10 * time.Millisecond
	engine.EventSpoolDirectory = t.TempDir()
	providerAddress := provider.Listener.Addr().String()
	engine.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, providerAddress)
	}
	upstream := &http.Transport{DialContext: engine.DialContext, TLSClientConfig: &tls.Config{RootCAs: providerRoots, MinVersion: tls.VersionTLS12}}
	defer upstream.CloseIdleConnections()
	engine.Transport = upstream
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
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the engine did not stop")
		}
	}()
	proxyURL, _ := url.Parse(endpoints.ProxyURL.Reveal())
	password, _ := proxyURL.User.Password()
	authorization := base64.StdEncoding.EncodeToString([]byte("phase:" + password))

	// The value is registered as the CLI registers one, through the engine's
	// own control API.
	environment := map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": proxyURL.String()}
	previous := leakguard.Environment
	leakguard.Environment = func(key string) string { return environment[key] }
	defer func() { leakguard.Environment = previous }()
	if result, err := leakguard.Register(context.Background(), []leakguard.Value{{Type: "secret", ID: "stripe", Value: leakSecretOne}}); err != nil || result.Added != 1 {
		t.Fatalf("registration: %+v %v", result, err)
	}

	// send posts one model request over a tunnel and reports whether the
	// proxy read it.
	body := anthropicBody("the key is " + leakSecretOne)
	both := x509.NewCertPool()
	both.AppendCertsFromPEM(phasePEM)
	both.AppendCertsFromPEM(providerPEM)
	send := func(host, path string, flow *FlowContext) bool {
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
		conn := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: both, NextProtos: []string{"http/1.1"}})
		if err := conn.Handshake(); err != nil {
			t.Fatalf("TLS with %s: %v", host, err)
		}
		request := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", path, host, len(body), body)
		if response, _ := exchange(t, conn, bufio.NewReader(conn), request); response.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", host, response.StatusCode)
		}
		sent, _ := received.Load(host)
		return !bytes.Contains(sent.([]byte), []byte(leakSecretOne))
	}
	// The session's own clients: every listed host, its tool's or not.
	for host, path := range map[string]string{"api.anthropic.com": "/v1/messages", "chatgpt.com": "/backend-api/codex/responses", "openrouter.ai": "/api/v1/chat/completions"} {
		if !send(host, path, nil) {
			t.Fatalf("%s was not read for the session's own client", host)
		}
	}
	// Flows noted through the engine: a tunnel's are read for their tool only.
	codex, unknown := tunnelFlow("codex"), tunnelFlow("")
	if send("api.anthropic.com", "/v1/messages", &unknown) || send("api.anthropic.com", "/v1/messages", &codex) {
		t.Fatal("a tunnel flow was read on a host that is not its tool's")
	}
	if !send("api.openai.com", "/v1/responses", &codex) {
		t.Fatal("a flow noted through the engine was not read as its tool")
	}

	// The events name the session's tool where its list holds the host.
	named := map[string]string{}
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		eventsMu.Lock()
		for _, event := range shipped {
			if event.EventType == leakEventType {
				named[event.Host] = fmt.Sprint(event.Detail["harness"]) + " " + fmt.Sprint(event.Detail["capture"])
			}
		}
		eventsMu.Unlock()
		if len(named) >= 4 || time.Now().After(deadline) {
			break
		}
	}
	want := map[string]string{
		"api.anthropic.com": "opencode proxy", "openrouter.ai": "opencode proxy", "chatgpt.com": "codex proxy", "api.openai.com": "codex tunnel",
	}
	if !reflect.DeepEqual(named, want) {
		t.Fatalf("the flows were named %v, want %v", named, want)
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
	if got := status.LeakProtection.InspectedHosts; !reflect.DeepEqual(got, []string{"api.anthropic.com", "api.openai.com", "chatgpt.com", "opencode.ai", "openrouter.ai"}) {
		t.Fatalf("a proxy started for one tool says it inspects %v", got)
	}
}

// A host a Connection covers is terminated for the Connection whatever the
// flow, and its credential is injected. The body is read for every client of
// the proxy environment, and for a tunnel's flow only when the host is
// listed for its tool.
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
		"a session for another tool":          {proxyFlow("claude"), true},
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
	// A request outside any tunnel is the proxy's own client's, and is read
	// whichever tool the proxy was started for.
	proxy.tool = "claude"
	request, _ := http.NewRequest(http.MethodPost, "https://api.example.test/v1/items", strings.NewReader(body))
	if result := processThrough(proxy, request); result.failure != nil {
		t.Fatalf("the request was refused: %+v", result.failure)
	}
	if forwarded, _ := io.ReadAll(upstream.last.Load().Body); string(forwarded) != replaced {
		t.Fatalf("a proxy started for another tool did not read the body: %q", forwarded)
	}
}
