package aiproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
)

// The tests of capture peers. What the proxy remembers of traffic it keeps
// per peer, and only code in this process says which peer a flow came from.

func peerFlow(peer, tool string) FlowContext {
	return FlowContext{Capture: CaptureTunnel, Tool: tool, Peer: peer}
}

// memoryOfPeer returns what is kept for a peer other than the local one, or
// nil when nothing was ever kept for it.
func (r *leakRig) memoryOfPeer(peer string) *peerMemory {
	r.guard.peerMu.Lock()
	defer r.guard.peerMu.Unlock()
	return r.guard.peers[peer]
}

func (r *leakRig) peersKept() int {
	r.guard.peerMu.Lock()
	defer r.guard.peerMu.Unlock()
	return len(r.guard.peers)
}

func TestAFlowsPeerIsAShortPlainID(t *testing.T) {
	engine := New()
	notes := engine.flowNotes()
	const address = "127.0.0.1:50400"
	for _, peer := range []string{"", PeerLocal, "a", "sandbox-1", "Peer_7.eu", strings.Repeat("0af3", 16)} {
		flow := peerFlow(peer, "claude")
		if err := engine.NoteFlow(address, flow); err != nil {
			t.Fatalf("peer %q: %v", peer, err)
		}
		// The note holds the peer as it was given: an id is never rewritten.
		if got, noted := notes.take(address); !noted || got != flow {
			t.Fatalf("peer %q was kept as %+v (%v)", peer, got, noted)
		}
	}
	if (FlowContext{}).peer() != PeerLocal || peerFlow(PeerLocal, "").peer() != PeerLocal || peerFlow("sandbox-1", "").peer() != "sandbox-1" {
		t.Fatal("a flow that names no peer is not the local peer's")
	}
	for _, peer := range []string{
		" ", " sandbox-1", "sandbox 1", "sandbox-1\n", "-sandbox", ".sandbox", "_sandbox", "sandbox/1", "sandbox:1", "sandbox,1",
		"sándbox", "local\x00", "peer=1;tool=claude", strings.Repeat("a", 65),
	} {
		if err := engine.NoteFlow(address, peerFlow(peer, "claude")); err == nil {
			t.Errorf("peer %q was accepted", peer)
		}
		if _, noted := notes.take(address); noted {
			t.Errorf("a note was kept for peer %q", peer)
		}
	}
}

// Two peers with the same tool on the same host share nothing of what is
// remembered: not with each other, and not with this machine.
func TestEachPeerHasAMemoryOfItsOwn(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	const host = "api.anthropic.com"
	key := leakStateKey{tool: "claude", host: host}
	match := func(flow FlowContext) *leakHostMatch {
		t.Helper()
		found := guard.inspects(flow, host, 443)
		if found == nil || found.key != key || found.flow.Peer != flow.peer() || found.flow.Tool != "claude" {
			t.Fatalf("%+v on %s: %+v", flow, host, found)
		}
		return found
	}
	// This machine's memory is the guard's own, however its peer is written.
	local := guard.peerMemory
	if guard.memoryOf(match(tunnelFlow("claude"))) != local || guard.memoryOf(match(peerFlow(PeerLocal, "claude"))) != local ||
		guard.memoryOf(match(proxyFlow("claude"))) != local || guard.memoryOf(nil) != local {
		t.Fatal("the local peer's memory is not the guard's own")
	}
	if len(guard.peers) != 0 {
		t.Fatalf("the local peer is kept among the others: %d", len(guard.peers))
	}
	one, two := guard.memoryOf(match(peerFlow("sandbox-1", "claude"))), guard.memoryOf(match(peerFlow("sandbox-2", "claude")))
	if one == two || one == local || two == local || guard.memoryOf(match(peerFlow("sandbox-1", "claude"))) != one {
		t.Fatal("two peers do not each have one memory of their own")
	}
	// A lookup made for one peer is never handed to another.
	if match(peerFlow("sandbox-1", "claude")) == match(peerFlow("sandbox-2", "claude")) || match(peerFlow("sandbox-1", "claude")) == match(tunnelFlow("claude")) {
		t.Fatal("two peers share what was looked up for one of them")
	}

	// Refused handshakes: the window they open is the peer's alone.
	one.handshakes.note(key, false)
	if window := two.handshakes.note(key, false); window != 0 {
		t.Fatal("two peers' refusals were counted together")
	}
	if window := one.handshakes.note(key, false); window != handshakeBypassFirst {
		t.Fatalf("a peer's second refusal opened a window of %v", window)
	}
	if !one.handshakes.bypassed(key) || two.handshakes.bypassed(key) || local.handshakes.bypassed(key) {
		t.Fatal("the window is not one peer's alone")
	}
	two.handshakes.note(key, true)
	local.handshakes.note(key, true)
	if !one.handshakes.bypassed(key) {
		t.Fatal("another peer's handshake closed the window")
	}
	// The limit on unread reports, and the placeholders already reported.
	placeholders := []string{"ph:secret:stripe"}
	for name, memory := range map[string]*peerMemory{"sandbox-1": one, "sandbox-2": two, PeerLocal: local} {
		if !memory.unread.fresh(key, leakReasonOverLimit) || memory.unread.fresh(key, leakReasonOverLimit) {
			t.Errorf("%s: an unread report is not limited by the peer's own reports alone", name)
		}
		if got := memory.reported.fresh(key, placeholders); !reflect.DeepEqual(got, placeholders) {
			t.Errorf("%s: a placeholder another peer reported is not new to it: %v", name, got)
		}
		if got := memory.reported.fresh(key, placeholders); got != nil {
			t.Errorf("%s: a placeholder was reported twice: %v", name, got)
		}
	}
	// Connections passed through unread. Status tells of this machine only.
	ended := one.connections.passed(host, leakReasonTLSRefused)
	defer ended()
	if _, _, passed := one.connections.counts(host); passed[leakReasonTLSRefused] != 1 {
		t.Fatalf("the peer's own connection was not counted: %v", passed)
	}
	if _, _, passed := two.connections.counts(host); passed != nil {
		t.Fatalf("one peer's connection was counted for another: %v", passed)
	}
	if status := guard.status(); len(status.UnreadHosts) != 0 || status.UnreadReasons != nil || !containsString(status.InspectedHosts, host) {
		t.Fatalf("another peer's window and connection changed this machine's status: %+v", status)
	}

	// Each memory is bounded by itself: a peer that fills its own, with the
	// names under a domain entry, takes nothing from another's.
	for i := 0; i < 2*maxRememberedHosts; i++ {
		filling := leakStateKey{tool: "claude", host: fmt.Sprintf("h%d.example", i)}
		one.reported.fresh(filling, placeholders)
		one.unread.fresh(filling, leakReasonOverLimit)
		one.handshakes.note(filling, false)
		one.mirrored.remember(filling, []byte{byte(i)})
		one.connections.passed(filling.host, leakReasonTLSRefused)()
	}
	for name, memory := range map[string]*peerMemory{"sandbox-2": two, PeerLocal: local} {
		if memory.unread.fresh(key, leakReasonOverLimit) || memory.reported.fresh(key, placeholders) != nil {
			t.Errorf("%s: another peer's hosts made it forget its own", name)
		}
		if len(memory.reported.hosts) != 1 || len(memory.unread.last) != 1 || len(memory.handshakes.hosts) != 0 || len(memory.mirrored.seen) != 0 {
			t.Errorf("%s holds something of another peer's", name)
		}
	}

	// The peers kept are bounded too. This machine's memory is not among them.
	for i := 0; i < maxRememberedPeers+8; i++ {
		guard.memoryOf(&leakHostMatch{flow: peerFlow(fmt.Sprintf("peer-%d", i), "claude")})
	}
	if len(guard.peers) > maxRememberedPeers || guard.peerMemory != local || local.reported.fresh(key, placeholders) != nil {
		t.Fatalf("%d peers are kept, or this machine's memory went with them", len(guard.peers))
	}
}

// peerRefusalKey is what a peer's client has its refused handshakes counted
// under once its hello was read: key with that hello's fingerprint, in the
// peer's own memory. While nothing is counted for such a client it is key.
func peerRefusalKey(memory *peerMemory, key leakStateKey) leakStateKey {
	if memory == nil {
		return key
	}
	memory.handshakes.mu.Lock()
	defer memory.handshakes.mu.Unlock()
	for counted := range memory.handshakes.hosts {
		if counted.hello != "" && counted.perHost() == key {
			return counted
		}
	}
	return key
}

// refuseCertificate opens a tunnel for flow and ends its TLS as a client
// that does not trust Phase does, until the peer's memory has counted it. Its
// hello is the one sendOver sends: a window is for the client that refused.
func (r *leakRig) refuseCertificate(t *testing.T, host string, flow FlowContext, key leakStateKey, want int) {
	t.Helper()
	raw := r.connectAs(t, host, &flow)
	if err := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: r.providerRoots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}).Handshake(); err == nil {
		t.Fatal("a client that does not trust Phase completed TLS with the proxy")
	}
	_ = raw.Close()
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		counted := false
		if memory := r.memoryOfPeer(flow.Peer); memory != nil {
			refused := peerRefusalKey(memory, key)
			memory.handshakes.mu.Lock()
			state := memory.handshakes.hosts[refused]
			counted = refused.hello != "" && state != nil && state.failures >= want
			memory.handshakes.mu.Unlock()
		}
		if counted {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusal %d was not counted for the peer's client", want)
		}
	}
}

func TestPeersWithTheSameToolAndHostAreReadApart(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.flows = newFlowNotes()
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	const host, path = "api.anthropic.com", "/v1/messages"
	key := leakStateKey{tool: "claude", host: host}
	one, two, local, named := peerFlow("sandbox-1", "claude"), peerFlow("sandbox-2", "claude"), tunnelFlow("claude"), peerFlow(PeerLocal, "claude")

	// Each peer's first sight of the value there is its own event; after it
	// the same history is quiet for that peer, whatever the others send.
	for _, flow := range []FlowContext{one, two, local, one, two, named, local} {
		if !rig.sendAs(t, host, path, &flow) {
			t.Fatalf("the flow of %q was not read", flow.peer())
		}
	}
	var peers []any
	for _, event := range rig.leakEventsNow() {
		if event.Outcome != outcomeCensored || event.Host != host || event.Detail["harness"] != "claude" || event.Detail["capture"] != CaptureTunnel {
			t.Fatalf("event: %+v", event)
		}
		peers = append(peers, event.Detail["peer"])
	}
	// This machine's event names no peer: it is what it was before peers.
	if !reflect.DeepEqual(peers, []any{"sandbox-1", "sandbox-2", nil}) {
		t.Fatalf("the events name the peers %v", peers)
	}
	if rig.peersKept() != 2 {
		t.Fatalf("%d peers are kept beside this machine", rig.peersKept())
	}

	// One peer's client refuses Phase's certificate twice. Its window is its
	// own: the other peer and this machine are still read on the same host.
	rig.refuseCertificate(t, host, one, key, 1)
	rig.refuseCertificate(t, host, one, key, 2)
	// The window is under the peer and the client's hello both: the same client
	// behind another peer, or on this machine, has none.
	refused := peerRefusalKey(rig.memoryOfPeer("sandbox-1"), key)
	if refused.hello == "" || !rig.memoryOfPeer("sandbox-1").handshakes.bypassed(refused) || rig.memoryOfPeer("sandbox-1").handshakes.bypassed(key) {
		t.Fatal("the window is not the peer's client's")
	}
	if rig.memoryOfPeer("sandbox-2").handshakes.bypassed(refused) || rig.guard.handshakes.bypassed(refused) {
		t.Fatal("the window is not one peer's alone")
	}
	if rig.sendAs(t, host, path, &one) {
		t.Fatal("a peer was read inside its window")
	}
	if !rig.sendAs(t, host, path, &two) || !rig.sendAs(t, host, path, &local) || !rig.sendAs(t, host, path, nil) {
		t.Fatal("another peer was passed through by one peer's window")
	}
	var window []agentapi.Event
	for _, event := range rig.leakEventsNow() {
		if event.Outcome == outcomeBypass {
			window = append(window, event)
		}
	}
	if len(window) != 1 || window[0].Reason != leakReasonTLSRefused || window[0].Detail["peer"] != "sandbox-1" || window[0].Detail["harness"] != "claude" {
		t.Fatalf("window events: %+v", window)
	}
	// Status is this machine's, and this machine is read.
	if status := rig.guard.status(); len(status.UnreadHosts) != 0 || status.UnreadReasons != nil {
		t.Fatalf("a peer's window is in this machine's status: %+v", status)
	}
	if _, _, passed := rig.memoryOfPeer("sandbox-1").connections.counts(host); passed[leakReasonTLSRefused] != 1 {
		t.Fatalf("the peer's passed connection was not counted for it: %v", passed)
	}
	if names := rig.guard.connections.hostNames(); len(names) != 0 {
		t.Fatalf("a peer's connection was counted for this machine: %v", names)
	}
}

// A hello kept for a host whose hello is copied is kept for the peer whose
// client sent it, and answers for no other peer's client.
func TestAPeersKeptHellosAreItsOwn(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.flows = newFlowNotes()
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	key := leakStateKey{tool: "opencode", host: mirrorHost}
	one := peerFlow("sandbox-1", "opencode")
	config := distinctiveTLS(rig.bothRoots)
	config.ServerName = mirrorHost
	conn := tls.Client(rig.connectAs(t, mirrorHost, &one), config)
	if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(mirrorHost, chatBody("the key is "+leakSecretOne))); response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	_ = conn.Close()
	if bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) {
		t.Fatal("the peer's request was not read")
	}
	memory := rig.memoryOfPeer("sandbox-1")
	memory.mirrored.mu.Lock()
	kept := memory.mirrored.seen[key]
	memory.mirrored.mu.Unlock()
	if len(kept) != 1 || !bytes.Equal(memory.mirrored.like(key, kept[0]), kept[0]) {
		t.Fatalf("%d hellos are kept for the peer whose client sent one", len(kept))
	}
	other := rig.guard.memoryOf(rig.guard.inspects(peerFlow("sandbox-2", "opencode"), mirrorHost, 443))
	if other.mirrored.like(key, kept[0]) != nil || rig.guard.mirrored.like(key, kept[0]) != nil || len(rig.guard.mirrored.seen) != 0 {
		t.Fatal("a hello kept for one peer answers for another")
	}
	// The connection opened with the copy is counted for that peer alone.
	if copied, _, _ := memory.connections.counts(mirrorHost); copied != 1 {
		t.Fatalf("%d connections were counted for the peer", copied)
	}
	if copied, _, _ := rig.guard.connections.counts(mirrorHost); copied != 0 {
		t.Fatalf("%d connections were counted for this machine", copied)
	}
}

// Nothing a client sends names a peer: no header, and nothing on the CONNECT
// line. A flow nobody noted is this machine's, and a noted one stays its own.
func TestAPeerCannotBeSetByAHeaderOrTheConnectLine(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.flows = newFlowNotes()
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	const host, path = "api.anthropic.com", "/v1/messages"
	claims := []string{
		"X-Phase-Peer: sandbox-1", "X-Phase-Flow: peer=sandbox-1", "Phase-Flow-Context: capture=tunnel; tool=claude; peer=sandbox-1",
		"Peer: sandbox-1", "Forwarded: for=sandbox-1;by=sandbox-1", "X-Forwarded-For: sandbox-1", "Via: 1.1 sandbox-1",
	}
	if !rig.sendAs(t, host, path, nil, claims...) {
		t.Fatal("a client of the proxy environment was not read")
	}
	// The CONNECT line itself: a user, a query and a peer's name in the target.
	password, _ := rig.proxyURL.User.Password()
	authorization := base64.StdEncoding.EncodeToString([]byte(rig.proxyURL.User.Username() + ":" + password))
	for _, target := range []string{"sandbox-1@" + host + ":443", host + ":443?peer=sandbox-1", host + ":443#sandbox-1"} {
		raw, err := net.Dial("tcp", rig.proxyURL.Host)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = raw.Close() })
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: Basic %s\r\n\r\n", target, host, authorization)
		response, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatalf("CONNECT %s: %v", target, err)
		}
		// A line the proxy takes is this machine's flow; one it refuses is nobody's.
		if response.StatusCode == http.StatusOK && !rig.sendOver(t, raw, host, path) {
			t.Fatalf("CONNECT %s was not read as a client of the proxy environment", target)
		}
	}
	if rig.peersKept() != 0 {
		t.Fatalf("a client named a peer for itself: %d peers are kept", rig.peersKept())
	}
	// A noted flow keeps the peer it was noted with, whatever its CONNECT says.
	two := peerFlow("sandbox-2", "claude")
	if !rig.sendAs(t, host, path, &two, append(claims, "X-Phase-Peer: "+PeerLocal)...) {
		t.Fatal("a peer's flow was not read")
	}
	if rig.memoryOfPeer("sandbox-1") != nil || rig.memoryOfPeer("sandbox-2") == nil || rig.peersKept() != 1 {
		t.Fatal("a header moved a flow to another peer")
	}
	events := rig.leakEventsNow()
	if len(events) != 2 || events[0].Detail["capture"] != CaptureProxy || events[1].Detail["peer"] != "sandbox-2" {
		t.Fatalf("events: %+v", events)
	}
	if _, named := events[0].Detail["peer"]; named {
		t.Fatalf("this machine's event names a peer: %+v", events[0])
	}
	// On the wire the one peer named is the one that was noted.
	if shipped := string(rig.shippedPayloads()); strings.Count(shipped, `"peer"`) != strings.Count(shipped, `"peer":"sandbox-2"`) || strings.Contains(shipped, "sandbox-1") {
		t.Fatalf("an event carries a peer a client sent: %s", shipped)
	}
}
