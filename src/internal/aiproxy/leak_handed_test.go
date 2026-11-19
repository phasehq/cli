package aiproxy

import (
	"context"
	"crypto/tls"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestATunnelIsToldOnceOfAConnectionHandedOnUnread(t *testing.T) {
	notes := newFlowNotes()
	told := 0
	closed := notes.tunnel("127.0.0.1:50001")
	notes.watch("127.0.0.1:50001", func() { told++ })
	// Another connection, and one no tunnel said is its own, have nobody to tell.
	notes.handedOver("127.0.0.1:50002")
	notes.watch("127.0.0.1:50003", func() { told += 100 })
	notes.handedOver("127.0.0.1:50003")
	notes.handedOver("192.0.2.10:50001")
	notes.handedOver("")
	if told != 0 {
		t.Fatalf("a tunnel was told of a connection that isn't its own: %d", told)
	}
	notes.handedOver("127.0.0.1:50001")
	notes.handedOver("[::ffff:127.0.0.1]:50001")
	if told != 1 {
		t.Fatalf("the tunnel was told %d times of one connection", told)
	}
	// Once the tunnel is done with a connection, what it asked goes with it: the
	// address may be another program's by then.
	closed()
	later := notes.tunnel("127.0.0.1:50004")
	notes.watch("127.0.0.1:50004", func() { told += 10 })
	later()
	notes.handedOver("127.0.0.1:50004")
	if told != 1 || len(notes.tunnelled) != 0 {
		t.Fatalf("a tunnel was told of a connection it had closed: %d", told)
	}
	// A proxy with no notes at all tells nobody, and a zero Engine keeps what it is asked.
	var none *flowNotes
	none.handedOver("127.0.0.1:50001")
	zero := &Engine{}
	defer zero.TunnelConnection("127.0.0.1:50005")()
	zero.OnTunnelUnread("127.0.0.1:50005", func() { told += 1000 })
	zero.flowNotes().handedOver("127.0.0.1:50005")
	if told != 1001 {
		t.Fatalf("an Engine's tunnel was not told: %d", told)
	}
}

// The proxy answers a CONNECT before it has read the client's hello, and a
// pass-through window is the client's that refused, known by its hello. So a
// tunnel that handed a flow over to be read gets an answer that says the
// proxy serves it, and only then is the flow handed to its service unread.
// The tunnel is told when that happens, and only then: not for a handshake
// the client refused, and not for a flow that is read.
func TestATunnelIsToldWhenItsFlowIsHandedOnUnread(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.flows = newFlowNotes()
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	const host, path = "api.anthropic.com", "/v1/messages"
	var mu sync.Mutex
	var told []string
	rig.opened = func(local string) {
		t.Cleanup(rig.proxy.flows.tunnel(local))
		rig.proxy.flows.watch(local, func() {
			mu.Lock()
			told = append(told, local)
			mu.Unlock()
		})
	}
	toldOf := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), told...)
	}
	opencode, claude := tunnelFlow("opencode"), tunnelFlow("claude")
	key := leakStateKey{tool: "opencode", host: host}
	for want := 1; want <= 2; want++ {
		raw := rig.connectAs(t, host, &opencode)
		if err := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: rig.providerRoots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}).Handshake(); err == nil {
			t.Fatal("a client that does not trust Phase completed TLS with the proxy")
		}
		_ = raw.Close()
		for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			key = refusalKey(rig.guard, key.perHost())
			rig.guard.handshakes.mu.Lock()
			state := rig.guard.handshakes.hosts[key]
			counted := state != nil && state.failures >= want
			rig.guard.handshakes.mu.Unlock()
			if counted {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("refusal %d was not counted for the client", want)
			}
		}
	}
	if got := toldOf(); len(got) != 0 {
		t.Fatalf("the tunnel was told a refused handshake was handed on: %v", got)
	}
	// Inside the window the client's next flow is answered as one the proxy
	// serves, and handed on once its hello is read.
	raw := rig.connectAs(t, host, &opencode)
	if rig.sendOver(t, raw, host, path) {
		t.Fatal("the client was read inside its window")
	}
	if got := toldOf(); !reflect.DeepEqual(got, []string{raw.LocalAddr().String()}) {
		t.Fatalf("the tunnel was told of %v, and the flow handed on came from %s", got, raw.LocalAddr())
	}
	// Another tool's flow to the same host is read, and nothing is said of it.
	if !rig.sendAs(t, host, path, &claude) {
		t.Fatal("another tool was passed through by the client's window")
	}
	if got := toldOf(); len(got) != 1 {
		t.Fatalf("the tunnel was told of a flow that was read: %v", got)
	}
}

// A hello that has to be copied, and can't be, is the other way a tunnel is
// handed on after its answer. The tunnel is told of that one too.
func TestATunnelIsToldWhenAHelloThatCannotBeCopiedIsHandedOn(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.flows = newFlowNotes()
	const host = "api.anthropic.com"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	local := client.LocalAddr().String()
	defer rig.proxy.flows.tunnel(local)()
	told := 0
	rig.proxy.flows.watch(local, func() { told++ })
	match := rig.guard.inspects(tunnelFlow("claude"), host, 443)
	if match == nil {
		t.Fatal("the host is not read for the tool")
	}
	// The client has gone by the time its tunnel is handed on, so the hand-over
	// ends as soon as it has begun.
	_ = client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rig.proxy.passThroughUnread(ctx, server, nil, host, 443, match, "", leakReasonHelloUnreadable)
	if told != 1 {
		t.Fatalf("the tunnel was told %d times", told)
	}
}
