package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// The tests of peers: a flow is named after the WireGuard peer its source
// address is taken from, and is read as that peer's own rule says.

func TestASourceAddressNamesItsPeer(t *testing.T) {
	sandbox := peer{id: "sandbox-1", sources: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32"), netip.MustParsePrefix("fd00:9::2/128")}}
	local := peer{id: LocalPeer, sources: everySource}
	// The narrowest range wins however the peers are listed, as in WireGuard.
	for _, peers := range [][]peer{{local, sandbox}, {sandbox, local}} {
		sources := sourcesOf(peers)
		for address, want := range map[string]string{
			"10.9.0.2": "sandbox-1", "::ffff:10.9.0.2": "sandbox-1", "fd00:9::2": "sandbox-1",
			"10.9.0.3": LocalPeer, "198.19.248.1": LocalPeer, "fd70:7068:6173::1": LocalPeer,
		} {
			if got, known := peerOf(sources, netip.MustParseAddr(address)); !known || got != want {
				t.Errorf("%s is %q's (known: %v), want %q", address, got, known, want)
			}
		}
	}
	// An address no peer sends from is nobody's.
	if got, known := peerOf(sourcesOf([]peer{sandbox}), LocalAddress); known || got != "" {
		t.Fatalf("an address outside every peer's range is %q's", got)
	}
	if (Flow{}).peer() != LocalPeer || (Flow{Peer: "sandbox-1"}).peer() != "sandbox-1" {
		t.Fatal("a flow that names no peer is not the local peer's")
	}
}

// syn is the packet a program's new TCP connection reaches the stack as.
func syn(source, dest netip.AddrPort) []byte {
	packet := make([]byte, 40)
	packet[0], packet[8], packet[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	from, to := source.Addr().As4(), dest.Addr().As4()
	copy(packet[12:], from[:])
	copy(packet[16:], to[:])
	binary.BigEndian.PutUint16(packet[10:], InternetChecksum(packet[:20]))
	segment := packet[20:]
	binary.BigEndian.PutUint16(segment, source.Port())
	binary.BigEndian.PutUint16(segment[2:], dest.Port())
	binary.BigEndian.PutUint32(segment[4:], 1)
	segment[12], segment[13] = 5<<4, 0x02
	binary.BigEndian.PutUint16(segment[14:], 65535)
	pseudo := make([]byte, 12, 32)
	copy(pseudo, from[:])
	copy(pseudo[4:], to[:])
	pseudo[9], pseudo[11] = 6, byte(len(segment))
	binary.BigEndian.PutUint16(segment[16:], InternetChecksum(append(pseudo, segment...)))
	return packet
}

func TestTheStackNamesAFlowAfterThePeerItCameFrom(t *testing.T) {
	seen := make(chan Flow, 8)
	stack, err := NewStack(Hooks{
		// Every flow is refused once it is seen: the stack answers with a reset.
		Prepare: func(flow Flow) (any, bool) { seen <- flow; return nil, false },
		TCP:     func(net.Conn, Flow) {}, UDP: func(net.Conn, Flow) {}, DNS: func([]byte) []byte { return nil },
	}, MTU)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	dest := netip.MustParseAddrPort("203.0.113.7:443")
	// open sends a new connection from source, and returns the flow the hooks
	// were asked about, if they were, once the stack has answered it.
	open := func(source string) (Flow, bool) {
		t.Helper()
		from := netip.MustParseAddrPort(source)
		stack.Inject(syn(from, dest))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for {
			reply := stack.Next(ctx)
			if reply == nil {
				t.Fatalf("the connection from %s was never answered", source)
			}
			reset := len(reply) >= 40 && reply[9] == 6 && reply[33]&0x04 != 0
			if reset && bytes.Equal(reply[16:20], from.Addr().AsSlice()) && binary.BigEndian.Uint16(reply[22:]) == from.Port() {
				break
			}
		}
		select {
		case flow := <-seen:
			return flow, true
		default:
			return Flow{}, false
		}
	}
	named := func(source, want string) {
		t.Helper()
		flow, asked := open(source)
		if !asked || flow.Peer != want || flow.Source != netip.MustParseAddrPort(source) || flow.Dest != dest {
			t.Fatalf("the flow from %s: %+v (asked: %v), want peer %q", source, flow, asked, want)
		}
	}
	// Behind the helper alone, every source is this machine's.
	named("198.19.248.1:50001", LocalPeer)
	named("10.9.0.2:50002", LocalPeer)
	// A second peer's flows are its own, by the range WireGuard takes from it.
	sandbox := peer{id: "sandbox-1", sources: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")}}
	stack.setPeers([]peer{{id: LocalPeer, sources: everySource}, sandbox})
	named("10.9.0.2:50003", "sandbox-1")
	named("10.9.0.3:50004", LocalPeer)
	named("198.19.248.1:50005", LocalPeer)
	// A source no peer sends from is refused before anything is asked of it.
	stack.setPeers([]peer{sandbox})
	named("10.9.0.2:50006", "sandbox-1")
	if flow, asked := open("198.19.248.1:50007"); asked {
		t.Fatalf("a flow from nobody's address was handed on: %+v", flow)
	}
}

// allowedBy reads, out of a device's configuration, the ranges WireGuard takes
// from each peer, by the peer's key. It lists the peers in no fixed order.
func allowedBy(config string) map[string][]string {
	allowed := map[string][]string{}
	key := ""
	for _, line := range strings.Split(config, "\n") {
		if name, value, _ := strings.Cut(line, "="); name == "public_key" {
			key = value
		} else if name == "allowed_ip" {
			allowed[key] = append(allowed[key], value)
		}
	}
	for _, ranges := range allowed {
		sort.Strings(ranges)
	}
	return allowed
}

// The ranges the stack names flows by are the ones WireGuard is given.
func TestTheDeviceGivesWireGuardAndTheStackTheSamePeers(t *testing.T) {
	stack, err := NewStack(Hooks{TCP: func(net.Conn, Flow) {}, UDP: func(net.Conn, Flow) {}, DNS: func([]byte) []byte { return nil }}, MTU)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	device, err := StartEngineDevice(stack, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	_, helperKey, _ := NewKeyPair()
	_, sandboxKey, _ := NewKeyPair()
	everything := []string{"0.0.0.0/0", "::/0"}
	if err := device.SetPeer(helperKey); err != nil {
		t.Fatal(err)
	}
	config, _ := device.device.IpcGet()
	if got := allowedBy(config); !reflect.DeepEqual(got, map[string][]string{helperKey: everything}) {
		t.Fatalf("the helper isn't the device's one peer: %v", got)
	}
	if got, known := peerOf(*stack.sources.Load(), netip.MustParseAddr("10.9.0.2")); !known || got != LocalPeer {
		t.Fatalf("behind the helper a source is %q's", got)
	}
	err = device.setPeers([]peer{
		{id: LocalPeer, publicKey: helperKey, sources: everySource},
		{id: "sandbox-1", publicKey: sandboxKey, sources: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	config, _ = device.device.IpcGet()
	if got := allowedBy(config); !reflect.DeepEqual(got, map[string][]string{helperKey: everything, sandboxKey: {"10.9.0.2/32"}}) {
		t.Fatalf("the peers' ranges aren't WireGuard's: %v", got)
	}
	if got, _ := peerOf(*stack.sources.Load(), netip.MustParseAddr("10.9.0.2")); got != "sandbox-1" {
		t.Fatalf("the second peer's address is %q's to the stack", got)
	}
	// Peers that are refused change nothing the stack knows.
	if err := device.setPeers([]peer{{id: "sandbox-2", publicKey: "not a key", sources: everySource}}); err == nil {
		t.Fatal("a malformed key was accepted")
	}
	if got, _ := peerOf(*stack.sources.Load(), netip.MustParseAddr("10.9.0.2")); got != "sandbox-1" {
		t.Fatalf("after a refused change the address is %q's", got)
	}
}

// openFrom is open for a flow that came from peer.
func (s *readSetup) openFrom(peer, host string) Flow {
	s.t.Helper()
	upstream, err := net.Dial("tcp", s.ends.destination)
	if err != nil {
		s.t.Fatal(err)
	}
	flow := Flow{
		Source: netip.AddrPortFrom(LocalAddress, uint16(50000+nextSourcePort.Add(1))),
		Dest:   netip.MustParseAddrPort("203.0.113.7:443"),
		Peer:   peer, Prepared: upstream,
	}
	s.run(host, flow)
	return flow
}

func (f *fakeReader) notedPeers() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.peers...)
}

// A peer of another kind names its flows by a rule of its own. Here it is a
// sandbox enrolled for one tool: the router asks that rule, not this machine.
func TestTheRouterAsksAPeersOwnRule(t *testing.T) {
	setup := newReadSetup(t)
	var mu sync.Mutex
	var asked []Flow
	setup.router.SetPeerRule("sandbox-1", func(flow Flow) (string, error) {
		mu.Lock()
		asked = append(asked, flow)
		mu.Unlock()
		return "claude", nil
	})
	// The sandbox's flow to Claude's host is read for Claude, and noted as its own.
	first := setup.openFrom("sandbox-1", modelHost)
	seen := setup.arrives(setup.ends.atProxy)
	if seen.authority != modelHost+":443" || !seen.noted || seen.tool != "claude" {
		t.Fatalf("CONNECT %s, noted %q (told at all: %v)", seen.authority, seen.tool, seen.noted)
	}
	if peers := setup.reader.notedPeers(); !reflect.DeepEqual(peers, []string{"sandbox-1"}) {
		t.Fatalf("the proxy was told the flow came from %v", peers)
	}
	if looked := setup.owners.lookups(); len(looked) != 0 {
		t.Fatalf("a program on this machine was looked for behind another peer's flow: %v", looked)
	}
	if direct := setup.arrives(setup.ends.atDestination); direct.hello != nil {
		t.Fatal("the hello also went straight to the destination")
	}
	// A host of another tool's is not that peer's tool's, so it is left unread.
	second := setup.openFrom("sandbox-1", otherModelHost)
	wholeHello(t, setup.arrives(setup.ends.atDestination).hello, otherModelHost)
	// The same host from this machine is still decided by the program behind it.
	setup.open(modelHost)
	wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
	if looked := setup.owners.lookups(); len(looked) != 1 {
		t.Fatalf("this machine's flow was looked up %d times", len(looked))
	}
	// A peer with no rule, and one whose rule can't say, are read for no tool.
	setup.openFrom("sandbox-2", modelHost)
	wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)
	setup.router.SetPeerRule("sandbox-3", func(Flow) (string, error) { return "", errors.New("the peer is gone") })
	setup.openFrom("sandbox-3", modelHost)
	wholeHello(t, setup.arrives(setup.ends.atDestination).hello, modelHost)

	setup.counts(map[string]int{"read": 1, "tcp": 4, "unread_not_tool": 2, "unread_no_peer_rule": 1, "owner_lookup_failed": 1})
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 2 || asked[0].Source != first.Source || asked[1].Source != second.Source || asked[0].Peer != "sandbox-1" {
		t.Fatalf("the peer's rule was asked about %+v", asked)
	}
	if looked := setup.owners.lookups(); len(looked) != 1 || setup.reader.noteCount() != 1 {
		t.Fatalf("%d lookups on this machine and %d notes", len(looked), setup.reader.noteCount())
	}
}

// A model host captured by name is noted with its flow's peer as well.
func TestAPeersFlowCapturedByNameIsNotedAsItsOwn(t *testing.T) {
	setup := newReadSetup(t)
	setup.router.Read(setup.reader, true)
	setup.router.SetPeerRule("sandbox-1", func(Flow) (string, error) { return "claude", nil })
	address, ok := setup.address(modelHost)
	if !ok {
		t.Fatalf("%s wasn't captured by name", modelHost)
	}
	setup.run(modelHost, Flow{Source: netip.AddrPortFrom(LocalAddress, 50990), Dest: netip.AddrPortFrom(address, 443), Peer: "sandbox-1"})
	if seen := setup.arrives(setup.ends.atProxy); !seen.noted || seen.tool != "claude" {
		t.Fatalf("noted %q (told at all: %v)", seen.tool, seen.noted)
	}
	if peers := setup.reader.notedPeers(); !reflect.DeepEqual(peers, []string{"sandbox-1"}) {
		t.Fatalf("the proxy was told the flow came from %v", peers)
	}
	if looked := setup.owners.lookups(); len(looked) != 0 {
		t.Fatalf("a program on this machine was looked for: %v", looked)
	}
}
