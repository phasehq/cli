package tunnel

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// datagram is the packet a program's UDP datagram reaches the stack as.
func datagram(source, dest netip.AddrPort, payload []byte) []byte {
	segment := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(segment, source.Port())
	binary.BigEndian.PutUint16(segment[2:], dest.Port())
	binary.BigEndian.PutUint16(segment[4:], uint16(len(segment)))
	copy(segment[8:], payload)
	if source.Addr().Is4() {
		packet := make([]byte, 20, 20+len(segment))
		packet[0], packet[8], packet[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(packet[2:], uint16(20+len(segment)))
		from, to := source.Addr().As4(), dest.Addr().As4()
		copy(packet[12:], from[:])
		copy(packet[16:], to[:])
		binary.BigEndian.PutUint16(packet[10:], InternetChecksum(packet[:20]))
		// Over IPv4 a datagram may go without a checksum of its own.
		return append(packet, segment...)
	}
	from, to := source.Addr().As16(), dest.Addr().As16()
	pseudo := make([]byte, 40, 40+len(segment))
	copy(pseudo, from[:])
	copy(pseudo[16:], to[:])
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(segment)))
	pseudo[39] = 17
	binary.BigEndian.PutUint16(segment[6:], InternetChecksum(append(pseudo, segment...)))
	packet := make([]byte, 40, 40+len(segment))
	packet[0], packet[6], packet[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(packet[4:], uint16(len(segment)))
	copy(packet[8:], from[:])
	copy(packet[24:], to[:])
	return append(packet, segment...)
}

// unreachable reads, out of a packet the stack sent, whom it tells that a port can't
// be reached, and the ports of the datagram it says so about.
func unreachable(packet []byte) (from, to netip.Addr, sourcePort, destPort uint16, ok bool) {
	var message []byte
	header := 0
	switch {
	case len(packet) >= 28 && packet[0]>>4 == 4 && packet[9] == 1:
		from, _ = netip.AddrFromSlice(packet[12:16])
		to, _ = netip.AddrFromSlice(packet[16:20])
		// Destination unreachable, port unreachable.
		message, header = packet[int(packet[0]&0x0f)*4:], 20
		ok = message[0] == 3 && message[1] == 3
	case len(packet) >= 48 && packet[0]>>4 == 6 && packet[6] == 58:
		from, _ = netip.AddrFromSlice(packet[8:24])
		to, _ = netip.AddrFromSlice(packet[24:40])
		message, header = packet[40:], 40
		ok = message[0] == 1 && message[1] == 4
	}
	// The datagram it is about follows, from its IP header on.
	if !ok || len(message) < 8+header+4 {
		return from, to, 0, 0, false
	}
	about := message[8+header:]
	return from, to, binary.BigEndian.Uint16(about), binary.BigEndian.Uint16(about[2:]), true
}

// A datagram the hooks refuse starts no conversation, and its sender is told at once
// that the port can't be reached: a program waiting on an answer that will never come
// would only find out when it gave up.
func TestTheStackAnswersARefusedDatagramAtOnce(t *testing.T) {
	var conversations atomic.Int32
	stack, err := NewStack(Hooks{
		TCP: func(net.Conn, Flow) {}, DNS: func([]byte) []byte { return nil },
		UDP:       func(conn net.Conn, _ Flow) { conversations.Add(1); conn.Close() },
		RefuseUDP: func(flow Flow) bool { return flow.Dest.Port() == 443 },
	}, MTU)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	for _, test := range []struct{ source, dest string }{
		{"198.19.248.1:50001", "203.0.113.7:443"},
		{"[fd70:7068:6173::1]:50002", "[2001:db8::7]:443"},
	} {
		source, dest := netip.MustParseAddrPort(test.source), netip.MustParseAddrPort(test.dest)
		stack.Inject(datagram(source, dest, []byte("a QUIC initial")))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		reply := stack.Next(ctx)
		cancel()
		from, to, sourcePort, destPort, ok := unreachable(reply)
		// It comes from the address the program sent to, and names the program's own
		// datagram, which is how the system finds the socket to tell.
		if !ok || from != dest.Addr() || to != source.Addr() || sourcePort != source.Port() || destPort != 443 {
			t.Fatalf("a datagram to %s was answered with %x", dest, reply)
		}
	}
	if conversations.Load() != 0 {
		t.Fatalf("%d refused datagrams started a conversation", conversations.Load())
	}
	// Any other datagram starts a conversation as before, and is told nothing.
	stack.Inject(datagram(netip.MustParseAddrPort("198.19.248.1:50003"), netip.MustParseAddrPort("203.0.113.7:3478"), []byte("other")))
	deadline := time.Now().Add(5 * time.Second)
	for conversations.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("a datagram nobody refused started no conversation")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if reply := stack.Next(ctx); reply != nil {
		t.Fatalf("a datagram nobody refused was answered with %x", reply)
	}
}

// With everything routed in, UDP to port 443 is refused: it is HTTP/3, whose host
// can't be told here, so nothing could say whether to read it or send it to the proxy.
// Everything else UDP carries is none of the router's business, and is relayed.
func TestTheRouterRefusesHTTP3OnlyWhileEverythingIsCaptured(t *testing.T) {
	flow := func(dest string) Flow {
		return Flow{Source: netip.MustParseAddrPort("198.19.248.1:50000"), Dest: netip.MustParseAddrPort(dest)}
	}
	reader := &fakeReader{hosts: map[string][]string{"claude": {modelHost}}}
	everything := NewRouter(&Upstream{OnlyOverrides: true}, nil)
	everything.Read(reader, false)
	for dest, refused := range map[string]bool{
		"203.0.113.7:443": true, "[2001:db8::7]:443": true,
		"203.0.113.7:53": false, "203.0.113.7:3478": false, "203.0.113.7:4433": false, "203.0.113.7:80": false,
		// A tunnel address gives UDP no answer already, as it did before.
		"198.19.249.7:443": false,
	} {
		if got := everything.RefuseUDP(flow(dest)); got != refused {
			t.Errorf("UDP to %s: refused %v, want %v", dest, got, refused)
		}
	}
	if counts := everything.Counts(); counts["udp_443_refused"] != 2 || len(counts) != 1 {
		t.Fatalf("counts %v", counts)
	}
	// It takes no question about the host or the program: there is none to ask.
	if len(reader.asked) != 0 {
		t.Fatalf("the reader was asked about %v", reader.asked)
	}

	// With less routed in, a host is caught by its name, and other UDP is left alone.
	part := NewRouter(&Upstream{OnlyOverrides: true}, nil)
	part.Read(reader, true)
	// Until a reader is set the router doesn't know what is captured, and refuses nothing.
	unset := NewRouter(&Upstream{OnlyOverrides: true}, nil)
	for name, router := range map[string]*Router{"with less routed in": part, "with no reader": unset} {
		if router.RefuseUDP(flow("203.0.113.7:443")) || len(router.Counts()) != 0 {
			t.Errorf("%s, UDP to port 443 was refused: %v", name, router.Counts())
		}
	}
}

// What is refused is never relayed, even when the router is handed the conversation
// with nobody having asked it first.
func TestUDPToPort443IsNotRelayedWhileEverythingIsCaptured(t *testing.T) {
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	var received atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			received.Add(1)
			_, _ = echo.WriteTo(buf[:n], from)
		}
	}()
	const real = "203.0.113.7:443"
	send := func(router *Router) (reply []byte) {
		client, inside := net.Pipe()
		defer client.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			router.HandleUDP(inside, Flow{Source: netip.MustParseAddrPort("198.19.248.1:50000"), Dest: netip.MustParseAddrPort(real)})
		}()
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := client.Write([]byte("a QUIC initial")); err == nil {
			buf := make([]byte, 2048)
			if n, err := client.Read(buf); err == nil {
				reply = buf[:n]
			}
		}
		client.Close()
		<-done
		return reply
	}
	owners := 0
	reader := &fakeReader{hosts: map[string][]string{"claude": {modelHost}}}
	router := NewRouter(&Upstream{Override: map[string]string{real: echo.LocalAddr().String()}, OnlyOverrides: true}, nil)
	router.Read(reader, false)
	router.SetPeerRule(LocalPeer, func(Flow) (string, error) { owners++; return "claude", nil })
	if reply := send(router); reply != nil || received.Load() != 0 {
		t.Fatalf("the datagram was relayed: %q came back, and its destination got %d", reply, received.Load())
	}
	if counts := router.Counts(); counts["udp_443_refused"] != 1 || len(counts) != 1 {
		t.Fatalf("counts %v", counts)
	}
	if owners != 0 || len(reader.asked) != 0 {
		t.Fatalf("the owner rule was asked %d times and the reader about %v", owners, reader.asked)
	}

	// With less routed in, the same conversation is relayed as it always was.
	router.Read(reader, true)
	if reply := send(router); string(reply) != "a QUIC initial" {
		t.Fatalf("with less routed in, %q came back", reply)
	}
	if counts := router.Counts(); counts["udp"] != 1 || counts["udp_443_refused"] != 1 {
		t.Fatalf("counts %v", counts)
	}
}
