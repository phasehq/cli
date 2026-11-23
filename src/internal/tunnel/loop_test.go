package tunnel

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRoutes stands in for the routing table: where a socket nothing pins would leave
// from, by destination.
type fakeRoutes struct {
	mu      sync.Mutex
	sources map[netip.Addr]netip.Addr
	err     error
	asked   []netip.Addr
}

func (f *fakeRoutes) route(dest netip.Addr) (netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, dest)
	if f.err != nil {
		return netip.Addr{}, f.err
	}
	if source, ok := f.sources[dest]; ok {
		return source, nil
	}
	return netip.MustParseAddr("192.168.1.20"), nil
}

func (f *fakeRoutes) lookups() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

// counted is a listener that counts what reaches it.
func counted(t *testing.T) (address string, reached *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	reached = &atomic.Int64{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			reached.Add(1)
			_ = conn.Close()
		}
	}()
	return listener.Addr().String(), reached
}

var (
	// A machine on a tailnet, and the tailnet's own resolver over IPv6.
	tailnetPeer   = netip.MustParseAddr("100.101.102.103")
	tailnetPeer6  = netip.MustParseAddr("fd7a:115c:a1e0::53")
	tailscaleSelf = netip.MustParseAddr("100.64.0.9")
)

// With its VPN down, an address in the VPN's range is routed into the tunnel like any
// other. The engine leaves such an address to its route, so what it sent there would
// come straight back to be sent again. It is refused instead, and counted.
func TestADestinationWhoseRouteLeadsBackIntoTheTunnelIsRefused(t *testing.T) {
	for name, test := range map[string]struct {
		dest, source netip.Addr
	}{
		"IPv4": {tailnetPeer, LocalAddress},
		"IPv6": {tailnetPeer6, LocalAddress6},
		// Any address of the tunnel's own device says the same.
		"another of the tunnel's addresses": {tailnetPeer, netip.MustParseAddr("198.19.250.4")},
		"an IPv4 address written as IPv6":   {netip.MustParseAddr("::ffff:100.101.102.103"), netip.MustParseAddr("::ffff:198.19.248.1")},
	} {
		t.Run(name, func(t *testing.T) {
			routes := &fakeRoutes{sources: map[netip.Addr]netip.Addr{test.dest: test.source}}
			standIn, reached := counted(t)
			target := netip.AddrPortFrom(test.dest, 443)
			router := NewRouter(&Upstream{Servers: []string{"127.0.0.1"}, OnlyOverrides: true, Override: map[string]string{target.String(): standIn}}, nil)
			router.FindRoutesWith(routes.route)

			t.Run("TCP", func(t *testing.T) {
				start := time.Now()
				prepared, ok := router.Prepare(Flow{Source: netip.AddrPortFrom(LocalAddress, 50001), Dest: target})
				if ok || prepared != nil {
					t.Fatal("a connection that would loop was opened")
				}
				if elapsed := time.Since(start); elapsed > time.Second {
					t.Fatalf("the refusal took %s, long enough to fill the table of connections that are still opening", elapsed)
				}
			})
			t.Run("UDP", func(t *testing.T) {
				program, routerEnd := net.Pipe()
				defer program.Close()
				done := make(chan struct{})
				go func() {
					defer close(done)
					router.HandleUDP(routerEnd, Flow{Source: netip.AddrPortFrom(LocalAddress, 50002), Dest: netip.AddrPortFrom(test.dest, 53)})
				}()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("a conversation that would loop was carried")
				}
			})
			t.Run("ping", func(t *testing.T) {
				if router.Echo(test.dest, 1, []byte("ping")) {
					t.Fatal("a ping that would loop was answered")
				}
			})
			if counts := router.Counts(); counts["loop_refused"] != 3 || counts["tcp_failed"] != 0 || counts["udp"] != 0 || counts["udp_failed"] != 0 {
				t.Fatalf("counts: %v", counts)
			}
			if reached.Load() != 0 {
				t.Fatal("something was sent to a destination that was refused")
			}
		})
	}
}

// While the VPN is up its own interface carries the range, and nothing changes.
func TestADestinationOnAnotherVPNsRouteIsReached(t *testing.T) {
	routes := &fakeRoutes{sources: map[netip.Addr]netip.Addr{tailnetPeer: tailscaleSelf}}
	standIn, reached := counted(t)
	target := netip.AddrPortFrom(tailnetPeer, 443)
	router := NewRouter(&Upstream{Servers: []string{"127.0.0.1"}, OnlyOverrides: true, Override: map[string]string{target.String(): standIn}}, nil)
	router.FindRoutesWith(routes.route)
	prepared, ok := router.Prepare(Flow{Source: netip.AddrPortFrom(LocalAddress, 50001), Dest: target})
	if !ok {
		t.Fatal("a destination on another VPN's own route was refused")
	}
	prepared.(net.Conn).Close()
	if routes.lookups() != 1 || router.Counts()["loop_refused"] != 0 {
		t.Fatalf("%d route lookups, counts %v", routes.lookups(), router.Counts())
	}
	deadline := time.Now().Add(5 * time.Second)
	for reached.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the destination was never reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A destination with no route at all can't come back either: reaching it fails by
// itself, as it would for any other address.
func TestADestinationWithNoRouteIsNotCalledALoop(t *testing.T) {
	routes := &fakeRoutes{err: errors.New("connect: network is unreachable")}
	router := NewRouter(&Upstream{Servers: []string{"127.0.0.1"}, OnlyOverrides: true}, nil)
	router.FindRoutesWith(routes.route)
	if _, ok := router.Prepare(Flow{Source: netip.AddrPortFrom(LocalAddress, 50001), Dest: netip.AddrPortFrom(tailnetPeer, 443)}); ok {
		t.Fatal("an address this run may not reach was reached")
	}
	if counts := router.Counts(); counts["loop_refused"] != 0 || counts["tcp_failed"] != 1 {
		t.Fatalf("counts: %v", counts)
	}
}

// Every other socket is pinned to the physical interface and can't come back, so the
// routing table isn't asked about it: ordinary traffic pays nothing for the check.
func TestOnlyDestinationsLeftToTheirRouteAreLookedUp(t *testing.T) {
	routes := &fakeRoutes{sources: map[netip.Addr]netip.Addr{}}
	standIn, _ := counted(t)
	router := NewRouter(&Upstream{Servers: []string{"127.0.0.1"}, OnlyOverrides: true, Override: map[string]string{"203.0.113.7:443": standIn, "[2001:db8::7]:443": standIn}}, nil)
	router.FindRoutesWith(routes.route)
	for _, dest := range []string{"203.0.113.7:443", "[2001:db8::7]:443"} {
		prepared, ok := router.Prepare(Flow{Source: netip.AddrPortFrom(LocalAddress, 50001), Dest: netip.MustParseAddrPort(dest)})
		if !ok {
			t.Fatalf("%s wasn't reached", dest)
		}
		prepared.(net.Conn).Close()
	}
	// The tunnel's own addresses are answered here, and never reached from here.
	if _, ok := router.Prepare(Flow{Source: netip.AddrPortFrom(LocalAddress, 50001), Dest: netip.AddrPortFrom(ProbeAddress, ProbePort)}); !ok {
		t.Fatal("the probe wasn't answered")
	}
	if routes.lookups() != 0 {
		t.Fatalf("the routing table was asked about %v", routes.asked)
	}
	for _, addr := range []string{"100.64.0.1", "100.127.255.254", "fd7a:115c:a1e0::1", "::ffff:100.100.100.100"} {
		if !leftToItsRoute(netip.MustParseAddr(addr)) {
			t.Errorf("%s isn't left to its route", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1", "::1", "100.63.255.255", "100.128.0.0", "1.1.1.1", "fd7a:115c:a1e1::1"} {
		if leftToItsRoute(netip.MustParseAddr(addr)) {
			t.Errorf("%s is left to its route, and would be looked up", addr)
		}
	}
	for addr, own := range map[string]bool{
		"198.19.248.1": true, "198.19.251.255": true, "fd70:7068:6173::1": true, "::ffff:198.19.248.1": true,
		"198.19.247.255": false, "198.19.252.0": false, "100.64.0.9": false, "192.168.1.20": false, "fd70:7068:6173::2": false,
	} {
		if ownAddress(netip.MustParseAddr(addr)) != own {
			t.Errorf("ownAddress(%s) = %v", addr, !own)
		}
	}
}

// The real lookup connects a UDP socket, which sends nothing. For this machine's own
// loopback it names a loopback address.
func TestUnpinnedSourceAsksTheSystem(t *testing.T) {
	source, err := unpinnedSource(netip.MustParseAddr("127.0.0.1"))
	if err != nil || !source.IsLoopback() {
		t.Fatalf("a socket to loopback would leave from %v: %v", source, err)
	}
}
