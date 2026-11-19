package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"
)

// With the whole machine captured, anything the engine sends has to leave by the real
// interface, or it would come straight back into the tunnel. Pinning a socket to an
// interface needs no privileges, and it's how other VPNs avoid the same loop.

// Physical is the interface the engine's own traffic leaves by.
var Physical = &PhysicalPath{}

type PhysicalPath struct {
	mu      sync.RWMutex
	name    string
	index   int
	enabled bool
	// seen is the default route as last looked at, none included, and changes
	// counts the looks that found another.
	seen    defaultRoute
	changes uint64
}

// defaultRoute is the default route's interface, and its gateway where that is known.
type defaultRoute struct {
	name    string
	index   int
	gateway string
}

// Refresh follows the default route, and turns pinning on.
func (p *PhysicalPath) Refresh() {
	name, index := DefaultRouteInterface()
	found := defaultRoute{name: name, index: index, gateway: defaultRouteGateway()}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = true
	p.observe(found)
}

// observe takes one look at the default route. A route that went away and came back
// is two changes, and so is the same interface with another gateway: either way the
// machine may be on another network.
func (p *PhysicalPath) observe(found defaultRoute) {
	if found != p.seen {
		p.seen = found
		p.changes++
	}
	if found.index != 0 {
		p.name, p.index = found.name, found.index
	}
}

// Changes counts the times the machine's way out has changed. Whatever was read from
// the network, its DNS servers above all, is read again once this has moved on.
func (p *PhysicalPath) Changes() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.changes
}

// Watch follows the default route until ctx ends, so a move from Wi-Fi to Ethernet
// takes effect on the next connection.
func (p *PhysicalPath) Watch(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.Refresh()
		}
	}
}

// Current returns the interface, and whether pinning is on at all.
func (p *PhysicalPath) Current() (name string, index int, enabled bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.name, p.index, p.enabled
}

var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// staysOnItsRoute is an address another interface is responsible for. It never reaches
// the tunnel, so pinning it to the physical interface could only break it.
func staysOnItsRoute(addr netip.Addr) bool {
	return addr.Unmap().IsLoopback() || leftToItsRoute(addr)
}

// leftToItsRoute is an address in another VPN's range, which that VPN's own routes
// carry for as long as it is up. See Router.loops for when it is down.
func leftToItsRoute(addr netip.Addr) bool {
	addr = addr.Unmap()
	return tailnetV4.Contains(addr) || tailnetV6.Contains(addr)
}

// ownAddress is an address of the tunnel's own device. A socket that is given one as
// its source is routed into the tunnel.
func ownAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	return TunnelPrefix.Contains(addr) || addr == LocalAddress6
}

// unpinnedSource asks the system which address a socket to dest would leave from,
// with no interface chosen for it. Connecting a UDP socket picks the route and the
// source address, and sends nothing.
func unpinnedSource(dest netip.Addr) (netip.Addr, error) {
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dest.Unmap(), 9)))
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("the socket has no address")
	}
	return local.AddrPort().Addr().Unmap().WithZone(""), nil
}

// Bind pins one socket that is about to reach address.
func (p *PhysicalPath) Bind(address string, bind func(ipv6 bool, name string, index int) error) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	addr, err := netip.ParseAddr(strings.SplitN(host, "%", 2)[0])
	if err != nil || staysOnItsRoute(addr) {
		return nil
	}
	name, index, enabled := p.Current()
	if !enabled {
		return nil
	}
	if index == 0 {
		return errors.New("no network: there's no default route to leave by")
	}
	return bind(addr.Unmap().Is6(), name, index)
}

// Control is a net.Dialer control function.
func (p *PhysicalPath) Control(_, address string, raw syscall.RawConn) error {
	return p.Bind(address, func(ipv6 bool, name string, index int) error {
		var bindErr error
		if err := raw.Control(func(fd uintptr) { bindErr = bindSocket(int(fd), ipv6, name, index) }); err != nil {
			return err
		}
		return bindErr
	})
}

// Dialer reaches anything that isn't on this machine.
func (p *PhysicalPath) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, Control: p.Control}
}
