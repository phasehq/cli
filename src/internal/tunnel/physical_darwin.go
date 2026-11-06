//go:build darwin

package tunnel

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// DefaultRoute is one IPv4 default route.
type DefaultRoute struct {
	Index   int
	Scoped  bool
	Gateway netip.Addr
}

// DefaultRoutes lists the IPv4 default routes: the system's, and any scoped to a
// single interface.
func DefaultRoutes() []DefaultRoute {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}
	var routes []DefaultRoute
	for _, message := range messages {
		entry, ok := message.(*route.RouteMessage)
		if !ok || entry.Flags&syscall.RTF_UP == 0 || len(entry.Addrs) <= syscall.RTAX_NETMASK {
			continue
		}
		dest, ok := entry.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok || dest.IP != [4]byte{} {
			continue
		}
		// A default route has an all-zero mask. The tunnel's halves share its key.
		mask, ok := entry.Addrs[syscall.RTAX_NETMASK].(*route.Inet4Addr)
		if !ok || mask.IP != [4]byte{} {
			continue
		}
		found := DefaultRoute{Index: entry.Index, Scoped: entry.Flags&unix.RTF_IFSCOPE != 0}
		if gateway, ok := entry.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr); ok {
			found.Gateway = netip.AddrFrom4(gateway.IP)
		}
		routes = append(routes, found)
	}
	return routes
}

// DefaultRouteInterface is the interface of the system's default route. The tunnel
// never takes the default route itself, so this is never the tunnel, and it follows
// another VPN's exit node.
func DefaultRouteInterface() (string, int) {
	for _, found := range DefaultRoutes() {
		if found.Scoped {
			continue
		}
		if iface, err := net.InterfaceByIndex(found.Index); err == nil {
			return iface.Name, iface.Index
		}
	}
	return "", 0
}

func bindSocket(fd int, ipv6 bool, _ string, index int) error {
	if ipv6 {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
}
