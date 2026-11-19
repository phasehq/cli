package helper

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/phasehq/cli/internal/tunnel"
)

// The helper runs as root and takes its routes from an unprivileged caller. The
// command line checks them too, but the helper is the one that changes the machine,
// so it decides for itself which routes a capture can be made of.

// neverCaptured are the ranges no capture means: addresses that aren't a unicast
// destination out on a network, and the tunnel's own.
var neverCaptured = []struct {
	prefix netip.Prefix
	what   string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), "the unspecified network"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
	{netip.MustParsePrefix("255.255.255.255/32"), "broadcast"},
	{netip.MustParsePrefix("::/127"), "the unspecified address and loopback"},
	{netip.MustParsePrefix("fe80::/10"), "link-local"},
	{netip.MustParsePrefix("ff00::/8"), "multicast"},
	{tunnel.TunnelPrefix, "the tunnel's own range"},
}

// captureRoutes reads the routes an engine asks for, and returns them written one
// way, each once. A capture is made of IPv4 and IPv6 unicast space. The default route
// itself is never one of them: capturing everything takes each half of the address
// space and leaves the default route alone, which the local network and other VPNs
// depend on. A route that lies inside a range no capture means is refused as well.
// One that only takes such a range in, as each half of the address space does, is
// fine: the system's own, more specific, routes still carry that range.
func captureRoutes(routes []string) ([]string, error) {
	var clean []string
	seen := map[string]bool{}
	for _, text := range routes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, fmt.Errorf("route %q is malformed", text)
		}
		prefix = prefix.Masked()
		switch {
		case prefix.Addr().Is4In6():
			return nil, fmt.Errorf("route %q is an IPv4 route written as IPv6", text)
		case prefix.Bits() == 0:
			return nil, fmt.Errorf("route %s would replace the default route", prefix)
		}
		for _, never := range neverCaptured {
			if never.prefix.Addr().Is4() == prefix.Addr().Is4() && prefix.Bits() >= never.prefix.Bits() && never.prefix.Contains(prefix.Addr()) {
				return nil, fmt.Errorf("route %s is %s, which a capture is never made of", prefix, never.what)
			}
		}
		if route := prefix.String(); !seen[route] {
			seen[route] = true
			clean = append(clean, route)
		}
	}
	return clean, nil
}

// ownRanges are the ranges Phase uses for itself, each with the block it was picked
// from. A route inside the range, or one for the block or a part of it that takes the
// range in, is something else using the same addresses. A wider route, such as the
// default route or another VPN's half of the address space, says nothing about them.
var ownRanges = []struct{ used, block netip.Prefix }{
	// The tunnel's addresses, the resolver, the probe and the pool that Connection
	// hosts get their addresses from, out of the benchmarking range.
	{tunnel.TunnelPrefix, netip.MustParsePrefix("198.18.0.0/15")},
	{netip.PrefixFrom(tunnel.LocalAddress6, 128), netip.MustParsePrefix("fd70:7068:6173::/48")},
}

// rangeConflict looks through a routing table, as netstat -rn lists it, for a route
// that uses one of Phase's own ranges. It returns the range and the route's line.
func rangeConflict(listing string) (used netip.Prefix, line string, found bool) {
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		route, ok := listedRoute(fields[0])
		if !ok {
			continue
		}
		for _, own := range ownRanges {
			if route.Addr().Is4() == own.used.Addr().Is4() && route.Bits() >= own.block.Bits() && route.Overlaps(own.used) {
				return own.used, strings.Join(fields, " "), true
			}
		}
	}
	return netip.Prefix{}, "", false
}

// listedRoute reads a destination as netstat -rn writes it. An IPv4 network is
// written without its trailing zeros, and without its length when that is the number
// of bytes written: 127 is 127.0.0.0/8, 198.19.248/22 is 198.19.248.0/22 and 0/1 is
// 0.0.0.0/1. An IPv6 destination may name its interface after a %. Anything else in
// the listing, the default route and the headings included, isn't a route to check.
func listedRoute(destination string) (netip.Prefix, bool) {
	address, length, hasLength := strings.Cut(destination, "/")
	address, _, _ = strings.Cut(address, "%")
	bits := -1
	if hasLength {
		parsed, err := strconv.Atoi(length)
		if err != nil {
			return netip.Prefix{}, false
		}
		bits = parsed
	}
	if strings.Contains(address, ":") {
		addr, err := netip.ParseAddr(address)
		if err != nil || !addr.Is6() || addr.Is4In6() {
			return netip.Prefix{}, false
		}
		if bits < 0 {
			bits = 128
		}
		prefix, err := addr.Prefix(bits)
		return prefix, err == nil
	}
	parts := strings.Split(address, ".")
	if len(parts) > 4 {
		return netip.Prefix{}, false
	}
	if bits < 0 {
		bits = 8 * len(parts)
	}
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	addr, err := netip.ParseAddr(strings.Join(parts, "."))
	if err != nil {
		return netip.Prefix{}, false
	}
	prefix, err := addr.Prefix(bits)
	return prefix, err == nil
}

// routeSteps adds and removes capture routes, with a look at the routing table around
// each step. The helper keeps track of what it added, and this is the same care taken
// where the machine is changed: route(8) removes a route by where it goes to, whoever
// added it, and doesn't always say when a step failed.
type routeSteps struct {
	// index is the interface index of the tunnel's device.
	index func(device string) (int, error)
	// leaves finds the route for exactly this destination, among the routes that
	// aren't scoped to one interface, and returns the interface it leaves by.
	leaves func(netip.Prefix) (index int, found bool, err error)
	// run runs one step of route(8).
	run func(step ...string) error
	// name names an interface for a message. Without it the index is given.
	name func(index int) string
}

func (s routeSteps) interfaceName(index int) string {
	if s.name != nil {
		if name := s.name(index); name != "" {
			return name
		}
	}
	return "index " + strconv.Itoa(index)
}

func familyFlag(prefix string) string {
	if strings.Contains(prefix, ":") {
		return "-inet6"
	}
	return "-inet"
}

// add takes the routes for the device, and returns the ones it added. A route to the
// same place that is already there is someone else's, another VPN's most likely. It
// is never replaced, and when there is one nothing is added at all: a capture is all
// of its routes or none. When the table can't be read, what route(8) reports is all
// there is to go by.
func (s routeSteps) add(device string, prefixes []string) (added []string, err error) {
	own, err := s.index(device)
	if err != nil {
		return nil, err
	}
	wanted := make([]netip.Prefix, 0, len(prefixes))
	for _, text := range prefixes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, fmt.Errorf("route %q is malformed", text)
		}
		if index, found, err := s.leaves(prefix); err == nil && found && index != own {
			return nil, fmt.Errorf("%s is already routed by another interface (%s), and was left alone", prefix, s.interfaceName(index))
		}
		wanted = append(wanted, prefix)
	}
	for i, prefix := range wanted {
		text := prefixes[i]
		if index, found, err := s.leaves(prefix); err == nil && found && index == own {
			// Left from an earlier capture, and this device's: there to be given back.
			added = append(added, text)
			continue
		}
		if err := s.run("/sbin/route", "-q", "-n", "add", familyFlag(text), text, "-interface", device); err != nil {
			return added, err
		}
		// route(8) doesn't always say when it failed. The table does.
		if index, found, err := s.leaves(prefix); err == nil && (!found || index != own) {
			return added, fmt.Errorf("the route for %s wasn't added", prefix)
		}
		added = append(added, text)
	}
	return added, nil
}

// remove gives back routes that add took. One that no longer leaves by the device
// isn't the helper's any more, and is left alone; so are all of them when the device
// has gone, since its routes went with it.
func (s routeSteps) remove(device string, prefixes []string) {
	own, err := s.index(device)
	if err != nil {
		return
	}
	for _, text := range prefixes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			continue
		}
		if index, found, err := s.leaves(prefix); err == nil && (!found || index != own) {
			continue
		}
		_ = s.run("/sbin/route", "-q", "-n", "delete", familyFlag(text), text, "-interface", device)
	}
}
