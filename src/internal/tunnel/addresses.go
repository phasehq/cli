package tunnel

import "net/netip"

// The tunnel's own addresses. They come from the benchmarking range, which nothing
// routes on a real network, and sit away from the parts of it other tools use for the
// same trick.
var (
	// TunnelPrefix is always routed into the tunnel, captured or not. It holds the
	// helper's address, the resolver, the probe host and the addresses handed out for
	// Connection hosts.
	TunnelPrefix = netip.MustParsePrefix("198.19.248.0/22")
	// LocalAddress is the helper's end of the tunnel, and the source address programs
	// use once everything is captured.
	LocalAddress = netip.MustParseAddr("198.19.248.1")
	// DNSAddress answers for Connection hosts.
	DNSAddress = netip.MustParseAddr("198.19.248.53")
	// ProbeAddress is answered by the engine itself, on port 7, so the helper can check
	// the whole path without depending on anything outside the machine.
	ProbeAddress = netip.MustParseAddr("198.19.248.7")
	// LocalAddress6 is the helper's IPv6 address, so programs have a source to use for
	// IPv6 destinations once everything is captured.
	LocalAddress6 = netip.MustParseAddr("fd70:7068:6173::1")
	// namePool is where Connection hosts get their addresses.
	namePool = netip.MustParsePrefix("198.19.249.0/24")
)

// FullRoutes take every destination that nothing more specific claims. Each family is
// split into two halves, so the default route itself is never replaced, and the local
// network and other VPNs keep their own, more specific, routes.
var FullRoutes = []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}

// MTU leaves room for WireGuard's overhead on a real network, so a laptop and a remote
// peer behave the same.
const MTU = 1420

// ProbePort is where the engine answers the helper's path check.
const ProbePort = 7

// ProbeReply is what it answers.
const ProbeReply = "ok\n"
