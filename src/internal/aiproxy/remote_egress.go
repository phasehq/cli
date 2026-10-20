package aiproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
)

var errUnsafeRemoteDestination = errors.New("remote Agent proxy destination is not publicly routable")

// IPResolver is the narrow DNS seam used by the remote egress guard. Resolving
// once and dialing only the returned, validated addresses prevents a hostname
// from being re-resolved to a private address between validation and connect.
type IPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type remoteEgressGuard struct{ resolver IPResolver }

var nonPublicRemotePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata.
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("168.63.129.16/32"), // Azure WireServer virtual IP.
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), // Well-known NAT64 translation prefix.
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fec0::/10"), // Deprecated IPv6 site-local space.
}

func newRemoteEgressGuard(resolver IPResolver) *remoteEgressGuard {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &remoteEgressGuard{resolver: resolver}
}

func guardedRemoteHTTPTransport(base *http.Transport, dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	guarded := base.Clone()
	guarded.Proxy = nil
	guarded.DialContext = dial
	// These hooks take precedence over DialContext for HTTPS. Retaining either
	// would let a caller-provided transport bypass validation and DNS pinning.
	guarded.DialTLSContext = nil
	guarded.DialTLS = nil
	return guarded
}

func (g *remoteEgressGuard) guardedDial(base func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, portRaw, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errUnsafeRemoteDestination
		}
		port, err := strconv.Atoi(portRaw)
		if err != nil || port < 1 || port > 65535 {
			return nil, errUnsafeRemoteDestination
		}
		addresses, err := g.resolvePublic(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, candidate := range addresses {
			if network == "tcp4" && !candidate.Is4() {
				continue
			}
			if network == "tcp6" && !candidate.Is6() {
				continue
			}
			connection, dialErr := base(ctx, network, net.JoinHostPort(candidate.String(), portRaw))
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errors.New("remote Agent proxy destination has no address for the requested network")
	}
}

func (g *remoteEgressGuard) resolvePublic(ctx context.Context, host string) ([]netip.Addr, error) {
	if parsed, err := netip.ParseAddr(host); err == nil {
		parsed = parsed.Unmap()
		if !remotePublicAddress(parsed) {
			return nil, errUnsafeRemoteDestination
		}
		return []netip.Addr{parsed}, nil
	}
	resolved, err := g.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(resolved) == 0 {
		return nil, errors.New("remote Agent proxy destination did not resolve")
	}
	addresses := make([]netip.Addr, 0, len(resolved))
	seen := make(map[netip.Addr]struct{}, len(resolved))
	for _, candidate := range resolved {
		address, ok := netip.AddrFromSlice(candidate.IP)
		if !ok {
			return nil, errUnsafeRemoteDestination
		}
		address = address.Unmap()
		// A mixed public/private answer is rejected as a whole. Selecting only its
		// public member would let a rebinding response influence retries.
		if !remotePublicAddress(address) {
			return nil, errUnsafeRemoteDestination
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	if len(addresses) == 0 {
		return nil, errors.New("remote Agent proxy destination did not resolve")
	}
	return addresses, nil
}

func remotePublicAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicRemotePrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
