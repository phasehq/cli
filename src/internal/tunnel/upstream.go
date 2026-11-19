package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Upstream is how the engine reaches the real world. The system resolver can't be
// used, because it answers for Connection hosts with the tunnel's addresses, and the
// default route can't either, because everything is captured. So names are resolved
// against the network's own DNS servers, and every socket is pinned to the physical
// interface.
type Upstream struct {
	Servers []string
	// Override sends an address somewhere else. Tests use it to reach stand-ins.
	Override map[string]string
	// OnlyOverrides refuses every address Override doesn't hold, and asks no DNS
	// server anything. A test that uses real host names sets it, so that nothing it
	// does can leave the machine.
	OnlyOverrides bool
	next          atomic.Uint32
}

// NewUpstream reads the network's DNS servers, ignoring the tunnel's own.
func NewUpstream() *Upstream {
	servers := []string{}
	for _, server := range upstreamNameservers() {
		if server != DNSAddress.String() {
			servers = append(servers, server)
		}
	}
	return &Upstream{Servers: append(servers, "1.1.1.1", "8.8.8.8")}
}

// Resolver asks the network's DNS servers directly, moving to the next on each attempt.
func (u *Upstream) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			server := u.Servers[int(u.next.Add(1)-1)%len(u.Servers)]
			return Physical.Dialer(3*time.Second).DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		},
	}
}

// DialContext reaches a host by name or address. It's the credential proxy's dialer.
func (u *Upstream) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if override, ok := u.Override[address]; ok {
		address = override
	} else if u.OnlyOverrides {
		return nil, fmt.Errorf("%s isn't one of the addresses this run may reach", address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	dialer := Physical.Dialer(15 * time.Second)
	if net.ParseIP(host) != nil {
		return dialer.DialContext(ctx, network, address)
	}
	addresses, err := u.Resolver().LookupIP(ctx, "ip", strings.TrimSuffix(host, ".")+".")
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	var lastErr error
	for _, ip := range preferIPv4(addresses) {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no addresses for %s", host)
	}
	return nil, lastErr
}

func preferIPv4(addresses []net.IP) []net.IP {
	ordered := make([]net.IP, 0, len(addresses))
	for _, ip := range addresses {
		if ip.To4() != nil {
			ordered = append(ordered, ip)
		}
	}
	for _, ip := range addresses {
		if ip.To4() == nil {
			ordered = append(ordered, ip)
		}
	}
	return ordered
}

// Transport is the proxy's own default transport, with this dialer.
func (u *Upstream) Transport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.DialContext = u.DialContext
	return transport
}

// Forward asks the network's DNS servers a raw query, for names under a Connection's
// domain that aren't themselves captured.
func (u *Upstream) Forward(query []byte) []byte {
	if u.OnlyOverrides {
		return refused(query)
	}
	for _, server := range u.Servers {
		conn, err := Physical.Dialer(2*time.Second).Dial("udp", net.JoinHostPort(server, "53"))
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		reply := make([]byte, 4096)
		_, err = conn.Write(query)
		n := 0
		if err == nil {
			n, err = conn.Read(reply)
		}
		_ = conn.Close()
		if err == nil {
			return reply[:n]
		}
	}
	return refused(query)
}

// refused answers a query that can't be answered, so the program fails at once.
func refused(query []byte) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil
	}
	question, err := parser.Question()
	if err != nil {
		return nil
	}
	reply := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: header.ID, Response: true, RCode: dnsmessage.RCodeServerFailure},
		Questions: []dnsmessage.Question{question},
	}
	packed, err := reply.Pack()
	if err != nil {
		return nil
	}
	return packed
}
