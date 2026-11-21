package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Upstream is how the engine reaches the real world. The system resolver can't be
// used, because it answers for Connection hosts with the tunnel's addresses, and the
// default route can't either, because everything is captured. So names are resolved
// against the network's own DNS servers, and every socket is pinned to the physical
// interface.
type Upstream struct {
	// Servers are the network's own DNS servers, in the order the system asks them.
	// One may name its port; the rest are asked on port 53.
	Servers []string
	// Scoped are the servers the system asks about one domain and the names under it,
	// as another VPN's split DNS sets up. A name under such a domain is asked of them
	// before the others.
	Scoped map[string][]string
	// Fallback are asked only when the network has no server of its own, or none of
	// them answers. A name the network's servers say doesn't exist is never taken
	// to them: they know nothing of a private name, or know another address for it.
	// Nor is a name under a Scoped domain.
	Fallback []string
	// Override sends an address somewhere else. Tests use it to reach stand-ins.
	Override map[string]string
	// OnlyOverrides refuses every address Override doesn't hold, and asks no DNS
	// server anything. A test that uses real host names sets it, so that nothing it
	// does can leave the machine.
	OnlyOverrides bool

	// changed counts the times the way out of the machine changed, and read reads
	// the system's servers again after one. NewUpstream sets both.
	changed func() uint64
	read    func() (servers []string, scoped map[string][]string)
	mu      sync.Mutex
	// readAt is the count of changes the servers were read at, and known says that
	// read found some. readTime is when they were read, by clock.
	readAt   uint64
	known    bool
	readTime time.Time
	clock    func() time.Time
	// wait replaces serverWait. Tests set it.
	wait time.Duration
}

// publicResolvers answer when the network has no DNS server that does.
var publicResolvers = []string{"1.1.1.1", "8.8.8.8"}

// serverWait is how long one DNS server has to answer before the next is asked.
const serverWait = 3 * time.Second

// resolverAge is how long the servers that were read are kept. A VPN that sets up
// its own servers for a domain changes no route out, so nothing else says to look.
const resolverAge = 30 * time.Second

// NewUpstream reads the network's DNS servers, ignoring the tunnel's own, and reads
// them again whenever the machine's way out changes: another network has other servers.
func NewUpstream() *Upstream {
	u := &Upstream{Fallback: publicResolvers, changed: Physical.Changes, read: upstreamResolvers}
	u.refresh()
	return u
}

// refresh reads the system's servers again when the way out has changed since they
// were read, or they are older than resolverAge. It reads again as well while there
// are none: the network they belong to may not have been up yet.
func (u *Upstream) refresh() {
	if u.read == nil {
		return
	}
	clock := u.clock
	if clock == nil {
		clock = time.Now
	}
	now, at := u.changed(), clock()
	if u.known && now == u.readAt && at.Sub(u.readTime) < resolverAge {
		return
	}
	servers, scoped := u.read()
	u.readTime = at
	if u.known && now == u.readAt && len(servers) == 0 {
		// Only their age called for this, and the read found nothing: the servers
		// that worked are kept rather than leave names to the fallback.
		return
	}
	u.Servers, u.Scoped = servers, scoped
	u.readAt, u.known = now, len(u.Servers) > 0
}

// serversFor lists the servers to ask about a name, in order: those the system keeps
// for the name's domain, then the network's own, then the fallback. A name under such
// a domain is a private one, and never goes to the fallback.
func (u *Upstream) serversFor(name string) []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.refresh()
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	domain := ""
	for scoped := range u.Scoped {
		if (name == scoped || strings.HasSuffix(name, "."+scoped)) && len(scoped) > len(domain) {
			domain = scoped
		}
	}
	groups := [][]string{u.Scoped[domain], u.Servers}
	if domain == "" {
		groups = append(groups, u.Fallback)
	}
	var ordered []string
	seen := map[string]bool{}
	for _, servers := range groups {
		for _, server := range servers {
			if !seen[server] {
				seen[server] = true
				ordered = append(ordered, server)
			}
		}
	}
	return ordered
}

// serverAddress is where a DNS server is asked: port 53, unless it names its own.
func serverAddress(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "53")
}

// lookup resolves a name against the network's DNS servers, each in its turn, and
// the next only when one doesn't answer. An answer that the name doesn't exist is an
// answer, and ends it.
func (u *Upstream) lookup(ctx context.Context, host string) ([]net.IP, error) {
	name := strings.TrimSuffix(host, ".") + "."
	wait := u.wait
	if wait <= 0 {
		wait = serverWait
	}
	lastErr := fmt.Errorf("there's no DNS server to ask")
	for _, server := range u.serversFor(name) {
		resolver := &net.Resolver{
			PreferGo: true,
			// Whichever server the resolver means to ask, this one is asked.
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return Physical.Dialer(wait).DialContext(ctx, network, serverAddress(server))
			},
		}
		attempt, cancel := context.WithTimeout(ctx, wait)
		addresses, err := resolver.LookupIP(attempt, "ip", name)
		cancel()
		if err == nil {
			return addresses, nil
		}
		var answer *net.DNSError
		if errors.As(err, &answer) && answer.IsNotFound {
			return nil, err
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
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
	addresses, err := u.lookup(ctx, host)
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

// Forward asks the network's DNS servers a raw query about name, for names under a
// Connection's domain that aren't themselves captured. The servers are asked as
// lookup asks them: each in its turn, and the next only when one doesn't answer.
func (u *Upstream) Forward(name string, query []byte) []byte {
	if u.OnlyOverrides {
		return refused(query)
	}
	for _, server := range u.serversFor(name) {
		conn, err := Physical.Dialer(2*time.Second).Dial("udp", serverAddress(server))
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
