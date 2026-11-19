package tunnel

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/tunnel/owner"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// ControlHost is the name programs use for the proxy's control API.
const ControlHost = phaseproxy.ManifestHost

// Rule is one Connection's host, without any credential.
type Rule struct {
	ConnectionID string
	Protocol     string
	Host         agentapi.HostRule
}

// RulesFromConnections copies the host rules out of a session.
func RulesFromConnections(connections []agentapi.Connection) []Rule {
	var rules []Rule
	for _, connection := range connections {
		for _, host := range connection.Hosts {
			rules = append(rules, Rule{ConnectionID: connection.ConnectionID, Protocol: connection.Protocol, Host: host})
		}
	}
	return rules
}

// Domains are the names the helper sends to the tunnel's resolver. Each covers its
// subdomains, and anything under them that isn't a Connection host is answered from
// the network's own DNS servers.
//
// The helper writes a DNS entry for each name, and refuses a whole attach over one it
// can't write an entry for. So a host whose name isn't one a DNS entry can hold is
// left out, and skipped counts those: such a host is still caught by the name in a
// TLS hello when its traffic reaches the tunnel.
func Domains(rules []Rule) (domains []string, skipped int) {
	seen, left := map[string]bool{ControlHost: true}, map[string]bool{}
	for _, rule := range rules {
		value := strings.Trim(strings.ToLower(strings.TrimSpace(rule.Host.Value)), ".")
		switch {
		case value == "":
		case CapturableDomain(value):
			seen[value] = true
		default:
			left[value] = true
		}
	}
	domains = make([]string, 0, len(seen))
	for domain := range seen {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains, len(left)
}

// Traffic counts what passed through, for status.
type Traffic struct {
	TCPUp, TCPDown, UDPUp, UDPDown atomic.Int64
	ActiveTCP, ActiveUDP           atomic.Int64
}

// Router decides where each captured flow goes. Nothing here reads or changes a
// credential: that stays in the proxy, which is why it works with or without a tunnel.
type Router struct {
	Upstream *Upstream
	Traffic  Traffic

	mu              sync.RWMutex
	rules           []Rule
	proxyAddress    string
	proxyAuth       string
	proxyURL        *url.URL
	postgresAddress string
	names           nameTable
	counts          map[string]int
	lastFailure     time.Time
	logf            func(string, ...any)

	// What decides whether a model host is read. See read.go.
	reader    Reader
	readNames bool
	owner     OwnerFunc
	ownerWait time.Duration
	lookups   chan struct{}

	// route says where a socket nothing pins would leave from. See loops.
	route    RouteFunc
	lastLoop time.Time
}

// NewRouter starts with no Connections. Until Update, Connection hosts aren't captured.
// Until Read, no model host is read.
func NewRouter(upstream *Upstream, logf func(string, ...any)) *Router {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Router{
		Upstream: upstream, names: newNameTable(namePool), counts: map[string]int{}, logf: logf,
		owner: owner.Lookup, ownerWait: ownerWait, lookups: make(chan struct{}, ownerLookups),
		route: unpinnedSource,
	}
}

// Update points the router at a proxy session's front doors and Connections.
func (r *Router) Update(proxyURL, postgresAddress string, rules []Rule) error {
	parsed, err := url.Parse(proxyURL)
	if err != nil || parsed.User == nil {
		return fmt.Errorf("the proxy's address is malformed")
	}
	password, _ := parsed.User.Password()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.proxyAddress = parsed.Host
	r.proxyURL = parsed
	r.proxyAuth = base64.StdEncoding.EncodeToString([]byte(parsed.User.Username() + ":" + password))
	r.postgresAddress = postgresAddress
	r.rules = append([]Rule(nil), rules...)
	return nil
}

// SetRules replaces the Connections' hosts, for a session that changed while it ran.
func (r *Router) SetRules(rules []Rule) {
	r.mu.Lock()
	r.rules = append([]Rule(nil), rules...)
	r.mu.Unlock()
}

// CapturedDomains are the names the helper sends to the tunnel's resolver: the
// Connections' hosts and, when model hosts are captured by name, those as well.
// skipped counts the Connections' hosts whose names couldn't be sent.
func (r *Router) CapturedDomains() (domains []string, skipped int) {
	r.mu.RLock()
	rules, reader, byName := append([]Rule(nil), r.rules...), r.reader, r.readNames
	r.mu.RUnlock()
	domains, skipped = Domains(rules)
	if reader == nil || !byName {
		return domains, skipped
	}
	seen := map[string]bool{}
	for _, domain := range domains {
		seen[domain] = true
	}
	for _, domain := range ReadDomains(reader.ToolHosts()) {
		if !seen[domain] {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	return domains, skipped
}

// Counts reports how many flows took each route.
func (r *Router) Counts() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	counts := make(map[string]int, len(r.counts))
	for key, value := range r.counts {
		counts[key] = value
	}
	return counts
}

func (r *Router) count(route string) {
	r.mu.Lock()
	r.counts[route]++
	r.mu.Unlock()
}

// captured reports whether a name belongs to a Connection, and its protocol at port.
func (r *Router) captured(name string, port int) (bool, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if strings.EqualFold(name, ControlHost) {
		return true, "control"
	}
	for _, rule := range r.rules {
		if phaseproxy.MatchHostOnly(rule.Host, name, port) {
			return true, rule.Protocol
		}
	}
	return false, ""
}

// capturedName reports whether a name belongs to a Connection on any port.
func (r *Router) capturedName(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if strings.EqualFold(name, ControlHost) {
		return true
	}
	for _, rule := range r.rules {
		port := rule.Host.Port
		if port == 0 {
			port = 443
		}
		if phaseproxy.MatchHostOnly(rule.Host, name, port) {
			return true
		}
	}
	return false
}

// AnswerDNS answers for Connection hosts with a tunnel address, and asks the network's
// own servers about everything else that reaches it. A model host captured by name
// gets a tunnel address too.
func (r *Router) AnswerDNS(query []byte) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil
	}
	question, err := parser.Question()
	if err != nil {
		return nil
	}
	name := strings.TrimSuffix(strings.ToLower(question.Name.String()), ".")
	if !r.capturedName(name) && !r.readByName(name) {
		return r.Upstream.Forward(query)
	}
	reply := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: header.ID, Response: true, RecursionDesired: header.RecursionDesired, RecursionAvailable: true},
		Questions: []dnsmessage.Question{question},
	}
	// Other record types get an empty answer, which keeps a program from learning a
	// real address through AAAA or HTTPS records.
	if question.Type == dnsmessage.TypeA && question.Class == dnsmessage.ClassINET {
		reply.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 10},
			Body:   &dnsmessage.AResource{A: r.names.address(name).As4()},
		}}
	}
	packed, err := reply.Pack()
	if err != nil {
		return nil
	}
	return packed
}

// Prepare reaches the real destination before the program's connection completes, so
// a refused connection looks refused.
func (r *Router) Prepare(flow Flow) (any, bool) {
	dest := flow.Dest.Addr()
	if dest == ProbeAddress {
		return nil, flow.Dest.Port() == ProbePort
	}
	if TunnelPrefix.Contains(dest) {
		_, known := r.names.name(dest)
		return nil, known
	}
	if r.loops(dest) {
		return nil, false
	}
	upstream, err := r.Upstream.DialContext(context.Background(), "tcp", flow.Dest.String())
	if err != nil {
		r.count("tcp_failed")
		r.noteFailure(flow, err)
		return nil, false
	}
	return upstream, true
}

// noteFailure logs why the engine couldn't reach a destination, at most every few
// seconds. It's the one clue to a machine-wide problem, such as no route out.
func (r *Router) noteFailure(flow Flow, err error) {
	r.mu.Lock()
	quiet := time.Since(r.lastFailure) < 5*time.Second
	if !quiet {
		r.lastFailure = time.Now()
	}
	r.mu.Unlock()
	if !quiet {
		name, index, _ := Physical.Current()
		r.logf("reaching %s failed, leaving by %s (%d): %v", flow.Dest, name, index, err)
	}
}

// HandleTCP routes one connection.
func (r *Router) HandleTCP(client net.Conn, flow Flow) {
	dest := flow.Dest.Addr()
	if dest == ProbeAddress {
		_, _ = io.WriteString(client, ProbeReply)
		return
	}
	if upstream, ok := flow.Prepared.(net.Conn); ok {
		defer upstream.Close()
		r.passThrough(client, upstream, flow)
		return
	}
	name, known := r.names.name(dest)
	if !known {
		return
	}
	port := int(flow.Dest.Port())
	_, protocol := r.captured(name, port)
	switch protocol {
	case "control":
		r.count("control")
		r.serveControl(client, port)
	case "postgres":
		r.count("postgres")
		r.mu.RLock()
		adapter := r.postgresAddress
		r.mu.RUnlock()
		if adapter == "" {
			return
		}
		upstream, err := net.DialTimeout("tcp", adapter, 5*time.Second)
		if err != nil {
			return
		}
		defer upstream.Close()
		relayTCP(client, upstream, &r.Traffic.TCPUp, &r.Traffic.TCPDown)
	default:
		r.byName(client, flow, name, port)
	}
}

// byName handles a flow to one of the tunnel's own addresses, whose name is known
// from the DNS answer that handed the address out.
func (r *Router) byName(client net.Conn, flow Flow, name string, port int) {
	authority := net.JoinHostPort(name, strconv.Itoa(port))
	connection := r.capturedName(name)
	reader, _ := r.reading()
	reads := reader != nil && reader.ReadsHost(name)
	tool := ""
	if reads {
		toProxy := connection
		if port == 443 {
			toProxy, tool = r.handOver(flow, name, connection)
		}
		if !toProxy {
			// A model host, and not its own tool's flow: it leaves from here unread.
			r.relayOut(client, authority)
			return
		}
	}
	// A model host's flow is at the proxy only to be read, and works without it.
	needed := connection || !reads
	if needed {
		r.count("proxy")
	}
	upstream, noted, err := r.connect(authority, tool, needed)
	if err != nil {
		if !needed {
			r.count(unreadBecause(err))
			r.relayOut(client, authority)
		}
		return
	}
	defer upstream.Close()
	if tool != "" && noted {
		r.count("read")
	}
	relayTCP(client, upstream, &r.Traffic.TCPUp, &r.Traffic.TCPDown)
}

// relayOut reaches a named host from here and relays the flow unread. It's for a flow
// that came to a tunnel address, so there was no real address to reach beforehand.
func (r *Router) relayOut(client net.Conn, authority string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	upstream, err := r.Upstream.DialContext(ctx, "tcp", authority)
	cancel()
	if err != nil {
		r.count("tcp_failed")
		return
	}
	defer upstream.Close()
	r.relayUnread(client, upstream, nil)
}

// passThrough relays a flow that came to a real address. The only thing read is the
// name in a TLS hello, to catch a host the proxy should have: a Connection host
// reached by a program with its own DNS or a hard-coded address, which never asks the
// system resolver, and a model host opened by the tool it is read for.
func (r *Router) passThrough(client, upstream net.Conn, flow Flow) {
	var head []byte
	if flow.Dest.Port() == 443 {
		var name string
		name, head = peekClientHello(client)
		captured, protocol := r.captured(name, 443)
		connection := captured && protocol != "postgres" && protocol != "control"
		if toProxy, tool := r.handOver(flow, name, connection); toProxy {
			if connection {
				r.count("proxy_by_tls_name")
			}
			proxied, noted, err := r.connect(net.JoinHostPort(name, "443"), tool, connection)
			if err == nil {
				_ = upstream.Close()
				defer proxied.Close()
				if tool != "" && noted {
					r.count("read")
				}
				if _, err := proxied.Write(head); err != nil {
					return
				}
				relayTCP(client, proxied, &r.Traffic.TCPUp, &r.Traffic.TCPDown)
				return
			}
			if connection {
				// It can't go on without the credential only the proxy holds.
				return
			}
			// A model host needs nothing from the proxy to work. When the proxy can't
			// take the flow, or can't be told whose it is, it goes on unread rather
			// than fail.
			r.count(unreadBecause(err))
		}
	}
	r.relayUnread(client, upstream, head)
}

// relayUnread carries a flow to its destination untouched, sending on first whatever
// was read of it to find its name.
func (r *Router) relayUnread(client, upstream net.Conn, head []byte) {
	r.count("tcp")
	r.Traffic.ActiveTCP.Add(1)
	defer r.Traffic.ActiveTCP.Add(-1)
	if len(head) > 0 {
		if _, err := upstream.Write(head); err != nil {
			return
		}
		r.Traffic.TCPUp.Add(int64(len(head)))
	}
	relayTCP(client, upstream, &r.Traffic.TCPUp, &r.Traffic.TCPDown)
}

// HandleUDP carries one UDP conversation. A Connection host's tunnel address gets no
// answer, so a QUIC program falls back to TCP, where the proxy can see it.
func (r *Router) HandleUDP(client net.Conn, flow Flow) {
	defer client.Close()
	if TunnelPrefix.Contains(flow.Dest.Addr()) || r.loops(flow.Dest.Addr()) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	upstream, err := r.Upstream.DialContext(ctx, "udp", flow.Dest.String())
	cancel()
	if err != nil {
		r.count("udp_failed")
		return
	}
	defer upstream.Close()
	r.count("udp")
	r.Traffic.ActiveUDP.Add(1)
	defer r.Traffic.ActiveUDP.Add(-1)
	idle := 2 * time.Minute
	if flow.Dest.Port() == 53 {
		idle = 30 * time.Second
	}
	relayUDP(client, upstream, idle, &r.Traffic.UDPUp, &r.Traffic.UDPDown)
}

// Echo pings the real destination. A tunnel address gets no answer.
func (r *Router) Echo(dest netip.Addr, sequence uint16, payload []byte) bool {
	if TunnelPrefix.Contains(dest) || r.loops(dest) {
		return false
	}
	return PingOnce(dest, sequence, payload)
}

// RouteFunc reports the address a socket of this process to dest would leave from
// when nothing pins it to an interface: an address of the interface its route goes
// by. unpinnedSource is the one used outside tests.
type RouteFunc func(dest netip.Addr) (source netip.Addr, err error)

// FindRoutesWith replaces how a destination's route is found. Tests use it.
func (r *Router) FindRoutesWith(route RouteFunc) {
	r.mu.Lock()
	r.route = route
	r.mu.Unlock()
}

// loops reports whether reaching dest from here would only bring it back, and counts
// it when so.
//
// Nearly every socket the engine opens is pinned to the physical interface, and can't
// come back. The ranges of another VPN are left to that VPN's own routes. When the
// VPN is down those routes are gone, the range falls under the routes that capture
// everything, and what the engine sends there re-enters the tunnel to be sent again:
// TCP until every place for a connection that is still opening is taken, UDP and
// pings for as long as they are sent. So a destination that is left to its route, and
// whose route leads into the tunnel, is refused.
func (r *Router) loops(dest netip.Addr) bool {
	if !leftToItsRoute(dest) {
		return false
	}
	r.mu.RLock()
	route := r.route
	r.mu.RUnlock()
	// With no route at all there is nothing to come back by.
	source, err := route(dest)
	if err != nil || !ownAddress(source) {
		return false
	}
	r.mu.Lock()
	r.counts["loop_refused"]++
	quiet := time.Since(r.lastLoop) < 5*time.Second
	if !quiet {
		r.lastLoop = time.Now()
	}
	r.mu.Unlock()
	if !quiet {
		r.logf("refused %s: its route leads back into Phase, as it does while the VPN it belongs to is down", dest)
	}
	return true
}

// connect opens a CONNECT tunnel through the proxy, as a program with proxy settings
// would. The proxy's password is presented here on the program's behalf, so behind a
// tunnel the decoy is the only thing a program has to hold.
//
// The proxy is told whose flow it is before the CONNECT is sent: tool is the tool it
// is read for, or "" when it isn't to be read. That is done for every CONNECT sent
// from here, because one the proxy knows nothing about is taken for a program that
// was given the proxy through its environment, for which any model host is read.
//
// When the proxy can't keep what it was told, a flow that is only there to be read
// isn't handed over, and the error is errNotNoted. A flow that needs the proxy, for
// a Connection's credential, still goes, with noted false: the proxy takes it as the
// tunnel's, from no known tool, and reads nothing of it.
func (r *Router) connect(authority, tool string, needed bool) (proxied net.Conn, noted bool, err error) {
	r.mu.RLock()
	address, auth, reader := r.proxyAddress, r.proxyAuth, r.reader
	r.mu.RUnlock()
	if address == "" {
		return nil, false, fmt.Errorf("the proxy isn't ready")
	}
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, false, err
	}
	closed := func() {}
	if reader != nil {
		forget, noteErr := reader.NoteFlow(conn.LocalAddr().String(), tool)
		if forget != nil {
			closed = forget
		}
		noted = noteErr == nil
		if !noted && !needed {
			_ = conn.Close()
			closed()
			return nil, false, errNotNoted
		}
		if !noted {
			r.count("proxy_not_noted")
		}
	}
	fail := func(err error) (net.Conn, bool, error) {
		_ = conn.Close()
		closed()
		return nil, false, err
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", authority, authority, auth); err != nil {
		return fail(err)
	}
	buffered := bufio.NewReader(conn)
	response, err := http.ReadResponse(buffered, nil)
	if err != nil {
		return fail(err)
	}
	if response.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("the proxy answered %s", response.Status))
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, reader: buffered, closed: closed}, noted, nil
}

// serveControl makes http://phase.invalid work with no proxy settings. port is the
// one the program connected to.
//
// It answers only for its own name. The proxy's password is presented here on the
// program's behalf, and a browser lets a page read whatever its own origin answers:
// a page whose name was pointed at this address would otherwise read a Connection's
// environment as if it were the page's own.
func (r *Router) serveControl(client net.Conn, port int) {
	r.mu.RLock()
	proxyURL := r.proxyURL
	r.mu.RUnlock()
	if proxyURL == nil {
		return
	}
	// The proxy's address carries its password, which the transport presents.
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	forward := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.Out.URL.Scheme = "http"
			request.Out.URL.Host = ControlHost
			request.Out.Host = ControlHost
		},
	}
	listener := newSingleConnListener(client)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if !controlAuthority(request.Host, port) {
				r.count("control_refused")
				http.Error(w, "This address answers only as "+ControlHost+".", http.StatusForbidden)
				return
			}
			forward.ServeHTTP(w, request)
		}),
		ReadHeaderTimeout: 30 * time.Second,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				listener.Close()
			}
		},
	}
	_ = server.Serve(listener)
	<-listener.closed
}

// controlAuthority reports whether a request names the control host itself: the name
// alone, or the name with the port the program connected to.
func controlAuthority(authority string, port int) bool {
	name := authority
	if host, named, err := net.SplitHostPort(authority); err == nil {
		if named != strconv.Itoa(port) {
			return false
		}
		name = host
	}
	return strings.EqualFold(strings.TrimSuffix(name, "."), ControlHost)
}

// bufferedConn keeps bytes the CONNECT reader already buffered, and says when the
// connection to the proxy has closed.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
	closed func()
	once   sync.Once
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *bufferedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.closed)
	return err
}

func (c *bufferedConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

// singleConnListener serves exactly one connection.
type singleConnListener struct {
	conn   chan net.Conn
	addr   net.Addr
	once   sync.Once
	closed chan struct{}
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	listener := &singleConnListener{conn: make(chan net.Conn, 1), addr: conn.LocalAddr(), closed: make(chan struct{})}
	listener.conn <- conn
	return listener
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conn:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.addr }

// nameTable hands out tunnel addresses to Connection hosts, reusing the oldest once
// the pool runs out.
type nameTable struct {
	mu     sync.Mutex
	pool   netip.Prefix
	byName map[string]netip.Addr
	byAddr map[netip.Addr]string
	next   netip.Addr
}

func newNameTable(pool netip.Prefix) nameTable {
	return nameTable{pool: pool, byName: map[string]netip.Addr{}, byAddr: map[netip.Addr]string{}, next: pool.Addr().Next()}
}

func (t *nameTable) address(name string) netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	if addr, ok := t.byName[name]; ok {
		return addr
	}
	addr := t.next
	t.next = addr.Next()
	if !t.pool.Contains(t.next) || t.next == lastAddress(t.pool) {
		t.next = t.pool.Addr().Next()
	}
	if old, ok := t.byAddr[addr]; ok {
		delete(t.byName, old)
	}
	t.byName[name] = addr
	t.byAddr[addr] = name
	return addr
}

func (t *nameTable) name(addr netip.Addr) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	name, ok := t.byAddr[addr]
	return name, ok
}

func lastAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr()
	for next := addr.Next(); prefix.Contains(next); next = next.Next() {
		addr = next
	}
	return addr
}
