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
func Domains(rules []Rule) []string {
	seen := map[string]bool{ControlHost: true}
	for _, rule := range rules {
		value := strings.Trim(strings.ToLower(rule.Host.Value), ".")
		if value != "" && strings.Contains(value, ".") {
			seen[value] = true
		}
	}
	domains := make([]string, 0, len(seen))
	for domain := range seen {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
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
}

// NewRouter starts with no Connections. Until Update, Connection hosts aren't captured.
func NewRouter(upstream *Upstream, logf func(string, ...any)) *Router {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Router{Upstream: upstream, names: newNameTable(namePool), counts: map[string]int{}, logf: logf}
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
// own servers about everything else that reaches it.
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
	if !r.capturedName(name) {
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
		r.serveControl(client)
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
		r.count("proxy")
		upstream, err := r.connect(net.JoinHostPort(name, strconv.Itoa(port)))
		if err != nil {
			return
		}
		defer upstream.Close()
		relayTCP(client, upstream, &r.Traffic.TCPUp, &r.Traffic.TCPDown)
	}
}

// passThrough relays a flow with no Connection. The only thing read is the name in a
// TLS hello, to catch a Connection host reached by a real address: a program with its
// own DNS, or a hard-coded address, never asks the system resolver.
func (r *Router) passThrough(client, upstream net.Conn, flow Flow) {
	var head []byte
	if flow.Dest.Port() == 443 {
		var name string
		name, head = peekClientHello(client)
		if captured, protocol := r.captured(name, 443); captured && protocol != "postgres" && protocol != "control" {
			r.count("proxy_by_tls_name")
			_ = upstream.Close()
			proxied, err := r.connect(net.JoinHostPort(name, "443"))
			if err != nil {
				return
			}
			defer proxied.Close()
			if _, err := proxied.Write(head); err != nil {
				return
			}
			relayTCP(client, proxied, &r.Traffic.TCPUp, &r.Traffic.TCPDown)
			return
		}
	}
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
	if TunnelPrefix.Contains(flow.Dest.Addr()) {
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
	if TunnelPrefix.Contains(dest) {
		return false
	}
	return PingOnce(dest, sequence, payload)
}

// connect opens a CONNECT tunnel through the proxy, as a program with proxy settings
// would. The proxy's password is presented here on the program's behalf, so behind a
// tunnel the decoy is the only thing a program has to hold.
func (r *Router) connect(authority string) (net.Conn, error) {
	r.mu.RLock()
	address, auth := r.proxyAddress, r.proxyAuth
	r.mu.RUnlock()
	if address == "" {
		return nil, fmt.Errorf("the proxy isn't ready")
	}
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", authority, authority, auth); err != nil {
		conn.Close()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("the proxy answered %s", response.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

// serveControl makes http://phase.invalid work with no proxy settings.
func (r *Router) serveControl(client net.Conn) {
	r.mu.RLock()
	proxyURL := r.proxyURL
	r.mu.RUnlock()
	if proxyURL == nil {
		return
	}
	// The proxy's address carries its password, which the transport presents.
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	listener := newSingleConnListener(client)
	server := &http.Server{
		Handler: &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(request *httputil.ProxyRequest) {
				request.Out.URL.Scheme = "http"
				request.Out.URL.Host = ControlHost
				request.Out.Host = ControlHost
			},
		},
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

// bufferedConn keeps bytes the CONNECT reader already buffered.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

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
