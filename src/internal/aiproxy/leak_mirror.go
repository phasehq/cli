package aiproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/tlsmirror"
)

// Some model services accept only their own client's TLS: a request re-sent
// over Go's TLS is refused. For a host the table flags MirrorHello the proxy
// re-sends inspected requests over connections that open with a copy of the
// ClientHello the client itself sent (package tlsmirror).
//
// A client that holds a session with the service offers to resume it. That
// offer is never copied: the session is the client's, not the proxy's. The
// proxy copies the hello that client sends when it has no session instead,
// and answers the client's own hello with a full handshake, which is what any
// server does that does not take a ticket. Without that, one connection that
// went through unread would leave the client with the service's ticket, and
// every later connection would offer it and go through unread too.
//
// It has to decide before it terminates the client's TLS, a technique known
// as peek and splice: read the client's hello, open the upstream connection
// with the copy, and only then answer the hello with the proxy's certificate.
// Until that answer the client's TLS has seen nothing of the proxy, so
// whenever the copy cannot be made or the service does not take it, the
// client's connection is handed to the service as it is, unread.
//
// This is for a host no Connection covers. A Connection's own host is always
// terminated: its requests carry a decoy that only the proxy can exchange, so
// there is nothing to gain from handing its tunnel over.

const (
	// mirrorHelloTimeout is how long a client may take to send its hello once
	// its CONNECT is answered. A TLS client sends it at once, so the wait is
	// short; a client that is still silent after it is handed to the service
	// unread, as one that sends something else is.
	mirrorHelloTimeout = 5 * time.Second
	// mirrorHandshakeTimeout bounds the proxy's handshake with the service,
	// as net/http bounds the handshakes of the proxy's usual transport.
	mirrorHandshakeTimeout = 10 * time.Second
	mirrorIdleTimeout      = 90 * time.Second
)

var (
	// errMirrorNotHTTP1 is a service that chose a protocol the tunnel cannot
	// carry: the proxy reads and re-sends HTTP/1.1 only.
	errMirrorNotHTTP1 = errors.New("the service chose a protocol other than HTTP/1.1")
	// errMirrorUnreachable is a service no connection could be opened to.
	errMirrorUnreachable = errors.New("the service cannot be reached")
)

// mirrorTunnel is the upstream side of one client connection to such a host.
// Every connection it opens starts with a copy of the hello that client
// opened its tunnel with, or of the one it sends with no session to resume;
// it never opens one any other way.
type mirrorTunnel struct {
	proxy   *httpProxy
	host    string
	address string
	// hello is the hello that is copied. It never offers a session.
	hello []byte
	roots *x509.CertPool
	// transport sends the tunnel's requests over the tunnel's connections.
	transport *http.Transport

	mu sync.Mutex
	// first is the connection opened before the client's TLS was terminated.
	// The first request uses it.
	first net.Conn
}

// replayConn reads recorded bytes before the connection's own.
type replayConn struct {
	net.Conn
	replay *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.replay != nil {
		if c.replay.Len() > 0 {
			return c.replay.Read(p)
		}
		c.replay = nil
	}
	return c.Conn.Read(p)
}

// openMirror reads the hello a client opens its tunnel with and opens the
// upstream connection with a copy of it. It returns the client's connection
// with the hello put back, ready for the proxy to terminate, and the tunnel's
// upstream. When the hello cannot be read or copied, or the service does not
// take the copy, the connection is passed through unread and ok is false.
func (p *httpProxy) openMirror(ctx context.Context, client net.Conn, pending *bufio.Reader, host string, port int, match *leakHostMatch, selection string) (net.Conn, *mirrorTunnel, bool) {
	source := client
	if ahead := pending.Buffered(); ahead > 0 {
		// The server read past the CONNECT request: a client may send its
		// hello without waiting for the answer.
		read, _ := pending.Peek(ahead)
		source = &replayConn{Conn: client, replay: bytes.NewReader(bytes.Clone(read))}
	}
	wait := p.mirrorHelloWait
	if wait <= 0 {
		wait = mirrorHelloTimeout
	}
	_ = client.SetReadDeadline(time.Now().Add(wait))
	hello, err := tlsmirror.ReadHello(source)
	_ = client.SetReadDeadline(time.Time{})
	var tunnel *mirrorTunnel
	reason := ""
	switch {
	case err == nil:
		if tunnel, reason, err = p.dialMirror(ctx, match, host, port, hello); err != nil {
			// No connection to the service could be opened: there is nothing
			// to hand the client to, and its connection ends.
			return nil, nil, false
		}
	case errors.Is(err, tlsmirror.ErrNotHello), errors.Is(err, os.ErrDeadlineExceeded):
		reason = leakReasonHelloUnreadable
	default:
		// The client went away: there is no connection left to hand over.
		return nil, nil, false
	}
	if reason != "" {
		p.passThroughUnread(ctx, source, hello, host, port, match, selection, reason)
		return nil, nil, false
	}
	return &replayConn{Conn: source, replay: bytes.NewReader(hello)}, tunnel, true
}

// maxFreshHellos is how many hellos are kept per tool and host. One client
// program sends one, and a few versions of it may run at once.
const maxFreshHellos = 4

// freshHellos keeps, per tool and host, the hellos clients opened connections
// with when they had no session to offer. What a client pads its hello with
// depends on the hello's length, so the hello it sends without a session
// cannot always be worked out from one that offers a session; the one it did
// send can be used as it was. Hellos hold nothing secret, and none is ever
// written anywhere.
type freshHellos struct {
	mu   sync.Mutex
	seen map[leakStateKey][][]byte
}

func newFreshHellos() *freshHellos {
	return &freshHellos{seen: map[leakStateKey][][]byte{}}
}

func (f *freshHellos) remember(key leakStateKey, hello []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.seen[key]
	for _, known := range kept {
		if tlsmirror.SameShape(known, hello) {
			return
		}
	}
	// A domain entry matches any number of subdomains.
	if kept == nil && len(f.seen) >= maxRememberedHosts {
		clear(f.seen)
	}
	if len(kept) >= maxFreshHellos {
		kept = kept[1:]
	}
	f.seen[key] = append(kept, bytes.Clone(hello))
}

// like returns the hello kept for a tool and host that is the same client's
// as fresh, a hello made from one that offered a session, or nil. The latest
// one kept comes first.
func (f *freshHellos) like(key leakStateKey, fresh []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.seen[key]
	for i := len(kept) - 1; i >= 0; i-- {
		if tlsmirror.SameClient(kept[i], fresh) {
			return kept[i]
		}
	}
	return nil
}

// mirroredHello returns the hello to copy for a client's hello: the hello
// itself, or, when it offers to resume a session, the one that client sends
// with no session. offered says the client's hello offered one. reason is
// set when the connection has to be passed through whatever could be copied.
func (p *httpProxy) mirroredHello(match *leakHostMatch, hello []byte) (mirrored []byte, offered bool, reason string) {
	parsed, err := tlsmirror.ParseHello(hello)
	if err != nil {
		return nil, false, leakReasonHelloNotMirrored
	}
	if !parsed.Resumes {
		return hello, false, ""
	}
	// A client that sends early data expects the server to read it or to
	// skip it. The proxy's TLS does neither and would end the handshake, so
	// such a connection is left to the service.
	if parsed.EarlyData {
		return nil, true, leakReasonHelloResumption
	}
	fresh, err := tlsmirror.Fresh(hello)
	if err != nil {
		return nil, true, leakReasonHelloResumption
	}
	// The hello this client sent when it had no session is its own in every
	// part, padding included. The one made here is used when none was seen.
	if seen := p.leak.mirrored.like(match.key, fresh); seen != nil {
		fresh = seen
	}
	return fresh, true, ""
}

// dialMirror opens a tunnel's first upstream connection. It returns the
// tunnel, or the reason the client's connection is passed through instead, or
// an error when the service cannot be reached at all.
func (p *httpProxy) dialMirror(ctx context.Context, match *leakHostMatch, host string, port int, hello []byte) (*mirrorTunnel, string, error) {
	hello, offered, reason := p.mirroredHello(match, hello)
	if reason != "" {
		return nil, reason, nil
	}
	// A client that offered a session is passed through for that when no
	// exact copy of its hello without one can be sent.
	notCopied := leakReasonHelloNotMirrored
	if offered {
		notCopied = leakReasonHelloResumption
	}
	// Checked before anything is dialled, so a hello that is never copied
	// costs the service no connection.
	if err := tlsmirror.Check(hello, host); err != nil {
		return nil, notCopied, nil
	}
	if !offered {
		// This is the hello the client sends without a session, as it sent it.
		p.leak.mirrored.remember(match.key, hello)
	}
	tunnel := &mirrorTunnel{
		proxy: p, host: host, address: net.JoinHostPort(host, strconv.Itoa(port)), hello: hello, roots: p.unboundRoots(),
	}
	first, err := tunnel.connect(ctx)
	switch {
	case err == nil:
	case errors.Is(err, errMirrorUnreachable):
		return nil, "", err
	case errors.Is(err, errMirrorNotHTTP1):
		return nil, leakReasonUpstreamNotHTTP1, nil
	case errors.Is(err, tlsmirror.ErrNotCopied), errors.Is(err, tlsmirror.ErrResumes), errors.Is(err, tlsmirror.ErrNotHello):
		return nil, notCopied, nil
	default:
		return nil, leakReasonUpstreamHandshake, nil
	}
	tunnel.first = first
	onlyHTTP1 := new(http.Protocols)
	onlyHTTP1.SetHTTP1(true)
	tunnel.transport = &http.Transport{
		// Every connection is one of the tunnel's own, opened with the copy:
		// no proxy from the environment, and nothing that is not TLS.
		Proxy:          nil,
		DialTLSContext: tunnel.dialTLS,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("the tunnel carries TLS only")
		},
		Protocols: onlyHTTP1,
		// A request leaves with the headers it came with and its answer comes
		// back as the service sent it: no Accept-Encoding of the transport's
		// own, and so nothing decompressed on the way back.
		DisableCompression:  true,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     mirrorIdleTimeout,
	}
	return tunnel, "", nil
}

// connect opens one upstream connection with the copy of the client's hello.
// It goes through the proxy's dialer for hosts no Connection covers, and the
// service's certificate is verified against the roots the proxy's own
// upstream TLS trusts, for the host the client asked for.
func (m *mirrorTunnel) connect(ctx context.Context) (net.Conn, error) {
	raw, err := m.proxy.dialUnbound(ctx, m.address)
	if err != nil {
		return nil, errMirrorUnreachable
	}
	handshakeContext, cancel := context.WithTimeout(ctx, mirrorHandshakeTimeout)
	defer cancel()
	conn, protocol, err := tlsmirror.Client(handshakeContext, raw, m.hello, m.host, m.roots)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if protocol != "" && protocol != "http/1.1" {
		_ = conn.Close()
		return nil, errMirrorNotHTTP1
	}
	return conn, nil
}

// dialTLS gives the transport its connections: the one opened before the
// client's TLS was terminated, then, when another is needed, one opened with
// the same copy. A failure is the transport's failure; there is no other way
// to reach the host.
func (m *mirrorTunnel) dialTLS(ctx context.Context, _, address string) (net.Conn, error) {
	if address != m.address {
		return nil, errors.New("the tunnel reaches one host only")
	}
	m.mu.Lock()
	first := m.first
	m.first = nil
	m.mu.Unlock()
	if first != nil {
		if stillOpen(first) {
			return first, nil
		}
		_ = first.Close()
	}
	return m.connect(ctx)
}

func (m *mirrorTunnel) close() {
	m.mu.Lock()
	first := m.first
	m.first = nil
	m.mu.Unlock()
	if first != nil {
		_ = first.Close()
	}
	m.transport.CloseIdleConnections()
}

// stillOpen reports whether the service has kept a connection that has
// carried no request yet. A client may open its tunnel long before it uses
// it, and the transport would not try again on a connection it takes for
// new. The wait is one millisecond: an expired deadline would not look at
// the connection at all.
func stillOpen(conn net.Conn) bool {
	if conn.SetReadDeadline(time.Now().Add(time.Millisecond)) != nil {
		return false
	}
	var one [1]byte
	n, err := conn.Read(one[:])
	return n == 0 && errors.Is(err, os.ErrDeadlineExceeded) && conn.SetReadDeadline(time.Time{}) == nil
}

// passThroughUnread hands a client's connection to the service as the client
// opened it: a new TCP connection, the bytes already read from the client,
// then both directions copied as they come. Nothing on it is read.
func (p *httpProxy) passThroughUnread(ctx context.Context, client net.Conn, read []byte, host string, port int, match *leakHostMatch, selection, reason string) {
	upstream, err := p.dialUnbound(ctx, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return
	}
	defer upstream.Close()
	p.noteUnreadTunnel(host, port, match, reason)
	if _, err := upstream.Write(read); err != nil {
		return
	}
	defer p.watchPassThrough(ctx, client, upstream, host, port, selection)()
	copyBidirectional(client, upstream)
}

// noteUnreadTunnel reports a connection to a host read for leak protection
// that was passed through unread, and why. It says nothing of what the
// connection carried: the proxy did not read it.
func (p *httpProxy) noteUnreadTunnel(host string, port int, match *leakHostMatch, reason string) {
	if p.observe != nil {
		p.observe(leakObservation{host: host, connection: reason})
	}
	if p.events == nil || !p.leak.unread.fresh(match.key, reason) {
		return
	}
	event := newRequestEvent(nil, http.MethodConnect, host, port, "/", "allow", outcomeUnread, reason, 0, 0, "")
	event.EventType = leakEventType
	event.Detail = leakFlowDetail(p.leak.mode, match)
	event.Detail["scope"] = leakScopeConnection
	p.events.Emit(event)
}

// unboundRoots returns the roots the proxy's own TLS trusts for a host no
// Connection covers; nil means the system's.
func (p *httpProxy) unboundRoots() *x509.CertPool {
	transport := p.unboundTransport
	if transport == nil {
		transport = p.transport
	}
	if own, ok := transport.(*http.Transport); ok && own.TLSClientConfig != nil {
		return own.TLSClientConfig.RootCAs
	}
	return nil
}
