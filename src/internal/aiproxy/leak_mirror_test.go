package aiproxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/internal/tlsmirror"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// The tests of hosts that accept only their own client's TLS. opencode.ai is
// the one such host in the table; in the rig every name reaches the fake
// provider, which keeps what each connection sent it before any TLS.

const mirrorHost = "opencode.ai"

// wireConn keeps the first bytes a connection to the fake provider carried,
// and whether its other end has closed it.
type wireConn struct {
	net.Conn
	mu     sync.Mutex
	seen   []byte
	closed atomic.Bool
}

func (c *wireConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	if room := 1<<16 - len(c.seen); room > 0 {
		c.seen = append(c.seen, p[:min(n, room)]...)
	}
	c.mu.Unlock()
	// The provider's server interrupts its own reads with a deadline; that
	// is not the other end closing.
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		c.closed.Store(true)
	}
	return n, err
}

// Close is the provider letting go of the connection, which within a test it
// does only once the other end has: a TLS end that says goodbye is not read
// from again.
func (c *wireConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// hello returns the first TLS record the connection carried.
func (c *wireConn) hello(t *testing.T) []byte {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	record, ok := firstRecord(c.seen)
	if !ok {
		t.Fatal("the connection did not start with a TLS record")
	}
	return bytes.Clone(record)
}

type wireKey struct{}

// keepWire lets the provider's handler find the connection a request came on.
func keepWire(ctx context.Context, conn net.Conn) context.Context {
	if secured, ok := conn.(*tls.Conn); ok {
		if wire, ok := secured.NetConn().(*wireConn); ok {
			return context.WithValue(ctx, wireKey{}, wire)
		}
	}
	return ctx
}

type wireLog struct {
	mu    sync.Mutex
	conns []*wireConn
}

type wireListener struct {
	net.Listener
	log *wireLog
}

func (l *wireListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wire := &wireConn{Conn: conn}
	l.log.mu.Lock()
	l.log.conns = append(l.log.conns, wire)
	l.log.mu.Unlock()
	return wire, nil
}

func (l *wireLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.conns)
}

// closed waits for the other end of connection index to close it.
func (l *wireLog) closed(t *testing.T, index int) {
	t.Helper()
	l.mu.Lock()
	conn := l.conns[index]
	l.mu.Unlock()
	for deadline := time.Now().Add(3 * time.Second); !conn.closed.Load(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("connection %d to the provider was left open", index)
		}
	}
}

// seen waits for connection index to have carried want bytes and returns
// what it carried.
func (l *wireLog) seen(t *testing.T, index, want int) []byte {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var seen []byte
		l.mu.Lock()
		if index < len(l.conns) {
			conn := l.conns[index]
			conn.mu.Lock()
			seen = bytes.Clone(conn.seen)
			conn.mu.Unlock()
		}
		l.mu.Unlock()
		if len(seen) >= want {
			return seen
		}
		if time.Now().After(deadline) {
			t.Fatalf("connection %d to the provider carried %d bytes, want %d", index, len(seen), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func firstRecord(raw []byte) ([]byte, bool) {
	if len(raw) < 5 {
		return nil, false
	}
	end := 5 + int(binary.BigEndian.Uint16(raw[3:]))
	if len(raw) < end {
		return nil, false
	}
	return raw[:end], true
}

// hello returns the first TLS record connection index sent the provider.
func (l *wireLog) hello(t *testing.T, index int) []byte {
	t.Helper()
	header := l.seen(t, index, 5)
	record, ok := firstRecord(l.seen(t, index, 5+int(binary.BigEndian.Uint16(header[3:]))))
	if !ok {
		t.Fatalf("connection %d to the provider did not start with a TLS record", index)
	}
	return record
}

// tapConn keeps what a client wrote to the proxy: its CONNECT, then its TLS.
type tapConn struct {
	net.Conn
	mu   sync.Mutex
	sent []byte
}

func (c *tapConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if room := 1<<16 - len(c.sent); room > 0 {
		c.sent = append(c.sent, p[:min(len(p), room)]...)
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}

// hello returns the client's own first TLS record: what it wrote after the
// blank line that ended its CONNECT.
func (c *tapConn) hello(t *testing.T) []byte {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	_, after, found := bytes.Cut(c.sent, []byte("\r\n\r\n"))
	record, ok := firstRecord(after)
	if !found || !ok {
		t.Fatal("the client sent no TLS record after its CONNECT")
	}
	return bytes.Clone(record)
}

type tapLog struct {
	mu    sync.Mutex
	conns []*tapConn
}

func (l *tapLog) dial(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	tap := &tapConn{Conn: conn}
	l.mu.Lock()
	l.conns = append(l.conns, tap)
	l.mu.Unlock()
	return tap, nil
}

func (l *tapLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.conns)
}

func (l *tapLog) hello(t *testing.T, index int) []byte {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if index >= len(l.conns) {
		t.Fatalf("the client opened %d connections, want more than %d", len(l.conns), index)
	}
	return l.conns[index].hello(t)
}

// distinctiveTLS is a client whose hello cannot be mistaken for the one Go
// sends by default: its own cipher suites, groups and protocol.
func distinctiveTLS(roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		RootCAs: roots, MinVersion: tls.VersionTLS12,
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		CurvePreferences: []tls.CurveID{tls.CurveP384, tls.X25519},
		NextProtos:       []string{"http/1.1"},
	}
}

// tappedClient is an HTTP client through the proxy with TLS of its own. The
// log holds what each of its connections wrote.
func (r *leakRig) tappedClient(config *tls.Config) (*http.Client, *tapLog) {
	taps := &tapLog{}
	transport := &http.Transport{Proxy: http.ProxyURL(r.proxyURL), TLSClientConfig: config, DialContext: taps.dial}
	r.t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, taps
}

// connect opens a tunnel to host through the proxy and returns the client's
// side of it, with nothing sent on it yet.
func (r *leakRig) connect(t *testing.T, host string) *tapConn {
	t.Helper()
	raw, err := net.Dial("tcp", r.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	tap := &tapConn{Conn: raw}
	password, _ := r.proxyURL.User.Password()
	authorization := base64.StdEncoding.EncodeToString([]byte(r.proxyURL.User.Username() + ":" + password))
	_, _ = fmt.Fprintf(tap, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: Basic %s\r\n\r\n", host, host, authorization)
	response, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s: %v %v", host, response, err)
	}
	return tap
}

// connectTLS opens a tunnel and completes the client's TLS over it.
func (r *leakRig) connectTLS(t *testing.T, host string, config *tls.Config) (*tls.Conn, *tapConn) {
	t.Helper()
	tap := r.connect(t, host)
	config = config.Clone()
	if config.ServerName == "" {
		config.ServerName = host
	}
	conn := tls.Client(tap, config)
	if err := conn.Handshake(); err != nil {
		t.Fatalf("the client's TLS with %s: %v", host, err)
	}
	return conn, tap
}

// exchange sends one HTTP/1.1 request on an open connection and reads the
// answer.
func exchange(t *testing.T, conn net.Conn, reader *bufio.Reader, request string) (*http.Response, []byte) {
	t.Helper()
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return response, body
}

func chatBody(content string) []byte {
	return []byte(`{"model":"big-pickle","messages":[{"role":"user","content":"` + content + `"}]}`)
}

func chatRequest(host string, body []byte) string {
	return fmt.Sprintf("POST /zen/v1/chat/completions HTTP/1.1\r\nHost: %s\r\nUser-Agent: opencode/2.0.25\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", host, len(body), body)
}

func postChat(t *testing.T, client *http.Client, host string, body []byte) (*http.Response, []byte) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, "https://"+host+"/zen/v1/chat/completions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	return response, answer
}

// sameHello fails unless upstream is a copy of the client's hello: the same
// offer in the same order, and not the client's own bytes sent again.
func sameHello(t *testing.T, client, upstream []byte) {
	t.Helper()
	if !tlsmirror.SameShape(client, upstream) {
		t.Fatal("the provider did not receive a copy of the client's hello")
	}
	if bytes.Equal(client, upstream) {
		t.Fatal("the provider received the client's own bytes, not a copy made for this connection")
	}
	want, err := tlsmirror.ParseHello(client)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tlsmirror.ParseHello(upstream)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.CipherSuites, want.CipherSuites) || !reflect.DeepEqual(got.Extensions, want.Extensions) ||
		!reflect.DeepEqual(got.Groups, want.Groups) || !reflect.DeepEqual(got.ALPN, want.ALPN) ||
		!reflect.DeepEqual(got.Versions, want.Versions) || !reflect.DeepEqual(got.KeyShareGroups, want.KeyShareGroups) ||
		got.ServerName != want.ServerName {
		t.Fatalf("the provider received %+v, the client sent %+v", got, want)
	}
}

// goHello returns the hello the proxy's own upstream TLS sends for host: what
// the provider sees on a direct connection made with the configuration of the
// proxy's transport.
func (r *leakRig) goHello(t *testing.T, host string) []byte {
	t.Helper()
	index := r.wire.count()
	raw, err := net.Dial("tcp", r.provider.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	config := r.proxy.transport.(*http.Transport).TLSClientConfig.Clone()
	config.ServerName = host
	if err := tls.Client(raw, config).Handshake(); err != nil {
		t.Fatal(err)
	}
	return r.wire.hello(t, index)
}

// unreadTunnels returns the events for whole connections passed through
// unread.
func (r *leakRig) unreadTunnels() []agentapi.Event {
	var events []agentapi.Event
	for _, event := range r.leakEventsNow() {
		if event.Outcome == outcomeUnread && event.Method == http.MethodConnect {
			events = append(events, event)
		}
	}
	return events
}

// passedThroughOnce fails unless exactly one event says a connection to the
// mirror host was passed through unread for reason.
func (r *leakRig) passedThroughOnce(t *testing.T, reason string) {
	t.Helper()
	events := r.unreadTunnels()
	if len(events) != 1 {
		t.Fatalf("%d events for connections passed through unread, want one: %+v", len(events), events)
	}
	event := events[0]
	// It says whose connection it was and that the whole of it went unread,
	// and nothing else: the proxy read nothing it could grade or count.
	if event.Reason != reason || event.Host != mirrorHost || event.Port != 443 || event.Path != "/" || event.ProxyDecision != "allow" ||
		event.EventType != leakEventType || event.Detail["harness"] != "opencode" || event.Detail["mode"] != leakModeCensor ||
		event.Detail["capture"] != CaptureProxy || event.Detail["scope"] != leakScopeConnection || len(event.Detail) != 4 {
		t.Fatalf("the event for a connection passed through for %s: %+v", reason, event)
	}
	if durableAuditEvent(event) {
		t.Fatal("an unread connection is spooled durably")
	}
}

func TestMirrorHostReceivesACopyOfTheClientsHello(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client, taps := rig.tappedClient(distinctiveTLS(rig.phaseRoots))

	body := chatBody("the key is " + leakSecretOne)
	response, answer := postChat(t, client, mirrorHost, body)
	if response.StatusCode != http.StatusOK || string(answer) != `{"type":"message","content":[]}` {
		t.Fatalf("the provider's answer did not come back: %d %s", response.StatusCode, answer)
	}
	received := rig.lastReceived()
	if want := bytes.Replace(body, []byte(leakSecretOne), []byte("ph:secret:stripe"), 1); received.host != mirrorHost || !bytes.Equal(received.body, want) {
		t.Fatalf("the provider received %s", received.body)
	}
	// One upstream connection, opened with a copy of what the client sent,
	// and the request came on it.
	if rig.wire.count() != 1 {
		t.Fatalf("the proxy opened %d connections to the provider, want one", rig.wire.count())
	}
	clientHello := taps.hello(t, 0)
	sameHello(t, clientHello, rig.wire.hello(t, 0))
	sameHello(t, clientHello, received.wire.hello(t))
	if tlsmirror.SameShape(clientHello, rig.goHello(t, mirrorHost)) {
		t.Fatal("the client's hello is no different from Go's: the test shows nothing")
	}
	// The next request of the client's connection goes out on the same one.
	before := rig.wire.count()
	if response, _ := postChat(t, client, mirrorHost, chatBody("nothing to hide")); response.StatusCode != http.StatusOK {
		t.Fatalf("second request: %d", response.StatusCode)
	}
	if rig.wire.count() != before || taps.count() != 1 {
		t.Fatalf("a second request opened a connection: %d to the provider, %d from the client", rig.wire.count()-before, taps.count())
	}
	events := rig.leakEventsNow()
	if len(events) != 1 || events[0].Outcome != outcomeCensored || events[0].Host != mirrorHost || events[0].Path != "/zen/v1/chat/completions" ||
		events[0].Detail["harness"] != "opencode" || events[0].Detail["placeholders"] != "ph:secret:stripe" {
		t.Fatalf("events: %+v", events)
	}

	// A host whose hello is not copied still gets Go's own, whatever the
	// client sent.
	index := rig.wire.count()
	if response, _ := postChat(t, client, "api.anthropic.com", body); response.StatusCode != http.StatusOK {
		t.Fatalf("an inspected host: %d", response.StatusCode)
	}
	proxyHello := rig.wire.hello(t, index)
	if tlsmirror.SameShape(taps.hello(t, 1), proxyHello) {
		t.Fatal("a host that is not flagged received a copy of the client's hello")
	}
	if !tlsmirror.SameShape(rig.goHello(t, "api.anthropic.com"), proxyHello) {
		t.Fatal("a host that is not flagged did not receive Go's own hello")
	}
}

// The three modes act on such a host as on any inspected host.
func TestMirrorHostFollowsTheMode(t *testing.T) {
	body := chatBody("the key is " + leakSecretOne)
	observe := newLeakRig(t, leakModeObserve)
	registerLeakValues(t, observe.guard, map[string]string{"stripe": leakSecretOne})
	client, taps := observe.tappedClient(distinctiveTLS(observe.phaseRoots))
	if response, _ := postChat(t, client, mirrorHost, body); response.StatusCode != http.StatusOK {
		t.Fatalf("observe: %d", response.StatusCode)
	}
	if !bytes.Equal(observe.lastReceived().body, body) {
		t.Fatal("observe mode changed the body")
	}
	sameHello(t, taps.hello(t, 0), observe.wire.hello(t, 0))
	if events := observe.leakEventsNow(); len(events) != 1 || events[0].Outcome != outcomeObserved {
		t.Fatalf("observe events: %+v", events)
	}

	// Off leaves the CONNECT a raw tunnel: the client's own TLS, end to end.
	off := newLeakRig(t, leakModeOff)
	registerLeakValues(t, off.guard, map[string]string{"stripe": leakSecretOne})
	rawTunnelHandshake(t, off, mirrorHost)
	index := off.wire.count()
	client, taps = off.tappedClient(distinctiveTLS(off.providerRoots))
	if response, _ := postChat(t, client, mirrorHost, body); response.StatusCode != http.StatusOK {
		t.Fatalf("off: %d", response.StatusCode)
	}
	if !bytes.Equal(off.lastReceived().body, body) {
		t.Fatal("off mode changed the body")
	}
	if sent := taps.hello(t, 0); off.wire.count() != index+1 || !bytes.Equal(off.wire.hello(t, index), sent) {
		t.Fatal("off mode did not pass the client's own hello to the provider on one connection")
	}
	if events := off.leakEventsNow(); len(events) != 0 {
		t.Fatalf("off mode reported: %+v", events)
	}

	// In lockdown a host no Connection covers stays blocked.
	locked := newLeakRig(t, leakModeCensor)
	locked.proxy.lockdown = true
	if _, err := locked.client(locked.phaseRoots).Post("https://"+mirrorHost+"/zen/v1/chat/completions", "application/json", bytes.NewReader(body)); err == nil {
		t.Fatal("lockdown let a connection through")
	}
	if locked.wire.count() != 0 {
		t.Fatal("lockdown reached the provider")
	}
}

// Bytes that are not a TLS hello are passed on as they came, and the
// service's answer comes back.
func TestMirrorPassesThroughWhatIsNotAHello(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	// A service that is no TLS server: it keeps what it is sent and greets.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	arrived := make(chan []byte, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.WriteString(conn, "220 ready\r\n")
				sent, _ := io.ReadAll(conn)
				arrived <- sent
			}()
		}
	}()
	rig.proxy.unboundDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}
	garbage := []byte("EHLO not-a-tls-client.example\r\nMAIL FROM:<nobody@example>\r\n")
	for attempt := 0; attempt < 2; attempt++ {
		tap := rig.connect(t, mirrorHost)
		if _, err := tap.Write(garbage); err != nil {
			t.Fatal(err)
		}
		greeting := make([]byte, len("220 ready\r\n"))
		if _, err := io.ReadFull(tap, greeting); err != nil || string(greeting) != "220 ready\r\n" {
			t.Fatalf("the service's answer did not come back: %q %v", greeting, err)
		}
		_ = tap.Close()
		select {
		case sent := <-arrived:
			if !bytes.Equal(sent, garbage) {
				t.Fatalf("the service received %q", sent)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("the service received nothing")
		}
	}
	// Two connections for one reason are reported once.
	rig.passedThroughOnce(t, leakReasonHelloUnreadable)
	if rig.guard.handshakes.bypassed(hostKey(mirrorHost)) {
		t.Fatal("bytes that are not TLS opened a pass-through window")
	}
}

// A client that sends nothing in time is handed over too; one that goes away
// is not reported.
func TestMirrorPassesThroughAClientThatSendsNoHelloInTime(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.mirrorHelloWait = 60 * time.Millisecond
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})

	gone := rig.connect(t, mirrorHost)
	_ = gone.Close()
	time.Sleep(150 * time.Millisecond)
	if rig.wire.count() != 0 || len(rig.unreadTunnels()) != 0 {
		t.Fatalf("a client that went away reached the provider or was reported: %d connections", rig.wire.count())
	}

	tap := rig.connect(t, mirrorHost)
	time.Sleep(250 * time.Millisecond)
	config := distinctiveTLS(rig.providerRoots)
	config.ServerName = mirrorHost
	conn := tls.Client(tap, config)
	if err := conn.Handshake(); err != nil {
		t.Fatalf("the late client did not reach the provider with its own TLS: %v", err)
	}
	if !bytes.Equal(rig.wire.hello(t, 0), tap.hello(t)) {
		t.Fatal("the provider did not receive the client's own hello")
	}
	body := chatBody("the key is " + leakSecretOne)
	if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(mirrorHost, body)); response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	if !bytes.Equal(rig.lastReceived().body, body) {
		t.Fatal("a connection passed through unread was changed")
	}
	rig.passedThroughOnce(t, leakReasonHelloUnreadable)
}

// directSession leaves a client holding a session of the service's own: one
// connection straight to the fake provider, as a client makes when a
// connection of its went through unread. It returns the hello the client
// opened that connection with, its hello when it has no session.
func (r *leakRig) directSession(t *testing.T, config *tls.Config) []byte {
	t.Helper()
	index := r.wire.count()
	raw, err := net.Dial("tcp", r.provider.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	direct := tls.Client(raw, config)
	// A ticket, when one is sent, arrives with the first answer.
	if response, _ := exchange(t, direct, bufio.NewReader(direct), "GET /zen/v1/models HTTP/1.1\r\nHost: "+config.ServerName+"\r\n\r\n"); response.StatusCode != http.StatusOK {
		t.Fatalf("the direct connection: %d", response.StatusCode)
	}
	_ = direct.Close()
	return r.wire.hello(t, index)
}

// A client that offers to resume a session is read like any other. The
// service is sent a copy of the hello that client opens a connection with
// when it has no session, and the client's own hello is answered with a full
// handshake. Before, one connection that went through unread left the client
// with the service's ticket, and every later connection went through unread.
func TestMirrorReadsAClientThatOffersToResumeASession(t *testing.T) {
	for name, version := range map[string]uint16{"a TLS 1.3 pre-shared key": tls.VersionTLS13, "a TLS 1.2 session ticket": tls.VersionTLS12} {
		t.Run(name, func(t *testing.T) {
			rig := newLeakRig(t, leakModeCensor)
			registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
			config := distinctiveTLS(rig.bothRoots)
			config.ServerName = mirrorHost
			config.MaxVersion = version
			config.ClientSessionCache = tls.NewLRUClientSessionCache(8)
			first := rig.directSession(t, config)
			if hello, err := tlsmirror.ParseHello(first); err != nil || hello.Resumes {
				t.Fatalf("the client's first hello offers a session: %+v %v", hello, err)
			}

			body := chatBody("the key is " + leakSecretOne)
			for attempt := 0; attempt < 2; attempt++ {
				index := rig.wire.count()
				conn, tap := rig.connectTLS(t, mirrorHost, config)
				sent := tap.hello(t)
				if hello, err := tlsmirror.ParseHello(sent); err != nil || !hello.Resumes {
					t.Fatalf("connection %d: the client's hello offers no session: %+v %v", attempt, hello, err)
				}
				// The client fell back to a full handshake, with the proxy.
				state := conn.ConnectionState()
				if state.DidResume || state.Version != version {
					t.Fatalf("connection %d: resumed = %v, TLS %04x", attempt, state.DidResume, state.Version)
				}
				if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: rig.phaseRoots, DNSName: mirrorHost}); err != nil {
					t.Fatalf("connection %d: the client was not answered by the proxy: %v", attempt, err)
				}
				if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(mirrorHost, body)); response.StatusCode != http.StatusOK {
					t.Fatalf("connection %d: status %d", attempt, response.StatusCode)
				}
				// The request was read.
				received := rig.lastReceived()
				if want := bytes.Replace(body, []byte(leakSecretOne), []byte("ph:secret:stripe"), 1); !bytes.Equal(received.body, want) {
					t.Fatalf("connection %d: the provider received %s", attempt, received.body)
				}
				// One connection to the service, opened with the client's hello
				// as it is when the client has no session: no offer in it, and
				// the same extensions in the same order as the client's first.
				if rig.wire.count() != index+1 {
					t.Fatalf("connection %d: %d connections to the provider, want one", attempt, rig.wire.count()-index)
				}
				upstream := rig.wire.hello(t, index)
				got, err := tlsmirror.ParseHello(upstream)
				if err != nil {
					t.Fatal(err)
				}
				want, _ := tlsmirror.ParseHello(first)
				if got.Resumes || !reflect.DeepEqual(got.Extensions, want.Extensions) {
					t.Fatalf("connection %d: the provider was sent extensions %v (offers a session: %v), the client's first hello had %v", attempt, got.Extensions, got.Resumes, want.Extensions)
				}
				if !tlsmirror.SameShape(first, upstream) || tlsmirror.SameShape(sent, upstream) {
					t.Fatalf("connection %d: the provider was not sent the client's hello as it is without a session", attempt)
				}
				sameHello(t, first, received.wire.hello(t))
				_ = conn.Close()
			}
			if events := rig.unreadTunnels(); len(events) != 0 {
				t.Fatalf("a connection that offered a session was passed through unread: %+v", events)
			}
			if events := rig.leakEventsNow(); len(events) != 1 || events[0].Outcome != outcomeCensored {
				t.Fatalf("events: %+v", events)
			}
		})
	}
}

// When a client that was seen without a session later offers one, the hello
// it sent then is what is copied: its own hello in every part, the padding a
// client adds by its hello's length included, which cannot be worked out
// from a hello that offers a session.
func TestMirrorCopiesTheHelloAClientSentWithoutASession(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	config := distinctiveTLS(rig.bothRoots)
	config.ServerName = mirrorHost
	config.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	body := chatBody("the key is " + leakSecretOne)
	key := hostKey(mirrorHost)

	// The client's first connection is read, and offers no session.
	conn, tap := rig.connectTLS(t, mirrorHost, config)
	if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(mirrorHost, body)); response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	_ = conn.Close()
	first := tap.hello(t)
	if kept := rig.guard.mirrored.like(key, first); !bytes.Equal(kept, first) {
		t.Fatal("the hello a client sent without a session was not kept")
	}
	if rig.guard.mirrored.like(leakStateKey{tool: "codex", host: mirrorHost}, first) != nil || rig.guard.mirrored.like(hostKey("api.anthropic.com"), first) != nil {
		t.Fatal("a hello kept for one tool and host answers for another")
	}

	// Stand in for a client that pads by length (Go's does not): what is kept
	// for it is the hello it sent, padded to 512 bytes as such a client pads.
	message := len(first) - 5
	if message <= 0xff || message >= 0x200-5 {
		t.Fatalf("the client's hello is %d bytes, not a length a client pads", message)
	}
	padded := withHelloExtension(t, first, 21, make([]byte, 0x200-message-4))
	rig.guard.mirrored.mu.Lock()
	rig.guard.mirrored.seen[key] = [][]byte{padded}
	rig.guard.mirrored.mu.Unlock()

	// A connection that went straight to the service leaves the client with
	// a session, which it offers on its next connection.
	rig.directSession(t, config)
	index := rig.wire.count()
	conn, tap = rig.connectTLS(t, mirrorHost, config)
	sent := tap.hello(t)
	if hello, err := tlsmirror.ParseHello(sent); err != nil || !hello.Resumes {
		t.Fatalf("the client's hello offers no session: %+v %v", hello, err)
	}
	if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(mirrorHost, body)); response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	if bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) {
		t.Fatal("the request was not read")
	}
	upstream := rig.wire.hello(t, index)
	got, err := tlsmirror.ParseHello(upstream)
	if err != nil {
		t.Fatal(err)
	}
	if got.Resumes || got.Extensions[len(got.Extensions)-1] != 21 || len(upstream)-5 != 0x200 || !tlsmirror.SameShape(padded, upstream) {
		t.Fatalf("the provider was sent %d bytes with extensions %v, not the hello the client sent without a session", len(upstream)-5, got.Extensions)
	}
	if events := rig.unreadTunnels(); len(events) != 0 {
		t.Fatalf("a connection was passed through unread: %+v", events)
	}

	// A hello that offered a session is never kept, and the hellos kept for
	// a tool and host are few: the oldest goes first.
	rig.guard.mirrored.mu.Lock()
	kept := len(rig.guard.mirrored.seen[key])
	rig.guard.mirrored.mu.Unlock()
	if kept != 1 {
		t.Fatalf("%d hellos are kept after a connection that offered a session", kept)
	}
	memory := newFreshHellos()
	var shapes [][]byte
	for i := 0; i < maxFreshHellos+2; i++ {
		shapes = append(shapes, withHelloExtension(t, first, 0xfe00+uint16(i), nil))
		memory.remember(key, shapes[i])
		memory.remember(key, shapes[i])
	}
	if len(memory.seen[key]) != maxFreshHellos || memory.like(key, shapes[0]) != nil || memory.like(key, shapes[1]) != nil ||
		!bytes.Equal(memory.like(key, shapes[len(shapes)-1]), shapes[len(shapes)-1]) {
		t.Fatalf("%d hellos are kept for one tool and host", len(memory.seen[key]))
	}
	for i := 0; i < 2*maxRememberedHosts; i++ {
		memory.remember(hostKey(fmt.Sprintf("h%d.example", i)), first)
	}
	if len(memory.seen) > maxRememberedHosts {
		t.Fatalf("hellos are kept for %d hosts", len(memory.seen))
	}
}

// withHelloExtension adds one extension to the end of a ClientHello record.
func withHelloExtension(t *testing.T, record []byte, kind uint16, data []byte) []byte {
	t.Helper()
	added := append([]byte{byte(kind >> 8), byte(kind), byte(len(data) >> 8), byte(len(data))}, data...)
	out := append(bytes.Clone(record), added...)
	grow := func(at, size int) {
		value := 0
		for _, b := range out[at : at+size] {
			value = value<<8 | int(b)
		}
		value += len(added)
		for i := range size {
			out[at+size-1-i] = byte(value >> (8 * i))
		}
	}
	// After the record and handshake headers, the version and the random:
	// the session id, the cipher suites and the compression methods.
	at := 5 + 4 + 2 + 32
	at += 1 + int(out[at])
	at += 2 + int(out[at])<<8 + int(out[at+1])
	at += 1 + int(out[at])
	grow(3, 2)  // the record
	grow(6, 3)  // the handshake message
	grow(at, 2) // the extensions
	if _, err := tlsmirror.ParseHello(out); err != nil {
		t.Fatalf("the extended hello is malformed: %v", err)
	}
	return out
}

// A hello that says early data follows it is left to the service. The
// proxy's own TLS can neither read that data nor skip it, so answering the
// client would end its connection; unread is the lesser harm.
func TestMirrorPassesThroughAHelloWithEarlyData(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	// A hello of a real client, with the extension added.
	conn, first := rig.connectTLS(t, mirrorHost, distinctiveTLS(rig.phaseRoots))
	_ = conn.Close()
	hello := withHelloExtension(t, first.hello(t), 42, nil)
	if parsed, err := tlsmirror.ParseHello(hello); err != nil || !parsed.EarlyData || !parsed.Resumes {
		t.Fatalf("the hello does not announce early data: %+v %v", parsed, err)
	}
	index := rig.wire.count()
	tap := rig.connect(t, mirrorHost)
	if _, err := tap.Write(hello); err != nil {
		t.Fatal(err)
	}
	// The service is sent the client's own bytes on one connection, and its
	// answer comes back: here a TLS alert, since this service takes no early
	// data either.
	if !bytes.Equal(rig.wire.hello(t, index), hello) {
		t.Fatal("the provider did not receive the client's own hello")
	}
	answer := make([]byte, 5)
	if _, err := io.ReadFull(tap, answer); err != nil || answer[0] != 21 {
		t.Fatalf("the service's answer did not come back: % x %v", answer, err)
	}
	if rig.wire.count() != index+1 {
		t.Fatalf("%d connections to the provider, want the client's own alone", rig.wire.count()-index)
	}
	rig.passedThroughOnce(t, leakReasonHelloResumption)
}

// A hello that offers a session and cannot be copied exactly even without the
// offer is still left to the service, as the client's business with it: here
// one that names another server than the CONNECT did.
func TestMirrorPassesThroughAResumingHelloItCannotCopy(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	config := distinctiveTLS(rig.providerRoots)
	config.ServerName = "elsewhere.example"
	config.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	rig.directSession(t, config)

	index := rig.wire.count()
	conn, tap := rig.connectTLS(t, mirrorHost, config)
	sent := tap.hello(t)
	if hello, err := tlsmirror.ParseHello(sent); err != nil || !hello.Resumes {
		t.Fatalf("the client's hello offers no session: %+v %v", hello, err)
	}
	// The session was resumed: the hello reached the service as it was sent,
	// on the only connection opened for it.
	if !conn.ConnectionState().DidResume {
		t.Fatal("the service did not resume the client's session")
	}
	if rig.wire.count() != index+1 || !bytes.Equal(rig.wire.hello(t, index), sent) {
		t.Fatalf("the provider did not receive the client's own hello on one connection (%d opened)", rig.wire.count()-index)
	}
	body := chatBody("the key is " + leakSecretOne)
	if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(mirrorHost, body)); response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	if !bytes.Equal(rig.lastReceived().body, body) {
		t.Fatal("a connection passed through unread was changed")
	}
	rig.passedThroughOnce(t, leakReasonHelloResumption)
}

// A hello no exact copy can be made of: here one that names another server
// than the CONNECT did.
func TestMirrorPassesThroughAHelloItCannotCopy(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	config := distinctiveTLS(rig.providerRoots)
	config.ServerName = "elsewhere.example"
	conn, tap := rig.connectTLS(t, mirrorHost, config)
	if name := conn.ConnectionState().PeerCertificates[0].DNSNames; len(name) != 1 || name[0] != "elsewhere.example" {
		t.Fatalf("the client was not answered by the provider: %v", name)
	}
	if rig.wire.count() != 1 || !bytes.Equal(rig.wire.hello(t, 0), tap.hello(t)) {
		t.Fatalf("the provider did not receive the client's own hello on one connection (%d opened)", rig.wire.count())
	}
	rig.passedThroughOnce(t, leakReasonHelloNotMirrored)
}

// A service that picks HTTP/2 from the copy cannot be relayed: the client
// gets the service, and its own HTTP/2, unread.
func TestMirrorPassesThroughWhenTheServiceChoosesHTTP2(t *testing.T) {
	rig := newLeakRigWith(t, leakModeCensor, func(provider *httptest.Server) { provider.EnableHTTP2 = true })
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	taps := &tapLog{}
	transport := &http.Transport{
		Proxy: http.ProxyURL(rig.proxyURL), DialContext: taps.dial, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: rig.providerRoots, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP384, tls.X25519}},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	body := chatBody("the key is " + leakSecretOne)
	response, answer := postChat(t, client, mirrorHost, body)
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 || string(answer) != `{"type":"message","content":[]}` {
		t.Fatalf("the client did not get the service over its own HTTP/2: %d %s %s", response.StatusCode, response.Proto, answer)
	}
	if !bytes.Equal(rig.lastReceived().body, body) {
		t.Fatal("a connection passed through unread was changed")
	}
	sent := taps.hello(t, 0)
	if hello, _ := tlsmirror.ParseHello(sent); !reflect.DeepEqual(hello.ALPN, []string{"h2", "http/1.1"}) {
		t.Fatalf("the client offered %v", hello.ALPN)
	}
	// The copy was tried first and given up; then the client's own hello.
	if rig.wire.count() != 2 {
		t.Fatalf("%d connections to the provider, want the copy and the client's own", rig.wire.count())
	}
	sameHello(t, sent, rig.wire.hello(t, 0))
	if !bytes.Equal(rig.wire.hello(t, 1), sent) {
		t.Fatal("the provider did not receive the client's own hello")
	}
	rig.passedThroughOnce(t, leakReasonUpstreamNotHTTP1)
}

// strangerProvider makes the fake provider answer the mirror host with a
// certificate the proxy does not trust while the returned switch is on.
func strangerProvider(t *testing.T) (configure func(*httptest.Server), roots *x509.CertPool, untrusted *atomic.Bool) {
	t.Helper()
	stranger, certificate, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	roots.AppendCertsFromPEM(certificate)
	untrusted = &atomic.Bool{}
	return func(provider *httptest.Server) {
		own := provider.TLS.GetCertificate
		provider.TLS.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if untrusted.Load() && hello.ServerName == mirrorHost {
				return stranger.CertificateForHost(hello.ServerName)
			}
			return own(hello)
		}
	}, roots, untrusted
}

// The proxy's own handshake with the service fails: here the service shows a
// certificate the proxy does not trust. The client is left to judge it.
func TestMirrorPassesThroughWhenItsHandshakeFails(t *testing.T) {
	configure, strangerRoots, untrusted := strangerProvider(t)
	rig := newLeakRigWith(t, leakModeCensor, configure)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	untrusted.Store(true)
	client, taps := rig.tappedClient(distinctiveTLS(strangerRoots))

	body := chatBody("the key is " + leakSecretOne)
	if response, _ := postChat(t, client, mirrorHost, body); response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	if !bytes.Equal(rig.lastReceived().body, body) {
		t.Fatal("a connection passed through unread was changed")
	}
	sent := taps.hello(t, 0)
	if rig.wire.count() != 2 {
		t.Fatalf("%d connections to the provider, want the copy and the client's own", rig.wire.count())
	}
	sameHello(t, sent, rig.wire.hello(t, 0))
	if !bytes.Equal(rig.wire.hello(t, 1), sent) {
		t.Fatal("the provider did not receive the client's own hello")
	}
	rig.passedThroughOnce(t, leakReasonUpstreamHandshake)
	// Nothing was terminated, so nothing was counted against the client.
	key := refusalKey(rig.guard, hostKey(mirrorHost))
	rig.guard.handshakes.mu.Lock()
	counted := rig.guard.handshakes.hosts[key]
	rig.guard.handshakes.mu.Unlock()
	if counted != nil {
		t.Fatalf("a connection passed through was counted as a handshake: %+v", counted)
	}
}

// A service that cannot be reached at all leaves nothing to hand the client
// to: its connection ends, and no event claims it was passed through.
func TestMirrorEndsTheTunnelWhenTheServiceCannotBeReached(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	var dials atomic.Int64
	rig.proxy.unboundDial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("connection refused")
	}
	tap := rig.connect(t, mirrorHost)
	config := distinctiveTLS(rig.phaseRoots)
	config.ServerName = mirrorHost
	if err := tls.Client(tap, config).Handshake(); err == nil {
		t.Fatal("the client completed TLS with a service that cannot be reached")
	}
	if dials.Load() != 1 || len(rig.unreadTunnels()) != 0 || rig.guard.handshakes.bypassed(hostKey(mirrorHost)) {
		t.Fatalf("%d dials, %d events", dials.Load(), len(rig.unreadTunnels()))
	}
}

// A client that refuses the proxy's certificate is counted as on any
// inspected host, and its window is the same raw tunnel.
func TestMirrorHostCountsARefusedCertificate(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	now := time.Now()
	var clockMu sync.Mutex
	rig.guard.handshakes.now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	refused := func() leakStateKey { return refusalKey(rig.guard, hostKey(mirrorHost)) }
	failures := func() int {
		key := refused()
		rig.guard.handshakes.mu.Lock()
		defer rig.guard.handshakes.mu.Unlock()
		if state := rig.guard.handshakes.hosts[key]; state != nil {
			return state.failures
		}
		return 0
	}
	body := chatBody("the key is " + leakSecretOne)
	for want := 1; want <= 2; want++ {
		if rig.guard.handshakes.bypassed(refused()) {
			t.Fatal("one refusal opened a window")
		}
		client, taps := rig.tappedClient(distinctiveTLS(rig.providerRoots))
		request, _ := http.NewRequest(http.MethodPost, "https://"+mirrorHost+"/zen/v1/chat/completions", bytes.NewReader(body))
		if _, err := client.Do(request); err == nil {
			t.Fatal("a client that does not trust Phase completed TLS with the proxy")
		}
		for deadline := time.Now().Add(2 * time.Second); failures() < want; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%d refusals counted, want %d", failures(), want)
			}
		}
		// The upstream connection stood before the client was answered, and
		// does not outlive the client's.
		sameHello(t, taps.hello(t, 0), rig.wire.hello(t, want-1))
		rig.wire.closed(t, want-1)
	}
	if !rig.guard.handshakes.bypassed(refused()) || rig.receivedCount() != 0 {
		t.Fatal("two refusals in a row did not open a window, or a refused request went out")
	}
	// Inside the window the tunnel is raw.
	index := rig.wire.count()
	client, taps := rig.tappedClient(distinctiveTLS(rig.providerRoots))
	if response, _ := postChat(t, client, mirrorHost, body); response.StatusCode != http.StatusOK {
		t.Fatalf("inside the window: %d", response.StatusCode)
	}
	if !bytes.Equal(rig.lastReceived().body, body) || !bytes.Equal(rig.wire.hello(t, index), taps.hello(t, 0)) {
		t.Fatal("the window did not pass the client's own TLS through")
	}
	events := rig.leakEventsNow()
	if len(events) != 1 || events[0].Outcome != outcomeBypass || events[0].Reason != leakReasonTLSRefused || events[0].Detail["harness"] != "opencode" {
		t.Fatalf("events: %+v", events)
	}
	// After it, a client that trusts Phase is read again, with its hello
	// copied, and the count is cleared.
	clockMu.Lock()
	now = now.Add(21 * time.Second)
	clockMu.Unlock()
	index = rig.wire.count()
	client, taps = rig.tappedClient(distinctiveTLS(rig.phaseRoots))
	if response, _ := postChat(t, client, mirrorHost, body); response.StatusCode != http.StatusOK {
		t.Fatalf("after the window: %d", response.StatusCode)
	}
	if bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) || failures() != 0 {
		t.Fatal("the host was not read after the window, or the count was not cleared")
	}
	sameHello(t, taps.hello(t, 0), rig.wire.hello(t, index))
}

// The proxy gives the client of such a host no session ticket, so the
// client's next hello offers none and is copied again. On any other inspected
// host it does give one, and the client's next hello offers it back.
func TestMirrorHostIssuesNoSessionTickets(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	body := chatBody("the key is " + leakSecretOne)
	for _, c := range []struct {
		host    string
		tickets bool
	}{{mirrorHost, false}, {"api.anthropic.com", true}} {
		config := distinctiveTLS(rig.phaseRoots)
		config.ClientSessionCache = tls.NewLRUClientSessionCache(8)
		for attempt := 0; attempt < 2; attempt++ {
			conn, tap := rig.connectTLS(t, c.host, config)
			// A ticket, when one is sent, arrives with the first answer.
			if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(c.host, body)); response.StatusCode != http.StatusOK {
				t.Fatalf("%s: status %d", c.host, response.StatusCode)
			}
			if bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) {
				t.Fatalf("%s: connection %d was not read", c.host, attempt)
			}
			hello, err := tlsmirror.ParseHello(tap.hello(t))
			if err != nil {
				t.Fatal(err)
			}
			if want := c.tickets && attempt == 1; hello.Resumes != want {
				t.Fatalf("%s, connection %d: the hello offers a session = %v, want %v", c.host, attempt, hello.Resumes, want)
			}
			_ = conn.Close()
		}
	}
	if events := rig.unreadTunnels(); len(events) != 0 {
		t.Fatalf("a connection was passed through unread: %+v", events)
	}
}

// When a tunnel needs another upstream connection it is opened with the same
// copy, and when that fails the request fails: Go's own hello never goes to
// such a host.
func TestMirrorTunnelNeverFallsBackToGosHello(t *testing.T) {
	configure, _, untrusted := strangerProvider(t)
	rig := newLeakRigWith(t, leakModeCensor, configure)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	conn, tap := rig.connectTLS(t, mirrorHost, distinctiveTLS(rig.phaseRoots))
	reader := bufio.NewReader(conn)
	body := chatBody("the key is " + leakSecretOne)
	send := func() *http.Response {
		t.Helper()
		response, _ := exchange(t, conn, reader, chatRequest(mirrorHost, body))
		return response
	}
	if response := send(); response.StatusCode != http.StatusOK {
		t.Fatalf("first request: %d", response.StatusCode)
	}
	// The service drops its connections; the next request needs a new one.
	dropConnections := func() {
		rig.provider.CloseClientConnections()
		// The proxy's end has to see it: a request written just as the
		// service hangs up fails like any other client's.
		time.Sleep(100 * time.Millisecond)
	}
	dropConnections()
	if response := send(); response.StatusCode != http.StatusOK {
		t.Fatalf("after the service closed its connection: %d", response.StatusCode)
	}
	if rig.wire.count() != 2 {
		t.Fatalf("%d connections to the provider, want two", rig.wire.count())
	}
	// Now a new connection cannot be made at all.
	untrusted.Store(true)
	dropConnections()
	requests := rig.receivedCount()
	response := send()
	if response.StatusCode != http.StatusBadGateway || response.Header.Get("X-Phase-Error-Code") != "upstream_unavailable" || rig.receivedCount() != requests {
		t.Fatalf("a request that could not be sent with the copy: %d %s", response.StatusCode, response.Header.Get("X-Phase-Error-Code"))
	}
	// The client's connection is still good once the service is.
	untrusted.Store(false)
	if response := send(); response.StatusCode != http.StatusOK {
		t.Fatalf("after the service came back: %d", response.StatusCode)
	}
	if bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) {
		t.Fatal("the value reached the provider")
	}
	// Every connection the provider saw opened with the copy.
	sent, goOwn := tap.hello(t), rig.goHello(t, mirrorHost)
	opened := rig.wire.count() - 1
	if opened < 4 {
		t.Fatalf("%d connections to the provider, want at least four", opened)
	}
	for index := 0; index < opened; index++ {
		sameHello(t, sent, rig.wire.hello(t, index))
		if tlsmirror.SameShape(goOwn, rig.wire.hello(t, index)) {
			t.Fatalf("connection %d to the provider opened with Go's own hello", index)
		}
	}
	if events := rig.unreadTunnels(); len(events) != 0 {
		t.Fatalf("a terminated tunnel was reported as passed through: %+v", events)
	}
}

// A client may open its tunnel long before it uses it. If the service has
// closed the connection made for it by then, another is opened with the copy.
func TestMirrorTunnelOutlivesItsFirstUpstreamConnection(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	conn, tap := rig.connectTLS(t, mirrorHost, distinctiveTLS(rig.phaseRoots))
	rig.provider.CloseClientConnections()
	time.Sleep(100 * time.Millisecond)
	if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(mirrorHost, chatBody("the key is "+leakSecretOne))); response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	if bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) {
		t.Fatal("the value reached the provider")
	}
	if rig.wire.count() != 2 {
		t.Fatalf("%d connections to the provider, want two", rig.wire.count())
	}
	sameHello(t, tap.hello(t), rig.wire.hello(t, 0))
	sameHello(t, tap.hello(t), rig.wire.hello(t, 1))
}

// A model's answer is a stream: it reaches the client as the service sends
// it, not when it ends.
func TestMirrorHostStreamsTheAnswer(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	firstRead := make(chan struct{})
	rig.upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		wire, _ := r.Context().Value(wireKey{}).(*wireConn)
		rig.mu.Lock()
		rig.received = append(rig.received, receivedRequest{host: r.Host, path: r.URL.Path, header: r.Header.Clone(), body: body, wire: wire})
		rig.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-firstRead:
		case <-time.After(5 * time.Second):
			return
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	})
	client, taps := rig.tappedClient(distinctiveTLS(rig.phaseRoots))
	for attempt := 0; attempt < 2; attempt++ {
		request, _ := http.NewRequest(http.MethodPost, "https://"+mirrorHost+"/zen/v1/chat/completions", bytes.NewReader(chatBody("the key is "+leakSecretOne)))
		request.Header.Set("X-Test-Handler", "stream")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(response.Body)
		if line, err := reader.ReadString('\n'); err != nil || !strings.Contains(line, "first") {
			t.Fatalf("the first event did not arrive before the answer ended: %q %v", line, err)
		}
		firstRead <- struct{}{}
		rest, _ := io.ReadAll(reader)
		_ = response.Body.Close()
		if !strings.Contains(string(rest), "[DONE]") {
			t.Fatalf("the answer did not finish: %q", rest)
		}
		received := rig.lastReceived()
		if bytes.Contains(received.body, []byte(leakSecretOne)) {
			t.Fatal("the value reached the provider")
		}
		sameHello(t, taps.hello(t, 0), received.wire.hello(t))
	}
	// Both answers came over the client's one tunnel and its one upstream
	// connection.
	if taps.count() != 1 || rig.wire.count() != 1 {
		t.Fatalf("%d tunnels and %d connections to the provider for two streamed answers", taps.count(), rig.wire.count())
	}
}

// Each tunnel has its own copy: clients with different hellos, at the same
// time, each reach the service with their own.
func TestMirrorTunnelsKeepTheirOwnHellos(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	other := distinctiveTLS(rig.phaseRoots)
	other.CurvePreferences = []tls.CurveID{tls.X25519}
	other.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	configs := []*tls.Config{distinctiveTLS(rig.phaseRoots), other}
	const workers, requests = 8, 4
	hellos, logs := make([][]byte, workers), make([]*tapLog, workers)
	failures := make(chan string, workers*(requests+1))
	var wait sync.WaitGroup
	for worker := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			client, taps := rig.tappedClient(configs[worker%2])
			logs[worker] = taps
			for i := range requests {
				body := chatBody(fmt.Sprintf("worker-%d-request-%d the key is %s", worker, i, leakSecretOne))
				request, _ := http.NewRequest(http.MethodPost, "https://"+mirrorHost+"/zen/v1/chat/completions", bytes.NewReader(body))
				response, err := client.Do(request)
				if err != nil {
					failures <- err.Error()
					return
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != http.StatusOK {
					failures <- fmt.Sprintf("worker %d: status %d", worker, response.StatusCode)
				}
			}
			if taps.count() != 1 {
				failures <- fmt.Sprintf("worker %d opened %d tunnels", worker, taps.count())
			}
		}()
	}
	wait.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	if t.Failed() {
		return
	}
	for worker := range workers {
		hellos[worker] = logs[worker].hello(t, 0)
	}
	if tlsmirror.SameShape(hellos[0], hellos[1]) {
		t.Fatal("the two kinds of client send the same hello: the test shows nothing")
	}
	rig.mu.Lock()
	received := append([]receivedRequest(nil), rig.received...)
	rig.mu.Unlock()
	if len(received) != workers*requests {
		t.Fatalf("the provider received %d requests, want %d", len(received), workers*requests)
	}
	for _, request := range received {
		var worker, index int
		at := bytes.Index(request.body, []byte("worker-"))
		if at < 0 {
			t.Fatalf("a request without its mark: %s", request.body)
		}
		if _, err := fmt.Sscanf(string(request.body[at:]), "worker-%d-request-%d", &worker, &index); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(request.body, []byte(leakSecretOne)) {
			t.Fatalf("worker %d: the value reached the provider", worker)
		}
		carried := request.wire.hello(t)
		if !tlsmirror.SameShape(hellos[worker], carried) || tlsmirror.SameShape(hellos[(worker+1)%2], carried) {
			t.Fatalf("worker %d's request arrived on a connection opened with another client's hello", worker)
		}
	}
	if rig.wire.count() != workers {
		t.Fatalf("%d connections to the provider for %d tunnels", rig.wire.count(), workers)
	}
}

// The connection made for a tunnel ends with it, used or not.
func TestMirrorClosesItsUpstreamConnectionWithTheTunnel(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	unused, _ := rig.connectTLS(t, mirrorHost, distinctiveTLS(rig.phaseRoots))
	_ = unused.Close()
	rig.wire.closed(t, 0)
	used, _ := rig.connectTLS(t, mirrorHost, distinctiveTLS(rig.phaseRoots))
	if response, _ := exchange(t, used, bufio.NewReader(used), chatRequest(mirrorHost, chatBody("hello"))); response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	_ = used.Close()
	rig.wire.closed(t, 1)
	if rig.wire.count() != 2 {
		t.Fatalf("%d connections to the provider for two tunnels", rig.wire.count())
	}
}

// The forwarding adds no header of its own and changes no answer: the
// transport's automatic Accept-Encoding and its decompression are off.
func TestMirrorForwardingAddsNothingOfItsOwn(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(writer, `{"answer":"compressed by the service"}`)
	_ = writer.Close()
	rig.upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rig.mu.Lock()
		rig.received = append(rig.received, receivedRequest{host: r.Host, path: r.URL.Path, header: r.Header.Clone(), body: body})
		rig.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	})
	names := func(header http.Header) string {
		var out []string
		for name := range header {
			out = append(out, name)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	body := chatBody("hello")
	request := func(host string) string {
		return fmt.Sprintf("POST /zen/v1/chat/completions HTTP/1.1\r\nHost: %s\r\nUser-Agent: opencode/2.0.25\r\nAuthorization: Bearer harness-login\r\nx-opencode-session: abc\r\nX-Test-Handler: gzip\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", host, len(body), body)
	}
	// The same request from a client that names no User-Agent.
	unnamed := func(host string) string {
		return fmt.Sprintf("POST /zen/v1/chat/completions HTTP/1.1\r\nHost: %s\r\nX-Test-Handler: gzip\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", host, len(body), body)
	}
	conn, _ := rig.connectTLS(t, mirrorHost, distinctiveTLS(rig.phaseRoots))
	reader := bufio.NewReader(conn)
	response, answer := exchange(t, conn, reader, request(mirrorHost))
	received := rig.lastReceived()
	if got := names(received.header); got != "Authorization,Content-Length,Content-Type,User-Agent,X-Opencode-Session,X-Test-Handler" {
		t.Fatalf("the provider received the headers %s", got)
	}
	if received.header.Get("User-Agent") != "opencode/2.0.25" || received.header.Get("Authorization") != "Bearer harness-login" || !bytes.Equal(received.body, body) {
		t.Fatalf("the request changed on the way: %v", received.header)
	}
	if response.Header.Get("Content-Encoding") != "gzip" || !bytes.Equal(answer, compressed.Bytes()) {
		t.Fatalf("the answer was not passed back as the service sent it: %v %q", response.Header, answer)
	}
	// A request that names no client is sent on naming none: the forwarding
	// does not put its own name in a User-Agent.
	if response, _ := exchange(t, conn, reader, unnamed(mirrorHost)); response.StatusCode != http.StatusOK {
		t.Fatalf("a request with no User-Agent: %d", response.StatusCode)
	}
	if received := rig.lastReceived(); names(received.header) != "Content-Length,Content-Type,X-Test-Handler" || !bytes.Equal(received.body, body) {
		t.Fatalf("for a request with no User-Agent the provider received the headers %s (User-Agent %q)", names(received.header), received.header.Get("User-Agent"))
	}
	// The proxy's usual transport, on a host whose hello is not copied, asks
	// for gzip itself and undoes it, and names itself when the client named
	// nothing: that is the difference.
	conn, _ = rig.connectTLS(t, "api.anthropic.com", distinctiveTLS(rig.phaseRoots))
	reader = bufio.NewReader(conn)
	response, answer = exchange(t, conn, reader, request("api.anthropic.com"))
	if got := names(rig.lastReceived().header); got != "Accept-Encoding,Authorization,Content-Length,Content-Type,User-Agent,X-Opencode-Session,X-Test-Handler" {
		t.Fatalf("on a host that is not flagged the provider received the headers %s", got)
	}
	if response.Header.Get("Content-Encoding") != "" || string(answer) != `{"answer":"compressed by the service"}` {
		t.Fatalf("on a host that is not flagged the answer came back as %v %q", response.Header, answer)
	}
	exchange(t, conn, reader, unnamed("api.anthropic.com"))
	if received := rig.lastReceived(); names(received.header) != "Accept-Encoding,Content-Length,Content-Type,User-Agent,X-Test-Handler" || !strings.HasPrefix(received.header.Get("User-Agent"), "Go-http-client/") {
		t.Fatalf("on a host that is not flagged a request with no User-Agent arrived with the headers %s", names(received.header))
	}
}

// A WebSocket on such a host is the inspected host's WebSocket, carried by a
// connection opened with the copy.
func TestMirrorHostCarriesAWebSocket(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	messages := make(chan []byte, 4)
	rig.upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = fmt.Fprintf(buffered, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", webSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
		_ = buffered.Flush()
		for {
			_, opcode, payload, err := readFrame(buffered.Reader)
			if err != nil || opcode == wsOpClose {
				return
			}
			messages <- payload
			_, _ = buffered.Write(append([]byte{0x81, byte(len("ok"))}, "ok"...))
			_ = buffered.Flush()
		}
	})
	conn, tap := rig.connectTLS(t, mirrorHost, distinctiveTLS(rig.phaseRoots))
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, _ = fmt.Fprintf(conn, "GET /zen/v1/realtime HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n", mirrorHost, key)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", response, err)
	}
	message := []byte(`{"type":"response.create","input":"STRIPE_KEY=` + leakSecretOne + `"}`)
	if _, err := conn.Write(clientFrame(true, wsOpText, message)); err != nil {
		t.Fatal(err)
	}
	if fin, opcode, payload, err := readFrame(reader); err != nil || !fin || opcode != wsOpText || string(payload) != "ok" {
		t.Fatalf("the service's frame did not come back: %v %v %q %v", fin, opcode, payload, err)
	}
	select {
	case got := <-messages:
		if want := bytes.Replace(message, []byte(leakSecretOne), []byte("ph:secret:stripe"), 1); !bytes.Equal(got, want) {
			t.Fatalf("the service received %s", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the service received no message")
	}
	if rig.wire.count() != 1 {
		t.Fatalf("%d connections to the provider, want one", rig.wire.count())
	}
	sameHello(t, tap.hello(t), rig.wire.hello(t, 0))
	if events := rig.leakEventsNow(); len(events) != 1 || events[0].Protocol != "websocket" || events[0].Outcome != outcomeCensored {
		t.Fatalf("events: %+v", events)
	}
}

// pipelinedConn sends the client's hello in the same write as its CONNECT,
// as a client that does not wait for the proxy's answer does.
type pipelinedConn struct {
	net.Conn
	connect []byte
	reader  *bufio.Reader
	err     error
}

func (c *pipelinedConn) Write(p []byte) (int, error) {
	if c.connect == nil {
		return c.Conn.Write(p)
	}
	first := append(c.connect, p...)
	c.connect = nil
	if _, err := c.Conn.Write(first); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *pipelinedConn) Read(p []byte) (int, error) {
	if c.reader == nil {
		c.reader = bufio.NewReader(c.Conn)
		response, err := http.ReadResponse(c.reader, &http.Request{Method: http.MethodConnect})
		if err == nil && response.StatusCode != http.StatusOK {
			err = fmt.Errorf("CONNECT answered %d", response.StatusCode)
		}
		c.err = err
	}
	if c.err != nil {
		return 0, c.err
	}
	return c.reader.Read(p)
}

func TestMirrorReadsAHelloSentWithTheConnect(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	raw, err := net.Dial("tcp", rig.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	tap := &tapConn{Conn: raw}
	authorization := base64.StdEncoding.EncodeToString([]byte("phase:runtime-test"))
	pipelined := &pipelinedConn{Conn: tap, connect: fmt.Appendf(nil, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: Basic %s\r\n\r\n", mirrorHost, mirrorHost, authorization)}
	config := distinctiveTLS(rig.phaseRoots)
	config.ServerName = mirrorHost
	conn := tls.Client(pipelined, config)
	if err := conn.Handshake(); err != nil {
		t.Fatalf("a hello sent with the CONNECT: %v", err)
	}
	if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(mirrorHost, chatBody("the key is "+leakSecretOne))); response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	if bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) {
		t.Fatal("the value reached the provider")
	}
	sameHello(t, tap.hello(t), rig.wire.hello(t, 0))
}

// A hello sent with the CONNECT is not lost on any other path either: a host
// read without its hello being copied, a host the proxy leaves alone, and a
// host inside a pass-through window. Before, each of them waited for a hello
// the client had already sent.
func TestAHelloSentWithTheConnectReachesEveryKindOfTunnel(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	// The mirror host's client has refused the certificate twice.
	rig.guard.handshakes.note(hostKey(mirrorHost), false)
	if rig.guard.handshakes.note(hostKey(mirrorHost), false) == 0 {
		t.Fatal("no window opened")
	}
	body := chatBody("the key is " + leakSecretOne)
	for _, c := range []struct {
		name, host string
		read       bool
	}{
		{"a host that is read", "api.anthropic.com", true},
		{"a host outside the table", "api.example.com", false},
		{"a host in a pass-through window", mirrorHost, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw, err := net.Dial("tcp", rig.proxyURL.Host)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			// Short: a hello that is lost is waited for until this passes.
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			authorization := base64.StdEncoding.EncodeToString([]byte("phase:runtime-test"))
			pipelined := &pipelinedConn{Conn: raw, connect: fmt.Appendf(nil, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: Basic %s\r\n\r\n", c.host, c.host, authorization)}
			config := distinctiveTLS(rig.bothRoots)
			config.ServerName = c.host
			conn := tls.Client(pipelined, config)
			if err := conn.Handshake(); err != nil {
				t.Fatalf("a hello sent with the CONNECT: %v", err)
			}
			_, phaseErr := conn.ConnectionState().PeerCertificates[0].Verify(x509.VerifyOptions{Roots: rig.phaseRoots, DNSName: c.host})
			if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(c.host, body)); response.StatusCode != http.StatusOK {
				t.Fatalf("status %d", response.StatusCode)
			}
			if replaced := !bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)); replaced != c.read || (phaseErr == nil) != c.read {
				t.Fatalf("answered by the proxy = %v, value replaced = %v, want %v", phaseErr == nil, replaced, c.read)
			}
		})
	}
}

// A Connection's own host is not handled here: its tunnel is terminated as
// for any Connection and sent with the proxy's usual transport, and it is
// never passed through, flagged or not.
func TestMirrorDoesNotApplyToAConnectionsHost(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-custom", 1,
		customConnectionPayload(customDecoyToken, customLiveToken)), "runtime-custom")
	t.Cleanup(state.destroy)
	rig.proxy.state = state
	rig.proxyURL.User = url.UserPassword("phase", "runtime-custom")
	rig.guard.hosts = leakHostTable{{Harness: "test", Hosts: []leakHostRule{{Host: "api.example.test", Treatment: leakTreatmentInspect, MirrorHello: true}}}}
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})

	client, taps := rig.tappedClient(distinctiveTLS(rig.phaseRoots))
	body := chatBody("the key is " + leakSecretOne)
	request, _ := http.NewRequest(http.MethodPost, "https://api.example.test/v1/items", bytes.NewReader(body))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	received := rig.lastReceived()
	if response.StatusCode != http.StatusOK || received.header.Get("Authorization") != "Bearer "+customLiveToken || bytes.Contains(received.body, []byte(leakSecretOne)) {
		t.Fatalf("the Connection was not applied: %d", response.StatusCode)
	}
	if tlsmirror.SameShape(taps.hello(t, 0), rig.wire.hello(t, 0)) || !tlsmirror.SameShape(rig.goHello(t, "api.example.test"), rig.wire.hello(t, 0)) {
		t.Fatal("a Connection's host did not receive the proxy's own hello")
	}
	// Bytes that are no hello end the tunnel; they are not passed on.
	before := rig.wire.count()
	tap := rig.connect(t, "api.example.test")
	_, _ = tap.Write([]byte("EHLO not-a-tls-client.example\r\n"))
	_ = tap.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadAll(tap)
	if rig.wire.count() != before {
		t.Fatal("a Connection's host was reached by a tunnel the proxy did not read")
	}
}

func TestUnreadTunnelsAreReportedOncePerHostAndReasonAMinute(t *testing.T) {
	log := newUnreadLog()
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	log.now = func() time.Time { return now }
	if !log.fresh(hostKey(mirrorHost), leakReasonHelloResumption) {
		t.Fatal("the first pass-through was not reported")
	}
	for i := 0; i < 50; i++ {
		now = now.Add(time.Second)
		if log.fresh(hostKey(mirrorHost), leakReasonHelloResumption) {
			t.Fatalf("a pass-through %d seconds after the report was reported again", i+1)
		}
	}
	if !log.fresh(hostKey(mirrorHost), leakReasonUpstreamNotHTTP1) || !log.fresh(hostKey("other.example"), leakReasonHelloResumption) {
		t.Fatal("another reason or another host was not reported")
	}
	// Another tool on the same host has a count of its own.
	if !log.fresh(leakStateKey{tool: "codex", host: mirrorHost}, leakReasonHelloResumption) || log.fresh(leakStateKey{tool: "codex", host: mirrorHost}, leakReasonHelloResumption) {
		t.Fatal("another tool on the same host was not reported once")
	}
	now = now.Add(unreadPeriod)
	if !log.fresh(hostKey(mirrorHost), leakReasonHelloResumption) || log.fresh(hostKey(mirrorHost), leakReasonHelloResumption) {
		t.Fatal("a pass-through a minute later was not reported once")
	}
	for i := 0; i < 4*maxRememberedHosts; i++ {
		log.fresh(hostKey(fmt.Sprintf("h%d.example", i)), leakReasonHelloUnreadable)
	}
	if len(log.last) > maxRememberedHosts {
		t.Fatalf("the log grew to %d entries", len(log.last))
	}
}

// What an event may say about a connection passed through is what the proxy
// keeps and what the Console takes: a reason and two labels.
func TestUnreadTunnelEventFitsTheConsole(t *testing.T) {
	for _, reason := range []string{leakReasonHelloUnreadable, leakReasonHelloResumption, leakReasonHelloNotMirrored, leakReasonUpstreamHandshake, leakReasonUpstreamNotHTTP1} {
		if !eventIdentifier.MatchString(reason) || len(reason) > 64 {
			t.Errorf("%q is not a reason the Console takes", reason)
		}
	}
	detail := map[string]any{"mode": leakModeCensor, "harness": "opencode", "capture": CaptureTunnel, "scope": leakScopeConnection}
	if kept := safeEventDetail(detail, nil); !reflect.DeepEqual(kept, detail) {
		t.Fatalf("the detail is cut before it reaches the Console: %+v", kept)
	}
}

// leakStatus is what GET /v1/status says of leak protection.
func (r *leakRig) leakStatus(t *testing.T) *remoteapi.LeakProtectionStatus {
	t.Helper()
	recorder := controlCall(r.proxy, http.MethodGet, "/v1/status", "", nil)
	var status remoteapi.StatusResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &status) != nil || status.LeakProtection == nil {
		t.Fatalf("status: %d %s", recorder.Code, recorder.Body.String())
	}
	return status.LeakProtection
}

// hostStatus is how status lists a host: inspected, or not and why.
func hostStatus(status *remoteapi.LeakProtectionStatus, host string) (inspected bool, reasons []string) {
	return containsString(status.InspectedHosts, host) && !containsString(status.UnreadHosts, host), status.UnreadReasons[host]
}

// passThrough opens a connection to the mirror host that the proxy hands to
// the service unread, and that the client keeps: its hello names another
// server than its CONNECT did, so no exact copy of it can be sent
// (hello_not_mirrored), and the client completes its own TLS with the service.
func (r *leakRig) passThrough(t *testing.T) *tls.Conn {
	t.Helper()
	config := distinctiveTLS(r.providerRoots)
	config.ServerName = "elsewhere.example"
	conn, _ := r.connectTLS(t, mirrorHost, config)
	return conn
}

// A connection handed to the service unread stays unread for as long as the
// client keeps it. Status lists its host as not read, with the reason, while
// it is open and for a minute after it was opened, and the event is sent
// again for as long as it stays open. Before, the host was listed as
// inspected throughout and one event was all there ever was.
func TestAPassedThroughConnectionIsSaidToBeUnreadWhileItLasts(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	clock := &testClock{now: time.Now()}
	rig.guard.connections.now, rig.guard.unread.now = clock.Now, clock.Now
	rig.proxy.unreadRepeat = 5 * time.Millisecond
	eventually := func(what string, done func() bool) {
		t.Helper()
		for deadline := time.Now().Add(3 * time.Second); !done(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
		}
	}
	if inspected, reasons := hostStatus(rig.leakStatus(t), mirrorHost); !inspected || reasons != nil {
		t.Fatalf("before any connection the host is not listed as inspected (%v)", reasons)
	}

	conn := rig.passThrough(t)
	status := rig.leakStatus(t)
	if inspected, reasons := hostStatus(status, mirrorHost); inspected || !reflect.DeepEqual(reasons, []string{leakReasonHelloNotMirrored}) {
		t.Fatalf("with a passed-through connection open the host is listed as inspected = %v, for %v", inspected, reasons)
	}
	if !reflect.DeepEqual(status.UnreadHosts, []string{mirrorHost}) || containsString(status.InspectedHosts, mirrorHost) {
		t.Fatalf("status hosts: %v and %v", status.InspectedHosts, status.UnreadHosts)
	}
	rig.passedThroughOnce(t, leakReasonHelloNotMirrored)

	// It is offered again all the time and sent at the pace every unread
	// report keeps: not again within the minute.
	time.Sleep(60 * time.Millisecond)
	if events := rig.unreadTunnels(); len(events) != 1 {
		t.Fatalf("%d events within a minute of the first", len(events))
	}
	// A minute on the connection is still open, and the event says so again.
	clock.advance(unreadPeriod)
	eventually("an open passed-through connection was not reported again a minute later", func() bool { return len(rig.unreadTunnels()) >= 2 })
	events := rig.unreadTunnels()
	if event := events[1]; len(events) != 2 || event.Reason != leakReasonHelloNotMirrored || event.Host != mirrorHost || event.Detail["scope"] != leakScopeConnection ||
		event.Detail["harness"] != "opencode" || len(event.Detail) != 4 || durableAuditEvent(event) {
		t.Fatalf("the repeated event: %+v", events)
	}
	// And the host is still not read, though the connection opened long ago:
	// what the client sends on it reaches the service as it is.
	body := chatBody("the key is " + leakSecretOne)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(mirrorHost, body)); response.StatusCode != http.StatusOK || !bytes.Equal(rig.lastReceived().body, body) {
		t.Fatalf("the passed-through connection: %d", response.StatusCode)
	}
	if inspected, reasons := hostStatus(rig.leakStatus(t), mirrorHost); inspected || !reflect.DeepEqual(reasons, []string{leakReasonHelloNotMirrored}) {
		t.Fatalf("a minute on, with the connection open: inspected = %v, for %v", inspected, reasons)
	}

	// Once the client lets go of it the host is read again, and the reports
	// stop.
	_ = conn.Close()
	eventually("the host was not listed as inspected after its passed-through connection closed", func() bool {
		inspected, reasons := hostStatus(rig.leakStatus(t), mirrorHost)
		return inspected && reasons == nil
	})
	clock.advance(unreadPeriod)
	time.Sleep(60 * time.Millisecond)
	if events := rig.unreadTunnels(); len(events) != 2 {
		t.Fatalf("%d events after the connection closed, want the two from while it was open", len(events))
	}

	// A connection that was passed through and is gone already is still said
	// for a minute: as long as its event is not repeated.
	_ = rig.passThrough(t).Close()
	eventually("a passed-through connection that closed at once was not counted", func() bool {
		_, _, passed := rig.guard.connections.counts(mirrorHost)
		rig.guard.connections.mu.Lock()
		defer rig.guard.connections.mu.Unlock()
		return passed[leakReasonHelloNotMirrored] == 2 && !rig.guard.connections.hosts[mirrorHost].anyOpen()
	})
	clock.advance(unreadPeriod - time.Second)
	if inspected, reasons := hostStatus(rig.leakStatus(t), mirrorHost); inspected || !reflect.DeepEqual(reasons, []string{leakReasonHelloNotMirrored}) {
		t.Fatalf("within a minute of a passed-through connection: inspected = %v, for %v", inspected, reasons)
	}
	clock.advance(time.Second)
	if inspected, reasons := hostStatus(rig.leakStatus(t), mirrorHost); !inspected || reasons != nil {
		t.Fatalf("a minute after the last passed-through connection: inspected = %v, for %v", inspected, reasons)
	}
	// Nothing in status is more than names, counts and reasons.
	encoded, _ := json.Marshal(rig.leakStatus(t))
	if bytes.Contains(encoded, []byte("elsewhere")) || bytes.Contains(encoded, []byte(leakSecretOne)) ||
		!bytes.Contains(encoded, []byte(`"mirroredHosts":[{"host":"opencode.ai","copied":0,"rebuilt":0,"passedThrough":{"hello_not_mirrored":2}}]`)) {
		t.Fatalf("status: %s", encoded)
	}
}

// Status counts how the connections to a host whose hello is copied went:
// read with a copy, sent a hello rebuilt from one that offered a session, or
// handed over unread and why.
func TestStatusCountsTheConnectionsOfAMirroredHost(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	counts := func() remoteapi.MirroredHostStatus {
		t.Helper()
		hosts := rig.leakStatus(t).MirroredHosts
		if len(hosts) != 1 || hosts[0].Host != mirrorHost {
			t.Fatalf("the mirrored hosts: %+v", hosts)
		}
		return hosts[0]
	}
	if got := counts(); got.Copied != 0 || got.Rebuilt != 0 || got.PassedThrough != nil {
		t.Fatalf("before any connection: %+v", got)
	}
	body := chatBody("the key is " + leakSecretOne)
	send := func(config *tls.Config) {
		t.Helper()
		conn, _ := rig.connectTLS(t, mirrorHost, config)
		if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(mirrorHost, body)); response.StatusCode != http.StatusOK {
			t.Fatalf("status %d", response.StatusCode)
		}
		if bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) {
			t.Fatal("the connection was not read")
		}
		_ = conn.Close()
	}
	// A client with no session: its own hello is copied.
	known := distinctiveTLS(rig.bothRoots)
	known.ServerName = mirrorHost
	known.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	send(known)
	if got := counts(); got.Copied != 1 || got.Rebuilt != 0 || got.PassedThrough != nil {
		t.Fatalf("after one connection read with a copy: %+v", got)
	}
	// The same client with a session to offer: the hello it sent before is
	// the one copied, so nothing was rebuilt.
	rig.directSession(t, known)
	send(known)
	if got := counts(); got.Copied != 2 || got.Rebuilt != 0 {
		t.Fatalf("after a client seen before offered a session: %+v", got)
	}
	// A client first seen with a session to offer: the hello sent is made
	// from the one it sent, and that is counted.
	stranger := distinctiveTLS(rig.bothRoots)
	stranger.ServerName = mirrorHost
	stranger.CurvePreferences = []tls.CurveID{tls.X25519}
	stranger.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	rig.directSession(t, stranger)
	send(stranger)
	send(stranger)
	if got := counts(); got.Copied != 4 || got.Rebuilt != 2 || got.PassedThrough != nil {
		t.Fatalf("after two connections of a client first seen with a session: %+v", got)
	}
	// Connections handed over unread are counted by reason: two whose hello
	// cannot be copied, and one whose hello says early data follows.
	_ = rig.passThrough(t).Close()
	_ = rig.passThrough(t).Close()
	opened, first := rig.connectTLS(t, mirrorHost, distinctiveTLS(rig.phaseRoots))
	_ = opened.Close()
	index := rig.wire.count()
	early := withHelloExtension(t, first.hello(t), 42, nil)
	tap := rig.connect(t, mirrorHost)
	if _, err := tap.Write(early); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rig.wire.hello(t, index), early) {
		t.Fatal("the provider did not receive the client's own hello")
	}
	_ = tap.Close()
	want := remoteapi.MirroredHostStatus{Host: mirrorHost, Copied: 5, Rebuilt: 2, PassedThrough: map[string]int{leakReasonHelloNotMirrored: 2, leakReasonHelloResumption: 1}}
	if got := counts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("the counts: %+v, want %+v", got, want)
	}
	// With leak protection off nothing is mirrored, and nothing is counted.
	if off := newTestLeakGuard(t, leakModeOff).status(); off.MirroredHosts != nil || off.UnreadReasons != nil {
		t.Fatalf("off mode: %+v", off)
	}
}

// A tunnel opened inside a pass-through window is raw for as long as the
// client keeps it, after the window has ended too. Status goes on listing the
// host as not read until it is gone.
func TestAHostStaysUnreadWhileATunnelOfItsWindowIsOpen(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	clock := &testClock{now: time.Now()}
	rig.guard.handshakes.now, rig.guard.connections.now = clock.Now, clock.Now
	const host = "api.anthropic.com"
	rig.guard.handshakes.note(hostKey(host), false)
	if rig.guard.handshakes.note(hostKey(host), false) != handshakeBypassFirst {
		t.Fatal("no window opened")
	}
	if inspected, reasons := hostStatus(rig.leakStatus(t), host); inspected || !reflect.DeepEqual(reasons, []string{leakReasonTLSRefused}) {
		t.Fatalf("in the window: inspected = %v, for %v", inspected, reasons)
	}
	// The client opens its tunnel in the window and keeps it.
	config := distinctiveTLS(rig.providerRoots)
	conn, _ := rig.connectTLS(t, host, config)
	reader := bufio.NewReader(conn)
	body := anthropicBody("key " + leakSecretOne)
	request := fmt.Sprintf("POST /v1/messages HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s", host, len(body), body)
	clock.advance(handshakeBypassFirst + unreadPeriod + time.Second)
	if rig.guard.handshakes.bypassed(hostKey(host)) {
		t.Fatal("the window did not end")
	}
	// The window is over, and what the client sends on its tunnel still
	// reaches the provider unread.
	if response, _ := exchange(t, conn, reader, request); response.StatusCode != http.StatusOK || !bytes.Equal(rig.lastReceived().body, body) {
		t.Fatalf("the tunnel of the window: %d", response.StatusCode)
	}
	if inspected, reasons := hostStatus(rig.leakStatus(t), host); inspected || !reflect.DeepEqual(reasons, []string{leakReasonTLSRefused}) {
		t.Fatalf("after the window, with its tunnel open: inspected = %v, for %v", inspected, reasons)
	}
	_ = conn.Close()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if inspected, reasons := hostStatus(rig.leakStatus(t), host); inspected && reasons == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the host was not listed as inspected after the tunnel of its window closed")
		}
	}
	// A host that is not flagged has no mirror counts.
	if hosts := rig.leakStatus(t).MirroredHosts; len(hosts) != 1 || hosts[0].Host != mirrorHost {
		t.Fatalf("the mirrored hosts: %+v", hosts)
	}
}

// What is counted per host is bounded, and a host with an open connection is
// never dropped for another: status has to go on naming it.
func TestConnectionCountsAreKeptForABoundedNumberOfHosts(t *testing.T) {
	log := newConnectionLog()
	ended := log.passed("open.models.example", leakReasonHelloUnreadable)
	for i := 0; i < 4*maxRememberedHosts; i++ {
		host := fmt.Sprintf("h%d.models.example", i)
		log.noteCopied(host)
		log.passed(host, leakReasonHelloResumption)()
		if len(log.hosts) > maxRememberedHosts {
			t.Fatalf("%d hosts are counted", len(log.hosts))
		}
	}
	if reasons := log.unreadNow()["open.models.example"]; !reflect.DeepEqual(reasons, []string{leakReasonHelloUnreadable}) {
		t.Fatalf("a host with an open connection was dropped: %v", reasons)
	}
	// Ending a connection twice counts once.
	ended()
	ended()
	log.mu.Lock()
	open := log.hosts["open.models.example"].unread[leakReasonHelloUnreadable].open
	log.mu.Unlock()
	if open != 0 {
		t.Fatalf("%d connections are open after the one ended", open)
	}
	// When every host counted has an open connection a new one is not
	// counted, and ending it is nothing.
	full := newConnectionLog()
	for i := 0; i < maxRememberedHosts; i++ {
		full.passed(fmt.Sprintf("h%d.models.example", i), leakReasonHelloUnreadable)
	}
	full.passed("one-more.models.example", leakReasonHelloUnreadable)()
	full.noteCopied("one-more.models.example")
	full.noteRebuilt("one-more.models.example")
	if copied, rebuilt, passed := full.counts("one-more.models.example"); len(full.hosts) != maxRememberedHosts || copied != 0 || rebuilt != 0 || passed != nil {
		t.Fatalf("%d hosts are counted", len(full.hosts))
	}
}

// A service that settles on a cipher suite Go's own TLS does not use is not
// sent the request over the proxy's connection: the client's own connection
// is handed over instead, as when the proxy's handshake fails.
func TestMirrorPassesThroughWhenTheServiceSettlesOnALegacySuite(t *testing.T) {
	const legacy = tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	rig := newLeakRigWith(t, leakModeCensor, func(provider *httptest.Server) {
		provider.TLS.MaxVersion = tls.VersionTLS12
		provider.TLS.CipherSuites = []uint16{legacy}
	})
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	// A client that still offers the suite, after the ones it prefers.
	config := distinctiveTLS(rig.providerRoots)
	config.MaxVersion = tls.VersionTLS12
	config.CipherSuites = append(config.CipherSuites, legacy)
	conn, tap := rig.connectTLS(t, mirrorHost, config)
	if suite := conn.ConnectionState().CipherSuite; suite != legacy {
		t.Fatalf("the client and the service settled on %04x", suite)
	}
	body := chatBody("the key is " + leakSecretOne)
	if response, _ := exchange(t, conn, bufio.NewReader(conn), chatRequest(mirrorHost, body)); response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	if !bytes.Equal(rig.lastReceived().body, body) {
		t.Fatal("a connection passed through unread was changed")
	}
	// The copy was tried, and given up once it was known what the service
	// chose; then the client's own hello.
	sent := tap.hello(t)
	if rig.wire.count() != 2 {
		t.Fatalf("%d connections to the provider, want the copy and the client's own", rig.wire.count())
	}
	sameHello(t, sent, rig.wire.hello(t, 0))
	if !bytes.Equal(rig.wire.hello(t, 1), sent) {
		t.Fatal("the provider did not receive the client's own hello")
	}
	rig.wire.closed(t, 0)
	rig.passedThroughOnce(t, leakReasonUpstreamHandshake)
}
