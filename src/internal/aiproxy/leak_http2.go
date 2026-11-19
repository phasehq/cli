package aiproxy

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"

	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"golang.org/x/net/http2"
)

// Some model hosts are spoken to over HTTP/2 and nothing else: Cursor's agent
// offers h2 alone for its stream and gives up on a proxy that answers with
// HTTP/1.1. For a host whose rule says its clients may speak HTTP/2 the
// proxy's TLS offers both, and a tunnel whose client chose h2 is served here.
//
// Each stream is one request, handled like a request of the HTTP/1.1 tunnel
// (httpProxy.process), with two differences that a stream needs. Its body is
// not waited for: the client may go on sending while the service answers, so
// what the service sends back goes to the client as it comes. And nothing is
// done to it that the client and the service did not do themselves: what is
// forwarded is what was sent, less the headers that belong to one hop.

// maxTunnelStreams is how many requests one HTTP/2 tunnel carries at a time.
// A client is told the limit and waits with the next request until one ends.
const maxTunnelStreams = 100

// serveHTTP2 serves the requests of a tunnel whose client chose HTTP/2 until
// the connection ends. It returns when the last of them has.
func (p *httpProxy) serveHTTP2(ctx context.Context, client *tls.Conn, host string, port int, authentication tunnelAuthentication) {
	streams := &streamCount{idle: make(chan struct{})}
	// The connection goes when the tunnel's context ends, and when the session
	// is revoked or expires, as a raw tunnel's does: ServeConn waits for that.
	stop := make(chan struct{})
	defer close(stop)
	go p.watchWebSocket(ctx, client, client, p.state.availability, stop)
	server := &http2.Server{MaxConcurrentStreams: maxTunnelStreams}
	server.ServeConn(client, &http2.ServeConnOpts{
		Context: ctx,
		// A client that breaks the protocol is that client's business, not a
		// line on the terminal of whoever runs the proxy.
		BaseConfig: &http.Server{MaxHeaderBytes: 1 << 20, ErrorLog: log.New(io.Discard, "", 0)},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !streams.enter() {
				return
			}
			defer streams.leave()
			p.serveTunnelStream(w, r, host, port, &authentication)
		}),
	})
	// The connection is gone. A stream still being served sees its context
	// end, and with it what it sent on; none outlives the tunnel.
	_ = client.Close()
	streams.wait()
}

// streamCount counts the streams of one connection that are being served, so
// that the tunnel is not let go of while one still runs.
type streamCount struct {
	mu     sync.Mutex
	open   int
	closed bool
	idle   chan struct{}
}

// enter counts a stream in. It reports false once the tunnel is being let
// go of: a stream that starts that late is not served.
func (c *streamCount) enter() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.open++
	return true
}

func (c *streamCount) leave() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open--; c.open == 0 && c.closed {
		close(c.idle)
	}
}

// wait lets no further stream in and returns when none is being served.
func (c *streamCount) wait() {
	c.mu.Lock()
	c.closed = true
	if c.open == 0 {
		close(c.idle)
	}
	c.mu.Unlock()
	<-c.idle
}

// serveTunnelStream handles one request of an HTTP/2 tunnel.
func (p *httpProxy) serveTunnelStream(w http.ResponseWriter, r *http.Request, host string, port int, authentication *tunnelAuthentication) {
	requestHost, requestPort, err := phaseproxy.ParseAuthority(r.Host, port)
	if err != nil || requestHost != host || requestPort != port {
		writeProxyError(w, &requestFailure{status: http.StatusForbidden, code: "connect_authority_mismatch", message: "The tunneled request target differs from CONNECT."})
		return
	}
	r.URL.Scheme = "https"
	r.URL.Host = net.JoinHostPort(host, strconv.Itoa(port))
	result := p.process(r, authentication)
	if result.failure != nil {
		result.failure.eventID = result.event.EventID
		if p.events != nil {
			p.events.Emit(result.event)
		}
		writeProxyError(w, result.failure)
		return
	}
	// Closing the answer's body is what tells the service when the client
	// went away before the answer was whole.
	defer result.response.Body.Close()
	if result.event.EventID != "" && p.events != nil {
		p.events.Emit(result.event)
	}
	relayStreamedResponse(w, result.response, result.event.EventID)
}

// relayStreamedResponse sends an answer on as it comes: its headers at once,
// each piece of its body as soon as it is read, and its trailers. An answer
// that breaks off resets the client's stream, so the client does not take
// what it got for the whole of it.
func relayStreamedResponse(w http.ResponseWriter, response *http.Response, eventID string) {
	removeHopHeaders(response.Header)
	header := w.Header()
	// Assigned by key, so names reach the client as the service wrote them.
	for key, values := range response.Header {
		header[key] = append(header[key], values...)
	}
	// Trailers the service announced are announced to the client. Those it
	// did not announce are sent all the same, when they come.
	announced := make(map[string]bool, len(response.Trailer))
	for name := range response.Trailer {
		announced[name] = true
		header.Add("Trailer", name)
	}
	if eventID != "" {
		header.Set(eventIDHeader, eventID)
	}
	w.WriteHeader(response.StatusCode)
	flusher, _ := w.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}
	flush()
	buffer := make([]byte, 32<<10)
	for {
		n, err := response.Body.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				return
			}
			flush()
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(http.ErrAbortHandler)
		}
	}
	for name, values := range response.Trailer {
		if announced[name] {
			header[name] = values
		} else {
			header[http.TrailerPrefix+name] = values
		}
	}
}

// unaltered sends a request with the headers it came with and none of the
// transport's own. net/http names itself in a User-Agent when a request has
// none; a header that is present and empty is how it is told to send none.
type unaltered struct{ base http.RoundTripper }

func (t unaltered) RoundTrip(request *http.Request) (*http.Response, error) {
	if _, sent := request.Header["User-Agent"]; !sent {
		// The request is the proxy's own copy of the client's, made to be sent.
		request.Header["User-Agent"] = []string{""}
	}
	return t.base.RoundTrip(request)
}

// unalteredTransport returns what sends the requests of a host whose clients
// may speak HTTP/2, when no Connection covers them: the proxy's transport for
// such hosts, so its TLS and its dialer, with two things changed. It asks for
// no encoding of its own, so an answer is never decompressed on its way back
// to a client that did not ask for it compressed; and it speaks HTTP/2 to a
// service that offers it, which a stream that stays open needs.
func (p *httpProxy) unalteredTransport() http.RoundTripper {
	p.unalteredOnce.Do(func() {
		base := p.unboundTransport
		if base == nil {
			base = p.transport
		}
		if own, ok := base.(*http.Transport); ok {
			own = own.Clone()
			own.DisableCompression = true
			own.ForceAttemptHTTP2 = true
			p.unalteredOwn, base = own, own
		}
		p.unaltered = unaltered{base: base}
	})
	return p.unaltered
}
