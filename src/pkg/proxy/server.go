package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Server is the egress proxy front door. It holds a snapshot of the provider
// config + secret values fetched from Phase (refreshable), terminates TLS for
// bound hosts, swaps the agent's dummy for the live credential, enforces policy,
// and audits per request.
//
// It is an L4 (TCP) proxy: one accept loop peeks the first bytes of every
// connection, classifies the protocol, and dispatches to a handler —
//   - HTTP CONNECT (explicit-proxy clients via HTTPS_PROXY)
//   - TLS ClientHello (transparently-redirected clients; routed by SNI)
//   - Postgres startup (transparently-redirected DB clients) [handler TODO]
//   - anything else → raw passthrough.
//
// Unbound hosts (no binding/policy) PASS THROUGH untouched by default so the
// agent's own traffic (e.g. its LLM API) keeps working — only bound hosts get
// intercepted. denyUnbound flips to egress-allowlist lockdown.
//
// The agent presents NO Phase token — it only ever holds dummy placeholders. The
// proxy is the sole holder of Phase auth (used to fetch live creds).
type Server struct {
	ca          *CA
	listen      string
	transport   *http.Transport
	denyUnbound bool

	mu      sync.RWMutex
	cfg     *Config
	secrets map[string]string
}

func NewServer(cfg *Config, ca *CA, secrets map[string]string, listen string, denyUnbound bool) *Server {
	// Clone the default transport but disable proxy-from-env, so the proxy's own
	// upstream calls never chain through HTTPS_PROXY (i.e. through itself).
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return &Server{ca: ca, listen: listen, transport: t, cfg: cfg, secrets: secrets, denyUnbound: denyUnbound}
}

// UpdateSecrets atomically swaps in a freshly fetched config + secret snapshot.
func (s *Server) UpdateSecrets(cfg *Config, secrets map[string]string) {
	s.mu.Lock()
	s.cfg, s.secrets = cfg, secrets
	s.mu.Unlock()
}

func (s *Server) snapshot() (*Config, map[string]string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg, s.secrets
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve runs the L4 accept loop on an already-bound listener. It serves BOTH
// explicit-proxy clients (which send CONNECT) and transparently-redirected
// clients (which send raw TLS/Postgres) — classification figures out which.
func (s *Server) Serve(ln net.Listener) error {
	s.startDBListeners() // explicit per-DB-port listeners (cross-platform capture)
	log.Printf("[proxy] listening on %s", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			c.Close()
			continue
		}
		go s.dispatch(tc)
	}
}

// dispatch peeks the first bytes, classifies the protocol, and routes.
func (s *Server) dispatch(conn *net.TCPConn) {
	defer conn.Close()
	who := conn.RemoteAddr().String()
	br := bufio.NewReader(conn)
	pc := &bufConn{Conn: conn, br: br}

	// Peek (non-consuming) enough to classify. A deadline guards against a
	// server-speaks-first protocol (e.g. MySQL) that would never send first.
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	head, _ := br.Peek(8)
	_ = conn.SetReadDeadline(time.Time{})
	if len(head) == 0 {
		return
	}

	switch {
	case looksHTTP(head):
		s.handleHTTPProxy(pc, br, who)
	case head[0] == 0x16:
		s.handleTLS(pc, conn, who)
	case looksPostgres(head):
		s.handlePostgres(pc, conn, who)
	default:
		s.handleUnknown(pc, conn, who)
	}
}

// handleHTTPProxy serves an explicit-proxy client (CONNECT host:port).
func (s *Server) handleHTTPProxy(pc *bufConn, br *bufio.Reader, who string) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		// Plain-HTTP forward proxying is not implemented (agents use HTTPS).
		io.WriteString(pc, "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n")
		return
	}
	host := req.Host
	hostname := host
	if h, _, e := net.SplitHostPort(host); e == nil {
		hostname = h
	}
	log.Printf("[conn] agent=%s CONNECT %s", who, host)

	cfg, secrets := s.snapshot()
	binding := cfg.httpBindingFor(hostname)
	if binding == nil && s.denyUnbound {
		log.Printf("[deny] agent=%s host=%s: no binding, egress denied (lockdown)", who, hostname)
		io.WriteString(pc, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if _, err := io.WriteString(pc, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if binding == nil {
		log.Printf("[pass] agent=%s %s (no rule — passthrough)", who, host)
		tunnel(pc, host)
		return
	}
	s.intercept(pc, hostname, binding, secrets, who)
}

// handleTLS serves a transparently-redirected TLS client: peek SNI, route.
func (s *Server) handleTLS(pc *bufConn, conn *net.TCPConn, who string) {
	origDst, err := originalDst(conn)
	if err != nil {
		origDst = "n/a"
	}
	sni, peeked, err := peekClientHello(pc)
	if err != nil {
		log.Printf("[conn] agent=%s origDst=%s: TLS peek failed: %v", who, origDst, err)
		return
	}
	log.Printf("[conn] agent=%s sni=%q origDst=%s (transparent)", who, sni, origDst)

	cfg, secrets := s.snapshot()
	var binding *Binding
	if sni != "" {
		binding = cfg.httpBindingFor(sni)
	}
	if binding == nil {
		if s.denyUnbound {
			log.Printf("[deny] agent=%s sni=%q dst=%s: no binding, egress denied (lockdown)", who, sni, origDst)
			return
		}
		if origDst == "n/a" {
			log.Printf("[pass] agent=%s sni=%q: unknown original dst, cannot passthrough", who, sni)
			return
		}
		log.Printf("[pass] agent=%s sni=%q dst=%s (no rule — passthrough)", who, sni, origDst)
		tunnelPrefixed(pc, origDst, peeked)
		return
	}
	// Replay the peeked ClientHello so the TLS server handshake sees a full stream.
	s.intercept(&prefixConn{Conn: pc, prefix: peeked}, sni, binding, secrets, who)
}

// handlePostgres routes a transparently-redirected Postgres connection to the
// engine, with the real upstream recovered via SO_ORIGINAL_DST.
func (s *Server) handlePostgres(pc *bufConn, conn *net.TCPConn, who string) {
	origDst, err := originalDst(conn)
	if err != nil || origDst == "n/a" || origDst == "" {
		log.Printf("[pg] agent=%s: Postgres but original dst unknown — cannot route", who)
		return
	}
	cfg, secrets := s.snapshot()
	b := cfg.dbBindingFor(origDst)
	if b == nil {
		if s.denyUnbound {
			log.Printf("[deny] agent=%s dst=%s: Postgres, no binding (lockdown)", who, origDst)
			return
		}
		log.Printf("[pass] agent=%s dst=%s: Postgres, no binding — passthrough", who, origDst)
		tunnel(pc, origDst)
		return
	}
	eng := dbEngines[b.Protocol]
	if eng == nil {
		tunnel(pc, origDst)
		return
	}
	eng.Handle(pc, origDst, b, secrets, NewStmtPolicy(b.Provider, who, b.DenyStatements), who)
}

// startDBListeners opens one local listener per DB binding that pins a
// ListenPort (explicit per-DB-port capture: the agent's DSN host:port points at
// the listener, whose identity selects the upstream). Cross-platform; no sudo.
func (s *Server) startDBListeners() {
	cfg, _ := s.snapshot()
	for i := range cfg.Bindings {
		b := cfg.Bindings[i] // copy; stable for the listener's lifetime
		eng := dbEngines[b.Protocol]
		if eng == nil || b.ListenPort == 0 {
			continue
		}
		addr := fmt.Sprintf("127.0.0.1:%d", b.ListenPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("[db] cannot listen %s for %s: %v", addr, b.Provider, err)
			continue
		}
		log.Printf("[db] %s %s on %s -> %s", b.Protocol, b.Provider, addr, b.Host)
		go s.serveDB(ln, eng, b)
	}
}

func (s *Server) serveDB(ln net.Listener, eng DBEngine, b Binding) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_, secrets := s.snapshot() // fresh secrets each connection (rotation)
			who := conn.RemoteAddr().String()
			eng.Handle(conn, b.Host, &b, secrets, NewStmtPolicy(b.Provider, who, b.DenyStatements), who)
		}(c)
	}
}

// handleUnknown passes an unrecognized protocol through to its original dst.
func (s *Server) handleUnknown(pc *bufConn, conn *net.TCPConn, who string) {
	origDst, err := originalDst(conn)
	if err != nil || origDst == "n/a" || origDst == "" {
		log.Printf("[pass] agent=%s: unrecognized protocol, no original dst — dropping", who)
		return
	}
	if s.denyUnbound {
		log.Printf("[deny] agent=%s dst=%s: unrecognized protocol (lockdown)", who, origDst)
		return
	}
	log.Printf("[pass] agent=%s dst=%s (unrecognized protocol — passthrough)", who, origDst)
	tunnel(pc, origDst)
}

// --- classification ---

func looksHTTP(head []byte) bool {
	for _, m := range []string{"CONNECT ", "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE "} {
		if len(head) >= len(m) && string(head[:len(m)]) == m {
			return true
		}
	}
	return false
}

func looksPostgres(head []byte) bool {
	if len(head) < 8 {
		return false
	}
	// bytes[4:8] = a known startup/request code (big-endian).
	code := uint32(head[4])<<24 | uint32(head[5])<<16 | uint32(head[6])<<8 | uint32(head[7])
	switch code {
	case 196608, // StartupMessage, protocol 3.0
		80877103, // SSLRequest
		80877104, // GSSENCRequest
		80877102: // CancelRequest
		return true
	}
	return false
}

// --- connection helpers ---

// bufConn reads via a bufio.Reader (so already-peeked bytes are replayed) while
// writes/close/etc. go to the underlying conn.
type bufConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.br.Read(b) }

// prefixConn replays an already-read prefix (a peeked ClientHello) before
// continuing to read from the underlying conn.
type prefixConn struct {
	net.Conn
	prefix []byte
	off    int
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if p.off < len(p.prefix) {
		n := copy(b, p.prefix[p.off:])
		p.off += n
		return n, nil
	}
	return p.Conn.Read(b)
}

// tunnel relays bytes verbatim between the client and the real upstream without
// terminating TLS — the client does end-to-end TLS directly with the upstream.
func tunnel(client net.Conn, hostport string) {
	upstream, err := net.DialTimeout("tcp", hostport, 15*time.Second)
	if err != nil {
		log.Printf("[pass] dial %s failed: %v", hostport, err)
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, client); done <- struct{}{} }()
	go func() { io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// tunnelPrefixed is tunnel() that first replays already-peeked bytes upstream.
func tunnelPrefixed(client net.Conn, dst string, prefix []byte) {
	upstream, err := net.DialTimeout("tcp", dst, 15*time.Second)
	if err != nil {
		log.Printf("[pass] dial %s failed: %v", dst, err)
		return
	}
	defer upstream.Close()
	if len(prefix) > 0 {
		if _, err := upstream.Write(prefix); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, client); done <- struct{}{} }()
	go func() { io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// peekClientHello reads the first TLS record (the ClientHello) in full, returns
// the SNI server name and the raw bytes read (to be replayed).
func peekClientHello(c net.Conn) (string, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", hdr, err
	}
	if hdr[0] != 0x16 { // not a TLS handshake record
		return "", hdr, nil
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > 16384 {
		return "", hdr, fmt.Errorf("invalid TLS record length %d", recLen)
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(c, body); err != nil {
		return "", append(hdr, body...), err
	}
	return parseSNI(body), append(hdr, body...), nil
}

// parseSNI extracts the host_name SNI from a ClientHello handshake message.
func parseSNI(b []byte) string {
	if len(b) < 38 || b[0] != 0x01 { // not a ClientHello
		return ""
	}
	pos := 38 // msg type(1) + length(3) + version(2) + random(32)
	if pos >= len(b) {
		return ""
	}
	pos += 1 + int(b[pos]) // session id
	if pos+2 > len(b) {
		return ""
	}
	pos += 2 + (int(b[pos])<<8 | int(b[pos+1])) // cipher suites
	if pos+1 > len(b) {
		return ""
	}
	pos += 1 + int(b[pos]) // compression methods
	if pos+2 > len(b) {
		return ""
	}
	extLen := int(b[pos])<<8 | int(b[pos+1])
	pos += 2
	end := pos + extLen
	if end > len(b) {
		end = len(b)
	}
	for pos+4 <= end {
		etype := int(b[pos])<<8 | int(b[pos+1])
		elen := int(b[pos+2])<<8 | int(b[pos+3])
		pos += 4
		if pos+elen > end {
			break
		}
		if etype == 0x0000 { // server_name
			return parseServerName(b[pos : pos+elen])
		}
		pos += elen
	}
	return ""
}

func parseServerName(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	pos := 2 // server_name_list length
	end := 2 + (int(b[0])<<8 | int(b[1]))
	if end > len(b) {
		end = len(b)
	}
	for pos+3 <= end {
		ntype := b[pos]
		nlen := int(b[pos+1])<<8 | int(b[pos+2])
		pos += 3
		if pos+nlen > end {
			break
		}
		if ntype == 0 { // host_name
			return string(b[pos : pos+nlen])
		}
		pos += nlen
	}
	return ""
}

// intercept terminates TLS toward the client, then swaps/injects + enforces +
// audits each request before forwarding to the real upstream.
func (s *Server) intercept(client net.Conn, hostname string, b *Binding, secrets map[string]string, who string) {
	tlsConn := tls.Server(client, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := chi.ServerName
			if name == "" {
				name = hostname
			}
			return s.ca.leafFor(name)
		},
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[deny] agent=%s host=%s client TLS handshake failed: %v (client may pin its CA)", who, hostname, err)
		return
	}
	defer tlsConn.Close()

	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = hostname
		req.RequestURI = ""

		method, urlPath := req.Method, req.URL.Path

		if reason := b.denied(method, urlPath); reason != "" {
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
			log.Printf("[block] agent=%s provider=%s %s %s%s (%s)", who, b.Provider, method, hostname, urlPath, reason)
			writeStatus(tlsConn, http.StatusForbidden, "blocked by Phase egress policy ("+b.Provider+": "+reason+")\n")
			if req.Close {
				return
			}
			continue
		}

		cred, applied := applyCredential(req, b, secrets)

		resp, err := s.transport.RoundTrip(req)
		if err != nil {
			log.Printf("[error] agent=%s provider=%s %s %s%s: %v", who, b.Provider, method, hostname, urlPath, err)
			writeStatus(tlsConn, http.StatusBadGateway, "upstream error\n")
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.TransferEncoding = nil
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		// The client speaks HTTP/1.1 to us; the upstream may have answered over
		// HTTP/2. Normalize so resp.Write emits a valid "HTTP/1.1 ..." status line.
		resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/1.1", 1, 1
		resp.Close = false
		log.Printf("[audit] agent=%s provider=%s %s %s%s cred=%s(%v) -> %d (%dB)",
			who, b.Provider, method, hostname, urlPath, cred, applied, resp.StatusCode, len(body))
		if err := resp.Write(tlsConn); err != nil {
			return
		}
		if req.Close || resp.Close {
			return
		}
	}
}

func writeStatus(w io.Writer, code int, body string) {
	resp := &http.Response{
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          io.NopCloser(bytes.NewReader([]byte(body))),
		ContentLength: int64(len(body)),
	}
	_ = resp.Write(w)
}
