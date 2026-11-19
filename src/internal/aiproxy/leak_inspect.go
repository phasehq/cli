package aiproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phasehq/cli/pkg/censor"
)

const (
	codeSecretInRequest = "secret_in_request"
	leakEventType       = "leak_protection"

	// The Console keeps at most this much of one detail string.
	maxLeakDetailText = 512
	// An event names at most this many placeholders.
	maxLeakPlaceholders = 20

	// outcomeCensored means something in the request was replaced before it
	// went out; outcomeReported that something was found and nothing changed
	// (a header, an alert, text the provider signed); outcomeObserved the same
	// in observe mode.
	outcomeCensored = "censored"
	outcomeReported = "reported"
	outcomeObserved = "observed"
	outcomeUnread   = "unread"
	outcomeBypass   = "bypass"

	leakReasonFound       = "secret_in_request"
	leakReasonOverLimit   = "body_over_limit"
	leakReasonUndecodable = "body_undecodable"
	leakReasonCompressed  = "message_compressed"
	leakReasonTLSRefused  = "tls_refused"
	// Why a message of a Connect stream went on unread: it is compressed with
	// an encoding the proxy does not undo (any but gzip, or none named), or
	// it is marked as gzip and does not inflate.
	leakReasonMessageEncoding    = "message_encoding_unsupported"
	leakReasonMessageUndecodable = "message_undecodable"
	// Why else an envelope went on unread: the request ended inside it, or it
	// was marked as the end of a stream, which only a service sends.
	leakReasonMessageTruncated = "message_truncated"
	leakReasonMessageFlags     = "message_flags_unexpected"
	// Why the rest of a stream went on unread: what came was no envelope.
	leakReasonNotEnvelopes = "body_not_enveloped"
	// Why a body went on unread: its length was not stated, and its kind may
	// never end or no byte of it came for leakBodyIdle.
	leakReasonStreamed = "body_streamed"

	// Why a whole connection to a host that takes only its own client's TLS
	// was passed through unread: its first bytes were not one whole
	// ClientHello in one TLS record; the hello resumes a session in a way the
	// proxy cannot answer or copy; no exact copy of it can be sent; the
	// proxy's own connection to the service failed; or the service chose a
	// protocol other than HTTP/1.1.
	leakReasonHelloUnreadable   = "hello_unreadable"
	leakReasonHelloResumption   = "hello_resumption"
	leakReasonHelloNotMirrored  = "hello_not_mirrored"
	leakReasonUpstreamHandshake = "upstream_handshake_failed"
	leakReasonUpstreamNotHTTP1  = "upstream_not_http1"

	// How much an unread event covers: one request, one message (of a
	// WebSocket, or of a Connect stream), or a whole connection.
	leakScopeRequest    = "request"
	leakScopeMessage    = "message"
	leakScopeConnection = "connection"

	// What a request came in as, for its events. A WebSocket's messages say
	// websocket instead.
	leakProtocolHTTP  = "http"
	leakProtocolHTTP2 = "http2"

	// An event's severity. A request is high when it held this many distinct
	// placeholders, or one of Phase's own tokens, or was blocked; medium from
	// leakSeverityMediumPlaceholders up; low when nothing in it could be
	// replaced or blocked (alerts, findings in text the provider signed).
	leakSeverityHigh               = "high"
	leakSeverityMedium             = "medium"
	leakSeverityLow                = "low"
	leakSeverityHighPlaceholders   = 5
	leakSeverityMediumPlaceholders = 1

	// maxScanPlaceholders is how many distinct placeholders one request is
	// counted to, exactly. A request that holds more says so
	// (placeholdersCapped) and its counts are a floor.
	maxScanPlaceholders = 4096
)

// Login headers are the harness's own business and never judged; the proxy
// authorization never leaves the proxy at all.
var leakSkippedHeaders = map[string]bool{
	"Authorization": true, "Proxy-Authorization": true, "X-Api-Key": true, "Cookie": true,
}

// Phase's own tokens block like an inventory hit in a URL; other pattern
// rules there are only reported.
var phaseTokenLabels = map[string]bool{"phase_pat": true, "phase_service_token": true, "phase_agent_token": true}

// phaseTokenRules are the rules that run on every path of an inspected host.
var phaseTokenRules = []string{"phase-user-token", "phase-service-token", "phase-agent-token"}

// leakScan is what inspecting one request or message found. It holds counts,
// placeholders, labels and where things were, never matched content.
type leakScan struct {
	match    *leakHostMatch
	mode     string
	protocol string
	opts     censor.ScanOptions
	where    []string
	// inventory and redacted count what would be replaced; left what was
	// found in text the provider signed and is never changed.
	inventory int
	redacted  int
	alerts    int
	left      int
	// placeholders are the distinct ones found, in order, as leakFound
	// remembers them and up to maxScanPlaceholders. One found many times is one.
	placeholders []string
	// replaceable are those of them found where the request can be rewritten.
	// They were replaced when changed is set.
	replaceable []string
	// seen and seenReplaceable hold the same placeholders, to look one up in.
	seen, seenReplaceable map[string]struct{}
	// capped says there were more distinct placeholders than are counted: a
	// list above is full, or a report listed only the first of its findings.
	capped bool
	// phaseToken says one of Phase's own tokens was found.
	phaseToken bool
	// text says the body or message was read as text, JSON or not.
	text bool
	// listed are the placeholders an event names.
	listed  []string
	labels  []string
	block   bool
	changed bool
	unread  string
	// scope says how much the unread reason covers.
	scope string
}

func (s *leakScan) found() bool {
	return s.inventory > 0 || s.redacted > 0 || s.alerts > 0 || s.left > 0
}

func (s *leakScan) noteWhere(where string) {
	if !containsString(s.where, where) {
		s.where = append(s.where, where)
	}
}

func (s *leakScan) addFinding(f censor.Finding, where string) {
	s.noteWhere(where)
	switch {
	case f.Action == "left":
		// Nothing was replaced, so no placeholder stands in the request.
		s.left++
		return
	case f.Kind == "inventory":
		s.inventory++
	case f.Action == "redact":
		s.redacted++
	default:
		s.alerts++
	}
	if phaseTokenLabels[f.Label] {
		s.phaseToken = true
	}
	if f.Label != "" && !containsString(s.labels, f.Label) {
		s.labels = append(s.labels, f.Label)
	}
	if f.Placeholder != "" {
		s.keep(&s.placeholders, &s.seen, leakFound(f))
	}
}

// leakFound is what a finding is remembered and counted by: its placeholder
// and, for a withheld value, its number among them. It is never written.
func leakFound(f censor.Finding) string {
	if f.Withheld == 0 {
		return f.Placeholder
	}
	return f.Placeholder + "\x00" + strconv.Itoa(f.Withheld)
}

// leakPlaceholder is the placeholder of what leakFound remembered.
func leakPlaceholder(found string) string {
	placeholder, _, _ := strings.Cut(found, "\x00")
	return placeholder
}

// keep adds a placeholder to one of the scan's lists unless the list holds it
// already. A list that is full says the scan's counts are capped.
func (s *leakScan) keep(list *[]string, seen *map[string]struct{}, placeholder string) {
	if _, known := (*seen)[placeholder]; known {
		return
	}
	if len(*list) >= maxScanPlaceholders {
		s.capped = true
		return
	}
	if *seen == nil {
		*seen = map[string]struct{}{}
	}
	(*seen)[placeholder] = struct{}{}
	*list = append(*list, placeholder)
}

// addReport records what was found in bytes that can be rewritten.
func (s *leakScan) addReport(report *censor.Report, where string) {
	if report == nil {
		return
	}
	// A report lists only the first of very many findings; the placeholders
	// of the rest are not known.
	if report.Truncated {
		s.capped = true
	}
	for _, finding := range report.Findings {
		s.addFinding(finding, where)
		if finding.Action != "left" && finding.Placeholder != "" {
			s.keep(&s.replaceable, &s.seenReplaceable, leakFound(finding))
		}
	}
}

// addFixed records findings in bytes that cannot be rewritten. In a URL an
// inventory hit or a Phase token blocks the request. Headers never block:
// Phase's default secret type is secret, so identity values such as an
// organisation id get registered, and the harness sends them in a header of
// every model request; blocking would end the session with no way out.
func (s *leakScan) addFixed(matches []censor.Match, where string, canBlock bool) {
	for _, match := range matches {
		s.addFinding(match.Finding, where)
		// A value known only from the store is reported and never blocks: one
		// that sits in every URL would otherwise stop every request for 30 days.
		if canBlock && ((match.Kind == "inventory" && !match.Loaded) || phaseTokenLabels[match.Label]) {
			s.block = true
		}
	}
}

// leaveUnread marks the scan as covering something that was not read.
func (s *leakScan) leaveUnread(reason, scope string) {
	s.unread, s.scope = reason, scope
}

// replaced is how many distinct placeholders were actually put in place of a
// value in what went out.
func (s *leakScan) replaced() int {
	if !s.changed {
		return 0
	}
	return len(s.replaceable)
}

// severity grades what the scan found. blocked says the request was stopped.
func (s *leakScan) severity(blocked bool) string {
	switch {
	case blocked || s.phaseToken || len(s.placeholders) >= leakSeverityHighPlaceholders:
		return leakSeverityHigh
	case len(s.placeholders) >= leakSeverityMediumPlaceholders:
		return leakSeverityMedium
	case s.alerts > 0 || s.left > 0:
		return leakSeverityLow
	}
	return ""
}

// leakObservation is one thing leak protection did, as a harness that
// measures it is told through httpProxy.observe. It holds request content:
// nothing in the proxy keeps one or sends one anywhere.
type leakObservation struct {
	// scan is what was found in a body or a message; nil for a connection.
	scan       *leakScan
	host, path string
	// original is the body or message as it came, decoded, and forwarded what
	// goes on in its place. Both are nil when it was too large to hold, and
	// forwarded when it was blocked.
	original, forwarded []byte
	blocked             bool
	// took is how long reading it and deciding took, once it was in hand.
	took time.Duration
	// streamed says it is one message of a Connect stream, of which a request
	// can send any number.
	streamed bool
	// connection is why a whole connection was passed through unread, and
	// window why a pass-through window opened.
	connection, window string
}

// observeRead tells the harness, when there is one, what was done to a body
// or a message. rewritten is what replaces it when the scan changed it.
func (p *httpProxy) observeRead(scan *leakScan, host, path string, original, rewritten []byte, blocked bool, began time.Time) {
	p.observeUnit(scan, host, path, original, rewritten, blocked, began, false)
}

// observeUnit is observeRead for a body, or for one message of a stream.
func (p *httpProxy) observeUnit(scan *leakScan, host, path string, original, rewritten []byte, blocked bool, began time.Time, streamed bool) {
	if p.observe == nil {
		return
	}
	observation := leakObservation{scan: scan, host: host, path: path, original: original, blocked: blocked, took: time.Since(began), streamed: streamed}
	switch {
	case blocked:
	case scan.changed:
		observation.forwarded = rewritten
	default:
		observation.forwarded = original
	}
	p.observe(observation)
}

var leakMetaBuffers = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// findInURL scans a request's path and query. It is run for every request
// on an inspected path, so it builds the bytes in a pooled buffer and costs
// nothing beyond the scan.
func (g *leakGuard) findInURL(target *url.URL, opts censor.ScanOptions) []censor.Match {
	buffer := leakMetaBuffers.Get().(*bytes.Buffer)
	buffer.Reset()
	defer leakMetaBuffers.Put(buffer)
	path, query := target.EscapedPath(), target.RawQuery
	writeURL := func(path, query string) {
		buffer.WriteString(path)
		if query != "" || target.ForceQuery {
			buffer.WriteByte('?')
			buffer.WriteString(query)
		}
	}
	writeURL(path, query)
	matches := g.index.FindWith(buffer.Bytes(), opts)
	// The service reads the URL decoded, so a value percent-encoded on the wire
	// is looked for in that form too. The wire form stays read: decoding turns
	// a '+' in a value into a space.
	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		decodedPath = path
	}
	decodedQuery, err := url.QueryUnescape(query)
	if err != nil {
		decodedQuery = query
	}
	if decodedPath == path && decodedQuery == query {
		return matches
	}
	type finding struct{ kind, placeholder, rule string }
	seen := make(map[finding]struct{}, len(matches))
	for _, match := range matches {
		seen[finding{match.Kind, match.Placeholder, match.Rule}] = struct{}{}
	}
	buffer.Reset()
	writeURL(decodedPath, decodedQuery)
	for _, match := range g.index.FindWith(buffer.Bytes(), opts) {
		if _, found := seen[finding{match.Kind, match.Placeholder, match.Rule}]; !found {
			matches = append(matches, match)
		}
	}
	return matches
}

// holdsRegistered reports whether text holds a value registered for leak
// protection, so an event field that carries one can be replaced. A request's
// path is cut from the wire form, so its decoded form is read too.
func (g *leakGuard) holdsRegistered(text string) bool {
	if g == nil || text == "" {
		return false
	}
	forms := []string{text}
	if decoded, err := url.PathUnescape(text); err == nil && decoded != text {
		forms = append(forms, decoded)
	}
	for _, form := range forms {
		for _, match := range g.index.Find([]byte(form)) {
			if match.Kind == "inventory" {
				return true
			}
		}
	}
	return false
}

// scanHeaders looks at every header but the login headers, for the report
// only: rewriting a header could change what it means, and blocking on one
// could stop every request of the session.
func (g *leakGuard) scanHeaders(scan *leakScan, header http.Header) {
	buffer := leakMetaBuffers.Get().(*bytes.Buffer)
	buffer.Reset()
	defer leakMetaBuffers.Put(buffer)
	for name, values := range header {
		if leakSkippedHeaders[http.CanonicalHeaderKey(name)] {
			continue
		}
		for _, value := range values {
			buffer.WriteString(value)
			buffer.WriteByte('\n')
		}
	}
	if buffer.Len() == 0 {
		return
	}
	if matches := g.index.FindWith(buffer.Bytes(), scan.opts); len(matches) > 0 {
		scan.addFound(leakPartHeader, matches, "header")
	}
}

// inspectForLeaks reads a request to a model host before anything else the
// proxy does to it: before the secret guard, the access policy and credential
// injection, so nothing the proxy adds is scanned and a rewritten body is what
// gets signed and sent. It changes upstream's body in place when it rewrites
// it, and returns a result only when the request is refused. flow says how
// the request's connection reached the proxy and whose it is, which is what
// the table decides by (leakHostTable.lookupFlow).
func (p *httpProxy) inspectForLeaks(req, upstream *http.Request, binding *binding, flow FlowContext, host string, port int, started time.Time) *processedResponse {
	guard := p.leak
	if guard == nil || req.URL == nil {
		return nil
	}
	match := guard.inspects(flow, host, port)
	if !match.inspectsPath(req.URL.Path) {
		return nil
	}
	if validWebSocketRequest(req) {
		// Frames stay plain only when no compression is agreed.
		upstream.Header.Del("Sec-WebSocket-Extensions")
	}
	opts := guard.scanOptionsFor(match, req.URL.Path)
	// On a host that speaks Connect the Content-Type says what the body is,
	// and a Connect or gRPC call carries conversation content whatever its path
	// or, on a path shaped like a call, whatever its type.
	kind := match.body(req.Header)
	if kind.conversation() || (match.inPlace() && connectCallPath(req.URL.Path)) {
		opts = censor.ScanOptions{}
	}
	protocol := leakProtocolHTTP
	if req.ProtoMajor == 2 {
		protocol = leakProtocolHTTP2
	}
	// The URL of every request is read, with a body or without one; a request
	// without a body (Codex polls about once a second) costs only this scan.
	urlMatches := guard.findInURL(req.URL, opts)
	if upstream.Body == nil || upstream.Body == http.NoBody || upstream.ContentLength == 0 {
		if len(urlMatches) == 0 {
			return nil
		}
		scan := guard.newScan(match, protocol, opts)
		scan.addFound(leakPartURL, urlMatches, "url")
		return p.finishLeakScan(req, upstream, binding, host, port, scan, nil, "", started)
	}
	scan := guard.newScan(match, protocol, opts)
	scan.addFound(leakPartURL, urlMatches, "url")
	if kind.stream() {
		// A stream has no end to wait for: it is read as it is sent.
		return p.readConnectStream(req, upstream, binding, host, port, scan, kind, started)
	}
	var body []byte
	var err error
	if upstream.ContentLength < 0 {
		// A body with no stated length, chunked over HTTP/1.1 or open over
		// HTTP/2, may stay open while the service answers. A unary call's end
		// comes, and is waited for a while.
		unread := leakReasonStreamed
		if kind.unary() {
			pump := newBodyPump(req.Context(), upstream.Body)
			var ended bool
			if body, ended, err = pump.collect(maxLeakBody, leakBodyIdle); err == nil && !ended {
				upstream.Body = struct {
					io.Reader
					io.Closer
				}{io.MultiReader(bytes.NewReader(body), pump), upstream.Body}
				upstream.GetBody = nil
				if len(body) > maxLeakBody {
					unread = leakReasonOverLimit
				}
			}
			if err == nil && ended {
				unread = ""
			}
		}
		if err == nil && unread != "" {
			scan.leaveUnread(unread, leakScopeRequest)
			stopped := p.finishLeakScan(req, upstream, binding, host, port, scan, nil, "", started)
			p.observeRead(scan, host, req.URL.EscapedPath(), nil, nil, stopped != nil, time.Now())
			return stopped
		}
	} else {
		body, err = io.ReadAll(io.LimitReader(upstream.Body, maxLeakBody+1))
	}
	if err != nil {
		failure := &requestFailure{status: http.StatusBadRequest, code: "invalid_proxy_request", message: "The request body could not be read.", decision: "block", reason: "unclassifiable_request", binding: binding}
		return &processedResponse{event: makeEvent(binding, req, "block", "denied", failure.reason, failure.status, time.Since(started), ""), failure: failure}
	}
	if len(body) > maxLeakBody {
		// Forwarded as it came: the part already read, then the rest.
		upstream.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), upstream.Body), upstream.Body}
		upstream.GetBody = nil
		scan.leaveUnread(leakReasonOverLimit, leakScopeRequest)
		stopped := p.finishLeakScan(req, upstream, binding, host, port, scan, nil, "", started)
		p.observeRead(scan, host, req.URL.EscapedPath(), nil, nil, stopped != nil, time.Now())
		return stopped
	}
	setUpstreamBody(upstream, body, false)
	// The body is in hand: what follows is the inspection itself.
	began := time.Now()
	guard.scanHeaders(scan, upstream.Header)

	encodings := upstream.Header.Values("Content-Encoding")
	encoding, known := leakEncoding(strings.Join(encodings, ","))
	var decoded []byte
	// gRPC-Web's base64 is left undone, like an encoding the proxy does not undo.
	if known && len(encodings) <= 1 && kind != leakBodyBase64 {
		decoded, encoding, err = decodeLeakBody(body, encoding)
	} else {
		err = errors.New("unsupported encoding")
	}
	var rewritten []byte
	original := decoded
	if err != nil {
		scan.leaveUnread(leakReasonUndecodable, leakScopeRequest)
		// The raw bytes are still looked at, so a value sent plainly in a body
		// the proxy cannot decode is caught.
		part := leakPartOpaque
		if match.inPlace() {
			part = leakPartOpaqueKept
		}
		guard.readFixed(scan, part, body, "body")
		original = body
	} else if kind.inPlace() {
		rewritten = guard.readProtobuf(scan, decoded, "body")
	} else {
		rewritten = guard.readPayload(scan, decoded, "body")
	}
	stopped := p.finishLeakScan(req, upstream, binding, host, port, scan, rewritten, encoding, started)
	p.observeRead(scan, host, req.URL.EscapedPath(), original, rewritten, stopped != nil, began)
	return stopped
}

// leakBodyIdle is how long a unary body with no stated length is waited for
// without a byte of it coming before it is sent on unread.
var leakBodyIdle = 30 * time.Second

// bodyPump reads a body that has no deadline of its own, so that waiting for
// it can stop. It is then the rest of the body, for whoever sends it on.
type bodyPump struct {
	ctx     context.Context
	chunks  chan []byte
	pending []byte
	err     error
}

func newBodyPump(ctx context.Context, source io.Reader) *bodyPump {
	pump := &bodyPump{ctx: ctx, chunks: make(chan []byte)}
	go func() {
		defer close(pump.chunks)
		for {
			chunk := make([]byte, 32<<10)
			n, err := source.Read(chunk)
			if n > 0 {
				select {
				case pump.chunks <- chunk[:n]:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				// Read once the channel is closed, which is after this.
				pump.err = err
				return
			}
		}
	}()
	return pump
}

// collect gathers the body until it ends, holds more than limit bytes, or
// no byte of it came for idle. ended says it is whole.
func (p *bodyPump) collect(limit int, idle time.Duration) (body []byte, ended bool, err error) {
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for len(body) <= limit {
		select {
		case chunk, open := <-p.chunks:
			if !open {
				if p.err == io.EOF {
					return body, true, nil
				}
				return body, false, p.failure()
			}
			body = append(body, chunk...)
			timer.Reset(idle)
		case <-timer.C:
			return body, false, nil
		case <-p.ctx.Done():
			return body, false, p.ctx.Err()
		}
	}
	return body, false, nil
}

// failure is why the body stopped short of its end.
func (p *bodyPump) failure() error {
	if p.err != nil {
		return p.err
	}
	return p.ctx.Err()
}

func (p *bodyPump) Read(buffer []byte) (int, error) {
	for len(p.pending) == 0 {
		select {
		case chunk, open := <-p.chunks:
			if !open {
				return 0, p.failure()
			}
			p.pending = chunk
		case <-p.ctx.Done():
			return 0, p.ctx.Err()
		}
	}
	n := copy(buffer, p.pending)
	p.pending = p.pending[n:]
	return n, nil
}

// finishLeakScan acts on what a request's inspection found: it refuses the
// request, sends the rewritten body, or lets it go as it was, and reports it
// when there is something new to say.
func (p *httpProxy) finishLeakScan(req, upstream *http.Request, binding *binding, host string, port int, scan *leakScan, rewritten []byte, encoding string, started time.Time) *processedResponse {
	switch scan.verdict(rewritten != nil) {
	case leakBlock:
		event := p.leakEvent(binding, req, host, port, scan, "block", "denied", leakReasonFound, http.StatusForbidden, started)
		failure := &requestFailure{
			status: http.StatusForbidden, code: codeSecretInRequest, decision: "block", reason: leakReasonFound, binding: binding,
			message: "Phase blocked this request: a secret value is in a part of it that cannot be rewritten (the URL or a binary body). Refer to the secret by its key name instead of its value.",
		}
		return &processedResponse{event: event, failure: failure}
	case leakReplace:
		encoded, encodeErr := encodeLeakBody(rewritten, encoding)
		if encodeErr != nil {
			// A body that cannot be made safe again does not go out.
			event := p.leakEvent(binding, req, host, port, scan, "block", "denied", leakReasonFound, http.StatusForbidden, started)
			failure := &requestFailure{
				status: http.StatusForbidden, code: codeSecretInRequest, decision: "block", reason: leakReasonFound, binding: binding,
				message: "Phase blocked this request: it holds a secret value that could not be removed.",
			}
			return &processedResponse{event: event, failure: failure}
		}
		setUpstreamBody(upstream, encoded, true)
		scan.changed = true
	}
	p.emitLeakEvent(binding, req, host, port, scan, 0, started)
	return nil
}

// setUpstreamBody replaces the body the transport sends. An unchanged body
// keeps the client's framing; a rewritten one gets a Content-Length of its own.
func setUpstreamBody(upstream *http.Request, body []byte, changed bool) {
	upstream.Body = io.NopCloser(bytes.NewReader(body))
	upstream.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	if changed {
		upstream.ContentLength = int64(len(body))
		upstream.TransferEncoding = nil
		upstream.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
}

// stateKey is what the scan's host is remembered under: its flow's tool and
// the host.
func (s *leakScan) stateKey(host string) leakStateKey {
	if s.match != nil && s.match.key.host != "" {
		return s.match.key
	}
	return leakStateKey{host: leakHostName(host)}
}

// emitLeakEvent reports a request that holds a placeholder not yet reported
// for its tool and host, one that was left unread, and one whose only finding
// sits in text the provider signed. The last two are reported once for their
// reason, then at most once a minute. Everything else is quiet: the same
// history is sent with every model request, and an event per request would
// say the same thing thousands of times.
func (p *httpProxy) emitLeakEvent(binding *binding, req *http.Request, host string, port int, scan *leakScan, status int, started time.Time) {
	if p.events == nil || p.leak == nil {
		return
	}
	key := scan.stateKey(host)
	fresh := p.leak.reported.fresh(key, scan.placeholders)
	report := len(fresh) > 0
	switch {
	case scan.unread != "":
		report = p.leak.unread.fresh(key, scan.unread) || report
	case scan.left > 0 && len(scan.placeholders) == 0:
		// Nothing was replaced and no placeholder names it, so the report-once
		// memory of placeholders does not cover it.
		report = p.leak.unread.fresh(key, leakQuietSignedText)
	}
	if !report {
		return
	}
	scan.listed = p.leak.eventPlaceholders(fresh)
	outcome, reason := outcomeReported, leakReasonFound
	switch {
	case scan.unread != "":
		outcome, reason = outcomeUnread, scan.unread
	case scan.mode == leakModeObserve:
		outcome = outcomeObserved
	case scan.changed:
		outcome = outcomeCensored
	}
	p.events.Emit(p.leakEvent(binding, req, host, port, scan, "allow", outcome, reason, status, started))
}

// leakEvent describes one inspection. A path that holds a finding is not
// repeated. A blocked request names what it found even when it was reported
// before: the block is new.
func (p *httpProxy) leakEvent(binding *binding, req *http.Request, host string, port int, scan *leakScan, decision, outcome, reason string, status int, started time.Time) agentEvent {
	blocked := decision == "block"
	if blocked {
		p.leak.reported.fresh(scan.stateKey(host), scan.placeholders)
		scan.listed = p.leak.eventPlaceholders(scan.placeholders)
	}
	method, path := req.Method, req.URL.EscapedPath()
	if p.leak != nil && len(p.leak.index.Find([]byte(path))) > 0 {
		path = "/redacted"
	}
	event := newRequestEvent(binding, method, host, port, path, decision, outcome, reason, status, time.Since(started), "")
	event.EventType = leakEventType
	event.Protocol = scan.protocol
	event.Detail = scan.detail()
	// What was not read cannot be graded.
	if outcome != outcomeUnread && outcome != outcomeBypass {
		if severity := scan.severity(blocked); severity != "" {
			event.Detail["severity"] = severity
		}
	}
	return event
}

// leakFlowDetail is what every leak protection event says of the connection
// it is about: the mode, the tool and how the connection reached the proxy.
func leakFlowDetail(mode string, match *leakHostMatch) map[string]any {
	detail := map[string]any{"mode": mode}
	if match != nil {
		detail["harness"] = match.harness
		detail["capture"] = match.flow.capture()
	}
	return detail
}

func (s *leakScan) detail() map[string]any {
	detail := leakFlowDetail(s.mode, s.match)
	if len(s.where) > 0 {
		sort.Strings(s.where)
		detail["where"] = strings.Join(s.where, ",")
	}
	if s.inventory > 0 {
		detail["inventoryHits"] = s.inventory
	}
	if s.redacted > 0 {
		detail["ruleRedactions"] = s.redacted
	}
	if s.alerts > 0 {
		detail["ruleAlerts"] = s.alerts
	}
	if s.left > 0 {
		detail["signedFindings"] = s.left
	}
	if len(s.labels) > 0 {
		sort.Strings(s.labels)
		detail["labels"] = joinWithin(s.labels, maxLeakDetailText)
	}
	if len(s.placeholders) > 0 {
		listed := s.listed
		if len(listed) > maxLeakPlaceholders {
			listed = listed[:maxLeakPlaceholders]
		}
		if len(listed) > 0 {
			detail["placeholders"] = joinWithin(listed, maxLeakDetailText)
		}
		detail["placeholderCount"] = len(s.placeholders)
		detail["replacedCount"] = s.replaced()
		// The two counts are of distinct placeholders, and exact unless this
		// says there were more.
		if s.capped {
			detail["placeholdersCapped"] = true
		}
	}
	if s.unread != "" && s.scope != "" {
		detail["scope"] = s.scope
	}
	return detail
}

// joinWithin joins as many values as fit in limit characters.
func joinWithin(values []string, limit int) string {
	var out strings.Builder
	for _, value := range values {
		if out.Len()+len(value)+1 > limit {
			break
		}
		if out.Len() > 0 {
			out.WriteByte(',')
		}
		out.WriteString(value)
	}
	return out.String()
}

// noteLeakHandshake records a client's TLS handshake with the proxy's
// certificate on a host read for leak protection, and reports each pass-through
// window it opens: nothing a client with that TLS hello sends to that host
// is read until the window ends.
func (p *httpProxy) noteLeakHandshake(host string, port int, match *leakHostMatch, ok bool) {
	window := p.leak.handshakes.note(match.key, ok)
	if window != 0 && p.observe != nil {
		p.observe(leakObservation{host: host, window: leakReasonTLSRefused})
	}
	if window == 0 || p.events == nil {
		return
	}
	event := newRequestEvent(nil, http.MethodConnect, host, port, "/", "allow", outcomeBypass, leakReasonTLSRefused, 0, 0, "")
	event.EventType = leakEventType
	event.Detail = leakFlowDetail(p.leak.mode, match)
	event.Detail["windowSeconds"] = int(window / time.Second)
	p.events.Emit(event)
}
