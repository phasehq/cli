package aiproxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
	// (a header, or an alert); outcomeObserved the same in observe mode.
	outcomeCensored = "censored"
	outcomeReported = "reported"
	outcomeObserved = "observed"
	outcomeUnread   = "unread"
	outcomeBypass   = "bypass"

	leakReasonFound       = "secret_in_request"
	leakReasonOverLimit   = "body_over_limit"
	leakReasonUndecodable = "body_undecodable"
	leakReasonNotJSON     = "message_not_json"
	leakReasonCompressed  = "message_compressed"
	leakReasonBinary      = "message_binary"
	leakReasonTLSRefused  = "tls_refused"

	// Why a whole connection to a host that takes only its own client's TLS
	// was passed through unread: its first bytes were not one whole
	// ClientHello in one TLS record; the hello resumes a session; no exact
	// copy of it can be sent; the proxy's own connection to the service
	// failed; or the service chose a protocol other than HTTP/1.1.
	leakReasonHelloUnreadable   = "hello_unreadable"
	leakReasonHelloResumption   = "hello_resumption"
	leakReasonHelloNotMirrored  = "hello_not_mirrored"
	leakReasonUpstreamHandshake = "upstream_handshake_failed"
	leakReasonUpstreamNotHTTP1  = "upstream_not_http1"

	// maxScanPlaceholders is how many distinct placeholders one request keeps
	// to compare with what was already reported; the count goes on past it.
	maxScanPlaceholders = 256
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
	// placeholders are the distinct placeholders found, up to
	// maxScanPlaceholders; count is how many there were.
	placeholders []string
	count        int
	// listed are the placeholders an event names.
	listed  []string
	labels  []string
	block   bool
	changed bool
	unread  string
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
	if f.Label != "" && !containsString(s.labels, f.Label) {
		s.labels = append(s.labels, f.Label)
	}
	if f.Placeholder != "" && !containsString(s.placeholders, f.Placeholder) {
		s.count++
		if len(s.placeholders) < maxScanPlaceholders {
			s.placeholders = append(s.placeholders, f.Placeholder)
		}
	}
}

func (s *leakScan) addReport(report *censor.Report, where string) {
	if report == nil {
		return
	}
	for _, finding := range report.Findings {
		s.addFinding(finding, where)
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
		if canBlock && (match.Kind == "inventory" || phaseTokenLabels[match.Label]) {
			s.block = true
		}
	}
}

var leakMetaBuffers = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// findInURL scans a request's path and query. It is run for every request
// on an inspected path, so it builds the bytes in a pooled buffer and costs
// nothing beyond the scan.
func (g *leakGuard) findInURL(target *url.URL, opts censor.ScanOptions) []censor.Match {
	buffer := leakMetaBuffers.Get().(*bytes.Buffer)
	buffer.Reset()
	defer leakMetaBuffers.Put(buffer)
	buffer.WriteString(target.EscapedPath())
	if target.RawQuery != "" || target.ForceQuery {
		buffer.WriteByte('?')
		buffer.WriteString(target.RawQuery)
	}
	return g.index.FindWith(buffer.Bytes(), opts)
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
		scan.addFixed(matches, "header", false)
	}
}

// scanPayload inspects a decoded body or message. It returns the rewritten
// payload, or nil when nothing in it is to change.
func (g *leakGuard) scanPayload(scan *leakScan, payload []byte, where string) []byte {
	out, report, err := g.index.RewriteJSON(payload, scan.opts)
	if errors.Is(err, censor.ErrNotJSON) {
		if utf8.Valid(payload) && bytes.IndexByte(payload, 0) < 0 {
			out, report = g.index.RedactWith(payload, scan.opts)
		} else {
			// A binary body cannot be rewritten; what blocks in it is what
			// blocks in a URL.
			scan.addFixed(g.index.FindWith(payload, scan.opts), where, true)
			return nil
		}
	} else if err != nil {
		return nil
	}
	scan.addReport(report, where)
	if report == nil || !report.Changed {
		return nil
	}
	return out
}

// inspectForLeaks reads a request to a model host before anything else the
// proxy does to it: before the secret guard, the access policy and credential
// injection, so nothing the proxy adds is scanned and a rewritten body is what
// gets signed and sent. It changes upstream's body in place when it rewrites
// it, and returns a result only when the request is refused.
func (p *httpProxy) inspectForLeaks(req, upstream *http.Request, binding *binding, host string, port int, started time.Time) *processedResponse {
	guard := p.leak
	if guard == nil || req.URL == nil {
		return nil
	}
	match := guard.inspects(host, port)
	if !match.inspectsPath(req.URL.Path) {
		return nil
	}
	if validWebSocketRequest(req) {
		// Frames stay plain only when no compression is agreed.
		upstream.Header.Del("Sec-WebSocket-Extensions")
	}
	opts := guard.scanOptionsFor(match, req.URL.Path)
	// The URL of every request is read, with a body or without one; a request
	// without a body (Codex polls about once a second) costs only this scan.
	urlMatches := guard.findInURL(req.URL, opts)
	if upstream.Body == nil || upstream.Body == http.NoBody || upstream.ContentLength == 0 {
		if len(urlMatches) == 0 {
			return nil
		}
		scan := guard.newScan(match, "http", opts)
		scan.addFixed(urlMatches, "url", true)
		return p.finishLeakScan(req, upstream, binding, host, port, scan, nil, "", started)
	}
	scan := guard.newScan(match, "http", opts)
	scan.addFixed(urlMatches, "url", true)
	body, err := io.ReadAll(io.LimitReader(upstream.Body, maxLeakBody+1))
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
		scan.unread = leakReasonOverLimit
		return p.finishLeakScan(req, upstream, binding, host, port, scan, nil, "", started)
	}
	setUpstreamBody(upstream, body, false)
	guard.scanHeaders(scan, upstream.Header)

	encodings := upstream.Header.Values("Content-Encoding")
	encoding, known := leakEncoding(strings.Join(encodings, ","))
	var decoded []byte
	if known && len(encodings) <= 1 {
		decoded, encoding, err = decodeLeakBody(body, encoding)
	} else {
		err = errors.New("unsupported encoding")
	}
	var rewritten []byte
	if err != nil {
		scan.unread = leakReasonUndecodable
		// The raw bytes are still looked at, so a value sent plainly in a body
		// the proxy cannot decode is caught.
		scan.addFixed(guard.index.FindWith(body, opts), "body", true)
	} else {
		rewritten = guard.scanPayload(scan, decoded, "body")
	}
	return p.finishLeakScan(req, upstream, binding, host, port, scan, rewritten, encoding, started)
}

// finishLeakScan acts on what a request's inspection found: it refuses the
// request, sends the rewritten body, or lets it go as it was, and reports it
// when there is something new to say.
func (p *httpProxy) finishLeakScan(req, upstream *http.Request, binding *binding, host string, port int, scan *leakScan, rewritten []byte, encoding string, started time.Time) *processedResponse {
	guard := p.leak
	if scan.block && guard.mode == leakModeCensor {
		event := p.leakEvent(binding, req, host, port, scan, "block", "denied", leakReasonFound, http.StatusForbidden, started)
		failure := &requestFailure{
			status: http.StatusForbidden, code: codeSecretInRequest, decision: "block", reason: leakReasonFound, binding: binding,
			message: "Phase blocked this request: a secret value is in a part of it that cannot be rewritten (the URL or a binary body). Refer to the secret by its key name instead of its value.",
		}
		return &processedResponse{event: event, failure: failure}
	}
	if rewritten != nil && guard.mode == leakModeCensor {
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

// emitLeakEvent reports a request that was left unread, or that holds a
// placeholder not yet reported for its host. Everything else is quiet: the
// same history is sent with every model request, and an event per request
// would say the same thing thousands of times.
func (p *httpProxy) emitLeakEvent(binding *binding, req *http.Request, host string, port int, scan *leakScan, status int, started time.Time) {
	if p.events == nil || p.leak == nil {
		return
	}
	fresh := p.leak.reported.fresh(host, scan.placeholders)
	if scan.unread == "" && len(fresh) == 0 {
		return
	}
	scan.listed = fresh
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
	if decision == "block" {
		p.leak.reported.fresh(host, scan.placeholders)
		scan.listed = scan.placeholders
	}
	method, path := req.Method, req.URL.EscapedPath()
	if p.leak != nil && len(p.leak.index.Find([]byte(path))) > 0 {
		path = "/redacted"
	}
	event := newRequestEvent(binding, method, host, port, path, decision, outcome, reason, status, time.Since(started), "")
	event.EventType = leakEventType
	event.Protocol = scan.protocol
	event.Detail = scan.detail()
	return event
}

func (s *leakScan) detail() map[string]any {
	detail := map[string]any{"mode": s.mode}
	if s.match != nil {
		detail["harness"] = s.match.harness
	}
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
	if s.count > 0 {
		listed := s.listed
		if len(listed) > maxLeakPlaceholders {
			listed = listed[:maxLeakPlaceholders]
		}
		if len(listed) > 0 {
			detail["placeholders"] = joinWithin(listed, maxLeakDetailText)
		}
		detail["placeholderCount"] = s.count
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
// window it opens: nothing on that host is read until the window ends.
func (p *httpProxy) noteLeakHandshake(host string, port int, match *leakHostMatch, ok bool) {
	window := p.leak.handshakes.note(host, ok)
	if window == 0 || p.events == nil {
		return
	}
	event := newRequestEvent(nil, http.MethodConnect, host, port, "/", "allow", outcomeBypass, leakReasonTLSRefused, 0, 0, "")
	event.EventType = leakEventType
	event.Detail = map[string]any{"mode": p.leak.mode, "harness": match.harness, "windowSeconds": int(window / time.Second)}
	p.events.Emit(event)
}
