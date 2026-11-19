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

	// How much an unread event covers: one request, one WebSocket message, or
	// a whole connection.
	leakScopeRequest    = "request"
	leakScopeMessage    = "message"
	leakScopeConnection = "connection"

	// An event's severity. A request is high when it held this many distinct
	// placeholders, or one of Phase's own tokens, or was blocked; medium from
	// leakSeverityMediumPlaceholders up; low when nothing in it could be
	// replaced or blocked (alerts, findings in text the provider signed).
	leakSeverityHigh               = "high"
	leakSeverityMedium             = "medium"
	leakSeverityLow                = "low"
	leakSeverityHighPlaceholders   = 5
	leakSeverityMediumPlaceholders = 1

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
	// replaceable are those of them found where the request can be rewritten,
	// counted the same way. They were replaced when changed is set.
	replaceable      []string
	replaceableCount int
	// phaseToken says one of Phase's own tokens was found.
	phaseToken bool
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
	if f.Placeholder != "" && !containsString(s.placeholders, f.Placeholder) {
		s.count++
		if len(s.placeholders) < maxScanPlaceholders {
			s.placeholders = append(s.placeholders, f.Placeholder)
		}
	}
}

// addReport records what was found in bytes that can be rewritten.
func (s *leakScan) addReport(report *censor.Report, where string) {
	if report == nil {
		return
	}
	for _, finding := range report.Findings {
		s.addFinding(finding, where)
		if finding.Action == "left" || finding.Placeholder == "" || containsString(s.replaceable, finding.Placeholder) {
			continue
		}
		s.replaceableCount++
		if len(s.replaceable) < maxScanPlaceholders {
			s.replaceable = append(s.replaceable, finding.Placeholder)
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
		if canBlock && (match.Kind == "inventory" || phaseTokenLabels[match.Label]) {
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
	return s.replaceableCount
}

// severity grades what the scan found. blocked says the request was stopped.
func (s *leakScan) severity(blocked bool) string {
	switch {
	case blocked || s.phaseToken || s.count >= leakSeverityHighPlaceholders:
		return leakSeverityHigh
	case s.count >= leakSeverityMediumPlaceholders:
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
	// connection is why a whole connection was passed through unread, and
	// window why a pass-through window opened.
	connection, window string
}

// observeRead tells the harness, when there is one, what was done to a body
// or a message. rewritten is what replaces it when the scan changed it.
func (p *httpProxy) observeRead(scan *leakScan, host, path string, original, rewritten []byte, blocked bool, began time.Time) {
	if p.observe == nil {
		return
	}
	observation := leakObservation{scan: scan, host: host, path: path, original: original, blocked: blocked, took: time.Since(began)}
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
	// The URL of every request is read, with a body or without one; a request
	// without a body (Codex polls about once a second) costs only this scan.
	urlMatches := guard.findInURL(req.URL, opts)
	if upstream.Body == nil || upstream.Body == http.NoBody || upstream.ContentLength == 0 {
		if len(urlMatches) == 0 {
			return nil
		}
		scan := guard.newScan(match, "http", opts)
		scan.addFound(leakPartURL, urlMatches, "url")
		return p.finishLeakScan(req, upstream, binding, host, port, scan, nil, "", started)
	}
	scan := guard.newScan(match, "http", opts)
	scan.addFound(leakPartURL, urlMatches, "url")
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
	if known && len(encodings) <= 1 {
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
		guard.readFixed(scan, leakPartOpaque, body, "body")
		original = body
	} else {
		rewritten = guard.readPayload(scan, decoded, "body")
	}
	stopped := p.finishLeakScan(req, upstream, binding, host, port, scan, rewritten, encoding, started)
	p.observeRead(scan, host, req.URL.EscapedPath(), original, rewritten, stopped != nil, began)
	return stopped
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
	case scan.left > 0 && scan.count == 0:
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
	if s.count > 0 {
		listed := s.listed
		if len(listed) > maxLeakPlaceholders {
			listed = listed[:maxLeakPlaceholders]
		}
		if len(listed) > 0 {
			detail["placeholders"] = joinWithin(listed, maxLeakDetailText)
		}
		detail["placeholderCount"] = s.count
		detail["replacedCount"] = s.replaced()
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
// window it opens: nothing that tool sends to that host is read until the
// window ends.
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
