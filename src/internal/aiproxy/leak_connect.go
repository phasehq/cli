package aiproxy

import (
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/phasehq/cli/pkg/censor"
)

// Connect (connectrpc.com/docs/protocol) is how Cursor's tools talk to their
// service. A unary call is one protobuf message in a body of type
// application/proto. A stream is a body of type application/connect+proto
// that stays open: a sequence of envelopes, each one flag byte, the payload's
// length in four bytes, big-endian, and the payload, which is one message.
// The agent's own stream is such a body over HTTP/2: the client keeps sending
// while the service answers.
//
// Protobuf writes the length of every string and nested message it holds, so
// nothing in a message may change length. What is found in one is therefore
// overwritten where it sits (censor.RewriteBinary), and the message is as long
// as it was.

const (
	// connectEnvelopePrefix is an envelope's flag byte and length.
	connectEnvelopePrefix = 5
	// connectCompressed marks a payload compressed with the encoding the
	// Connect-Content-Encoding header names. connectEndStream marks the
	// envelope that ends a stream; it holds no message.
	connectCompressed = 0x01
	connectEndStream  = 0x02

	connectEncodingHeader = "Connect-Content-Encoding"
)

// leakBody is what a request's Content-Type says its body is, on a host whose
// rule says it speaks Connect.
type leakBody int

const (
	// leakBodyAsItReads is every other body: JSON, other text or neither, as
	// its bytes say.
	leakBodyAsItReads leakBody = iota
	// leakBodyProtobuf is one protobuf message.
	leakBodyProtobuf
	// leakBodyProtobufStream and leakBodyJSONStream are streams of envelopes
	// holding protobuf messages, or JSON ones.
	leakBodyProtobufStream
	leakBodyJSONStream
)

// body says what a request's body is by its Content-Type. Only a host whose
// rule says it speaks Connect is asked: everywhere else a body is what its
// bytes say.
func (m *leakHostMatch) body(header http.Header) leakBody {
	if m == nil || !m.rule.Connect {
		return leakBodyAsItReads
	}
	// The type alone: "application/connect+proto; charset=utf-8" is the same.
	mediaType, _, _ := strings.Cut(header.Get("Content-Type"), ";")
	switch strings.ToLower(strings.TrimSpace(mediaType)) {
	case "application/proto":
		return leakBodyProtobuf
	case "application/connect+proto":
		return leakBodyProtobufStream
	case "application/connect+json":
		return leakBodyJSONStream
	}
	return leakBodyAsItReads
}

// conversation reports whether a body of this kind carries conversation
// content whatever the path: on a host that speaks Connect, every protobuf
// call does.
func (b leakBody) conversation() bool {
	return b == leakBodyProtobuf || b == leakBodyProtobufStream
}

func (b leakBody) stream() bool {
	return b == leakBodyProtobufStream || b == leakBodyJSONStream
}

// errLeakMessageBlocked ends a stream one of whose messages must not go out.
var errLeakMessageBlocked = errors.New("a message of the stream holds a secret value that cannot be removed")

// connectStream is a Connect stream's request body on its way to the service.
// It hands on one envelope at a time, as each arrives, and holds no more than
// that one: the client goes on sending while the service answers, so the body
// has no end to wait for. A message is read like a body of the same bytes;
// what is replaced in it goes on in its place, and every other envelope goes
// on exactly as it came.
type connectStream struct {
	proxy   *httpProxy
	source  io.ReadCloser
	request *http.Request
	binding *binding
	host    string
	port    int
	match   *leakHostMatch
	opts    censor.ScanOptions
	// protocol is what the client spoke to the proxy, for the events.
	protocol string
	// json says the messages are JSON, as in application/connect+json.
	json bool
	// encoding is what compressed payloads are compressed with.
	encoding string

	// ready is what goes on next: an envelope's prefix, then its payload.
	ready [][]byte
	// passing is how much of an envelope too large to hold is still to come.
	// It goes on as it arrives.
	passing int64
	err     error
}

func (s *connectStream) Close() error { return s.source.Close() }

func (s *connectStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		switch {
		case len(s.ready) > 0:
			n := copy(p, s.ready[0])
			if s.ready[0] = s.ready[0][n:]; len(s.ready[0]) == 0 {
				s.ready = s.ready[1:]
			}
			return n, nil
		case s.passing > 0:
			n, err := s.source.Read(p[:min(int64(len(p)), s.passing)])
			s.passing -= int64(n)
			if err != nil {
				// The stream ended inside the envelope: there is no more of
				// it to wait for.
				s.err, s.passing = err, 0
			}
			if n > 0 {
				return n, nil
			}
		case s.err != nil:
			return 0, s.err
		default:
			s.next()
		}
	}
}

// next reads one envelope from the client and makes ready what goes on in
// its place. What was read of an envelope the client never finished goes on
// as it came, and the stream then ends as the client's did: at its end, or
// with the error that broke it.
func (s *connectStream) next() {
	prefix := make([]byte, connectEnvelopePrefix)
	if n, err := readWhole(s.source, prefix); err != nil {
		s.ready, s.err = keep(prefix[:n]), err
		return
	}
	length := int64(binary.BigEndian.Uint32(prefix[1:]))
	if length > maxLeakBody {
		// Too long to hold: it goes on as it comes, unread.
		s.unread(leakReasonOverLimit)
		s.ready, s.passing = [][]byte{prefix}, length
		return
	}
	// Room is taken as the payload arrives, so a prefix that announces more
	// than is ever sent costs nothing.
	const step = 1 << 20
	payload := make([]byte, min(length, step))
	for filled := 0; ; payload = append(payload, make([]byte, min(length-int64(filled), max(step, int64(filled))))...) {
		n, err := readWhole(s.source, payload[filled:])
		if filled += n; err != nil {
			s.ready, s.err = keep(prefix, payload[:filled]), err
			return
		}
		if int64(filled) == length {
			break
		}
	}
	s.envelope(prefix, payload)
}

// readWhole fills buffer from source. Unlike io.ReadFull it returns the
// source's own error when the source ends first: io.EOF for a stream that
// ended, anything else for one that broke.
func readWhole(source io.Reader, buffer []byte) (int, error) {
	filled := 0
	for filled < len(buffer) {
		n, err := source.Read(buffer[filled:])
		if filled += n; err != nil && filled < len(buffer) {
			return filled, err
		}
	}
	return filled, nil
}

// keep returns the parts that hold anything.
func keep(parts ...[]byte) [][]byte {
	var kept [][]byte
	for _, part := range parts {
		if len(part) > 0 {
			kept = append(kept, part)
		}
	}
	return kept
}

// envelope reads one whole envelope and makes ready what goes on.
func (s *connectStream) envelope(prefix, payload []byte) {
	s.ready = [][]byte{prefix, payload}
	flags := prefix[0]
	// The envelope that ends a stream holds no message, and an empty one
	// nothing at all.
	if flags&connectEndStream != 0 || len(payload) == 0 {
		return
	}
	guard := s.proxy.leak
	began := time.Now()
	message := payload
	compressed := flags&connectCompressed != 0
	if compressed {
		if encoding, known := leakEncoding(s.encoding); !known || encoding != "gzip" {
			s.unread(leakReasonMessageEncoding)
			return
		}
		decoded, _, err := decodeLeakBody(payload, "gzip")
		if err != nil {
			s.unread(leakReasonMessageUndecodable)
			return
		}
		message = decoded
	}
	scan := guard.newScan(s.match, s.protocol, s.opts)
	var rewritten []byte
	if s.json {
		rewritten = guard.readPayload(scan, message, "message")
	} else {
		rewritten = guard.readProtobuf(scan, message, "message")
	}
	verdict := scan.verdict(rewritten != nil)
	if verdict == leakReplace {
		out := rewritten
		if compressed {
			encoded, err := encodeLeakBody(rewritten, "gzip")
			if err != nil {
				// A message that cannot be made safe again does not go out.
				verdict = leakBlock
			}
			out = encoded
		}
		if verdict == leakReplace {
			// The prefix is this envelope's own: its length is the new payload's.
			binary.BigEndian.PutUint32(prefix[1:], uint32(len(out)))
			s.ready[1] = out
			scan.changed = true
		}
	}
	path := s.request.URL.EscapedPath()
	s.proxy.observeUnit(scan, s.host, path, message, rewritten, verdict == leakBlock, began, true)
	if verdict == leakBlock {
		// Nothing of the message goes on, and nothing after it.
		if s.proxy.events != nil {
			s.proxy.events.Emit(s.proxy.leakEvent(s.binding, s.request, s.host, s.port, scan, "block", "denied", leakReasonFound, 0, time.Now()))
		}
		s.ready, s.err = nil, errLeakMessageBlocked
		return
	}
	s.proxy.emitLeakEvent(s.binding, s.request, s.host, s.port, scan, 0, time.Now())
}

// unread reports a message that goes on as it came without being read.
func (s *connectStream) unread(reason string) {
	scan := s.proxy.leak.newScan(s.match, s.protocol, s.opts)
	scan.leaveUnread(reason, leakScopeMessage)
	s.proxy.emitLeakEvent(s.binding, s.request, s.host, s.port, scan, 0, time.Now())
	s.proxy.observeUnit(scan, s.host, s.request.URL.EscapedPath(), nil, nil, false, time.Now(), true)
}

// readConnectStream sets a Connect stream up to be read as it is sent. The
// request's URL and headers are judged first, as any request's are; it
// returns a result only when they refuse the request.
func (p *httpProxy) readConnectStream(req, upstream *http.Request, binding *binding, host string, port int, scan *leakScan, body leakBody, started time.Time) *processedResponse {
	p.leak.scanHeaders(scan, upstream.Header)
	if stopped := p.finishLeakScan(req, upstream, binding, host, port, scan, nil, "", started); stopped != nil {
		return stopped
	}
	path := req.URL.EscapedPath()
	// A stream compressed as a whole does not show its envelopes.
	if encoding, _ := leakEncoding(strings.Join(upstream.Header.Values("Content-Encoding"), ",")); encoding != "identity" {
		unread := p.leak.newScan(scan.match, scan.protocol, scan.opts)
		unread.leaveUnread(leakReasonUndecodable, leakScopeRequest)
		p.emitLeakEvent(binding, req, host, port, unread, 0, started)
		p.observeRead(unread, host, path, nil, nil, false, time.Now())
		return nil
	}
	stream := &connectStream{
		proxy: p, source: upstream.Body, request: req, binding: binding, host: host, port: port,
		match: scan.match, opts: scan.opts, protocol: scan.protocol, json: body == leakBodyJSONStream,
		encoding: upstream.Header.Get(connectEncodingHeader),
	}
	if upstream.ContentLength > 0 && upstream.ContentLength <= maxLeakBody {
		// A body whose length the client stated is whole before any answer:
		// it is read here, so what is sent states the length it then has.
		read, err := io.ReadAll(stream)
		switch {
		case errors.Is(err, errLeakMessageBlocked):
			return &processedResponse{failure: leakMessageBlocked(binding)}
		case err != nil:
			failure := &requestFailure{status: http.StatusBadRequest, code: "invalid_proxy_request", message: "The request body could not be read.", decision: "block", reason: "unclassifiable_request", binding: binding}
			return &processedResponse{event: makeEvent(binding, req, "block", "denied", failure.reason, failure.status, time.Since(started), ""), failure: failure}
		}
		setUpstreamBody(upstream, read, int64(len(read)) != upstream.ContentLength)
		return nil
	}
	upstream.Body, upstream.GetBody = stream, nil
	if upstream.ContentLength > 0 && p.leak.mode == leakModeCensor {
		// Longer than is held at once, and a message in it may come out
		// another length: how long the body is, is no longer known.
		upstream.ContentLength = -1
		upstream.Header.Del("Content-Length")
	}
	return nil
}

// leakMessageBlocked is what the client is told when a message of its stream
// was stopped. The stream's own event says what was found.
func leakMessageBlocked(binding *binding) *requestFailure {
	return &requestFailure{
		status: http.StatusForbidden, code: codeSecretInRequest, decision: "block", reason: leakReasonFound, binding: binding,
		message: "Phase blocked this request: a message of its stream holds a secret value in bytes that cannot be rewritten. Refer to the secret by its key name instead of its value.",
	}
}
