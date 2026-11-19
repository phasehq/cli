package aiproxy

import (
	"bytes"
	"errors"
	"unicode/utf8"

	"github.com/phasehq/cli/pkg/censor"
)

// What leak protection does with something it finds depends on the kind of
// bytes it was found in and on nothing else: not on whether those bytes came
// as a request body or as a WebSocket message, and not on what the client
// called them (a Content-Type, a text or binary opcode). This file is the
// one place that decides it. The HTTP adapter (leak_inspect.go), the
// WebSocket adapter (leak_websocket.go) and the Connect adapter
// (leak_connect.go) read what they hold through readPayload, readProtobuf,
// readFixed and addFound, and act on the scan's verdict. Protobuf is the one
// kind the bytes do not show: there the host's rule and the Content-Type say.

// leakPart is a kind of bytes a request is made of.
type leakPart int

const (
	// leakPartURL is a request's path and query.
	leakPartURL leakPart = iota
	// leakPartHeader is a header that is not a login header.
	leakPartHeader
	// leakPartJSON and leakPartText are a body or a message that is text.
	leakPartJSON
	leakPartText
	// leakPartBinary is a body or a message that is not text.
	leakPartBinary
	// leakPartOpaque is a body or a message that could not be decoded: its
	// encoding is one the proxy does not undo, or it is compressed. Its bytes
	// are looked at as they came.
	leakPartOpaque
	// leakPartOversize is a body or a message too large to hold.
	leakPartOversize
	// leakPartProtobuf is a protobuf message: a body, or a message of a
	// stream, that a host which speaks Connect says is one. Every length in
	// it is written down elsewhere in it, so nothing in it may change length.
	leakPartProtobuf
)

// leakPartRule is what happens in one kind of bytes.
type leakPartRule struct {
	// read: the bytes are looked at. What is not read goes out as it came.
	read bool
	// rewrite: what is found is replaced in place.
	rewrite bool
	// block: a known value, or one of Phase's own tokens, that cannot be
	// replaced stops the request. Anything else found there is only reported.
	block bool
}

// leakPartRules is the whole policy:
//
//	part      read  a known value or a Phase token found there
//	URL       yes   blocks
//	header    yes   is reported: a harness's own headers may carry a registered
//	                value on every request, and blocking would end the session
//	JSON      yes   is replaced
//	text      yes   is replaced
//	binary    yes   blocks
//	opaque    yes   blocks; the request or message is reported as unread
//	oversize  no    passes unread
//	protobuf  yes   is overwritten where it sits, by a placeholder padded or
//	                cut to its length; it never blocks
//
// A body or a message is JSON, text or binary by its bytes: valid JSON,
// otherwise valid UTF-8 with no NUL byte, otherwise binary. Protobuf cannot
// be told from its bytes: it is what a host whose rule says it speaks Connect
// sends as application/proto or in an application/connect+proto stream
// (leakHostMatch.body).
//
// observe mode reads the same way and never replaces or blocks.
var leakPartRules = map[leakPart]leakPartRule{
	leakPartURL:      {read: true, block: true},
	leakPartHeader:   {read: true},
	leakPartJSON:     {read: true, rewrite: true},
	leakPartText:     {read: true, rewrite: true},
	leakPartBinary:   {read: true, block: true},
	leakPartOpaque:   {read: true, block: true},
	leakPartOversize: {},
	leakPartProtobuf: {read: true, rewrite: true},
}

// leakVerdict is what happens to a request or a message once it is read.
type leakVerdict int

const (
	// leakPass sends it as it came.
	leakPass leakVerdict = iota
	// leakReplace sends it with what was found replaced.
	leakReplace
	// leakBlock does not send it.
	leakBlock
)

// verdict decides what happens to what the scan read, given whether reading
// produced bytes to send in its place. Only censor mode changes or stops
// anything, and a block wins over a replacement: what could not be replaced
// would still go out.
func (s *leakScan) verdict(rewritten bool) leakVerdict {
	switch {
	case s.mode != leakModeCensor:
		return leakPass
	case s.block:
		return leakBlock
	case rewritten:
		return leakReplace
	default:
		return leakPass
	}
}

// addFound records what was found in bytes that cannot be rewritten. The
// part's rule says whether a known value or a Phase token there blocks.
func (s *leakScan) addFound(part leakPart, matches []censor.Match, where string) {
	s.addFixed(matches, where, leakPartRules[part].block)
}

// addRewritten records what reading a part that can be rewritten found, and
// returns the bytes to send in its place, or nil when nothing changed.
func (s *leakScan) addRewritten(part leakPart, out []byte, report *censor.Report, where string) []byte {
	s.addReport(report, where)
	if !leakPartRules[part].rewrite || report == nil || !report.Changed {
		return nil
	}
	return out
}

// readFixed looks at bytes that cannot be rewritten: binary or opaque ones.
func (g *leakGuard) readFixed(scan *leakScan, part leakPart, data []byte, where string) {
	if !leakPartRules[part].read {
		return
	}
	scan.addFound(part, g.index.FindWith(data, scan.opts), where)
}

// readPayload reads a decoded body or a whole message: as JSON when it is
// JSON, as plain text when it is other text, and as binary when it is
// neither. It returns what to send in its place, or nil when nothing in it
// is to change, and notes on the scan whether the bytes were text.
func (g *leakGuard) readPayload(scan *leakScan, payload []byte, where string) []byte {
	out, report, err := g.index.RewriteJSON(payload, scan.opts)
	switch {
	case err == nil:
		scan.text = true
		return scan.addRewritten(leakPartJSON, out, report, where)
	case !errors.Is(err, censor.ErrNotJSON):
		return nil
	case utf8.Valid(payload) && bytes.IndexByte(payload, 0) < 0:
		scan.text = true
		out, report = g.index.RedactWith(payload, scan.opts)
		return scan.addRewritten(leakPartText, out, report, where)
	default:
		g.readFixed(scan, leakPartBinary, payload, where)
		return nil
	}
}

// readProtobuf reads a protobuf message. It returns what to send in its
// place, which is exactly as long, or nil when nothing in it is to change.
func (g *leakGuard) readProtobuf(scan *leakScan, payload []byte, where string) []byte {
	out, report := g.index.RewriteBinary(payload, scan.opts)
	return scan.addRewritten(leakPartProtobuf, out, report, where)
}
