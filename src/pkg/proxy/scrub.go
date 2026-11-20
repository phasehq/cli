package proxy

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Response scrubbing: the secret guard's backstop for AWS Connections.
//
// The guard refuses the calls it knows mint credentials. Should a response on
// an AWS Connection still carry credential material in the shape STS uses (an
// access key ID next to a secret access key, with or without a session token,
// as XML elements or JSON members), the secret values are replaced before the
// response reaches the Agent. This is not general response scrubbing: only
// that shape, only XML and JSON bodies, only AWS Connections.
//
// What counts as credential material: a SecretAccessKey (or SecretKey) value
// with an AccessKeyId value within scrubProximity bytes of it. That secret
// key, the access key ID nearest to it and the SessionToken nearest to it
// within the same distance are replaced with scrubMarker. Any other
// AccessKeyId, as in a list of a user's keys, is left alone: identities in
// provider output stay real.
//
// Bodies are scrubbed as they stream, so there is no size limit and a chunked
// or very large body is handled like any other. The scanner keeps a bounded
// window (scrubHoldback) and never holds a whole body in memory. A value
// longer than scrubMaxValue is not treated as a credential. Because the
// length of a scrubbed body is not known up front, Content-Length is removed
// and the proxy frames the body itself.

const (
	scrubMarker = "PHASE_REDACTED_CREDENTIAL"
	// scrubMaxValue bounds a credential value. AWS session tokens are a few
	// kilobytes at most.
	scrubMaxValue = 8 << 10
	// scrubProximity is how far apart the members of one credential block may
	// be.
	scrubProximity = 8 << 10
	// scrubHoldback is how much of the stream is kept back so that every
	// decision is made with the whole block in view: a session token, the
	// secret key that anchors it and the access key ID that confirms the key.
	scrubHoldback = 2*scrubProximity + scrubMaxValue + 1024
	// scrubMaxRebuiltGzip bounds a gzip body that has to be re-encoded.
	scrubMaxRebuiltGzip = 2 * defaultAWSBodyBufferBytes
)

// ErrScrubUninspectable is returned when a body that has to be inspected
// cannot be. Callers fail closed and do not return the response.
var ErrScrubUninspectable = errors.New("response could not be inspected for credential material")

type scrubKind uint8

const (
	scrubSecretKey scrubKind = iota + 1
	scrubSessionToken
	scrubAccessKeyID
)

var (
	// An XML element, any namespace prefix, with text or one CDATA section.
	scrubXMLPattern = regexp.MustCompile(`(?i)<(?:[a-z_][\w.\-]*:)?(secretaccesskey|secretkey|sessiontoken|accesskeyid)(?:\s[^<>]*)?>(<!\[CDATA\[(?s:.*?)\]\]>|[^<]*)</`)
	// A JSON member with a string value. An escaped quote never ends the key
	// or the value, so text inside another string does not match.
	scrubJSONPattern = regexp.MustCompile(`(?i)"(secretaccesskey|secretkey|sessiontoken|accesskeyid)"\s*:\s*"((?:[^"\\]|\\.)*)"`)
	scrubTriggers    = [][]byte{[]byte("secretaccesskey"), []byte("secretkey")}
)

func scrubKindOf(name []byte) scrubKind {
	switch strings.ToLower(string(name)) {
	case "secretaccesskey", "secretkey":
		return scrubSecretKey
	case "sessiontoken":
		return scrubSessionToken
	default:
		return scrubAccessKeyID
	}
}

// ScrubAWSCredentialResponse arranges for credential material to be replaced
// in the response body. onScrubbed is called once, when the body has been
// read to its end or closed, with the number of values replaced, and only if
// there were any; it never receives a value.
//
// A gzip body (S3 returns a stored object's encoding whatever the request
// accepts) is decoded in full to look for credential material. It is passed
// on byte for byte when there is none and re-encoded when there is. Any other
// encoding cannot be inspected and is refused with ErrScrubUninspectable.
func ScrubAWSCredentialResponse(response *http.Response, onScrubbed func(values int)) error {
	if response == nil || response.Body == nil || response.Body == http.NoBody ||
		response.StatusCode < 200 || response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusNotModified ||
		!scrubbableContentType(response.Header.Get("Content-Type")) {
		return nil
	}
	encoding := strings.TrimSpace(strings.Join(response.Header.Values("Content-Encoding"), ","))
	switch {
	case encoding == "" || strings.EqualFold(encoding, "identity"):
		response.Header.Del("Content-Length")
		response.Header.Del("Content-MD5")
		response.Header.Del("Digest")
		response.ContentLength = -1
		response.Body = &scrubbingReadCloser{source: response.Body, onScrubbed: onScrubbed}
		return nil
	case strings.EqualFold(encoding, "gzip"):
		return scrubGzipResponse(response, onScrubbed)
	default:
		return ErrScrubUninspectable
	}
}

// scrubbableContentType reports whether a body is XML or JSON, or does not
// say what it is. Anything else, such as a downloaded object, is left alone.
func scrubbableContentType(contentType string) bool {
	if strings.TrimSpace(contentType) == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return true
	}
	return strings.Contains(mediaType, "xml") || strings.Contains(mediaType, "json")
}

func scrubGzipResponse(response *http.Response, onScrubbed func(int)) error {
	compressed, err := readBounded(response.Body, defaultAWSBodyBufferBytes)
	_ = response.Body.Close()
	if err != nil {
		return ErrScrubUninspectable
	}
	scrubbedThrough := func(destination io.Writer) (int, error) {
		decoded, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return 0, err
		}
		scrubber := &scrubbingReadCloser{source: decoded}
		if _, err := io.Copy(destination, scrubber); err != nil {
			return 0, err
		}
		return scrubber.values, scrubber.Close()
	}
	values, err := scrubbedThrough(io.Discard)
	if err != nil {
		return ErrScrubUninspectable
	}
	if values == 0 {
		response.Body = io.NopCloser(bytes.NewReader(compressed))
		return nil
	}
	rebuilt := &boundedBuffer{limit: scrubMaxRebuiltGzip}
	encoder := gzip.NewWriter(rebuilt)
	if _, err := scrubbedThrough(encoder); err != nil {
		return ErrScrubUninspectable
	}
	if err := encoder.Close(); err != nil {
		return ErrScrubUninspectable
	}
	response.Header.Del("Content-MD5")
	response.Header.Del("Digest")
	response.Header.Set("Content-Length", strconv.Itoa(rebuilt.buffer.Len()))
	response.ContentLength = int64(rebuilt.buffer.Len())
	response.Body = io.NopCloser(bytes.NewReader(rebuilt.buffer.Bytes()))
	if onScrubbed != nil {
		onScrubbed(values)
	}
	return nil
}

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if int64(b.buffer.Len()+len(data)) > b.limit {
		return 0, ErrScrubUninspectable
	}
	return b.buffer.Write(data)
}

// scrubMatch is one candidate value, in offsets of the input stream.
type scrubMatch struct {
	kind       scrubKind
	start      int64 // where the element or member begins
	valueStart int64
	valueEnd   int64
	end        int64
}

// scrubbingReadCloser replaces credential material in a stream. Offsets are
// those of the input; pending is the part not yet released, starting at base.
type scrubbingReadCloser struct {
	source     io.ReadCloser
	onScrubbed func(int)

	pending []byte
	lowered []byte
	base    int64
	output  []byte
	readErr error
	// released remembers where the values already passed on were, so a block
	// spanning two windows is still recognised and judged the same way.
	released []scrubMatch
	values   int
	done     bool
	scratch  [32 << 10]byte
}

func (r *scrubbingReadCloser) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	for len(r.output) == 0 {
		if r.readErr != nil {
			r.release(true)
			if len(r.output) == 0 {
				err := r.readErr
				r.finish()
				return 0, err
			}
			break
		}
		read, err := r.source.Read(r.scratch[:])
		if read > 0 {
			r.pending = append(r.pending, r.scratch[:read]...)
		}
		if err != nil {
			r.readErr = err
			continue
		}
		if read == 0 {
			return 0, nil
		}
		r.release(false)
	}
	read := copy(destination, r.output)
	r.output = r.output[read:]
	return read, nil
}

func (r *scrubbingReadCloser) Close() error {
	r.finish()
	return r.source.Close()
}

func (r *scrubbingReadCloser) finish() {
	if r.done {
		return
	}
	r.done = true
	clear(r.pending)
	clear(r.lowered)
	r.pending, r.lowered = nil, nil
	if r.values > 0 && r.onScrubbed != nil {
		r.onScrubbed(r.values)
	}
}

// release moves everything that can be decided from pending to output. With
// final unset the last scrubHoldback bytes stay, so each released byte was
// judged with its whole neighbourhood in view.
func (r *scrubbingReadCloser) release(final bool) {
	cut := len(r.pending)
	if !final {
		cut -= scrubHoldback
		if cut <= 0 {
			return
		}
	}
	matches := r.findMatches()
	replace := r.confirmed(matches)
	cursor := 0
	for index, match := range matches {
		start, end := int(match.start-r.base), int(match.end-r.base)
		if start >= cut {
			break
		}
		// A match that begins before the cut is released whole.
		if end > cut {
			cut = end
		}
		r.released = append(r.released, match)
		if !replace[index] {
			continue
		}
		r.output = append(r.output, r.pending[cursor:int(match.valueStart-r.base)]...)
		r.output = append(r.output, scrubMarker...)
		cursor = int(match.valueEnd - r.base)
		r.values++
	}
	r.output = append(r.output, r.pending[cursor:cut]...)
	r.pending = append(r.pending[:0], r.pending[cut:]...)
	r.base += int64(cut)
	// Only matches near the new window can still confirm anything.
	kept := r.released[:0]
	for _, match := range r.released {
		if r.base-match.start <= 2*scrubProximity {
			kept = append(kept, match)
		}
	}
	r.released = kept
}

// findMatches returns the candidate values in pending, in stream order. The
// patterns run only when a secret key name is present at all, which keeps an
// ordinary body at the cost of one pass over it.
func (r *scrubbingReadCloser) findMatches() []scrubMatch {
	r.lowered = r.lowered[:0]
	for _, character := range r.pending {
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		r.lowered = append(r.lowered, character)
	}
	triggered := false
	for _, trigger := range scrubTriggers {
		if bytes.Contains(r.lowered, trigger) {
			triggered = true
			break
		}
	}
	if !triggered {
		// A released secret key may still be waiting for its access key ID.
		for _, match := range r.released {
			if match.kind == scrubSecretKey {
				triggered = true
				break
			}
		}
		if !triggered {
			return nil
		}
	}
	var matches []scrubMatch
	for _, pattern := range []*regexp.Regexp{scrubXMLPattern, scrubJSONPattern} {
		for _, location := range pattern.FindAllSubmatchIndex(r.pending, -1) {
			valueStart, valueEnd := location[4], location[5]
			if valueEnd <= valueStart || valueEnd-valueStart > scrubMaxValue {
				continue
			}
			matches = append(matches, scrubMatch{
				kind:  scrubKindOf(r.pending[location[2]:location[3]]),
				start: r.base + int64(location[0]), valueStart: r.base + int64(valueStart),
				valueEnd: r.base + int64(valueEnd), end: r.base + int64(location[1]),
			})
		}
	}
	// Two patterns, one order: by position in the stream.
	for index := 1; index < len(matches); index++ {
		for position := index; position > 0 && matches[position].start < matches[position-1].start; position-- {
			matches[position], matches[position-1] = matches[position-1], matches[position]
		}
	}
	// An XML match and a JSON match cannot overlap in well-formed data; if
	// they do, the later one is dropped so replacements never cross.
	deduplicated := matches[:0]
	var lastEnd int64 = -1
	for _, match := range matches {
		if match.start < lastEnd {
			continue
		}
		deduplicated = append(deduplicated, match)
		lastEnd = match.end
	}
	return deduplicated
}

// confirmed marks the matches to replace. A secret key is confirmed by an
// access key ID within scrubProximity. It takes with it the access key ID
// nearest to it and the session token nearest to it, and nothing else: an
// unrelated access key ID that merely sits in the same response is left as
// it is.
func (r *scrubbingReadCloser) confirmed(matches []scrubMatch) []bool {
	all := append(append([]scrubMatch(nil), r.released...), matches...)
	nearest := func(anchor scrubMatch, kind scrubKind) (int64, bool) {
		var best, bestDistance int64 = 0, -1
		for _, candidate := range all {
			if candidate.kind != kind {
				continue
			}
			distance := candidate.start - anchor.start
			if distance < 0 {
				distance = -distance
			}
			if distance <= scrubProximity && (bestDistance < 0 || distance < bestDistance) {
				best, bestDistance = candidate.start, distance
			}
		}
		return best, bestDistance >= 0
	}
	replaced := make(map[int64]struct{})
	for _, candidate := range all {
		if candidate.kind != scrubSecretKey {
			continue
		}
		accessKeyID, found := nearest(candidate, scrubAccessKeyID)
		if !found {
			continue
		}
		replaced[candidate.start], replaced[accessKeyID] = struct{}{}, struct{}{}
		if sessionToken, found := nearest(candidate, scrubSessionToken); found {
			replaced[sessionToken] = struct{}{}
		}
	}
	replace := make([]bool, len(matches))
	for index, match := range matches {
		_, replace[index] = replaced[match.start]
	}
	return replace
}
