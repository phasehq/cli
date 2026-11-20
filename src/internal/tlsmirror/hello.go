package tlsmirror

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	recordHeaderLength       = 5
	recordTypeHandshake      = 22
	handshakeTypeClientHello = 1
	// maxRecordPayload is the most a TLS record carries before encryption
	// (RFC 8446, section 5.1). A ClientHello is always sent unencrypted.
	maxRecordPayload = 1 << 14

	extensionServerName        = 0
	extensionSupportedGroups   = 10
	extensionALPN              = 16
	extensionPadding           = 21
	extensionSessionTicket     = 35
	extensionPreSharedKey      = 41
	extensionEarlyData         = 42
	extensionSupportedVersions = 43
	extensionKeyShare          = 51
)

// ErrNotHello means the bytes are not one TLS record holding exactly one
// whole ClientHello.
var ErrNotHello = errors.New("tlsmirror: not one TLS record holding one whole ClientHello")

// ReadHello reads the first TLS record a client sends. It returns the bytes it
// read in every case, so a caller that cannot use them can still pass them on,
// and it never reads past the record. The error is ErrNotHello when the bytes
// are not one record holding exactly one whole ClientHello, and the reader's
// own error when reading failed first.
func ReadHello(r io.Reader) ([]byte, error) {
	record := make([]byte, recordHeaderLength, recordHeaderLength+1024)
	if n, err := io.ReadFull(r, record); err != nil {
		return record[:n], err
	}
	length := int(binary.BigEndian.Uint16(record[3:]))
	if record[0] != recordTypeHandshake || record[1] != 3 || length < 4 || length > maxRecordPayload {
		return record, ErrNotHello
	}
	record = append(record, make([]byte, length)...)
	if n, err := io.ReadFull(r, record[recordHeaderLength:]); err != nil {
		return record[:recordHeaderLength+n], err
	}
	if _, err := ParseHello(record); err != nil {
		return record, err
	}
	return record, nil
}

// Hello is what a ClientHello shows of the client that sent it: what it offers
// and in what order. It holds nothing that is new for each connection (the
// random, the session id, key share values).
type Hello struct {
	// Version is the legacy version field; Versions is the supported_versions
	// extension.
	Version      uint16
	CipherSuites []uint16
	// Extensions are the extension types in the order sent.
	Extensions     []uint16
	ServerName     string
	Groups         []uint16
	ALPN           []string
	Versions       []uint16
	KeyShareGroups []uint16
	// Resumes reports a hello that offers a session to resume: it carries a
	// pre_shared_key or early_data extension, or a session ticket.
	Resumes bool
	// EarlyData reports a hello that says data follows it at once, before the
	// server has answered. Only a server that holds the session can read it.
	EarlyData bool
}

// ParseHello reads the shape of a ClientHello from the TLS record that holds
// it. Anything but one record holding exactly one whole, well-formed
// ClientHello is ErrNotHello.
func ParseHello(record []byte) (*Hello, error) {
	return parseHello(record, false)
}

// SameShape reports whether two ClientHello records are the same hello to a
// server telling clients apart: equal byte for byte once what is new for
// every connection is set aside (the random, the session id's bytes, key
// share values and GREASE values).
func SameShape(a, b []byte) bool {
	x, y := bytes.Clone(a), bytes.Clone(b)
	if _, err := parseHello(x, true); err != nil {
		return false
	}
	if _, err := parseHello(y, true); err != nil {
		return false
	}
	return bytes.Equal(x, y)
}

// Fresh returns the hello the client that sent record opens a connection with
// when it has no session to offer: the same record without its pre_shared_key
// and early_data extensions and with its session ticket emptied, everything
// else as it was and in the order it was sent. A hello that offers no session
// is returned as it is. Nothing of a session the client holds is left in the
// result, so a copy of it promises the server nothing. The error is
// ErrNotHello for bytes that are not one whole ClientHello.
//
// One thing cannot be worked out from a hello that offers a session: a client
// that pads its hellos by their length (RFC 7685) pads the shorter hello it
// sends without a session differently. SameClient tells whether a hello such
// a client did send without a session is the same client's.
func Fresh(record []byte) ([]byte, error) {
	hello, err := ParseHello(record)
	if err != nil {
		return nil, err
	}
	if !hello.Resumes {
		return record, nil
	}
	fresh := rebuilt(record, func(kind uint16, data []byte) ([]byte, bool) {
		switch kind {
		case extensionPreSharedKey, extensionEarlyData:
			return nil, false
		case extensionSessionTicket:
			// Empty, it only says the client takes tickets.
			return nil, true
		}
		return data, true
	})
	if again, err := ParseHello(fresh); err != nil || again.Resumes {
		return nil, ErrNotHello
	}
	return fresh, nil
}

// SameClient reports whether two ClientHello records are hellos of one
// client that differ, past what is new for every connection, in padding
// alone: the same shape once the padding extension is set aside. That is how
// a client's hello with a session to offer, made fresh, relates to the hello
// the same client sent when it had none.
func SameClient(a, b []byte) bool {
	if _, err := ParseHello(a); err != nil {
		return false
	}
	if _, err := ParseHello(b); err != nil {
		return false
	}
	unpadded := func(kind uint16, data []byte) ([]byte, bool) { return data, kind != extensionPadding }
	return SameShape(rebuilt(a, unpadded), rebuilt(b, unpadded))
}

// rebuilt returns a copy of a ClientHello record with each extension as each
// says: dropped, or kept with the data it returns. record must have parsed.
func rebuilt(record []byte, each func(kind uint16, data []byte) ([]byte, bool)) []byte {
	// The parse has checked every length read here: past the version, the
	// random, the session id, the cipher suites and the compression methods.
	at := recordHeaderLength + 4 + 2 + 32
	at += 1 + int(record[at])
	at += 2 + int(binary.BigEndian.Uint16(record[at:]))
	at += 1 + int(record[at])
	if at == len(record) {
		// A hello with no extensions at all.
		return bytes.Clone(record)
	}
	start := at + 2
	out := make([]byte, start, len(record))
	copy(out, record)
	for extensions := (fields{record[start:]}); !extensions.empty(); {
		rawKind, kind, _ := extensions.uint16()
		data, _ := extensions.vector(2)
		kept, keep := each(kind, data.rest)
		if !keep {
			continue
		}
		out = append(out, rawKind...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(kept)))
		out = append(out, kept...)
	}
	setLength := func(at, size, value int) {
		for i := range size {
			out[at+size-1-i] = byte(value >> (8 * i))
		}
	}
	setLength(start-2, 2, len(out)-start)                             // the extensions
	setLength(recordHeaderLength+1, 3, len(out)-recordHeaderLength-4) // the handshake message
	setLength(3, 2, len(out)-recordHeaderLength)                      // the record
	return out
}

// isGREASE reports a reserved value clients send at random to keep servers
// tolerant of unknown ones (RFC 8701).
func isGREASE(value uint16) bool {
	return value&0x0f0f == 0x0a0a && value>>8 == value&0xff
}

// fields reads the length-prefixed structures of a TLS message. What it
// returns shares memory with what it was given.
type fields struct{ rest []byte }

func (f *fields) take(n int) ([]byte, bool) {
	if n < 0 || len(f.rest) < n {
		return nil, false
	}
	out := f.rest[:n:n]
	f.rest = f.rest[n:]
	return out, true
}

func (f *fields) uint16() ([]byte, uint16, bool) {
	raw, ok := f.take(2)
	if !ok {
		return nil, 0, false
	}
	return raw, binary.BigEndian.Uint16(raw), true
}

// vector reads a field whose length is written in the prefix bytes before it.
func (f *fields) vector(prefix int) (fields, bool) {
	raw, ok := f.take(prefix)
	if !ok {
		return fields{}, false
	}
	length := 0
	for _, b := range raw {
		length = length<<8 | int(b)
	}
	body, ok := f.take(length)
	return fields{body}, ok
}

func (f *fields) empty() bool { return len(f.rest) == 0 }

// uint16s reads a whole field as a list of 16-bit values. With blank set, a
// GREASE value is replaced by one fixed GREASE value in place.
func (f *fields) uint16s(blank bool) ([]uint16, bool) {
	if len(f.rest)%2 != 0 {
		return nil, false
	}
	values := make([]uint16, 0, len(f.rest)/2)
	for !f.empty() {
		raw, value, _ := f.uint16()
		if blank {
			blankGREASE(raw)
		}
		values = append(values, value)
	}
	return values, true
}

func blankGREASE(raw []byte) {
	if isGREASE(binary.BigEndian.Uint16(raw)) {
		raw[0], raw[1] = 0x0a, 0x0a
	}
}

// parseHello reads a ClientHello record. With blank set it also overwrites, in
// record itself, everything that is new for each connection: two hellos from
// one client are then equal byte for byte.
func parseHello(record []byte, blank bool) (*Hello, error) {
	if len(record) < recordHeaderLength || record[0] != recordTypeHandshake || record[1] != 3 ||
		int(binary.BigEndian.Uint16(record[3:])) != len(record)-recordHeaderLength {
		return nil, ErrNotHello
	}
	message := fields{record[recordHeaderLength:]}
	kind, ok := message.take(1)
	if !ok || kind[0] != handshakeTypeClientHello {
		return nil, ErrNotHello
	}
	// A hello split over several records, or followed by another message in
	// this one, is not one whole hello in one record.
	body, ok := message.vector(3)
	if !ok || !message.empty() {
		return nil, ErrNotHello
	}
	hello := &Hello{}
	if _, hello.Version, ok = body.uint16(); !ok {
		return nil, ErrNotHello
	}
	random, ok := body.take(32)
	if !ok {
		return nil, ErrNotHello
	}
	sessionID, ok := body.vector(1)
	if !ok {
		return nil, ErrNotHello
	}
	if blank {
		clear(random)
		clear(sessionID.rest)
	}
	suites, ok := body.vector(2)
	if !ok || suites.empty() {
		return nil, ErrNotHello
	}
	if hello.CipherSuites, ok = suites.uint16s(blank); !ok {
		return nil, ErrNotHello
	}
	if compression, ok := body.vector(1); !ok || compression.empty() {
		return nil, ErrNotHello
	}
	if body.empty() {
		return hello, nil
	}
	extensions, ok := body.vector(2)
	if !ok || !body.empty() {
		return nil, ErrNotHello
	}
	for !extensions.empty() {
		rawKind, kind, ok := extensions.uint16()
		if !ok {
			return nil, ErrNotHello
		}
		data, ok := extensions.vector(2)
		if !ok {
			return nil, ErrNotHello
		}
		if blank {
			blankGREASE(rawKind)
		}
		hello.Extensions = append(hello.Extensions, kind)
		if !hello.readExtension(kind, data, blank) {
			return nil, ErrNotHello
		}
	}
	return hello, nil
}

// readExtension reads the extensions that say something about the client, and
// reports whether the one it was given is well formed.
func (h *Hello) readExtension(kind uint16, data fields, blank bool) bool {
	switch kind {
	case extensionServerName:
		names, ok := data.vector(2)
		if !ok || !data.empty() {
			return false
		}
		for !names.empty() {
			nameKind, ok := names.take(1)
			if !ok {
				return false
			}
			name, ok := names.vector(2)
			if !ok {
				return false
			}
			if nameKind[0] == 0 && h.ServerName == "" {
				h.ServerName = string(name.rest)
			}
		}
	case extensionSupportedGroups:
		groups, ok := data.vector(2)
		if !ok || !data.empty() {
			return false
		}
		if h.Groups, ok = groups.uint16s(blank); !ok {
			return false
		}
	case extensionALPN:
		protocols, ok := data.vector(2)
		if !ok || !data.empty() {
			return false
		}
		for !protocols.empty() {
			protocol, ok := protocols.vector(1)
			if !ok || protocol.empty() {
				return false
			}
			h.ALPN = append(h.ALPN, string(protocol.rest))
		}
	case extensionSessionTicket:
		h.Resumes = h.Resumes || !data.empty()
	case extensionPreSharedKey:
		h.Resumes = true
	case extensionEarlyData:
		h.Resumes, h.EarlyData = true, true
	case extensionSupportedVersions:
		versions, ok := data.vector(1)
		if !ok || !data.empty() {
			return false
		}
		if h.Versions, ok = versions.uint16s(blank); !ok {
			return false
		}
	case extensionKeyShare:
		shares, ok := data.vector(2)
		if !ok || !data.empty() {
			return false
		}
		for !shares.empty() {
			rawGroup, group, ok := shares.uint16()
			if !ok {
				return false
			}
			share, ok := shares.vector(2)
			if !ok {
				return false
			}
			if blank {
				blankGREASE(rawGroup)
				clear(share.rest)
			}
			h.KeyShareGroups = append(h.KeyShareGroups, group)
		}
	}
	return true
}
