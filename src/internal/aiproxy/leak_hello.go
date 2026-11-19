package aiproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/phasehq/cli/internal/tlsmirror"
)

// Behind the proxy environment every program is named as the one tool the
// proxy serves. A program the tool starts that does not trust Phase's
// certificate (a Go client on macOS reads no CA variable) refuses it on every
// connection, and a pass-through window counted per tool and host would then
// let the tool's own traffic to that host through unread as well. So the
// window belongs to the client that refused: clients are told apart by what
// their TLS hello offers, which is all the proxy sees of a program. No process
// is looked up.

// helloFingerprint names a TLS client by what its hello offers: the cipher
// suites, groups, versions, signature schemes and application protocols. Each
// list counts without its order and without GREASE values (RFC 8701), so a
// client that shuffles its hello or salts it with random values, as Chromium
// does, is one client.
func helloFingerprint(hello *tls.ClientHelloInfo) string {
	digest := sha256.New()
	hashOffered(digest, hello.CipherSuites)
	hashOffered(digest, hello.SupportedCurves)
	hashOffered(digest, hello.SupportedVersions)
	hashOffered(digest, hello.SignatureSchemes)
	protocols := slices.Sorted(slices.Values(hello.SupportedProtos))
	for _, protocol := range protocols {
		_ = binary.Write(digest, binary.BigEndian, uint16(len(protocol)))
		digest.Write([]byte(protocol))
	}
	return hex.EncodeToString(digest.Sum(nil)[:8])
}

func hashOffered[T ~uint16](digest hash.Hash, offered []T) {
	values := make([]uint16, 0, len(offered))
	for _, value := range offered {
		if v := uint16(value); v&0x0f0f != 0x0a0a || v>>8 != v&0xff {
			values = append(values, v)
		}
	}
	slices.Sort(values)
	_ = binary.Write(digest, binary.BigEndian, uint16(len(values)))
	_ = binary.Write(digest, binary.BigEndian, values)
}

var errHelloRead = errors.New("the hello was read")

// recordFingerprint is the fingerprint of the hello in a client's first TLS
// record, or "" when crypto/tls reads no hello from it. The record is parsed
// by a handshake that ends as soon as the hello is known.
func recordFingerprint(record []byte) string {
	fingerprint := ""
	_ = tls.Server(helloRecord{bytes.NewReader(record)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			fingerprint = helloFingerprint(hello)
			return nil, errHelloRead
		},
	}).Handshake()
	return fingerprint
}

// helloRecord is a connection that holds one record and drops what is
// written to it: the alert that ends recordFingerprint's handshake.
type helloRecord struct{ record *bytes.Reader }

func (c helloRecord) Read(p []byte) (int, error)     { return c.record.Read(p) }
func (helloRecord) Write(p []byte) (int, error)      { return len(p), nil }
func (helloRecord) Close() error                     { return nil }
func (helloRecord) LocalAddr() net.Addr              { return nil }
func (helloRecord) RemoteAddr() net.Addr             { return nil }
func (helloRecord) SetDeadline(time.Time) error      { return nil }
func (helloRecord) SetReadDeadline(time.Time) error  { return nil }
func (helloRecord) SetWriteDeadline(time.Time) error { return nil }

// scopeToHello reads the hello a client opens a tunnel with, on a host read
// for leak protection, before the proxy answers it. source is the client's
// connection as withBuffered returns it. It returns that connection with the
// hello put back, and the match keyed to this client, under which its
// handshake is counted. A client in a pass-through window of its own is
// handed to the service here instead, and handedOver is true.
//
// A client whose hello cannot be read keeps the match as it came: it is
// counted per tool and host, and a window opened that way was looked for
// when its CONNECT came.
func (p *httpProxy) scopeToHello(ctx context.Context, source net.Conn, host string, port int, match *leakHostMatch, selection string) (client net.Conn, scoped *leakHostMatch, handedOver bool) {
	// The wait is the one a host whose hello is copied gives its client. A
	// client that takes longer is answered all the same, by its tool and host.
	wait := p.mirrorHelloWait
	if wait <= 0 {
		wait = mirrorHelloTimeout
	}
	_ = source.SetReadDeadline(time.Now().Add(wait))
	hello, _ := tlsmirror.ReadHello(source)
	_ = source.SetReadDeadline(time.Time{})
	client = &replayConn{Conn: source, replay: bytes.NewReader(hello)}
	fingerprint := recordFingerprint(hello)
	if fingerprint == "" {
		return client, match, false
	}
	own := *match
	own.key.hello = fingerprint
	if !p.leak.memoryOf(match).handshakes.bypassed(own.key) {
		return client, &own, false
	}
	p.passThroughRefused(ctx, source, hello, host, port, match, selection)
	return nil, nil, true
}

// passThroughRefused hands the connection of a client in a pass-through
// window to the service as the client opened it. It is raw for as long as the
// client keeps it, after the window too; status goes on saying so.
func (p *httpProxy) passThroughRefused(ctx context.Context, client net.Conn, read []byte, host string, port int, match *leakHostMatch, selection string) {
	upstream, err := p.dialUnbound(ctx, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return
	}
	defer upstream.Close()
	defer p.leak.memoryOf(match).connections.passed(match.key.host, leakReasonTLSRefused)()
	// As for any raw tunnel, the host is remembered for GET /v1/hints.
	p.state.hints.noteUnboundHost(host, port)
	if _, err := upstream.Write(read); err != nil {
		return
	}
	defer p.watchPassThrough(ctx, client, upstream, host, port, selection)()
	copyBidirectional(client, upstream)
}
