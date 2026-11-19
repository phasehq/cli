// Package tlsmirror opens a TLS connection whose ClientHello is a copy of one
// a real client sent.
//
// Some model services accept only their own client. They look at the TLS
// ClientHello (which cipher suites, extensions, groups and protocols it
// offers, and in what order) and refuse requests that arrive over anything
// else, Go's own TLS included. The Phase AI proxy still has to read that
// traffic to remove secret values from it, so it cannot leave the client's
// connection alone. For such a host it keeps the hello the client opened its
// tunnel with and re-sends the inspected requests over connections that open
// with the same hello: the service sees what that client would have sent it.
//
// It is used for the hosts flagged MirrorHello in the leak protection table
// (internal/aiproxy/leak_hosts.go) and nowhere else. This file is the only
// place in the tree that imports github.com/refraction-networking/utls, which
// builds the hello; nothing else may import it.
//
// Only the shape of the hello is the client's. The random, the session id and
// the key shares are new for every connection, the handshake is the proxy's
// own, and the server's certificate is verified as crypto/tls verifies it. A
// hello that cannot be copied exactly is refused, so the caller can leave
// that connection to the client instead.
package tlsmirror

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

var (
	// ErrResumes means the hello offers to resume a session. That session is
	// between the client and the service; a copy of the offer would be a
	// promise the proxy cannot keep.
	ErrResumes = errors.New("tlsmirror: the ClientHello resumes a session")
	// ErrNotCopied means no exact copy of the hello can be sent.
	ErrNotCopied = errors.New("tlsmirror: the ClientHello cannot be copied exactly")
)

// Check reports whether Client can send a copy of the hello in record to
// serverName, without a connection: nil, ErrNotHello, ErrResumes or
// ErrNotCopied.
func Check(record []byte, serverName string) error {
	_, _, err := prepare(nil, record, serverName, nil)
	return err
}

// Client completes a TLS handshake over conn as a client whose ClientHello is
// a copy of the one in record, a client's own first TLS record as ReadHello
// returns it. It returns the connection and the application protocol the
// server chose, empty when it chose none.
//
// The server's certificate is verified for serverName against roots (nil
// means the system's) exactly as crypto/tls does, and nothing a caller passes
// can turn that off. A connection below TLS 1.2 is refused, as it is by the
// proxy's own upstream TLS. On error conn is still the caller's to close.
func Client(ctx context.Context, conn net.Conn, record []byte, serverName string, roots *x509.CertPool) (net.Conn, string, error) {
	client, config, err := prepare(conn, record, serverName, roots)
	if err != nil {
		return nil, "", err
	}
	if err := handshake(ctx, client); err != nil {
		return nil, "", err
	}
	// The hello says about renegotiation what the client's says. The
	// connection itself never renegotiates, as Go's own client does not.
	config.Renegotiation = utls.RenegotiateNever
	state := client.ConnectionState()
	if state.Version < utls.VersionTLS12 {
		return nil, "", errors.New("tlsmirror: the server chose a TLS version below 1.2")
	}
	return client, state.NegotiatedProtocol, nil
}

// prepare builds the client and its hello, and checks the hello against the
// one it copies before a byte of it is sent.
func prepare(conn net.Conn, record []byte, serverName string, roots *x509.CertPool) (client *utls.UConn, config *utls.Config, err error) {
	if serverName == "" {
		return nil, nil, errors.New("tlsmirror: a server name is required to verify the server's certificate")
	}
	hello, err := ParseHello(record)
	if err != nil {
		return nil, nil, err
	}
	if hello.Resumes {
		return nil, nil, ErrResumes
	}
	// utls stops on states it does not expect by panicking. A hello that
	// trips it is one it cannot copy.
	defer func() {
		if recover() != nil {
			client, config, err = nil, nil, ErrNotCopied
		}
	}()
	// Extensions utls has no type for are carried over byte for byte. The
	// check below is what makes that safe to allow: whatever utls builds is
	// compared with the original before it is used.
	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).RawClientHello(record)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNotCopied, err)
	}
	// The configuration holds what verifies the server and nothing else; the
	// rest of the connection's behaviour comes from the hello. utls keeps this
	// very value and writes to it, so each connection has its own.
	config = &utls.Config{ServerName: serverName, RootCAs: roots}
	client = utls.UClient(conn, config, utls.HelloCustom)
	if err := client.ApplyPreset(spec); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNotCopied, err)
	}
	if err := client.BuildHandshakeState(); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNotCopied, err)
	}
	// The hello goes out in one record marked TLS 1.0, as nearly every client
	// marks its first. A client that marks it otherwise is not copied.
	built := client.HandshakeState.Hello.Raw
	if len(built) > maxRecordPayload {
		return nil, nil, ErrNotCopied
	}
	copied := make([]byte, 0, recordHeaderLength+len(built))
	copied = append(copied, recordTypeHandshake, 3, 1, byte(len(built)>>8), byte(len(built)))
	copied = append(copied, built...)
	if !SameShape(record, copied) {
		return nil, nil, ErrNotCopied
	}
	return client, config, nil
}

func handshake(ctx context.Context, client *utls.UConn) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("tlsmirror: the handshake could not be completed")
		}
	}()
	return client.HandshakeContext(ctx)
}
