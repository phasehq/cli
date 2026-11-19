package tlsmirror

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// distinctiveConfig is a Go client set up so its hello cannot be mistaken for
// Go's default: its own cipher suites, groups and protocol.
func distinctiveConfig(serverName string, roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS12,
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		CurvePreferences: []tls.CurveID{tls.CurveP384, tls.X25519},
		NextProtos:       []string{"http/1.1"},
	}
}

// helloOf returns the first TLS record a Go client with this configuration
// sends.
func helloOf(t *testing.T, config *tls.Config) []byte {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_ = tls.Client(conn, config).Handshake()
	}()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	record, err := ReadHello(conn)
	if err != nil {
		t.Fatalf("the client's hello was not read: %v", err)
	}
	return record
}

// teeConn keeps the first bytes read from a connection.
type teeConn struct {
	net.Conn
	mu   sync.Mutex
	seen []byte
}

func (c *teeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	if room := 1<<16 - len(c.seen); room > 0 {
		c.seen = append(c.seen, p[:min(n, room)]...)
	}
	c.mu.Unlock()
	return n, err
}

// firstRecord returns the first TLS record in what a connection sent.
func (c *teeConn) firstRecord(t *testing.T) []byte {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) < recordHeaderLength {
		t.Fatalf("the server saw %d bytes", len(c.seen))
	}
	end := recordHeaderLength + int(binary.BigEndian.Uint16(c.seen[3:]))
	if len(c.seen) < end {
		t.Fatalf("the server saw %d bytes of a %d byte record", len(c.seen), end)
	}
	return bytes.Clone(c.seen[:end])
}

// recordingServer is a TLS server that echoes what it is sent and keeps the
// raw bytes of every connection.
type recordingServer struct {
	address string
	roots   *x509.CertPool

	mu     sync.Mutex
	conns  []*teeConn
	infos  []*tls.ClientHelloInfo
	states []tls.ConnectionState
}

func newRecordingServer(t *testing.T, configure func(*tls.Config)) *recordingServer {
	t.Helper()
	authority, certificate, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := &recordingServer{roots: x509.NewCertPool()}
	server.roots.AppendCertsFromPEM(certificate)
	config := &tls.Config{
		MinVersion: tls.VersionTLS10,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			server.mu.Lock()
			server.infos = append(server.infos, hello)
			server.mu.Unlock()
			return authority.CertificateForHost("mirror.test")
		},
	}
	if configure != nil {
		configure(config)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server.address = listener.Addr().String()
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			tee := &teeConn{Conn: raw}
			server.mu.Lock()
			server.conns = append(server.conns, tee)
			server.mu.Unlock()
			go func() {
				defer raw.Close()
				conn := tls.Server(tee, config)
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if conn.Handshake() != nil {
					return
				}
				server.mu.Lock()
				server.states = append(server.states, conn.ConnectionState())
				server.mu.Unlock()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return server
}

func (s *recordingServer) dial(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", s.address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn
}

// connections is how many connections the server has accepted.
func (s *recordingServer) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// received is how many bytes arrived on the connections accepted after the
// first skip.
func (s *recordingServer) received(skip int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, conn := range s.conns[skip:] {
		conn.mu.Lock()
		total += len(conn.seen)
		conn.mu.Unlock()
	}
	return total
}

// version is the TLS version of the last handshake the server completed.
func (s *recordingServer) version(t *testing.T) uint16 {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.states) == 0 {
		t.Fatal("the server completed no handshake")
	}
	return s.states[len(s.states)-1].Version
}

// last returns the hello of the most recent connection: the raw record and
// what crypto/tls read from it.
func (s *recordingServer) last(t *testing.T) ([]byte, *tls.ClientHelloInfo) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.conns) == 0 || len(s.infos) == 0 {
		t.Fatal("the server saw no hello")
	}
	return s.conns[len(s.conns)-1].firstRecord(t), s.infos[len(s.infos)-1]
}

func TestReadHelloTakesExactlyOneRecord(t *testing.T) {
	record := helloOf(t, distinctiveConfig("mirror.test", nil))
	source := bytes.NewReader(append(bytes.Clone(record), "what follows"...))
	read, err := ReadHello(source)
	if err != nil || !bytes.Equal(read, record) {
		t.Fatalf("a whole hello was not read back: %v", err)
	}
	if rest, _ := io.ReadAll(source); string(rest) != "what follows" {
		t.Fatalf("the reader was read past the record: %q is left", rest)
	}
}

func TestReadHelloRefusesAnythingButOneWholeHello(t *testing.T) {
	record := helloOf(t, distinctiveConfig("mirror.test", nil))
	message := record[recordHeaderLength:]
	framed := func(payload []byte) []byte {
		out := []byte{recordTypeHandshake, 3, 1, byte(len(payload) >> 8), byte(len(payload))}
		return append(out, payload...)
	}
	half := len(message) / 2
	serverHello := bytes.Clone(record)
	serverHello[recordHeaderLength] = 2
	alert := bytes.Clone(record)
	alert[0] = 21
	notTLS := bytes.Clone(record)
	notTLS[1] = 2
	cases := map[string]struct {
		input []byte
		read  int
	}{
		"plain text":                    {[]byte("GET / HTTP/1.1\r\nHost: mirror.test\r\n\r\n"), recordHeaderLength},
		"another record type":           {alert, recordHeaderLength},
		"not a TLS version":             {notTLS, recordHeaderLength},
		"another handshake message":     {serverHello, len(record)},
		"a hello split over two":        {append(framed(message[:half]), framed(message[half:])...), recordHeaderLength + half},
		"a hello and more in a record":  {framed(append(bytes.Clone(message), 0x0e, 0, 0, 0)), len(record) + 4},
		"a record too short to hold it": {framed([]byte{1, 0, 0}), recordHeaderLength},
		"a record over the size limit":  {append([]byte{recordTypeHandshake, 3, 1, 0x40, 0x01}, make([]byte, maxRecordPayload+1)...), recordHeaderLength},
		"a length that lies":            {framed(append([]byte{1, 0, 0, 9}, message[4:]...)), len(record)},
		"extensions cut short":          {framed(append([]byte{1, 0, byte((len(message) - 6) >> 8), byte(len(message) - 6)}, message[4:len(message)-2]...)), len(record) - 2},
	}
	for name, c := range cases {
		read, err := ReadHello(bytes.NewReader(c.input))
		if !errors.Is(err, ErrNotHello) {
			t.Errorf("%s: %v", name, err)
		}
		// What was read comes back, so it can be passed on untouched.
		if len(read) != c.read || !bytes.Equal(read, c.input[:c.read]) {
			t.Errorf("%s: %d bytes returned, want the first %d", name, len(read), c.read)
		}
	}
	// A reader that ends first reports its own error, with what it gave.
	for _, cut := range []int{0, 3, recordHeaderLength, len(record) - 1} {
		read, err := ReadHello(bytes.NewReader(record[:cut]))
		if err == nil || errors.Is(err, ErrNotHello) || !bytes.Equal(read, record[:cut]) {
			t.Errorf("cut at %d: %d bytes, %v", cut, len(read), err)
		}
	}
}

// The parser agrees with crypto/tls about a hello, for the parts crypto/tls
// reports.
func TestParseHelloAgreesWithCryptoTLS(t *testing.T) {
	server := newRecordingServer(t, nil)
	for name, config := range map[string]*tls.Config{
		"distinctive": distinctiveConfig("mirror.test", server.roots),
		"default":     {ServerName: "mirror.test", RootCAs: server.roots},
		"tls 1.2":     {ServerName: "mirror.test", RootCAs: server.roots, MaxVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}},
	} {
		conn := tls.Client(server.dial(t), config)
		if err := conn.Handshake(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		record, info := server.last(t)
		hello, err := ParseHello(record)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		groups := make([]uint16, len(info.SupportedCurves))
		for i, curve := range info.SupportedCurves {
			groups[i] = uint16(curve)
		}
		if !reflect.DeepEqual(hello.CipherSuites, info.CipherSuites) || !reflect.DeepEqual(hello.Extensions, info.Extensions) ||
			!reflect.DeepEqual(hello.Groups, groups) || !reflect.DeepEqual(hello.ALPN, info.SupportedProtos) ||
			hello.ServerName != info.ServerName || hello.Resumes {
			t.Errorf("%s: parsed %+v, crypto/tls read %+v", name, hello, info)
		}
		// crypto/tls reports the versions of a hello without the extension
		// too; the parser reports the extension.
		if len(hello.Versions) > 0 && !reflect.DeepEqual(hello.Versions, info.SupportedVersions) {
			t.Errorf("%s: versions %x, crypto/tls read %x", name, hello.Versions, info.SupportedVersions)
		}
		if conn.ConnectionState().Version == tls.VersionTLS13 && len(hello.KeyShareGroups) == 0 {
			t.Errorf("%s: no key share was read from a TLS 1.3 hello", name)
		}
	}
	distinctive, err := ParseHello(helloOf(t, distinctiveConfig("mirror.test", nil)))
	if err != nil {
		t.Fatal(err)
	}
	// crypto/tls offers the configured groups in an order of its own.
	groups := slices.Clone(distinctive.Groups)
	slices.Sort(groups)
	if !slices.Equal(groups, []uint16{uint16(tls.CurveP384), uint16(tls.X25519)}) ||
		len(distinctive.KeyShareGroups) != 1 || !slices.Contains(groups, distinctive.KeyShareGroups[0]) ||
		!slices.Equal(distinctive.ALPN, []string{"http/1.1"}) || distinctive.ServerName != "mirror.test" {
		t.Fatalf("the distinctive hello: %+v", distinctive)
	}
}

func TestSameShapeSetsAsideOnlyWhatIsNewPerConnection(t *testing.T) {
	config := distinctiveConfig("mirror.test", nil)
	first, second := helloOf(t, config), helloOf(t, config)
	if bytes.Equal(first, second) {
		t.Fatal("two hellos of one client are byte for byte equal: nothing was random")
	}
	if !SameShape(first, second) {
		t.Fatal("two hellos of one client are not the same shape")
	}
	other := distinctiveConfig("mirror.test", nil)
	other.CurvePreferences = []tls.CurveID{tls.X25519}
	if SameShape(first, helloOf(t, other)) {
		t.Fatal("hellos that offer different groups are the same shape")
	}
	renamed := distinctiveConfig("other.test", nil)
	if SameShape(first, helloOf(t, renamed)) {
		t.Fatal("hellos for different server names are the same shape")
	}
	// One changed byte anywhere outside the random, the session id and the
	// key share values is a different hello.
	hello, err := ParseHello(first)
	if err != nil {
		t.Fatal(err)
	}
	ignored := 0
	for at := range first {
		changed := bytes.Clone(first)
		changed[at] ^= 0x01
		if SameShape(first, changed) {
			ignored++
		}
	}
	// 32 bytes of random, 32 of session id and the value of the one key share.
	keyShare := map[uint16]int{uint16(tls.X25519): 32, uint16(tls.CurveP384): 97}[hello.KeyShareGroups[0]]
	if want := 32 + 32 + keyShare; keyShare == 0 || ignored != want {
		t.Fatalf("%d bytes of the hello can change without changing its shape, want %d", ignored, want)
	}
	if SameShape(first, first[:len(first)-1]) || SameShape([]byte("not a hello"), []byte("not a hello")) {
		t.Fatal("bytes that are not a hello have a shape")
	}
}

// greasedHello builds a small hello the way BoringSSL sends one, with a GREASE
// value in every list that takes one.
func greasedHello(grease uint16, random byte) []byte {
	u16 := func(values ...uint16) []byte {
		var out []byte
		for _, value := range values {
			out = binary.BigEndian.AppendUint16(out, value)
		}
		return out
	}
	prefixed := func(size int, body []byte) []byte {
		out := make([]byte, size)
		for i := range size {
			out[size-1-i] = byte(len(body) >> (8 * i))
		}
		return append(out, body...)
	}
	extension := func(kind uint16, body []byte) []byte { return append(u16(kind), prefixed(2, body)...) }
	var extensions []byte
	extensions = append(extensions, extension(grease, nil)...)
	extensions = append(extensions, extension(extensionSupportedGroups, prefixed(2, u16(grease, 0x001d)))...)
	extensions = append(extensions, extension(extensionSupportedVersions, prefixed(1, u16(grease, 0x0304)))...)
	share := append(u16(grease), prefixed(2, []byte{0})...)
	share = append(share, u16(0x001d)...)
	share = append(share, prefixed(2, bytes.Repeat([]byte{random}, 32))...)
	extensions = append(extensions, extension(extensionKeyShare, prefixed(2, share))...)
	body := u16(0x0303)
	body = append(body, bytes.Repeat([]byte{random}, 32)...)
	body = append(body, prefixed(1, bytes.Repeat([]byte{random}, 32))...)
	body = append(body, prefixed(2, u16(grease, 0x1301))...)
	body = append(body, 1, 0)
	body = append(body, prefixed(2, extensions)...)
	message := append([]byte{handshakeTypeClientHello}, prefixed(3, body)...)
	return append([]byte{recordTypeHandshake, 3, 1}, prefixed(2, message)...)
}

func TestSameShapeSetsAsideGREASEValues(t *testing.T) {
	first, second := greasedHello(0x1a1a, 1), greasedHello(0xdada, 2)
	hello, err := ParseHello(first)
	if err != nil {
		t.Fatal(err)
	}
	if hello.Extensions[0] != 0x1a1a || hello.Groups[0] != 0x1a1a || hello.Versions[0] != 0x1a1a ||
		hello.KeyShareGroups[0] != 0x1a1a || hello.CipherSuites[0] != 0x1a1a {
		t.Fatalf("the parser changed what the hello holds: %+v", hello)
	}
	if !SameShape(first, second) {
		t.Fatal("hellos that differ only in their GREASE values are not the same shape")
	}
	// A value that is not GREASE is not set aside.
	if SameShape(first, greasedHello(0x1301, 1)) {
		t.Fatal("a value that is not GREASE was taken for one")
	}
	for value, want := range map[uint16]bool{0x0a0a: true, 0xfafa: true, 0x1a1a: true, 0x0a1a: false, 0x1301: false, 0x0b0b: false} {
		if isGREASE(value) != want {
			t.Errorf("isGREASE(%04x) = %v", value, !want)
		}
	}
}
