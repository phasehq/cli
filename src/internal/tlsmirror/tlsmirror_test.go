package tlsmirror

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"math/rand/v2"
	"net"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// echo checks that a connection carries data both ways.
func echo(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := io.WriteString(conn, "over the copied hello\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || line != "over the copied hello\n" {
		t.Fatalf("the connection did not carry data: %q %v", line, err)
	}
}

func TestClientOpensWithACopyOfTheHello(t *testing.T) {
	for name, c := range map[string]struct {
		client   func(roots *x509.CertPool) *tls.Config
		server   func(*tls.Config)
		protocol string
		version  uint16
	}{
		"distinctive": {
			client:   func(roots *x509.CertPool) *tls.Config { return distinctiveConfig("mirror.test", roots) },
			server:   func(config *tls.Config) { config.NextProtos = []string{"http/1.1"} },
			protocol: "http/1.1", version: tls.VersionTLS13,
		},
		"go's default": {
			client:  func(roots *x509.CertPool) *tls.Config { return &tls.Config{ServerName: "mirror.test", RootCAs: roots} },
			version: tls.VersionTLS13,
		},
		"tls 1.3 only, two protocols": {
			client: func(roots *x509.CertPool) *tls.Config {
				return &tls.Config{ServerName: "mirror.test", RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
			},
			server:   func(config *tls.Config) { config.NextProtos = []string{"h2", "http/1.1"} },
			protocol: "h2", version: tls.VersionTLS13,
		},
		"tls 1.2 only": {
			client: func(roots *x509.CertPool) *tls.Config {
				config := distinctiveConfig("mirror.test", roots)
				config.MaxVersion = tls.VersionTLS12
				return config
			},
			version: tls.VersionTLS12,
		},
		"a session cache and no session": {
			client: func(roots *x509.CertPool) *tls.Config {
				config := distinctiveConfig("mirror.test", roots)
				config.ClientSessionCache = tls.NewLRUClientSessionCache(4)
				return config
			},
			version: tls.VersionTLS13,
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := newRecordingServer(t, c.server)
			original := helloOf(t, c.client(server.roots))
			if err := Check(original, "mirror.test"); err != nil {
				t.Fatalf("the hello cannot be copied: %v", err)
			}
			conn, protocol, err := Client(testContext(t), server.dial(t), original, "mirror.test", server.roots)
			if err != nil {
				t.Fatal(err)
			}
			if protocol != c.protocol {
				t.Fatalf("the server chose %q, want %q", protocol, c.protocol)
			}
			echo(t, conn)
			sent, info := server.last(t)
			if !SameShape(original, sent) {
				t.Fatal("what the server received is not a copy of the client's hello")
			}
			// Nothing that is new for each connection was copied.
			if bytes.Equal(original[recordHeaderLength+6:recordHeaderLength+38], sent[recordHeaderLength+6:recordHeaderLength+38]) {
				t.Fatal("the client's random was sent again")
			}
			want, _ := ParseHello(original)
			got, _ := ParseHello(sent)
			if !reflect.DeepEqual(want, got) || len(got.CipherSuites) == 0 || len(got.Extensions) == 0 {
				t.Fatalf("the copy offers %+v, the client offered %+v", got, want)
			}
			if !reflect.DeepEqual(info.CipherSuites, want.CipherSuites) || !reflect.DeepEqual(info.Extensions, want.Extensions) {
				t.Fatalf("crypto/tls read another hello than the client's: %+v", info)
			}
			// The handshake is the copy's own, completed with key shares of
			// its own.
			if version := server.version(t); version != c.version {
				t.Fatalf("the connection is TLS %04x, want %04x", version, c.version)
			}
		})
	}
}

// extensionsOf returns where a hello record's extensions start, past their
// length.
func extensionsOf(record []byte) int {
	// After the version, the random, the session id, the cipher suites and
	// the compression methods.
	at := recordHeaderLength + 4 + 2 + 32
	at += 1 + int(record[at])
	at += 2 + int(record[at])<<8 + int(record[at+1])
	at += 1 + int(record[at])
	return at + 2
}

// withExtension adds one extension to the end of a hello record.
func withExtension(t *testing.T, record []byte, kind uint16, data []byte) []byte {
	t.Helper()
	added := append([]byte{byte(kind >> 8), byte(kind), byte(len(data) >> 8), byte(len(data))}, data...)
	out := append(bytes.Clone(record), added...)
	grow := func(at, size int) {
		value := 0
		for _, b := range out[at : at+size] {
			value = value<<8 | int(b)
		}
		value += len(added)
		for i := range size {
			out[at+size-1-i] = byte(value >> (8 * i))
		}
	}
	grow(3, 2)                    // the record
	grow(recordHeaderLength+1, 3) // the handshake message
	grow(extensionsOf(out)-2, 2)  // the extensions
	if _, err := ParseHello(out); err != nil {
		t.Fatalf("the extended hello is malformed: %v", err)
	}
	return out
}

// An extension the library has no type for is carried over as it was sent.
func TestClientCopiesAnExtensionItDoesNotKnow(t *testing.T) {
	server := newRecordingServer(t, nil)
	original := withExtension(t, helloOf(t, distinctiveConfig("mirror.test", server.roots)), 0xfe01, []byte("private use"))
	conn, _, err := Client(testContext(t), server.dial(t), original, "mirror.test", server.roots)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, conn)
	sent, _ := server.last(t)
	hello, _ := ParseHello(sent)
	if !SameShape(original, sent) || hello.Extensions[len(hello.Extensions)-1] != 0xfe01 {
		t.Fatal("the unknown extension did not reach the server as the client sent it")
	}
}

// A server may answer the hello by asking for a key share of another group.
// The copy's handshake goes on from there as the client's would.
func TestClientFollowsAHelloRetryRequest(t *testing.T) {
	server := newRecordingServer(t, func(config *tls.Config) { config.CurvePreferences = []tls.CurveID{tls.CurveP384} })
	original := helloOf(t, distinctiveConfig("mirror.test", server.roots))
	if hello, _ := ParseHello(original); len(hello.KeyShareGroups) != 1 || hello.KeyShareGroups[0] != uint16(tls.X25519) {
		t.Fatalf("the client's hello does not make this server ask again: %+v", hello)
	}
	conn, _, err := Client(testContext(t), server.dial(t), original, "mirror.test", server.roots)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, conn)
	if sent, _ := server.last(t); !SameShape(original, sent) {
		t.Fatal("the first hello the server received is not a copy of the client's")
	}
}

// GREASE values are a client's random filler. The copy carries its own in the
// same places.
func TestClientCopiesGREASEWithValuesOfItsOwn(t *testing.T) {
	if err := Check(greasedHello(0x1a1a, 1), "mirror.test"); err != nil {
		t.Fatalf("a hello with GREASE in every list: %v", err)
	}
	server := newRecordingServer(t, nil)
	original := withExtension(t, helloOf(t, distinctiveConfig("mirror.test", server.roots)), 0x3a3a, nil)
	conn, _, err := Client(testContext(t), server.dial(t), original, "mirror.test", server.roots)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, conn)
	sent, _ := server.last(t)
	hello, _ := ParseHello(sent)
	if last := hello.Extensions[len(hello.Extensions)-1]; !SameShape(original, sent) || !isGREASE(last) {
		t.Fatalf("the copy's last extension is %04x", last)
	}
}

// A hello that offers to resume a session is never copied: the session is
// between the client and the real server.
func TestClientRefusesAHelloThatResumesASession(t *testing.T) {
	server := newRecordingServer(t, nil)
	config := distinctiveConfig("mirror.test", server.roots)
	config.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	// A first connection of the client's own gets a ticket from the server.
	first := tls.Client(server.dial(t), config)
	if err := first.Handshake(); err != nil {
		t.Fatal(err)
	}
	echo(t, first)
	_ = first.Close()
	resuming := helloOf(t, config)
	hello, err := ParseHello(resuming)
	if err != nil || !hello.Resumes || hello.Extensions[len(hello.Extensions)-1] != extensionPreSharedKey {
		t.Fatalf("the client's second hello offers no session: %+v %v", hello, err)
	}
	if err := Check(resuming, "mirror.test"); !errors.Is(err, ErrResumes) {
		t.Fatalf("Check: %v", err)
	}
	before := server.connections()
	if _, _, err := Client(testContext(t), server.dial(t), resuming, "mirror.test", server.roots); !errors.Is(err, ErrResumes) {
		t.Fatalf("Client: %v", err)
	}
	// The refusal comes before anything is sent.
	time.Sleep(50 * time.Millisecond)
	if sent := server.received(before); sent != 0 {
		t.Fatalf("%d bytes of a refused hello were sent", sent)
	}
	// So do early data and a TLS 1.2 session ticket.
	plain := helloOf(t, distinctiveConfig("mirror.test", server.roots))
	for name, record := range map[string][]byte{
		"early data":     withExtension(t, plain, extensionEarlyData, nil),
		"session ticket": withExtension(t, plain, extensionSessionTicket, []byte("a ticket from the server")),
	} {
		if err := Check(record, "mirror.test"); !errors.Is(err, ErrResumes) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An empty session ticket extension only says the client takes tickets.
	if err := Check(withExtension(t, plain, extensionSessionTicket, nil), "mirror.test"); err != nil {
		t.Errorf("an empty session ticket extension: %v", err)
	}
}

func TestClientRefusesAHelloItCannotCopyExactly(t *testing.T) {
	server := newRecordingServer(t, nil)
	original := helloOf(t, distinctiveConfig("mirror.test", server.roots))
	marked := bytes.Clone(original)
	marked[2] = 3 // the record marked TLS 1.2, which the copy's would not be
	for name, c := range map[string]struct {
		record     []byte
		serverName string
	}{
		"another server name":      {original, "other.test"},
		"another record version":   {marked, "mirror.test"},
		"a key share for no group": {keyShareFor(t, original, 0x9999), "mirror.test"},
	} {
		if err := Check(c.record, c.serverName); !errors.Is(err, ErrNotCopied) {
			t.Errorf("%s: Check: %v", name, err)
		}
		before := server.connections()
		if _, _, err := Client(testContext(t), server.dial(t), c.record, c.serverName, server.roots); !errors.Is(err, ErrNotCopied) {
			t.Errorf("%s: Client: %v", name, err)
		}
		time.Sleep(20 * time.Millisecond)
		if sent := server.received(before); sent != 0 {
			t.Errorf("%s: %d bytes of a hello that is no copy were sent", name, sent)
		}
	}
	for name, record := range map[string][]byte{"not a hello": []byte("GET / HTTP/1.1\r\n\r\n"), "nothing": nil} {
		if err := Check(record, "mirror.test"); !errors.Is(err, ErrNotHello) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A hello the library stops on by panicking is one it cannot copy; the
	// panic goes no further.
	twice := withExtension(t, withExtension(t, original, extensionSessionTicket, nil), extensionSessionTicket, nil)
	if err := Check(twice, "mirror.test"); !errors.Is(err, ErrNotCopied) {
		t.Errorf("a hello with the same extension twice: %v", err)
	}
	if _, _, err := Client(testContext(t), server.dial(t), twice, "mirror.test", server.roots); !errors.Is(err, ErrNotCopied) {
		t.Errorf("a hello with the same extension twice: Client: %v", err)
	}
	if err := Check(original, ""); err == nil {
		t.Error("a hello was accepted with no server name to verify")
	}
}

// The hello is whatever a client chose to send. Bytes damaged in any way are
// refused or copied; they never stop the process, whatever the library that
// builds the copy makes of them.
func TestDamagedHellosAreRefusedQuietly(t *testing.T) {
	originals := [][]byte{
		helloOf(t, distinctiveConfig("mirror.test", nil)),
		helloOf(t, &tls.Config{ServerName: "mirror.test", InsecureSkipVerify: true}),
		greasedHello(0x1a1a, 7),
	}
	random := rand.New(rand.NewPCG(20261119, 41))
	copied := 0
	for round := 0; round < 4000; round++ {
		damaged := bytes.Clone(originals[round%len(originals)])
		switch random.IntN(4) {
		case 0:
			damaged = damaged[:random.IntN(len(damaged))]
		case 1:
			damaged = append(damaged, byte(random.IntN(256)))
		default:
			for flips := 1 + random.IntN(3); flips > 0; flips-- {
				damaged[random.IntN(len(damaged))] ^= byte(1 << random.IntN(8))
			}
		}
		hello, parseErr := ParseHello(damaged)
		SameShape(originals[round%len(originals)], damaged)
		err := Check(damaged, "mirror.test")
		switch {
		case err == nil:
			copied++
			if parseErr != nil || hello.Resumes {
				t.Fatalf("round %d: a hello that does not parse, or resumes a session, can be copied", round)
			}
		case !errors.Is(err, ErrNotHello) && !errors.Is(err, ErrNotCopied) && !errors.Is(err, ErrResumes):
			t.Fatalf("round %d: %v", round, err)
		case (parseErr != nil) != errors.Is(err, ErrNotHello):
			t.Fatalf("round %d: the parser said %v and the check %v", round, parseErr, err)
		}
	}
	// A changed byte in the random, the session id or a key share is the
	// same hello; nearly every other change is not one.
	t.Logf("%d of 4000 damaged hellos could still be copied", copied)
	if copied == 0 || copied > 2000 {
		t.Fatalf("%d of 4000 damaged hellos could be copied", copied)
	}
}

// keyShareFor rewrites the group of a hello's first key share.
func keyShareFor(t *testing.T, record []byte, group uint16) []byte {
	t.Helper()
	out := bytes.Clone(record)
	for at := extensionsOf(out); at+4 <= len(out); {
		kind := int(out[at])<<8 | int(out[at+1])
		length := int(out[at+2])<<8 | int(out[at+3])
		if kind == extensionKeyShare {
			// Past the extension's header and the list's length.
			out[at+6], out[at+7] = byte(group>>8), byte(group)
			if hello, err := ParseHello(out); err != nil || hello.KeyShareGroups[0] != group {
				t.Fatalf("the key share was not rewritten: %v", err)
			}
			return out
		}
		at += 4 + length
	}
	t.Fatal("the hello has no key share")
	return nil
}

// The server's certificate is verified as crypto/tls verifies it, and there
// is no way to ask for less.
func TestClientVerifiesTheServer(t *testing.T) {
	server := newRecordingServer(t, nil)
	original := helloOf(t, distinctiveConfig("mirror.test", server.roots))
	otherHello := helloOf(t, distinctiveConfig("other.test", server.roots))
	_, strangerPEM, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	strangers := x509.NewCertPool()
	strangers.AppendCertsFromPEM(strangerPEM)
	type refusal struct {
		record     []byte
		serverName string
		roots      *x509.CertPool
	}
	cases := map[string]refusal{
		"roots that did not sign it": {original, "mirror.test", strangers},
		"no roots at all":            {original, "mirror.test", x509.NewCertPool()},
		// The server answers every name with a certificate for mirror.test.
		"a certificate for another name": {otherHello, "other.test", server.roots},
	}
	// No roots given means the system's, not none. Windows may ask the
	// network about a root it has not seen, so it is left out there.
	if runtime.GOOS != "windows" {
		cases["the system's roots"] = refusal{original, "mirror.test", nil}
	}
	for name, c := range cases {
		conn, _, err := Client(testContext(t), server.dial(t), c.record, c.serverName, c.roots)
		if err == nil {
			_ = conn.Close()
			t.Errorf("%s: the handshake completed", name)
			continue
		}
		var unknown x509.UnknownAuthorityError
		var hostname x509.HostnameError
		if !errors.As(err, &unknown) && !errors.As(err, &hostname) && !strings.Contains(err.Error(), "certificate") {
			t.Errorf("%s: not a certificate error: %v", name, err)
		}
		if errors.Is(err, ErrNotCopied) || errors.Is(err, ErrResumes) || errors.Is(err, ErrNotHello) {
			t.Errorf("%s: a failed handshake was reported as a hello that cannot be copied: %v", name, err)
		}
	}
	// The same hello and server with the right roots completes.
	conn, _, err := Client(testContext(t), server.dial(t), original, "mirror.test", server.roots)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, conn)
}

func TestClientRefusesAConnectionBelowTLS12(t *testing.T) {
	server := newRecordingServer(t, func(config *tls.Config) { config.MaxVersion = tls.VersionTLS11 })
	config := distinctiveConfig("mirror.test", server.roots)
	config.MinVersion = tls.VersionTLS10
	config.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
	original := helloOf(t, config)
	// The client itself would accept what the server offers.
	own := tls.Client(server.dial(t), config)
	if err := own.Handshake(); err != nil || own.ConnectionState().Version != tls.VersionTLS11 {
		t.Fatalf("the client's own handshake: %v", err)
	}
	if conn, _, err := Client(testContext(t), server.dial(t), original, "mirror.test", server.roots); err == nil {
		_ = conn.Close()
		t.Fatal("a connection below TLS 1.2 was returned")
	}
}

func TestClientStopsWithItsContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		// A server that takes the hello and never answers.
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, err = Client(ctx, conn, helloOf(t, distinctiveConfig("mirror.test", nil)), "mirror.test", nil)
	if err == nil || time.Since(started) > 5*time.Second {
		t.Fatalf("a handshake with a silent server did not stop with its context: %v", err)
	}
}

// Nothing but this package's one file may import the library that builds the
// hello: the copy stays behind Check and Client.
func TestOnlyOneFileImportsUTLS(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	const library = "github.com/refraction-networking/utls"
	var importers []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			imported, _ := strconv.Unquote(spec.Path.Value)
			if imported == library || strings.HasPrefix(imported, library+"/") {
				relative, _ := filepath.Rel(root, path)
				importers = append(importers, filepath.ToSlash(relative))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(importers, []string{"internal/tlsmirror/tlsmirror.go"}) {
		t.Fatalf("%s is imported by %v; only internal/tlsmirror/tlsmirror.go may import it", library, importers)
	}
}
