package aiproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/tlsmirror"
)

// helloRecordOf returns the first TLS record a client with this configuration
// sends.
func helloRecordOf(t *testing.T, config *tls.Config) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		_ = tls.Client(client, config).Handshake()
		_ = client.Close()
	}()
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	record, err := tlsmirror.ReadHello(server)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// A client is one client however it orders what it offers and whatever
// GREASE values it adds, as Chromium does on every connection; a client that
// offers something else is another.
func TestHelloFingerprintIgnoresOrderAndGREASE(t *testing.T) {
	plain := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
		SupportedProtos:   []string{"h2", "http/1.1"},
	}
	shuffled := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x3a3a, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{0xdada, tls.CurveP256, tls.X25519},
		SupportedVersions: []uint16{0x0a0a, tls.VersionTLS12, tls.VersionTLS13},
		SignatureSchemes:  []tls.SignatureScheme{tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256},
		SupportedProtos:   []string{"http/1.1", "h2"},
	}
	want := helloFingerprint(plain)
	if want == "" || helloFingerprint(shuffled) != want {
		t.Fatalf("one client has two fingerprints: %q and %q", want, helloFingerprint(shuffled))
	}
	for name, change := range map[string]func(*tls.ClientHelloInfo){
		"cipher suites":     func(h *tls.ClientHelloInfo) { h.CipherSuites = h.CipherSuites[:2] },
		"groups":            func(h *tls.ClientHelloInfo) { h.SupportedCurves = append(h.SupportedCurves, tls.CurveP384) },
		"versions":          func(h *tls.ClientHelloInfo) { h.SupportedVersions = []uint16{tls.VersionTLS12} },
		"signature schemes": func(h *tls.ClientHelloInfo) { h.SignatureSchemes = h.SignatureSchemes[:1] },
		"protocols":         func(h *tls.ClientHelloInfo) { h.SupportedProtos = nil },
	} {
		other := *plain
		change(&other)
		if helloFingerprint(&other) == want {
			t.Fatalf("a client that offers other %s has the same fingerprint", name)
		}
	}
}

// The fingerprint is read from the record a client opens its tunnel with. Two
// connections of one client give the same one, though each hello holds a new
// random and new key shares; bytes that are no hello give none.
func TestRecordFingerprintIsTheClientsOnEveryConnection(t *testing.T) {
	config := func() *tls.Config {
		return &tls.Config{ServerName: "api.anthropic.com", NextProtos: []string{"http/1.1"}}
	}
	first, second := helloRecordOf(t, config()), helloRecordOf(t, config())
	if bytes.Equal(first, second) {
		t.Fatal("two hellos of one client are the same bytes")
	}
	fingerprint := recordFingerprint(first)
	if fingerprint == "" || recordFingerprint(second) != fingerprint {
		t.Fatalf("one client's connections have the fingerprints %q and %q", fingerprint, recordFingerprint(second))
	}
	other := config()
	other.NextProtos = nil
	if recordFingerprint(helloRecordOf(t, other)) == fingerprint {
		t.Fatal("a client that offers no protocol has the fingerprint of one that does")
	}
	for _, record := range [][]byte{nil, []byte("EHLO not-a-tls-client.example\r\n"), first[:len(first)/2]} {
		if got := recordFingerprint(record); got != "" {
			t.Fatalf("%d bytes that are no hello have the fingerprint %q", len(record), got)
		}
	}
}

// Behind the proxy environment a program the harness starts is named as the
// harness's tool. One that does not trust Phase's certificate refuses it on
// every connection: its window is its own, and the harness's own traffic to
// the same host is still read. Status and the window's event name the host
// as not read all the same.
func TestARefusingClientsWindowLeavesTheToolsOtherClientsRead(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.tool = "claude"
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	const host, path = "api.anthropic.com", "/v1/messages"
	// The child's hello offers no protocol; the harness's, which sendOver
	// sends, offers http/1.1.
	child := func() *tls.Config { return &tls.Config{ServerName: host, RootCAs: rig.providerRoots} }
	perHost := leakStateKey{tool: "claude", host: host}
	for want := 1; want <= 2; want++ {
		raw := rig.connectAs(t, host, nil)
		if err := tls.Client(raw, child()).Handshake(); err == nil {
			t.Fatal("a client that does not trust Phase completed TLS with the proxy")
		}
		_ = raw.Close()
		for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			key := refusalKey(rig.guard, perHost)
			rig.guard.handshakes.mu.Lock()
			state := rig.guard.handshakes.hosts[key]
			counted := state != nil && state.failures >= want
			rig.guard.handshakes.mu.Unlock()
			if counted {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("refusal %d was not counted", want)
			}
		}
	}
	refused := refusalKey(rig.guard, perHost)
	if refused.hello == "" || !rig.guard.handshakes.bypassed(refused) || rig.guard.handshakes.bypassed(perHost) {
		t.Fatalf("the window is not the refusing client's alone: %+v", refused)
	}

	// The harness's own request to the same host is read.
	if !rig.sendAs(t, host, path, nil) {
		t.Fatal("a child program's refusals passed the harness's own traffic through unread")
	}
	if !rig.guard.handshakes.bypassed(refused) {
		t.Fatal("another client's handshake closed the refusing client's window")
	}

	// The client that refused is passed through to the service as it is.
	conn := tls.Client(rig.connectAs(t, host, nil), child())
	if err := conn.Handshake(); err != nil {
		t.Fatalf("the refusing client was not handed to the service inside its window: %v", err)
	}
	body := anthropicBody("the key is " + leakSecretOne)
	request := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", path, host, len(body), body)
	if response, _ := exchange(t, conn, bufio.NewReader(conn), request); response.StatusCode != http.StatusOK {
		t.Fatalf("inside the window: status %d", response.StatusCode)
	}
	if !bytes.Equal(rig.lastReceived().body, body) {
		t.Fatal("the refusing client was read inside its window")
	}

	// The tunnel is still open, and the window too: the host is not read for
	// every client, and status says so.
	status := rig.guard.status()
	if !containsString(status.UnreadHosts, host) || containsString(status.InspectedHosts, host) ||
		!reflect.DeepEqual(status.UnreadReasons, map[string][]string{host: {leakReasonTLSRefused}}) {
		t.Fatalf("status: inspected %v, not inspected %v for %v", status.InspectedHosts, status.UnreadHosts, status.UnreadReasons)
	}
	_ = conn.Close()
	windows := 0
	for _, event := range rig.leakEventsNow() {
		if event.Outcome != outcomeBypass {
			continue
		}
		windows++
		if event.Host != host || event.Reason != leakReasonTLSRefused || event.Detail["harness"] != "claude" || event.Detail["windowSeconds"] != float64(20) {
			t.Fatalf("the window's event: %+v", event)
		}
	}
	if windows != 1 {
		t.Fatalf("%d window events, want 1", windows)
	}
}

// With leak protection off the proxy reads no host, and names none to the
// session's NO_PROXY.
func TestReadHostNamesAreNoneWhenLeakProtectionIsOff(t *testing.T) {
	off, err := newLeakGuard(leakModeOff)
	if err != nil {
		t.Fatal(err)
	}
	if names := off.readHostNames(); len(names) != 0 {
		t.Fatalf("a proxy that reads nothing names %v", names)
	}
	for _, mode := range []string{leakModeCensor, leakModeObserve} {
		guard, err := newLeakGuard(mode)
		if err != nil {
			t.Fatal(err)
		}
		names := guard.readHostNames()
		for _, host := range []string{"api.anthropic.com", "api.openai.com", "chatgpt.com", "cursor.sh", "*.cursor.sh"} {
			if !containsString(names, host) {
				t.Fatalf("%s: %s is read and not named: %v", mode, host, names)
			}
		}
	}
}
