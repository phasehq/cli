package aiproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/leakguard"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
)

// The tests of the one policy for what is replaced, blocked and left unread,
// for a request body and a WebSocket message alike, and of what an event says.

// More fake values, unlike each other in every stretch of twelve characters.
const (
	leakSecretThree = "Zx9Qv7Lm3Tn8Rk2Wp6Yc4Hd1Bf5Gj0Ks"
	leakSecretFour  = "Mn4Xc8Vb2Zq6Lk0Jh3Gf7Ds1Ap5Oi9Uy"
	leakSecretFive  = "Qw7Er2Ty9Ui4Op6As1Df8Gh3Jk5Lz0Xc"
	leakSecretSix   = "Wr5Te9Yu3Io7Pa1Sd4Fg8Hj2Kl6Zx0Cv"
	codexSocketPath = "/backend-api/codex/responses"
)

// distinctLeakEvents waits for want leak protection events and returns what
// was shipped, one per ID in the order shipped. An event that is spooled, as
// a block is, can be shipped again before the spool learns it arrived.
func (r *leakRig) distinctLeakEvents(t *testing.T, want int) []agentapi.Event {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		r.mu.Lock()
		var events []agentapi.Event
		seen := map[string]bool{}
		for _, event := range r.shipped {
			if event.EventType == leakEventType && !seen[event.EventID] {
				seen[event.EventID] = true
				events = append(events, event)
			}
		}
		r.mu.Unlock()
		if len(events) >= want {
			return events
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d leak protection events shipped, want %d", len(events), want)
		}
	}
}

func phaseServiceToken() string {
	return "pss_service:v2:" + strings.Repeat("a1b2c3d4", 8) + ":" + strings.Repeat("e5f6a7b8", 8) + ":" + strings.Repeat("c9d0e1f2", 8) + ":" + strings.Repeat("a3b4c5d6", 8)
}

// What happens to something leak protection finds depends on the kind of
// bytes it is in and on nothing else. Every row of the policy that a body and
// a message share is sent through both adapters: as a request body under two
// content types, and as a WebSocket message under each opcode. The same bytes
// meet the same end. (The oversize row has a test of its own: it needs
// sixteen megabytes.)
func TestOnePolicySaysWhatHappensInEachPart(t *testing.T) {
	for part, rule := range leakPartRules {
		// What can be replaced never needs to block, and nothing is acted on
		// that was not read.
		if (rule.rewrite && rule.block) || (!rule.read && (rule.rewrite || rule.block)) {
			t.Errorf("part %d: %+v", part, rule)
		}
	}
	for _, c := range []struct {
		mode             string
		block, rewritten bool
		want             leakVerdict
	}{
		{leakModeCensor, false, false, leakPass},
		{leakModeCensor, false, true, leakReplace},
		{leakModeCensor, true, false, leakBlock},
		// What could not be replaced would still go out.
		{leakModeCensor, true, true, leakBlock},
		{leakModeObserve, true, true, leakPass},
		{leakModeObserve, false, true, leakPass},
		{leakModeOff, true, true, leakPass},
	} {
		scan := &leakScan{mode: c.mode, block: c.block}
		if got := scan.verdict(c.rewritten); got != c.want {
			t.Errorf("mode %s, block %v, rewritten %v: verdict %d, want %d", c.mode, c.block, c.rewritten, got, c.want)
		}
	}

	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.client(rig.phaseRoots)
	target := "https://chatgpt.com" + codexSocketPath

	// The URL and the headers belong to a request alone.
	request, _ := http.NewRequest(http.MethodPost, target+"?key="+url.QueryEscape(leakSecretOne), strings.NewReader(`{"input":"nothing"}`))
	if status := doRequest(t, client, request); status != http.StatusForbidden || rig.receivedCount() != 0 {
		t.Fatalf("a known value in the URL: %d", status)
	}
	request, _ = http.NewRequest(http.MethodPost, target, strings.NewReader(`{"input":"nothing"}`))
	request.Header.Set("X-Note", leakSecretOne)
	if status := doRequest(t, client, request); status != http.StatusOK || rig.lastReceived().header.Get("X-Note") != leakSecretOne {
		t.Fatalf("a known value in a header: %d", status)
	}

	const (
		replaced = "replaced"
		blocked  = "blocked"
		passed   = "passed as it came"
	)
	token := phaseServiceToken()
	for _, c := range []struct {
		name    string
		payload []byte
		want    string
		// sent is what goes out in its place, when that is known exactly.
		sent []byte
		// opaque sends it as bytes the proxy cannot decode: a body in an
		// encoding it does not undo, a message compressed against the
		// handshake.
		opaque bool
	}{
		{name: "JSON", payload: []byte(`{"input":"key ` + leakSecretOne + `"}`), want: replaced, sent: []byte(`{"input":"key ph:secret:stripe"}`)},
		{name: "text that is not JSON", payload: []byte("KEY=" + leakSecretOne + "\n"), want: replaced, sent: []byte("KEY=ph:secret:stripe\n")},
		{name: "text holding a Phase token", payload: []byte("token " + token), want: replaced},
		{name: "bytes that are not text", payload: append([]byte{0xff, 0x00, 0xfe}, leakSecretOne...), want: blocked},
		{name: "a Phase token in bytes that are not text", payload: append([]byte{0xff, 0x00, 0xfe}, token...), want: blocked},
		{name: "clean JSON", payload: []byte(`{"input" : "nothing to see"}`), want: passed},
		{name: "clean text", payload: []byte("nothing to see"), want: passed},
		{name: "clean bytes", payload: []byte{0xff, 0x00, 0xfe, 0x01}, want: passed},
		{name: "a known value in bytes that cannot be decoded", payload: []byte("not brotli, not deflate: " + leakSecretOne), want: blocked, opaque: true},
		{name: "clean bytes that cannot be decoded", payload: []byte("not brotli, not deflate"), want: passed, opaque: true},
	} {
		// went checks what reached the provider against the row.
		went := func(t *testing.T, how string, got []byte) {
			t.Helper()
			switch {
			case c.want == passed && !bytes.Equal(got, c.payload):
				t.Fatalf("%s: %q was changed to %q", how, c.payload, got)
			case c.want == replaced && (bytes.Contains(got, []byte(leakSecretOne)) || bytes.Contains(got, []byte(token)) || !bytes.Contains(got, []byte("ph:"))):
				t.Fatalf("%s: the value was not replaced: %q", how, got)
			case c.want == replaced && c.sent != nil && !bytes.Equal(got, c.sent):
				t.Fatalf("%s: the provider received %q, want %q", how, got, c.sent)
			}
		}
		t.Run(c.name, func(t *testing.T) {
			// As a request body, whatever the client calls it.
			for _, contentType := range []string{"application/json", "application/octet-stream"} {
				how := "a body sent as " + contentType
				before := rig.receivedCount()
				request, _ := http.NewRequest(http.MethodPost, target, bytes.NewReader(c.payload))
				request.Header.Set("Content-Type", contentType)
				if c.opaque {
					request.Header.Set("Content-Encoding", "br")
				}
				status := doRequest(t, client, request)
				if c.want == blocked {
					if status != http.StatusForbidden || rig.receivedCount() != before {
						t.Fatalf("%s: status %d, and %d requests reached the provider", how, status, rig.receivedCount()-before)
					}
					continue
				}
				if status != http.StatusOK || rig.receivedCount() != before+1 {
					t.Fatalf("%s: status %d", how, status)
				}
				went(t, how, rig.lastReceived().body)
			}
			// As a WebSocket message, whichever opcode the client frames it
			// with. What goes out keeps that opcode.
			for _, opcode := range []byte{wsOpText, 0x2} {
				how := fmt.Sprintf("a message framed with opcode %d", opcode)
				peer := rig.openWebSocket(t, "chatgpt.com", codexSocketPath)
				frame := clientFrame(true, opcode, c.payload)
				if c.opaque {
					frame[0] |= 0x40
				}
				peer.send(t, frame)
				if c.want == blocked {
					fin, closing, payload, err := readFrame(peer.reader)
					if err != nil || !fin || closing != wsOpClose || len(payload) < 2 || binary.BigEndian.Uint16(payload) != wsClosePolicyViolation {
						t.Fatalf("%s: the client was not told its message broke policy: %v %v %x %v", how, fin, closing, payload, err)
					}
					for {
						got, open := peer.received(t)
						if !open {
							break
						}
						if got.opcode != wsOpClose {
							t.Fatalf("%s: the service received opcode %d after a blocked message", how, got.opcode)
						}
					}
					continue
				}
				got, open := peer.received(t)
				if !open || got.opcode != opcode {
					t.Fatalf("%s: the service received opcode %d (still open: %v)", how, got.opcode, open)
				}
				went(t, how, got.payload)
				_ = peer.conn.Close()
			}
		})
	}
}

// wsPeer is a client's WebSocket through the proxy, and what the fake
// provider received on it: whole messages, and control frames.
type wsPeer struct {
	conn     *tls.Conn
	reader   *bufio.Reader
	messages chan wsMessage
}

func (r *leakRig) openWebSocket(t *testing.T, host, path string) *wsPeer {
	t.Helper()
	messages := make(chan wsMessage, 32)
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		connection, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		defer close(messages)
		_, _ = fmt.Fprintf(buffered, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", webSocketAccept(req.Header.Get("Sec-WebSocket-Key")))
		_ = buffered.Flush()
		var message []byte
		var opcode byte
		for {
			fin, op, payload, err := readFrame(buffered.Reader)
			if err != nil {
				return
			}
			if op >= wsOpClose {
				messages <- wsMessage{opcode: op, payload: payload}
				if op == wsOpClose {
					return
				}
				continue
			}
			if op != wsOpContinuation {
				opcode = op
			}
			message = append(message, payload...)
			if fin {
				messages <- wsMessage{opcode: opcode, payload: message}
				message = nil
			}
		}
	})
	r.mu.Lock()
	r.upstream = handler
	r.mu.Unlock()
	conn := connectThroughProxy(t, r, host, r.phaseRoots)
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n", path, host, key)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", response, err)
	}
	return &wsPeer{conn: conn, reader: reader, messages: messages}
}

func (p *wsPeer) send(t *testing.T, frame []byte) {
	t.Helper()
	if _, err := p.conn.Write(frame); err != nil {
		t.Fatal(err)
	}
}

// received returns the next thing the provider got; open is false once its
// side of the WebSocket has ended.
func (p *wsPeer) received(t *testing.T) (message wsMessage, open bool) {
	t.Helper()
	select {
	case message, open = <-p.messages:
		return message, open
	case <-time.After(3 * time.Second):
		t.Fatal("the provider got nothing")
	}
	return wsMessage{}, false
}

// Text that is not JSON is read and replaced in a message as it is in a
// request body.
func TestWebSocketTextThatIsNotJSONIsReplacedLikeABody(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	text := "STRIPE_KEY=" + leakSecretOne + "\nnot json at all"
	want := strings.Replace(text, leakSecretOne, "ph:secret:stripe", 1)

	peer := rig.openWebSocket(t, "chatgpt.com", codexSocketPath)
	half := len(text) / 2
	peer.send(t, clientFrame(false, wsOpText, []byte(text[:half])))
	peer.send(t, clientFrame(true, wsOpContinuation, []byte(text[half:])))
	if got, _ := peer.received(t); got.opcode != wsOpText || string(got.payload) != want {
		t.Fatalf("the provider received %q", got.payload)
	}
	// Text with nothing in it goes out as the client framed it.
	peer.send(t, clientFrame(true, wsOpText, []byte("plain text, not json")))
	if got, _ := peer.received(t); string(got.payload) != "plain text, not json" {
		t.Fatalf("clean text was changed: %q", got.payload)
	}
	events := rig.leakEventsNow()
	if len(events) != 1 {
		t.Fatalf("events: %+v", events)
	}
	if event := events[0]; event.Protocol != "websocket" || event.Outcome != outcomeCensored || event.Detail["where"] != "message" ||
		event.Detail["placeholders"] != "ph:secret:stripe" || event.Detail["replacedCount"] != float64(1) || event.Detail["severity"] != leakSeverityMedium {
		t.Fatalf("event: %+v", event)
	}

	// The same text as a request body is replaced the same way.
	postMessages(t, rig.client(rig.phaseRoots), "https://chatgpt.com"+codexSocketPath, []byte(text), "")
	if got := rig.lastReceived().body; string(got) != want {
		t.Fatalf("as a body the provider received %q", got)
	}
}

// A known value, or one of Phase's own tokens, in a message that cannot be
// rewritten ends the WebSocket: the client is told its message broke policy,
// and the service never sees the message. A request body of the same kind is
// refused.
func TestWebSocketMessageThatCannotBeRewrittenIsBlockedLikeABody(t *testing.T) {
	compressed := clientFrame(true, wsOpText, []byte("deflated? "+leakSecretOne))
	compressed[0] |= 0x40
	for name, c := range map[string]struct {
		frame []byte
		// body is the same bytes as a request body, when there is such a body.
		body         []byte
		placeholders any
		labels       any
	}{
		"a known value in a binary message": {
			frame: clientFrame(true, 0x2, append([]byte{0xff, 0x00, 0xfe}, leakSecretOne...)),
			body:  append([]byte{0xff, 0x00, 0xfe}, leakSecretOne...), placeholders: "ph:secret:stripe",
		},
		"a Phase token in a binary message": {
			frame: clientFrame(true, 0x2, append([]byte{0xff, 0x00, 0xfe}, phaseServiceToken()...)),
			body:  append([]byte{0xff, 0x00, 0xfe}, phaseServiceToken()...), placeholders: "ph:phase_service_token:1", labels: "phase_service_token",
		},
		"a known value in two frames of a binary message": {
			frame:        append(clientFrame(false, 0x2, append([]byte{0xff, 0x00}, leakSecretOne[:10]...)), clientFrame(true, wsOpContinuation, []byte(leakSecretOne[10:]))...),
			placeholders: "ph:secret:stripe",
		},
		"a known value in a message compressed against the handshake": {frame: compressed, placeholders: "ph:secret:stripe"},
	} {
		t.Run(name, func(t *testing.T) {
			rig := newLeakRig(t, leakModeCensor)
			registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
			peer := rig.openWebSocket(t, "chatgpt.com", codexSocketPath)
			// The WebSocket works until the message arrives.
			peer.send(t, clientFrame(true, wsOpText, []byte(`{"type":"hello"}`)))
			if got, _ := peer.received(t); string(got.payload) != `{"type":"hello"}` {
				t.Fatalf("a clean message: %q", got.payload)
			}
			peer.send(t, c.frame)

			fin, opcode, payload, err := readFrame(peer.reader)
			if err != nil || !fin || opcode != wsOpClose || len(payload) < 2 {
				t.Fatalf("the client was not sent a close frame: %v %v %x %v", fin, opcode, payload, err)
			}
			if code := binary.BigEndian.Uint16(payload); code != wsClosePolicyViolation || string(payload[2:]) != wsBlockedReason {
				t.Fatalf("close code %d, reason %q", code, payload[2:])
			}
			if _, _, _, err := readFrame(peer.reader); err == nil {
				t.Fatal("something followed the close frame")
			}
			// The service is told the client is going away, and nothing else.
			for {
				got, open := peer.received(t)
				if !open {
					break
				}
				if got.opcode != wsOpClose || len(got.payload) != 2 || binary.BigEndian.Uint16(got.payload) != wsCloseGoingAway {
					t.Fatalf("the service received opcode %d, %d bytes after the blocked message was sent", got.opcode, len(got.payload))
				}
			}

			rig.distinctLeakEvents(t, 1)
			events := rig.leakEventsNow()
			if len(events) != 1 {
				t.Fatalf("events: %+v", events)
			}
			event := events[0]
			if event.ProxyDecision != "block" || event.Outcome != "denied" || event.Reason != leakReasonFound || event.Protocol != "websocket" ||
				event.Path != codexSocketPath || event.StatusCode != 0 || !durableAuditEvent(event) {
				t.Fatalf("the block event: %+v", event)
			}
			if event.Detail["where"] != "message" || event.Detail["severity"] != leakSeverityHigh || event.Detail["capture"] != CaptureProxy ||
				event.Detail["harness"] != "codex" || event.Detail["placeholders"] != c.placeholders || event.Detail["labels"] != c.labels ||
				event.Detail["replacedCount"] != float64(0) {
				t.Fatalf("the block event's detail: %+v", event.Detail)
			}
			if shipped := rig.shippedPayloads(); bytes.Contains(shipped, []byte(leakSecretOne)) || bytes.Contains(shipped, []byte(phaseServiceToken())) {
				t.Fatal("an event carries a value")
			}

			if c.body == nil {
				return
			}
			// The same bytes as a request body are refused.
			before := rig.receivedCount()
			request, _ := http.NewRequest(http.MethodPost, "https://chatgpt.com"+codexSocketPath, bytes.NewReader(c.body))
			request.Header.Set("Content-Type", "application/octet-stream")
			if status := doRequest(t, rig.client(rig.phaseRoots), request); status != http.StatusForbidden || rig.receivedCount() != before {
				t.Fatalf("as a body: %d", status)
			}
		})
	}

	// A close frame fits its reason.
	if len(wsBlockedReason) > 123 || len(wsClosePayload(wsClosePolicyViolation, strings.Repeat("x", 500))) != 125 {
		t.Fatalf("a close frame's reason of %d bytes", len(wsBlockedReason))
	}
}

// Observe mode changes and stops nothing on a WebSocket either, and a binary
// message with nothing known in it is no event at all.
func TestWebSocketObserveModeAndCleanBinaryMessages(t *testing.T) {
	rig := newLeakRig(t, leakModeObserve)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	peer := rig.openWebSocket(t, "chatgpt.com", codexSocketPath)
	held := append([]byte{0xff, 0x00, 0xfe}, leakSecretOne...)
	clean := []byte{0xff, 0x00, 0xfe, 0x01, 0x02}
	text := []byte("KEY=" + leakSecretOne)
	for _, c := range []struct {
		opcode  byte
		payload []byte
	}{{0x2, clean}, {0x2, held}, {wsOpText, text}} {
		peer.send(t, clientFrame(true, c.opcode, c.payload))
		if got, _ := peer.received(t); got.opcode != c.opcode || !bytes.Equal(got.payload, c.payload) {
			t.Fatalf("observe mode changed or stopped a message: %q", got.payload)
		}
	}
	events := rig.leakEventsNow()
	if len(events) != 1 || events[0].Outcome != outcomeObserved || events[0].ProxyDecision != "allow" || events[0].Detail["replacedCount"] != float64(0) {
		t.Fatalf("events: %+v", events)
	}
}

// On a host that speaks Connect a binary message is protobuf even when its
// bytes read as text: a value in it is overwritten where it sits, so every
// length the message states still holds.
func TestWebSocketBinaryMessageOnAConnectHostKeepsItsLength(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	peer := rig.openWebSocket(t, "api2.cursor.sh", "/aiserver.v1.AnyService/AnyCall")
	field := "key " + leakSecretOne
	message := append([]byte{0x0a, byte(len(field))}, field...)
	if !utf8.Valid(message) {
		t.Fatal("the message must read as text")
	}
	peer.send(t, clientFrame(true, 0x2, message))
	got, _ := peer.received(t)
	if got.opcode != 0x2 || len(got.payload) != len(message) || bytes.Contains(got.payload, []byte(leakSecretOne)) ||
		!bytes.HasPrefix(got.payload, []byte{0x0a, byte(len(field)), 'k', 'e', 'y', ' ', 'p', 'h'}) {
		t.Fatalf("the binary message: %q", got.payload)
	}
	// A text message on the same host is still read as text.
	peer.send(t, clientFrame(true, wsOpText, []byte("KEY="+leakSecretOne)))
	if got, _ := peer.received(t); got.opcode != wsOpText || string(got.payload) != "KEY=ph:secret:stripe" {
		t.Fatalf("the text message: %q", got.payload)
	}
}

// lockedBuffer is a writer two goroutines can use.
type lockedBuffer struct {
	mu   sync.Mutex
	data []byte
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *lockedBuffer) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.data)
}

func (b *lockedBuffer) waitFor(t *testing.T, want int) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); len(b.bytes()) < want; time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the client was sent %d bytes, want %d", len(b.bytes()), want)
		}
	}
}

// The proxy's close frame goes out between two of the service's frames,
// never inside one, and nothing follows it.
func TestProxyCloseFrameWaitsForTheServicesFrame(t *testing.T) {
	service, proxy := net.Pipe()
	defer service.Close()
	defer proxy.Close()
	client := &lockedBuffer{}
	downstream := &wsDownstream{client: client}
	relayed := make(chan struct{})
	go func() { downstream.relay(proxy); close(relayed) }()

	frame := append([]byte{0x82, 10}, []byte("0123456789")...)
	// The service is in the middle of a frame.
	if _, err := service.Write(frame[:6]); err != nil {
		t.Fatal(err)
	}
	client.waitFor(t, 6)
	closed := make(chan struct{})
	go func() { downstream.close(wsClosePolicyViolation, "why"); close(closed) }()
	select {
	case <-closed:
		t.Fatal("the close frame did not wait for the frame being sent")
	case <-time.After(60 * time.Millisecond):
	}
	if got := client.bytes(); !bytes.Equal(got, frame[:6]) {
		t.Fatalf("the client was sent % x inside the service's frame", got)
	}
	if _, err := service.Write(frame[6:]); err != nil {
		t.Fatal(err)
	}
	<-closed
	closeFrame := append([]byte{0x88, 5}, wsClosePayload(wsClosePolicyViolation, "why")...)
	if got := client.bytes(); !bytes.Equal(got, append(bytes.Clone(frame), closeFrame...)) {
		t.Fatalf("the client was sent % x", got)
	}
	// What the service sends afterwards is not passed on.
	go func() { _, _ = service.Write([]byte{0x81, 2, 'o', 'k'}) }()
	select {
	case <-relayed:
	case <-time.After(3 * time.Second):
		t.Fatal("the relay went on after the close frame")
	}
	if got := client.bytes(); len(got) != len(frame)+len(closeFrame) {
		t.Fatalf("%d bytes followed the close frame", len(got)-len(frame)-len(closeFrame))
	}
	// A second close says nothing more.
	downstream.close(wsClosePolicyViolation, "again")
	if got := client.bytes(); len(got) != len(frame)+len(closeFrame) {
		t.Fatal("a second close frame was sent")
	}

	// A service that stalls inside a frame gets no close frame after it.
	stalled, stalledProxy := net.Pipe()
	defer stalled.Close()
	defer stalledProxy.Close()
	other := &lockedBuffer{}
	waiting := &wsDownstream{client: other, wait: 40 * time.Millisecond}
	go waiting.relay(stalledProxy)
	if _, err := stalled.Write(frame[:6]); err != nil {
		t.Fatal(err)
	}
	other.waitFor(t, 6)
	started := time.Now()
	waiting.close(wsClosePolicyViolation, "why")
	if elapsed := time.Since(started); elapsed > 2*time.Second || !bytes.Equal(other.bytes(), frame[:6]) {
		t.Fatalf("after %v the client was sent % x", elapsed, other.bytes())
	}
}

// exchangeAs sends one raw request over a tunnel opened for flow.
func (r *leakRig) exchangeAs(t *testing.T, host string, flow *FlowContext, request string) *http.Response {
	t.Helper()
	raw := r.connectAs(t, host, flow)
	conn := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: r.bothRoots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("TLS with %s: %v", host, err)
	}
	defer conn.Close()
	response, _ := exchange(t, conn, bufio.NewReader(conn), request)
	return response
}

// testClock is a clock a test moves.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// A body the proxy cannot decode is reported once for its tool, host and
// reason, then at most once a minute: a client that sends one sends many.
func TestUnreadRequestsAreReportedOnceAMinute(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	rig.proxy.flows = newFlowNotes()
	clock := &testClock{now: time.Now()}
	rig.guard.unread.now = clock.Now
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	body := "this is not brotli, and holds nothing known"
	undecodable := func(host, path string) string {
		return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Encoding: br\r\nContent-Length: %d\r\n\r\n%s", path, host, len(body), body)
	}
	send := func(host, path string, flow *FlowContext) {
		t.Helper()
		if response := rig.exchangeAs(t, host, flow, undecodable(host, path)); response.StatusCode != http.StatusOK {
			t.Fatalf("status %d", response.StatusCode)
		}
		if got := rig.lastReceived(); string(got.body) != body || got.header.Get("Content-Encoding") != "br" {
			t.Fatal("a body left unread was changed")
		}
	}
	unread := func() []agentapi.Event {
		var events []agentapi.Event
		for _, event := range rig.leakEventsNow() {
			if event.Outcome == outcomeUnread {
				events = append(events, event)
			}
		}
		return events
	}
	for i := 0; i < 3; i++ {
		send("api.anthropic.com", "/v1/messages", nil)
	}
	events := unread()
	if len(events) != 1 {
		t.Fatalf("%d unread events for three bodies with one reason", len(events))
	}
	if event := events[0]; event.Reason != leakReasonUndecodable || event.ProxyDecision != "allow" || event.Method != http.MethodPost ||
		event.Detail["scope"] != leakScopeRequest || event.Detail["capture"] != CaptureProxy || event.Detail["harness"] != "claude" ||
		event.Detail["severity"] != nil || durableAuditEvent(event) {
		t.Fatalf("event: %+v", event)
	}
	// Another host, and another tool on the same host, are told apart.
	opencode := tunnelFlow("opencode")
	send("api.openai.com", "/v1/responses", nil)
	send("api.anthropic.com", "/v1/messages", &opencode)
	send("api.anthropic.com", "/v1/messages", &opencode)
	if events = unread(); len(events) != 3 || events[1].Host != "api.openai.com" || events[2].Detail["harness"] != "opencode" || events[2].Detail["capture"] != CaptureTunnel {
		t.Fatalf("unread events: %+v", events)
	}
	// A minute later the same reason is reported once more.
	clock.advance(unreadPeriod)
	send("api.anthropic.com", "/v1/messages", nil)
	send("api.anthropic.com", "/v1/messages", nil)
	if events = unread(); len(events) != 4 {
		t.Fatalf("%d unread events a minute later, want one more", len(events)-3)
	}
	// A known value in a body the proxy cannot decode is still caught, and a
	// block is always reported.
	held := "not brotli either: " + leakSecretOne
	blocked := fmt.Sprintf("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Encoding: br\r\nContent-Length: %d\r\n\r\n%s", len(held), held)
	before := rig.receivedCount()
	for i := 0; i < 2; i++ {
		if response := rig.exchangeAs(t, "api.anthropic.com", nil, blocked); response.StatusCode != http.StatusForbidden {
			t.Fatalf("a known value in an undecodable body: %d", response.StatusCode)
		}
	}
	blocks := 0
	for _, event := range rig.leakEventsNow() {
		if event.ProxyDecision == "block" {
			blocks++
			if event.Detail["severity"] != leakSeverityHigh || event.Detail["scope"] != leakScopeRequest {
				t.Fatalf("block event: %+v", event)
			}
		}
	}
	if blocks != 2 || rig.receivedCount() != before {
		t.Fatalf("%d block events for two blocked requests", blocks)
	}
}

// A message the client compressed against the handshake is reported once a
// minute too, per message.
func TestUnreadMessagesAreReportedOnceAMinute(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	clock := &testClock{now: time.Now()}
	rig.guard.unread.now = clock.Now
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	peer := rig.openWebSocket(t, "chatgpt.com", codexSocketPath)
	payload := []byte{0x4a, 0xcd, 0xc9, 0xc9, 0x07, 0x00}
	send := func() {
		t.Helper()
		frame := clientFrame(true, wsOpText, payload)
		frame[0] |= 0x40
		peer.send(t, frame)
		if got, _ := peer.received(t); !bytes.Equal(got.payload, payload) {
			t.Fatal("a message left unread was changed")
		}
	}
	for i := 0; i < 3; i++ {
		send()
	}
	events := rig.leakEventsNow()
	if len(events) != 1 {
		t.Fatalf("%d events for three compressed messages", len(events))
	}
	if event := events[0]; event.Outcome != outcomeUnread || event.Reason != leakReasonCompressed || event.Protocol != "websocket" ||
		event.Detail["scope"] != leakScopeMessage || event.Detail["severity"] != nil {
		t.Fatalf("event: %+v", event)
	}
	clock.advance(unreadPeriod)
	send()
	send()
	if events = rig.leakEventsNow(); len(events) != 2 {
		t.Fatalf("%d events a minute later, want one more", len(events)-1)
	}
}

// A value too short or plain to protect is counted once however often it is
// registered, and the names kept for the count are bounded.
func TestUnprotectableValuesAreCountedOnceAndBounded(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	short := func(id string) []*censor.Entries {
		entry, err := censor.IndexValue(guard.key, "secret", id, "abc")
		if err != nil {
			t.Fatal(err)
		}
		if entry.Protected() {
			t.Fatal("the value is protected")
		}
		return []*censor.Entries{entry}
	}
	for i := 0; i < 200; i++ {
		if _, unprotected, err := guard.add(short("LOG_LEVEL"), nil); err != nil || unprotected != 1 {
			t.Fatalf("registration %d: %d %v", i, unprotected, err)
		}
	}
	if count := guard.status().Unprotected; count != 1 {
		t.Fatalf("one value registered 200 times is counted %d times", count)
	}
	// The index's own caps do not see a value with nothing to index, so the
	// names are bounded here.
	for i := 0; i < maxUnprotectedNames+500; i++ {
		if _, _, err := guard.add(short(fmt.Sprintf("lease-%d", i)), nil); err != nil {
			t.Fatal(err)
		}
	}
	if count := guard.status().Unprotected; count != maxUnprotectedNames || len(guard.unprotected) != maxUnprotectedNames {
		t.Fatalf("%d unprotectable values are counted, %d names kept, want %d", count, len(guard.unprotected), maxUnprotectedNames)
	}
	if guard.index.Stats().Secrets != 0 {
		t.Fatal("an unprotectable value took a place in the index")
	}
	// One that is kept is still counted once, and stops counting when the
	// same id is registered with a value that can be protected.
	if _, _, err := guard.add(short("LOG_LEVEL"), nil); err != nil || guard.status().Unprotected != maxUnprotectedNames {
		t.Fatal("a value already counted was counted again")
	}
	long, err := censor.IndexValue(guard.key, "secret", "LOG_LEVEL", leakSecretOne)
	if err != nil {
		t.Fatal(err)
	}
	if added, _, err := guard.add([]*censor.Entries{long}, nil); err != nil || added != 1 || guard.status().Unprotected != maxUnprotectedNames-1 {
		t.Fatalf("a value that became protectable is still counted: %d", guard.status().Unprotected)
	}
}

// registerThroughControl registers values the way the CLI does: it fetches
// the key, indexes, and posts the entries with what each id is.
func registerThroughControl(t *testing.T, proxy *httpProxy, values []leakguard.Value, kinds []string) *remoteapi.InventoryResponse {
	t.Helper()
	recorder := controlCall(proxy, http.MethodGet, "/v1/inventory/key", "", nil)
	var keyAnswer remoteapi.InventoryKeyResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &keyAnswer) != nil {
		t.Fatalf("key: %d", recorder.Code)
	}
	key := answeredKey(t, keyAnswer)
	request := remoteapi.InventoryRequest{SchemaVersion: 1, IDKinds: kinds}
	for _, value := range values {
		entry, err := censor.IndexValue(key, value.Type, value.ID, value.Value)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := entry.Marshal()
		request.Entries = append(request.Entries, encoded)
	}
	body, _ := json.Marshal(request)
	recorder = controlCall(proxy, http.MethodPost, "/v1/inventory", "application/json", body)
	if recorder.Code != http.StatusOK {
		return nil
	}
	var answer remoteapi.InventoryResponse
	if json.Unmarshal(recorder.Body.Bytes(), &answer) != nil {
		t.Fatal("the registration's answer is not JSON")
	}
	return &answer
}

func sortedList(value any) string {
	text, _ := value.(string)
	parts := strings.Split(text, ",")
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// A secret's key name never reaches the Console in an event: the client says
// which ids are key names, the proxy remembers it per placeholder, and an
// event names such a placeholder by its type alone. What the model is shown
// keeps the whole placeholder.
func TestKeyNamesStayOutOfEvents(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	const phaseID = "0b0e6c1c-5a3f-4f0e-9d64-7a1c2b3d4e5f"
	values := []leakguard.Value{
		{Type: "secret", ID: "STRIPE_KEY", Value: leakSecretOne},
		{Type: "secret", ID: "DATABASE_URL", Value: leakSecretTwo},
		{Type: "secret", ID: phaseID, Value: leakSecretThree},
	}
	kinds := []string{remoteapi.InventoryIDKeyName, remoteapi.InventoryIDKeyName, remoteapi.InventoryIDPhase}
	if answer := registerThroughControl(t, rig.proxy, values, kinds); answer == nil || answer.Added != 3 {
		t.Fatalf("registration: %+v", answer)
	}
	client := rig.client(rig.phaseRoots)
	postMessages(t, client, "https://api.anthropic.com/v1/messages", anthropicBody(leakSecretOne+" "+leakSecretTwo+" "+leakSecretThree), "")
	// The model sees the key names: they are what it refers to a secret by.
	received := rig.lastReceived().body
	for _, placeholder := range []string{"ph:secret:STRIPE_KEY", "ph:secret:DATABASE_URL", "ph:secret:" + phaseID} {
		if !bytes.Contains(received, []byte(placeholder)) {
			t.Fatalf("the provider did not receive %s: %s", placeholder, received)
		}
	}
	events := rig.distinctLeakEvents(t, 1)
	detail := events[0].Detail
	// Two key names of one type are one ph:secret; the counts stay whole.
	if sortedList(detail["placeholders"]) != "ph:secret,ph:secret:"+phaseID || detail["placeholderCount"] != float64(3) ||
		detail["replacedCount"] != float64(3) || detail["inventoryHits"] != float64(3) {
		t.Fatalf("event detail: %+v", detail)
	}

	// A block names them the same way.
	request, _ := http.NewRequest(http.MethodGet, "https://api.anthropic.com/v1/models?k="+url.QueryEscape(leakSecretOne), nil)
	if status := doRequest(t, client, request); status != http.StatusForbidden {
		t.Fatalf("a value in the URL: %d", status)
	}
	events = rig.distinctLeakEvents(t, 2)
	if events[1].ProxyDecision != "block" || events[1].Detail["placeholders"] != "ph:secret" || events[1].Detail["placeholderCount"] != float64(1) {
		t.Fatalf("block event: %+v", events[1])
	}
	// Once an id is known to be a key name it stays one, whatever a later
	// registration of the same id says.
	if answer := registerThroughControl(t, rig.proxy, values[:1], []string{remoteapi.InventoryIDPhase}); answer == nil {
		t.Fatal("the second registration was refused")
	}
	request, _ = http.NewRequest(http.MethodGet, "https://api.anthropic.com/v1/models?k="+url.QueryEscape(leakSecretOne), nil)
	doRequest(t, client, request)
	if events = rig.distinctLeakEvents(t, 3); events[2].Detail["placeholders"] != "ph:secret" {
		t.Fatalf("a key name was shown after a second registration: %+v", events[2].Detail)
	}

	// A registration that does not say what its ids are is taken to hold key
	// names; one that says it wrongly is refused whole.
	silent := []leakguard.Value{{Type: "sealed", ID: "SIGNING_KEY", Value: leakSecretFour}}
	if answer := registerThroughControl(t, rig.proxy, silent, nil); answer == nil || answer.Added != 1 {
		t.Fatalf("a registration without kinds: %+v", answer)
	}
	postMessages(t, client, "https://api.anthropic.com/v1/messages", anthropicBody(leakSecretFour), "")
	if events = rig.distinctLeakEvents(t, 4); events[3].Detail["placeholders"] != "ph:sealed" || !bytes.Contains(rig.lastReceived().body, []byte("ph:sealed:SIGNING_KEY")) {
		t.Fatalf("an id of no stated kind: %+v", events[3].Detail)
	}
	known := rig.guard.index.Stats().Secrets
	other := []leakguard.Value{{Type: "secret", ID: "OTHER", Value: leakSecretFive}}
	for name, kinds := range map[string][]string{
		"too few kinds":   {},
		"too many kinds":  {remoteapi.InventoryIDPhase, remoteapi.InventoryIDPhase},
		"an unknown kind": {"uuid"},
		"an empty kind":   {""},
	} {
		if name == "too few kinds" {
			// One kind for two entries.
			if answer := registerThroughControl(t, rig.proxy, append(other, silent...), []string{remoteapi.InventoryIDPhase}); answer != nil {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		if answer := registerThroughControl(t, rig.proxy, other, kinds); answer != nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if rig.guard.index.Stats().Secrets != known {
		t.Fatal("a refused registration changed the index")
	}
	recorder := controlCall(rig.proxy, http.MethodPost, "/v1/inventory", "application/json", []byte(`{"schemaVersion":1,"entries":[],"idKinds":[1]}`))
	if recorder.Code != http.StatusBadRequest || errorCode(recorder) != "invalid_inventory" {
		t.Fatalf("kinds that are not text: %d", recorder.Code)
	}

	// No event ever named a key.
	shipped := rig.shippedPayloads()
	for _, name := range []string{"STRIPE_KEY", "DATABASE_URL", "SIGNING_KEY"} {
		if bytes.Contains(shipped, []byte(name)) {
			t.Fatalf("an event carries the key name %s", name)
		}
	}
	if !bytes.Contains(shipped, []byte(phaseID)) {
		t.Fatal("an id the Console issued was left out of the events")
	}
}

// The CLI's own client says which ids are key names.
func TestRegistrationSaysWhichIDsAreKeyNames(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	environment := map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": rig.proxyURL.String()}
	previous := leakguard.Environment
	leakguard.Environment = func(key string) string { return environment[key] }
	defer func() { leakguard.Environment = previous }()
	result, err := leakguard.Register(context.Background(), []leakguard.Value{
		{Type: "secret", ID: "STRIPE_KEY", KeyName: true, Value: leakSecretOne},
		{Type: "secret", ID: "secret-id-2", Value: leakSecretTwo},
		// A name that is no id is registered under a digest of it, which is
		// still the name's.
		{Type: "secret", ID: "MY KEY/with spaces", KeyName: true, Value: leakSecretThree},
	})
	if err != nil || result.Added != 3 {
		t.Fatalf("registration: %+v %v", result, err)
	}
	postMessages(t, rig.client(rig.phaseRoots), "https://api.anthropic.com/v1/messages", anthropicBody(leakSecretOne+" "+leakSecretTwo+" "+leakSecretThree), "")
	digest := leakguard.PlaceholderID("MY KEY/with spaces")
	if received := rig.lastReceived().body; !bytes.Contains(received, []byte("ph:secret:STRIPE_KEY")) || !bytes.Contains(received, []byte("ph:secret:"+digest)) {
		t.Fatalf("the provider received %s", received)
	}
	detail := rig.leakEvents(1)[0].Detail
	if sortedList(detail["placeholders"]) != "ph:secret,ph:secret:secret-id-2" || detail["placeholderCount"] != float64(3) {
		t.Fatalf("event detail: %+v", detail)
	}
	if shipped := rig.shippedPayloads(); bytes.Contains(shipped, []byte("STRIPE_KEY")) || bytes.Contains(shipped, []byte(digest)) {
		t.Fatal("an event carries a key name")
	}
}

func scanWith(mode string, findings ...censor.Finding) *leakScan {
	scan := &leakScan{match: &leakHostMatch{harness: "claude", flow: FlowContext{Capture: CaptureTunnel, Tool: "claude"}}, mode: mode, protocol: "http"}
	scan.addReport(&censor.Report{Findings: findings}, "body")
	return scan
}

func inventoryFindings(count int) []censor.Finding {
	findings := make([]censor.Finding, 0, count)
	for i := 0; i < count; i++ {
		findings = append(findings, censor.Finding{Kind: "inventory", Placeholder: fmt.Sprintf("ph:secret:id-%d", i), Action: "redact"})
	}
	return findings
}

func TestLeakSeverityFollowsWhatWasFound(t *testing.T) {
	if leakSeverityHighPlaceholders != 5 || leakSeverityMediumPlaceholders != 1 {
		t.Fatalf("the thresholds are %d and %d", leakSeverityHighPlaceholders, leakSeverityMediumPlaceholders)
	}
	alert := censor.Finding{Kind: "rule", Label: "jwt", Action: "alert"}
	signed := censor.Finding{Kind: "inventory", Placeholder: "ph:secret:signed", Action: "left"}
	phaseToken := censor.Finding{Kind: "rule", Label: "phase_service_token", Placeholder: "ph:phase_service_token:1", Action: "redact"}
	format := censor.Finding{Kind: "rule", Label: "github_token", Placeholder: "ph:github_token:1", Action: "redact"}
	for name, c := range map[string]struct {
		findings []censor.Finding
		blocked  bool
		want     string
	}{
		"nothing":                         {nil, false, ""},
		"one known value":                 {inventoryFindings(1), false, leakSeverityMedium},
		"a token format":                  {[]censor.Finding{format}, false, leakSeverityMedium},
		"four distinct placeholders":      {inventoryFindings(4), false, leakSeverityMedium},
		"one value found four times over": {append(inventoryFindings(4), append(inventoryFindings(4), inventoryFindings(4)...)...), false, leakSeverityMedium},
		"five distinct placeholders":      {inventoryFindings(5), false, leakSeverityHigh},
		"a Phase token":                   {[]censor.Finding{phaseToken}, false, leakSeverityHigh},
		"one known value, blocked":        {inventoryFindings(1), true, leakSeverityHigh},
		"an alert":                        {[]censor.Finding{alert}, false, leakSeverityLow},
		"a finding in signed text":        {[]censor.Finding{signed}, false, leakSeverityLow},
		"an alert and signed text":        {[]censor.Finding{alert, signed}, false, leakSeverityLow},
		"signed text beside one value":    {append(inventoryFindings(1), signed), false, leakSeverityMedium},
	} {
		if got := scanWith(leakModeCensor, c.findings...).severity(c.blocked); got != c.want {
			t.Errorf("%s: severity %q, want %q", name, got, c.want)
		}
	}

	// replacedCount is what went out replaced: nothing when the request was
	// not rewritten, and never what was found where it cannot be rewritten.
	scan := scanWith(leakModeCensor, inventoryFindings(3)...)
	scan.addFixed([]censor.Match{{Finding: censor.Finding{Kind: "inventory", Placeholder: "ph:secret:in-header", Action: "redact"}}}, "header", false)
	if detail := scan.detail(); detail["placeholderCount"] != 4 || detail["replacedCount"] != 0 {
		t.Fatalf("before the body is rewritten: %+v", detail)
	}
	scan.changed = true
	detail := scan.detail()
	if detail["placeholderCount"] != 4 || detail["replacedCount"] != 3 || detail["capture"] != CaptureTunnel || detail["harness"] != "claude" || detail["scope"] != nil {
		t.Fatalf("after the body is rewritten: %+v", detail)
	}
	if clean := scanWith(leakModeCensor).detail(); clean["replacedCount"] != nil || clean["placeholderCount"] != nil {
		t.Fatalf("a scan that found nothing: %+v", clean)
	}
	// A scope is said of what was left unread and of nothing else.
	scan.scope = leakScopeRequest
	if scan.detail()["scope"] != nil {
		t.Fatal("a request that was read has a scope")
	}
	scan.leaveUnread(leakReasonOverLimit, leakScopeMessage)
	if scan.detail()["scope"] != leakScopeMessage {
		t.Fatal("an unread message has no scope")
	}
}

// What the events of real requests say: how severe, how captured, how much
// was replaced, and how much an unread reason covers.
func TestLeakEventsSaySeverityCaptureAndWhatWasReplaced(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	values := map[string]string{"one": leakSecretOne, "two": leakSecretTwo, "three": leakSecretThree, "four": leakSecretFour, "five": leakSecretFive}
	registerLeakValues(t, rig.guard, values)
	client := rig.client(rig.phaseRoots)
	target := "https://api.anthropic.com/v1/messages"
	last := func(want int) agentapi.Event {
		t.Helper()
		return rig.distinctLeakEvents(t, want)[want-1]
	}

	// One value: medium.
	postMessages(t, client, target, anthropicBody("key "+leakSecretOne), "")
	if event := last(1); event.Outcome != outcomeCensored || event.Detail["severity"] != leakSeverityMedium || event.Detail["capture"] != CaptureProxy ||
		event.Detail["placeholderCount"] != float64(1) || event.Detail["replacedCount"] != float64(1) || event.Detail["scope"] != nil {
		t.Fatalf("one value: %+v", event)
	}
	// Five distinct values in one request: high.
	var all []string
	for _, value := range values {
		all = append(all, value)
	}
	sort.Strings(all)
	postMessages(t, client, target, anthropicBody(strings.Join(all, " ")), "")
	if event := last(2); event.Detail["severity"] != leakSeverityHigh || event.Detail["placeholderCount"] != float64(5) || event.Detail["replacedCount"] != float64(5) {
		t.Fatalf("five values: %+v", event)
	}
	// A value in a header is reported and not replaced.
	request, _ := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses", strings.NewReader(`{"input":"hello there"}`))
	request.Header.Set("X-Note", leakSecretOne)
	doRequest(t, client, request)
	if event := last(3); event.Outcome != outcomeReported || event.Detail["severity"] != leakSeverityMedium || event.Detail["replacedCount"] != float64(0) || event.Detail["where"] != "header" {
		t.Fatalf("a value in a header: %+v", event)
	}
	// One of Phase's own tokens: high, whatever else there is.
	postMessages(t, client, "https://openrouter.ai/api/v1/chat/completions", anthropicBody("token "+phaseServiceToken()), "")
	if event := last(4); event.Outcome != outcomeCensored || event.Detail["severity"] != leakSeverityHigh || event.Detail["placeholderCount"] != float64(1) ||
		event.Detail["labels"] != "phase_service_token" || bytes.Contains(rig.lastReceived().body, []byte(phaseServiceToken())) {
		t.Fatalf("a Phase token: %+v", event)
	}
	// A block: high.
	request, _ = http.NewRequest(http.MethodGet, target+"?k="+url.QueryEscape(leakSecretTwo), nil)
	doRequest(t, client, request)
	if event := last(5); event.ProxyDecision != "block" || event.Detail["severity"] != leakSeverityHigh || event.Detail["replacedCount"] != float64(0) {
		t.Fatalf("a block: %+v", event)
	}

	// Observe mode replaces nothing, and says so.
	observe := newLeakRig(t, leakModeObserve)
	registerLeakValues(t, observe.guard, map[string]string{"one": leakSecretOne})
	postMessages(t, observe.client(observe.phaseRoots), target, anthropicBody("key "+leakSecretOne), "")
	if event := observe.leakEvents(1)[0]; event.Outcome != outcomeObserved || event.Detail["severity"] != leakSeverityMedium || event.Detail["replacedCount"] != float64(0) {
		t.Fatalf("observe mode: %+v", event)
	}
}

// A finding that sits only in text the provider signed changes nothing in the
// request, and is reported: once, then at most once a minute.
func TestAFindingOnlyInSignedTextIsReported(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	clock := &testClock{now: time.Now()}
	rig.guard.unread.now = clock.Now
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	body, _ := json.Marshal(map[string]any{
		"model": "claude-test", "messages": []any{
			map[string]any{"role": "user", "content": "go on"},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "thinking", "thinking": "the key they pasted was " + leakSecretOne, "signature": "c2lnbmVk"},
			}},
		},
	})
	client := rig.client(rig.phaseRoots)
	target := "https://api.anthropic.com/v1/messages"
	for i := 0; i < 3; i++ {
		postMessages(t, client, target, body, "")
		if !bytes.Equal(rig.lastReceived().body, body) {
			t.Fatal("text the provider signed was changed")
		}
	}
	events := rig.leakEventsNow()
	if len(events) != 1 {
		t.Fatalf("%d events for one finding in signed text sent three times", len(events))
	}
	event := events[0]
	if event.Outcome != outcomeReported || event.ProxyDecision != "allow" || event.Reason != leakReasonFound || durableAuditEvent(event) {
		t.Fatalf("event: %+v", event)
	}
	if event.Detail["signedFindings"] != float64(1) || event.Detail["severity"] != leakSeverityLow || event.Detail["where"] != "body" ||
		event.Detail["placeholders"] != nil || event.Detail["placeholderCount"] != nil || event.Detail["inventoryHits"] != nil || event.Detail["scope"] != nil {
		t.Fatalf("event detail: %+v", event.Detail)
	}
	clock.advance(unreadPeriod)
	postMessages(t, client, target, body, "")
	postMessages(t, client, target, body, "")
	if events = rig.leakEventsNow(); len(events) != 2 {
		t.Fatalf("%d events a minute later, want one more", len(events)-1)
	}
	// Beside a value that is replaced it is part of that request's event, as
	// before.
	both, _ := json.Marshal(map[string]any{
		"model": "claude-test", "messages": []any{
			map[string]any{"role": "user", "content": "and this one: " + leakSecretOne},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "thinking", "thinking": "again " + leakSecretOne, "signature": "c2lnbmVk"},
			}},
		},
	})
	postMessages(t, client, target, both, "")
	events = rig.leakEvents(3)
	if event := events[2]; event.Outcome != outcomeCensored || event.Detail["signedFindings"] != float64(1) || event.Detail["severity"] != leakSeverityMedium ||
		event.Detail["placeholders"] != "ph:secret:stripe" {
		t.Fatalf("a value replaced beside signed text: %+v", event)
	}
}

// Every member an event may hold is one the proxy keeps and the Console
// takes: a short identifier for a name, a short string or a whole number for
// a value, sixteen at most.
func TestEveryLeakDetailMemberReachesTheConsole(t *testing.T) {
	consoleKey := regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,64}$`)
	scan := scanWith(leakModeCensor, append(inventoryFindings(30),
		censor.Finding{Kind: "rule", Label: "jwt", Placeholder: "ph:jwt:1", Action: "redact"},
		censor.Finding{Kind: "rule", Label: "private_key_header", Action: "alert"},
		censor.Finding{Kind: "inventory", Placeholder: "ph:secret:signed", Action: "left"})...)
	scan.changed, scan.listed = true, scan.placeholders
	guard := newTestLeakGuard(t, leakModeCensor)
	proxy := &httpProxy{leak: guard}
	request, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	details := map[string]map[string]any{
		"censored": proxy.leakEvent(nil, request, "api.anthropic.com", 443, scan, "allow", outcomeCensored, leakReasonFound, 0, time.Now()).Detail,
	}
	unread := scanWith(leakModeCensor, inventoryFindings(2)...)
	unread.leaveUnread(leakReasonUndecodable, leakScopeRequest)
	details["unread"] = proxy.leakEvent(nil, request, "api.anthropic.com", 443, unread, "allow", outcomeUnread, leakReasonUndecodable, 0, time.Now()).Detail
	window := leakFlowDetail(leakModeCensor, scan.match)
	window["windowSeconds"] = 20
	details["window"] = window
	// More distinct placeholders than are counted: the event with the most
	// members there is.
	capped := scanWith(leakModeCensor, append(inventoryFindings(maxScanPlaceholders+1),
		censor.Finding{Kind: "rule", Label: "jwt", Placeholder: "ph:jwt:1", Action: "redact"},
		censor.Finding{Kind: "rule", Label: "private_key_header", Action: "alert"},
		censor.Finding{Kind: "inventory", Placeholder: "ph:secret:signed", Action: "left"})...)
	capped.changed, capped.listed = true, capped.placeholders
	details["capped"] = proxy.leakEvent(nil, request, "api.anthropic.com", 443, capped, "allow", outcomeCensored, leakReasonFound, 0, time.Now()).Detail
	seen := map[string]bool{}
	for name, detail := range details {
		if len(detail) > 16 {
			t.Errorf("%s: %d members", name, len(detail))
		}
		kept := safeEventDetail(detail, nil)
		for member, value := range detail {
			seen[member] = true
			if !consoleKey.MatchString(member) {
				t.Errorf("%s: the Console refuses the name %q", name, member)
			}
			if _, ok := kept[member]; !ok {
				t.Errorf("%s: detail.%s is dropped before it reaches the Console", name, member)
			}
			switch typed := value.(type) {
			case string:
				if typed == "" || len(typed) > maxLeakDetailText {
					t.Errorf("%s: detail.%s is %d characters", name, member, len(typed))
				}
			case int:
			case bool:
				// A flag is sent only when it is set.
				if !typed {
					t.Errorf("%s: detail.%s is false", name, member)
				}
			default:
				t.Errorf("%s: detail.%s is a %T", name, member, value)
			}
		}
	}
	for _, member := range []string{
		"mode", "harness", "capture", "where", "inventoryHits", "ruleRedactions", "ruleAlerts", "signedFindings", "labels",
		"placeholders", "placeholderCount", "replacedCount", "placeholdersCapped", "severity", "scope", "windowSeconds",
	} {
		if !seen[member] {
			t.Errorf("no event holds detail.%s", member)
		}
	}
	if details["censored"]["severity"] != leakSeverityHigh || details["censored"]["capture"] != CaptureTunnel || details["censored"]["scope"] != nil ||
		details["unread"]["severity"] != nil || details["unread"]["scope"] != leakScopeRequest || details["window"]["severity"] != nil {
		t.Fatalf("details: %+v", details)
	}
	// A spooled event comes back from JSON; its numbers are kept as numbers.
	encoded, _ := json.Marshal(details["censored"])
	var decoded map[string]any
	_ = json.Unmarshal(encoded, &decoded)
	if kept := safeEventDetail(decoded, nil); kept["replacedCount"] != 31 || kept["severity"] != leakSeverityHigh {
		t.Fatalf("after a round trip through the spool: %+v", kept)
	}
	// What is not a known scope, capture or severity is still only text: the
	// proxy writes these from its own constants.
	for _, value := range []string{leakScopeRequest, leakScopeMessage, leakScopeConnection, CaptureProxy, CaptureTunnel, leakSeverityHigh, leakSeverityMedium, leakSeverityLow} {
		if !eventIdentifier.MatchString(value) {
			t.Errorf("%q is not an identifier", value)
		}
	}
}

// A value cannot be found before its placeholder is known to hold a key
// name: a request scanned in between would put the name in an event. The
// registration is held here at the guard's lock, where it records what an id
// is, and the index is looked at while it waits.
func TestAKeyNameIsKnownBeforeItsValueCanBeFound(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	entry, err := censor.IndexValue(guard.key, "secret", "DATABASE_PASSWORD", leakSecretThree)
	if err != nil {
		t.Fatal(err)
	}
	placeholder := entry.Placeholder()
	// found reports the registered value found as itself, whatever a pattern
	// rule makes of the same bytes.
	found := func(guard *leakGuard) bool {
		return slices.ContainsFunc(guard.index.Find([]byte(leakSecretThree)), func(match censor.Match) bool {
			return match.Placeholder == placeholder
		})
	}
	guard.mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, _, err := guard.add([]*censor.Entries{entry}, []bool{true})
		done <- err
	}()
	findable := false
	for deadline := time.Now().Add(150 * time.Millisecond); !findable && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		findable = found(guard)
	}
	_, named := guard.keyNamed[placeholder]
	guard.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if findable && !named {
		t.Fatal("the value could be found while its placeholder was not yet known to hold a key name")
	}
	if got := guard.eventPlaceholders([]string{placeholder}); !found(guard) || !reflect.DeepEqual(got, []string{"ph:secret"}) {
		t.Fatalf("after the registration an event would name %v", got)
	}

	// The same with nothing held: a request is scanned while the value is
	// registered, and what its event would say is read the moment the value
	// is found.
	for round := 0; round < 200; round++ {
		guard := newTestLeakGuard(t, leakModeCensor)
		entry, err := censor.IndexValue(guard.key, "secret", "DATABASE_PASSWORD", leakSecretThree)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		named := make(chan string, 1)
		go func() {
			<-start
			for deadline := time.Now().Add(5 * time.Second); !found(guard); {
				if time.Now().After(deadline) {
					named <- "the value was never found"
					return
				}
			}
			named <- strings.Join(guard.eventPlaceholders([]string{placeholder}), ",")
		}()
		close(start)
		if _, _, err := guard.add([]*censor.Entries{entry}, []bool{true}); err != nil {
			t.Fatal(err)
		}
		if got := <-named; got != "ph:secret" {
			t.Fatalf("round %d: an event would name %q", round, got)
		}
	}
}

// manyLeakValues returns count fake values that share nothing.
func manyLeakValues(count int) map[string]string {
	random := mathrand.New(mathrand.NewPCG(20261119, 5))
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	values := make(map[string]string, count)
	for i := 0; i < count; i++ {
		value := make([]byte, 40)
		for at := range value {
			value[at] = alphabet[random.IntN(len(alphabet))]
		}
		values[fmt.Sprintf("id-%04d", i)] = string(value)
	}
	return values
}

// placeholderCount and replacedCount are counts of distinct placeholders
// however many there are, up to a bound; past it the event says the counts
// are a floor. Before, past 256 distinct placeholders every further
// occurrence was counted.
func TestPlaceholdersAreCountedOnceEachHoweverMany(t *testing.T) {
	repeated := func(distinct, times int) []censor.Finding {
		var findings []censor.Finding
		for round := 0; round < times; round++ {
			findings = append(findings, inventoryFindings(distinct)...)
		}
		return findings
	}
	scan := scanWith(leakModeCensor, repeated(300, 3)...)
	scan.changed = true
	if detail := scan.detail(); detail["placeholderCount"] != 300 || detail["replacedCount"] != 300 || detail["inventoryHits"] != 900 || detail["placeholdersCapped"] != nil {
		t.Fatalf("300 distinct placeholders, each three times: %+v", detail)
	}
	// One of them again, where it cannot be replaced, is still one of the 300.
	scan.addFixed([]censor.Match{{Finding: censor.Finding{Kind: "inventory", Placeholder: "ph:secret:id-7", Action: "redact"}}}, "header", false)
	if detail := scan.detail(); detail["placeholderCount"] != 300 || detail["replacedCount"] != 300 {
		t.Fatalf("a placeholder found again in a header: %+v", detail)
	}

	// Exactly as many as are counted is still exact.
	scan = scanWith(leakModeCensor, repeated(maxScanPlaceholders, 2)...)
	scan.changed = true
	if detail := scan.detail(); detail["placeholderCount"] != maxScanPlaceholders || detail["placeholdersCapped"] != nil {
		t.Fatalf("%d distinct placeholders: count %v, capped %v", maxScanPlaceholders, detail["placeholderCount"], detail["placeholdersCapped"])
	}
	// One more is "or more": the counts stop at the bound and say so.
	scan = scanWith(leakModeCensor, repeated(maxScanPlaceholders+50, 2)...)
	scan.changed = true
	detail := scan.detail()
	if detail["placeholderCount"] != maxScanPlaceholders || detail["replacedCount"] != maxScanPlaceholders || detail["placeholdersCapped"] != true {
		t.Fatalf("%d distinct placeholders: count %v, replaced %v, capped %v", maxScanPlaceholders+50, detail["placeholderCount"], detail["replacedCount"], detail["placeholdersCapped"])
	}
	if len(scan.placeholders) != maxScanPlaceholders || len(scan.replaceable) != maxScanPlaceholders || len(scan.seen) != maxScanPlaceholders {
		t.Fatalf("the scan keeps %d placeholders", len(scan.placeholders))
	}
	// A report that lists only the first of its findings cannot be counted
	// to the end either.
	scan = &leakScan{mode: leakModeCensor}
	scan.addReport(&censor.Report{Findings: inventoryFindings(3), Truncated: true}, "body")
	if detail := scan.detail(); detail["placeholderCount"] != 3 || detail["placeholdersCapped"] != true {
		t.Fatalf("a truncated report: %+v", detail)
	}

	// The flag reaches the Console when it is set, as itself, and through
	// the spool; anything else under its name does not.
	for name, c := range map[string]struct {
		value any
		kept  bool
	}{"set": {true, true}, "not set": {false, false}, "a word": {"true", false}, "a number": {1, false}} {
		kept := safeEventDetail(map[string]any{"placeholdersCapped": c.value}, nil)
		if value, ok := kept["placeholdersCapped"]; ok != c.kept || (ok && value != true) {
			t.Errorf("%s: kept as %v", name, kept)
		}
	}
	encoded, _ := json.Marshal(detail)
	var spooled map[string]any
	_ = json.Unmarshal(encoded, &spooled)
	if kept := safeEventDetail(spooled, nil); kept["placeholdersCapped"] != true || kept["placeholderCount"] != maxScanPlaceholders {
		t.Fatalf("after a round trip through the spool: %+v", kept)
	}

	// And through the proxy: 300 registered values, each three times in one
	// body, are 300 placeholders. Off the conversation paths only registered
	// values are looked for, so nothing else is counted.
	rig := newLeakRig(t, leakModeCensor)
	values := manyLeakValues(300)
	registerLeakValues(t, rig.guard, values)
	var all []string
	for _, value := range values {
		all = append(all, value)
	}
	sort.Strings(all)
	content := strings.Repeat(strings.Join(all, " ")+"\n", 3)
	postMessages(t, rig.client(rig.phaseRoots), "https://api.anthropic.com/api/event_logging/batch", anthropicBody(content), "")
	received := rig.lastReceived().body
	for _, value := range all {
		if bytes.Contains(received, []byte(value)) {
			t.Fatal("a registered value reached the provider")
		}
	}
	event := rig.leakEvents(1)[0]
	if event.Detail["placeholderCount"] != float64(300) || event.Detail["replacedCount"] != float64(300) || event.Detail["inventoryHits"] != float64(900) ||
		event.Detail["placeholdersCapped"] != nil || event.Detail["severity"] != leakSeverityHigh {
		t.Fatalf("the event for 300 values, each three times: %+v", event.Detail)
	}
}

// A message cut into frames that carry nothing never reaches the limit on
// the bytes held, so the frames held are limited too. Past the limit the
// message passes unread, like one that is too long.
func TestAMessageInTooManyFramesPassesUnread(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	peer := rig.openWebSocket(t, "chatgpt.com", codexSocketPath)
	_ = peer.conn.SetDeadline(time.Now().Add(30 * time.Second))
	peer.send(t, clientFrame(false, wsOpText, []byte("a")))
	peer.send(t, bytes.Repeat(clientFrame(false, wsOpContinuation, nil), maxLeakFrames+8))
	// The message has not ended, and is already on its way: the proxy holds
	// no more of it.
	unread := func() []agentapi.Event {
		var events []agentapi.Event
		for _, event := range rig.leakEventsNow() {
			if event.Outcome == outcomeUnread {
				events = append(events, event)
			}
		}
		return events
	}
	var events []agentapi.Event
	for deadline := time.Now().Add(5 * time.Second); len(events) == 0; events = unread() {
		if time.Now().After(deadline) {
			t.Fatalf("%d empty frames of one message are still held", maxLeakFrames+8)
		}
	}
	if event := events[0]; len(events) != 1 || event.Reason != leakReasonOverLimit || event.Protocol != "websocket" || event.Detail["scope"] != leakScopeMessage {
		t.Fatalf("events: %+v", events)
	}
	peer.send(t, clientFrame(true, wsOpContinuation, []byte("b")))
	if got, open := peer.received(t); !open || got.opcode != wsOpText || string(got.payload) != "ab" {
		t.Fatalf("the message arrived as opcode %d, %q", got.opcode, got.payload)
	}
	// The next message is read like any other.
	peer.send(t, clientFrame(true, wsOpText, []byte("KEY="+leakSecretOne)))
	if got, _ := peer.received(t); string(got.payload) != "KEY=ph:secret:stripe" {
		t.Fatalf("the message after it: %q", got.payload)
	}
	// A message in as many frames as are held is still read whole.
	fragments := clientFrame(false, wsOpText, []byte("KEY="))
	fragments = append(fragments, bytes.Repeat(clientFrame(false, wsOpContinuation, nil), maxLeakFrames-2)...)
	fragments = append(fragments, clientFrame(true, wsOpContinuation, []byte(leakSecretOne))...)
	peer.send(t, fragments)
	if got, _ := peer.received(t); string(got.payload) != "KEY=ph:secret:stripe" {
		t.Fatalf("a message in %d frames: %q", maxLeakFrames, got.payload)
	}
}

// A body and a message over the size limit are not read: they reach the
// service byte for byte, and one unread event says so. What follows on the
// same connection is read again.
func TestOversizeBodiesAndMessagesPassUnread(t *testing.T) {
	if testing.Short() {
		t.Skip("sends two payloads of seventeen megabytes")
	}
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	big := bytes.Repeat([]byte("0123456789abcdef"), (maxLeakBody+(1<<20))/16)
	// A known value at its end: nothing of an oversize payload is looked at.
	copy(big[len(big)-len(leakSecretOne):], leakSecretOne)
	client := rig.client(rig.phaseRoots)
	client.Timeout = 60 * time.Second
	request, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(big))
	request.Header.Set("Content-Type", "text/plain")
	if status := doRequest(t, client, request); status != http.StatusOK {
		t.Fatalf("an oversize body: status %d", status)
	}
	if got := rig.lastReceived().body; sha256.Sum256(got) != sha256.Sum256(big) {
		t.Fatalf("an oversize body of %d bytes arrived as %d bytes, or changed", len(big), len(got))
	}
	// The same connection reads the next body.
	postMessages(t, client, "https://api.anthropic.com/v1/messages", anthropicBody("key "+leakSecretOne), "")
	if bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) {
		t.Fatal("the body after an oversize one was not read")
	}

	peer := rig.openWebSocket(t, "chatgpt.com", codexSocketPath)
	_ = peer.conn.SetDeadline(time.Now().Add(60 * time.Second))
	third := len(big) / 3
	sent := make(chan error, 1)
	go func() {
		var err error
		for _, frame := range [][]byte{
			clientFrame(false, wsOpText, big[:third]),
			clientFrame(false, wsOpContinuation, big[third:2*third]),
			clientFrame(true, wsOpContinuation, big[2*third:]),
			clientFrame(true, wsOpText, []byte("KEY="+leakSecretOne)),
		} {
			if _, err = peer.conn.Write(frame); err != nil {
				break
			}
		}
		sent <- err
	}()
	next := func() wsMessage {
		t.Helper()
		select {
		case message, open := <-peer.messages:
			if !open {
				t.Fatal("the WebSocket ended")
			}
			return message
		case <-time.After(30 * time.Second):
			t.Fatal("the service received nothing")
		}
		return wsMessage{}
	}
	if got := next(); got.opcode != wsOpText || sha256.Sum256(got.payload) != sha256.Sum256(big) {
		t.Fatalf("an oversize message of %d bytes arrived as %d bytes under opcode %d, or changed", len(big), len(got.payload), got.opcode)
	}
	if got := next(); string(got.payload) != "KEY=ph:secret:stripe" {
		t.Fatalf("the message after an oversize one: %q", got.payload)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}

	var unread []agentapi.Event
	for _, event := range rig.leakEventsNow() {
		if event.Outcome == outcomeUnread {
			if event.Reason != leakReasonOverLimit || event.ProxyDecision != "allow" || event.Detail["severity"] != nil || event.Detail["placeholderCount"] != nil {
				t.Fatalf("event: %+v", event)
			}
			unread = append(unread, event)
		}
	}
	if len(unread) != 2 || unread[0].Protocol != "http" || unread[0].Detail["scope"] != leakScopeRequest ||
		unread[1].Protocol != "websocket" || unread[1].Detail["scope"] != leakScopeMessage {
		t.Fatalf("unread events: %+v", unread)
	}
}

// The hosts remembered for their refused handshakes are bounded: a domain
// entry matches any number of subdomains. A host in an open window is kept
// for as long as there is anything else to drop.
func TestRefusedHandshakesAreRememberedForABoundedNumberOfHosts(t *testing.T) {
	tracker := newHandshakeTracker()
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	tracker.now = func() time.Time { return now }
	window := leakStateKey{tool: "opencode", host: "eu.models.example"}
	tracker.note(window, false)
	if tracker.note(window, false) == 0 || !tracker.bypassed(window) {
		t.Fatal("two refusals opened no window")
	}
	for i := 0; i < 4*maxRememberedHosts; i++ {
		tracker.note(leakStateKey{tool: "opencode", host: fmt.Sprintf("h%d.models.example", i)}, false)
		if len(tracker.hosts) > maxRememberedHosts {
			t.Fatalf("%d hosts are remembered", len(tracker.hosts))
		}
	}
	if !tracker.bypassed(window) {
		t.Fatal("a host in a window was dropped for hosts that refused once")
	}
	// When every host remembered is in a window they all go: their hosts are
	// read again, which is the safe way to be wrong.
	for i := 0; i < 2*maxRememberedHosts; i++ {
		key := leakStateKey{tool: "opencode", host: fmt.Sprintf("w%d.models.example", i)}
		tracker.note(key, false)
		tracker.note(key, false)
		if len(tracker.hosts) > maxRememberedHosts {
			t.Fatalf("%d hosts are remembered", len(tracker.hosts))
		}
	}
	if len(tracker.bypassedHosts()) > maxRememberedHosts {
		t.Fatalf("%d hosts are in a window", len(tracker.bypassedHosts()))
	}
	// A window that has ended makes room before one that is open.
	tracker = newHandshakeTracker()
	tracker.now = func() time.Time { return now }
	tracker.note(window, false)
	tracker.note(window, false)
	now = now.Add(handshakeBypassFirst + time.Second)
	open := leakStateKey{tool: "opencode", host: "us.models.example"}
	tracker.note(open, false)
	tracker.note(open, false)
	for i := 0; i < maxRememberedHosts; i++ {
		tracker.note(leakStateKey{tool: "opencode", host: fmt.Sprintf("h%d.models.example", i)}, false)
	}
	if !tracker.bypassed(open) || len(tracker.hosts) > maxRememberedHosts {
		t.Fatalf("an open window was dropped (%d hosts remembered)", len(tracker.hosts))
	}
	tracker.mu.Lock()
	_, kept := tracker.hosts[window]
	tracker.mu.Unlock()
	if kept {
		t.Fatal("a window that had ended was kept while hosts were dropped")
	}
}
