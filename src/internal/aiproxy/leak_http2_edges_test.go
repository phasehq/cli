package aiproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/phasehq/cli/pkg/censor"
	"golang.org/x/net/http2"
)

// What a host that speaks Connect is sent besides Connect: other protobuf,
// gRPC, bodies with no end. None of it is corrupted, held or refused.

// protoParses reports whether data reads as one protobuf message, with a
// reader of the test's own.
func protoParses(data []byte) bool {
	for at := 0; at < len(data); {
		tag, size := binary.Uvarint(data[at:])
		if size <= 0 || tag>>3 == 0 {
			return false
		}
		at += size
		switch tag & 7 {
		case 0:
			_, size := binary.Uvarint(data[at:])
			if size <= 0 {
				return false
			}
			at += size
		case 1:
			at += 8
		case 5:
			at += 4
		case 2:
			length, size := binary.Uvarint(data[at:])
			if size <= 0 || length > uint64(len(data)-at-size) {
				return false
			}
			at += size + int(length)
		default:
			return false
		}
		if at > len(data) {
			return false
		}
	}
	return len(data) > 0
}

// Protobuf under another type is still protobuf: a value in it is overwritten
// in place, by its path's rules, even when its bytes are text. None is refused.
func TestCursorBodiesAreOverwrittenInPlaceUnlessTheirTypeSaysText(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.clientOffering(rig.phaseRoots, false, true)
	padded := overwritten("ph:secret:stripe", len(leakSecretOne))
	inPlace := func(body []byte) []byte { return bytes.Replace(body, []byte(leakSecretOne), []byte(padded), 1) }
	token := "gh" + "p_" + strings.Repeat("Ab3dEf6hIj9lMn2pQr5t", 2)[:36]
	// A span of a trace: a message whose every byte is text.
	textual := protoBytesField(protoBytesField(nil, 1, []byte("span.name")), 2, []byte("the key is "+leakSecretOne+" and "+token))
	notText := append(protoVarintField(bytes.Clone(textual), 3, 1<<40), 0x29, 0, 0, 0, 0, 0xff, 0xfe, 0, 0)
	if !utf8.Valid(textual) || utf8.Valid(notText) || !protoParses(textual) || !protoParses(notText) {
		t.Fatal("the messages are not one of text and one that is not")
	}
	traces := "https://" + cursorAPIHost + "/v1/traces"
	for _, c := range []struct {
		name, contentType string
		body              []byte
	}{
		{"x-protobuf whose bytes are text", "application/x-protobuf", textual},
		{"x-protobuf", "application/x-protobuf", notText},
		{"protobuf", "application/protobuf; proto=trace", textual},
		{"octet-stream", "application/octet-stream", textual},
		{"no type", "", textual},
		{"a type of no known kind", "application/vnd.cursor.blob", notText},
		{"JSON by its type and not by its bytes", "application/json", notText},
	} {
		response, _ := postConnect(t, client, traces, c.contentType, c.body, nil)
		got := service.last(t).body
		// As long as it was, still a message, the value gone; the token stays,
		// since traces are no conversation.
		if response.StatusCode != http.StatusOK || !bytes.Equal(got, inPlace(c.body)) || !protoParses(got) {
			t.Fatalf("%s: status %d, %d bytes sent and %d arrived: %q", c.name, response.StatusCode, len(c.body), len(got), got)
		}
		postConnect(t, client, traces, c.contentType, gzipBytes(t, c.body), map[string]string{"Content-Encoding": "gzip"})
		if got := gunzipBytes(t, service.last(t).body); !bytes.Equal(got, inPlace(c.body)) {
			t.Fatalf("%s in gzip: %q", c.name, got)
		}
	}
	// A body in an encoding the proxy does not undo goes on as it came.
	response, _ := postConnect(t, client, traces, "application/x-protobuf", textual, map[string]string{"Content-Encoding": "br"})
	if got := service.last(t).body; response.StatusCode != http.StatusOK || !bytes.Equal(got, textual) {
		t.Fatalf("a body that cannot be decoded: status %d, %q", response.StatusCode, got)
	}
	// A Connect call to the same path is conversation content: the token goes too.
	postConnect(t, client, traces, "application/proto", textual, nil)
	if got := service.last(t).body; len(got) != len(textual) || bytes.Contains(got, []byte(token)) || bytes.Contains(got, []byte(leakSecretOne)) || !protoParses(got) {
		t.Fatalf("a Connect call: %q", got)
	}

	// gRPC and gRPC-Web frame their messages as Connect does, and name the
	// encoding of a compressed one in Grpc-Encoding.
	message := agentMessage("the key is " + leakSecretOne)
	frames := append(connectEnvelope(0, message), connectEnvelope(connectCompressed, gzipBytes(t, message))...)
	for _, contentType := range []string{"application/grpc", "application/grpc+proto", "application/grpc-web", "application/grpc-web+proto"} {
		response, _ := postConnect(t, client, "https://"+cursorAPIHost+cursorUnaryPath, contentType, frames, map[string]string{"Grpc-Encoding": "gzip", "X-Stream-Id": contentType})
		got := service.stream(t, contentType, 2).envelopes
		if response.StatusCode != http.StatusOK || !bytes.Equal(got[0], connectEnvelope(0, inPlace(message))) || got[1][0] != connectCompressed ||
			!bytes.Equal(gunzipBytes(t, got[1][connectEnvelopePrefix:]), inPlace(message)) {
			t.Fatalf("%s: status %d, %q", contentType, response.StatusCode, got)
		}
	}
	json := []byte(`{"text":"the key is ` + leakSecretOne + `"}`)
	postConnect(t, client, "https://"+cursorAPIHost+cursorUnaryPath, "application/grpc+json", connectEnvelope(0, json), map[string]string{"X-Stream-Id": "grpc-json"})
	if got, want := service.stream(t, "grpc-json", 1).envelopes[0], connectEnvelope(0, []byte(`{"text":"the key is ph:secret:stripe"}`)); !bytes.Equal(got, want) {
		t.Fatalf("a JSON message of gRPC: %q, want %q", got, want)
	}
	// A gRPC stream that stays open is answered while it is open.
	stream := openConnectStream(t, client, "grpc-open", map[string]string{"Content-Type": "application/grpc"})
	for count := 1; count <= 2; count++ {
		stream.send(connectEnvelope(0, message))
		stream.mustAnswer(fmt.Sprintf("answer %d to %d bytes", count, len(message)))
	}
	stream.end()
	if got := service.stream(t, "grpc-open", 2).envelopes[1]; !bytes.Equal(got, connectEnvelope(0, inPlace(message))) {
		t.Fatalf("a message of an open gRPC stream: %q", got)
	}
	for _, event := range rig.leakEventsNow() {
		if event.ProxyDecision == "block" {
			t.Fatalf("something in a body stopped a request: %+v", event)
		}
	}
}

// A unary call over HTTP/2 that states no length ends, and is read whole: a
// value in it is overwritten in place, or replaced when its type says JSON.
func TestHTTP2UnaryCallWithNoStatedLengthIsReadWhole(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.clientOffering(rig.phaseRoots, false, true)
	message := agentMessage("the key is " + leakSecretOne)
	padded := bytes.Replace(message, []byte(leakSecretOne), []byte(overwritten("ph:secret:stripe", len(leakSecretOne))), 1)
	json := []byte(`{"text":"the key is ` + leakSecretOne + `"}`)
	for contentType, c := range map[string][2][]byte{
		"application/proto": {message, padded}, "application/x-protobuf": {message, padded}, "application/protobuf": {message, padded},
		"application/json": {json, []byte(`{"text":"the key is ph:secret:stripe"}`)},
	} {
		// In two pieces from a reader of no known length.
		request, _ := http.NewRequest(http.MethodPost, "https://"+cursorAPIHost+cursorUnaryPath, io.MultiReader(bytes.NewReader(c[0][:9]), bytes.NewReader(c[0][9:])))
		request.Header.Set("Content-Type", contentType)
		if status := doRequest(t, client, request); status != http.StatusOK {
			t.Fatalf("%s: status %d", contentType, status)
		}
		if call := service.last(t); !bytes.Equal(call.body, c[1]) || call.proto != "HTTP/2.0" {
			t.Fatalf("%s over %s arrived as %q, want %q", contentType, call.proto, call.body, c[1])
		}
	}
	for _, event := range rig.leakEventsNow() {
		if event.Outcome == outcomeUnread {
			t.Fatalf("a unary call was not read: %+v", event)
		}
	}
}

// A unary body that stops coming is waited for only so long: what came is
// then sent on with the rest, unread, and the request is reported.
func TestHTTP2UnaryBodyThatStallsIsSentOnUnread(t *testing.T) {
	idle := leakBodyIdle
	leakBodyIdle = 200 * time.Millisecond
	t.Cleanup(func() { leakBodyIdle = idle })
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.clientOffering(rig.phaseRoots, false, true)
	envelope := connectEnvelope(0, agentMessage("the key is "+leakSecretOne))
	stream := openConnectStream(t, client, "stalled", map[string]string{"Content-Type": "application/json", "X-Envelopes": "1"})
	for count := 1; count <= 2; count++ {
		stream.send(envelope)
		stream.mustAnswer(fmt.Sprintf("answer %d to %d bytes", count, len(envelope)-connectEnvelopePrefix))
	}
	stream.end()
	if got := service.stream(t, "stalled", 2).envelopes; !bytes.Equal(got[0], envelope) || !bytes.Equal(got[1], envelope) {
		t.Fatal("what was not read arrived changed")
	}
	if events := rig.distinctLeakEvents(t, 1); events[0].Outcome != outcomeUnread || events[0].Reason != leakReasonStreamed || events[0].Detail["scope"] != leakScopeRequest {
		t.Fatalf("event: %+v", events[0])
	}
}

// A body over HTTP/2 with no stated length whose type says nothing of its
// framing may never end: it is sent on at once and reported as unread, once.
func TestHTTP2BodyWithNoEndToWaitForIsNotHeld(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.clientOffering(rig.phaseRoots, false, true)
	envelope := connectEnvelope(0, agentMessage("the key is "+leakSecretOne))
	for _, contentType := range []string{"application/octet-stream", "application/vnd.cursor.blob", "", "application/grpc-web-text"} {
		stream := openConnectStream(t, client, "open "+contentType, map[string]string{"Content-Type": contentType, "X-Envelopes": "1"})
		for count := 1; count <= 2; count++ {
			stream.send(envelope)
			stream.mustAnswer(fmt.Sprintf("answer %d to %d bytes", count, len(envelope)-connectEnvelopePrefix))
		}
		stream.end()
		if got := service.stream(t, "open "+contentType, 2).envelopes; !bytes.Equal(got[0], envelope) || !bytes.Equal(got[1], envelope) {
			t.Fatalf("%s: what was not read arrived changed", contentType)
		}
	}
	events := rig.distinctLeakEvents(t, 1)
	if all := rig.leakEventsNow(); len(all) != 1 || events[0].Outcome != outcomeUnread || events[0].Reason != leakReasonStreamed || events[0].ProxyDecision != "allow" ||
		events[0].Detail["scope"] != leakScopeRequest || events[0].Protocol != leakProtocolHTTP2 || events[0].Host != cursorStreamHost {
		t.Fatalf("four bodies sent on unread within a minute: %+v", all)
	}
	// The same body with its length stated is read whole, as before.
	response, _ := postConnect(t, client, "https://"+cursorAPIHost+"/v1/traces", "application/octet-stream", envelope, nil)
	if got := service.last(t).body; response.StatusCode != http.StatusOK || bytes.Contains(got, []byte(leakSecretOne)) || len(got) != len(envelope) {
		t.Fatalf("a body of a stated length: status %d, %q", response.StatusCode, got)
	}
	// And a known value in the URL stops such a request like any other.
	before := service.count()
	request, _ := http.NewRequest(http.MethodPost, "https://"+cursorStreamHost+"/upload?key="+leakSecretOne, io.MultiReader(bytes.NewReader(envelope), bytes.NewReader(envelope)))
	request.Header.Set("Content-Type", "application/octet-stream")
	if status := doRequest(t, client, request); status != http.StatusForbidden || service.count() != before {
		t.Fatalf("a known value in the URL: status %d", status)
	}
}

// gRPC-Web's text form is base64, which an overwrite in place would break: a
// value in it is reported, and the body goes on as it came.
func TestGRPCWebTextIsSentOnUnread(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.clientOffering(rig.phaseRoots, true, false)
	body := []byte(base64.StdEncoding.EncodeToString(connectEnvelope(0, agentMessage("key "+leakSecretOne))))
	response, _ := postConnect(t, client, "https://"+cursorAPIHost+"/aiserver.v1.AnyService/AnyCall", "application/grpc-web-text", body, nil)
	if got := service.last(t).body; response.StatusCode != http.StatusOK || !bytes.Equal(got, body) {
		t.Fatalf("status %d, the body arrived changed: %q", response.StatusCode, got)
	}
	if events := rig.distinctLeakEvents(t, 1); events[0].Outcome != outcomeUnread || events[0].Reason != leakReasonUndecodable || events[0].Detail["scope"] != leakScopeRequest {
		t.Fatalf("event: %+v", events[0])
	}
}

// A chunked body over HTTP/1.1 is held no more than one over HTTP/2: one of no
// kind that ends is sent on at once, unread, and a unary one that ends is read.
func TestHTTP1ChunkedBodyWithNoEndToWaitForIsNotHeld(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.clientOffering(rig.phaseRoots, true, false)
	reader, writer := io.Pipe()
	request, _ := http.NewRequest(http.MethodPost, "https://"+cursorAPIHost+"/aiserver.v1.Some/Upload", reader)
	request.Header.Set("Content-Type", "application/octet-stream")
	done := make(chan int, 1)
	go func() {
		response, err := client.Do(request)
		if err != nil {
			done <- -1
			return
		}
		_ = response.Body.Close()
		done <- response.StatusCode
	}()
	first := []byte("first chunk " + leakSecretOne)
	if _, err := writer.Write(first); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for service.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if service.count() == 0 {
		t.Fatal("the service was not called while the body was still open")
	}
	_ = writer.Close()
	if status := <-done; status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if got := service.last(t).body; !bytes.Equal(got, first) {
		t.Fatalf("what was not read arrived changed: %q", got)
	}
	if events := rig.distinctLeakEvents(t, 1); events[0].Outcome != outcomeUnread || events[0].Reason != leakReasonStreamed || events[0].Protocol != leakProtocolHTTP {
		t.Fatalf("event: %+v", events[0])
	}
	// A unary body with no stated length ends, and is read whole.
	message := agentMessage("the key is " + leakSecretOne)
	request, _ = http.NewRequest(http.MethodPost, "https://"+cursorAPIHost+cursorUnaryPath, io.MultiReader(bytes.NewReader(message[:10]), bytes.NewReader(message[10:])))
	request.Header.Set("Content-Type", "application/proto")
	if request.ContentLength != 0 {
		t.Fatal("the body's length is stated")
	}
	if status := doRequest(t, client, request); status != http.StatusOK {
		t.Fatalf("unary status %d", status)
	}
	if got := service.last(t).body; len(got) != len(message) || bytes.Contains(got, []byte(leakSecretOne)) {
		t.Fatalf("a unary body with no stated length was not read: %q", got)
	}
}

// An HTTP/2 tunnel ends with its session, as a raw tunnel does: a stream that
// is open breaks off at both ends, and no further one is served.
func TestHTTP2TunnelEndsWithItsSession(t *testing.T) {
	for name, end := range map[string]func(*runtimeState){
		"revoked": (*runtimeState).markRevoked,
		// Nothing announces that a session's time is up.
		"expired": func(state *runtimeState) {
			state.mu.Lock()
			state.expiresAt = time.Now()
			state.mu.Unlock()
		},
	} {
		rig, service := newConnectRig(t, leakModeCensor)
		client := rig.clientOffering(rig.phaseRoots, false, true)
		stream := openConnectStream(t, client, name, nil)
		envelope := connectEnvelope(0, agentMessage("hello"))
		stream.send(envelope)
		if _, err := stream.answer(); err != nil {
			t.Fatal(err)
		}
		end(rig.proxy.state)
		broke := make(chan error, 1)
		go func() {
			_, err := stream.answer()
			broke <- err
		}()
		select {
		case err := <-broke:
			if err == nil || err == io.EOF {
				t.Fatalf("%s: the stream ended as if it were whole: %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the stream outlived its session", name)
		}
		service.waitFor(t, "the stream break off", func(call *connectCall) bool { return call.header.Get("X-Stream-Id") == name && call.gone })
		before := service.count()
		request, _ := http.NewRequest(http.MethodPost, "https://"+cursorStreamHost+cursorStreamPath, bytes.NewReader(envelope))
		request.Header.Set("Content-Type", "application/connect+proto")
		if response, err := client.Do(request); err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				t.Fatalf("%s: a stream was served after the session ended", name)
			}
		}
		if service.count() != before {
			t.Fatalf("%s: a request reached the service after the session ended", name)
		}
	}
}

// What a stream's reader does not read it reports: a cut envelope, one marked
// as a stream's end, and a body of no envelopes, which it does not hold back.
func TestConnectStreamReportsWhatItDoesNotRead(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	registerLeakValues(t, guard, map[string]string{"stripe": leakSecretOne})
	var mu sync.Mutex
	var unread []leakObservation
	proxy := &httpProxy{leak: guard, observe: func(observation leakObservation) {
		mu.Lock()
		defer mu.Unlock()
		if observation.scan != nil && observation.scan.unread != "" {
			unread = append(unread, observation)
		}
	}}
	reported := func() []leakObservation {
		mu.Lock()
		defer mu.Unlock()
		taken := unread
		unread = nil
		return taken
	}
	request := httptest.NewRequest(http.MethodPost, "https://"+cursorStreamHost+cursorStreamPath, nil)
	newStream := func(source io.Reader) *connectStream {
		return &connectStream{
			proxy: proxy, source: io.NopCloser(source), request: request, host: cursorStreamHost, port: 443,
			match: guard.inspects(envFlow, cursorStreamHost, 443), opts: censor.ScanOptions{}, protocol: leakProtocolHTTP2,
		}
	}
	secret := agentMessage("the key is " + leakSecretOne)
	whole := connectEnvelope(0, agentMessage("nothing"))

	// Cut inside the prefix and inside the payload; a stream that ends
	// between two envelopes has nothing unread.
	for cut, want := range map[int]string{len(whole): "", len(whole) + 3: leakReasonMessageTruncated, len(whole) + connectEnvelopePrefix + 9: leakReasonMessageTruncated} {
		sent := append(bytes.Clone(whole), connectEnvelope(0, secret)...)[:cut]
		got, err := io.ReadAll(newStream(bytes.NewReader(sent)))
		reports := reported()
		if err != nil || !bytes.Equal(got, sent) || (want == "") != (len(reports) == 0) || (want != "" && (reports[0].scan.unread != want || reports[0].scan.scope != leakScopeMessage)) {
			t.Fatalf("cut at %d: %v, %d bytes, %d reports", cut, err, len(got), len(reports))
		}
	}

	// Marked as the end of a stream: it goes on as it came, and what is in it
	// is in the report.
	sent := append(connectEnvelope(connectEndStream, secret), connectEnvelope(0, secret)...)
	got, err := io.ReadAll(newStream(bytes.NewReader(sent)))
	reports := reported()
	changed := connectEnvelope(0, bytes.Replace(secret, []byte(leakSecretOne), []byte(overwritten("ph:secret:stripe", len(leakSecretOne))), 1))
	if err != nil || !bytes.Equal(got, append(connectEnvelope(connectEndStream, secret), changed...)) {
		t.Fatalf("an envelope marked as the end of a stream: %v, %q", err, got)
	}
	if len(reports) != 1 || reports[0].scan.unread != leakReasonMessageFlags || reports[0].scan.inventory != 1 || reports[0].scan.block || reports[0].blocked ||
		len(reports[0].scan.placeholders) != 1 || reports[0].scan.placeholders[0] != "ph:secret:stripe" {
		t.Fatalf("its report: %+v", reports)
	}

	// Protobuf under a stream's type reads as a flag byte no envelope has and
	// a length of some megabytes. What came goes on while the body is open.
	reader, writer := io.Pipe()
	defer writer.Close()
	body := append([]byte{0x0a, 0x00, 0x12, 0x34, 0x56}, secret...)
	go func() { _, _ = writer.Write(body) }()
	stream := newStream(reader)
	arrived := make(chan []byte, 1)
	go func() {
		got := make([]byte, len(body))
		_, _ = io.ReadFull(stream, got)
		arrived <- got
	}()
	select {
	case got := <-arrived:
		if !bytes.Equal(got, body) {
			t.Fatalf("a body that is no envelopes arrived changed: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a body that is no envelopes was held for the length it reads as")
	}
	if reports := reported(); len(reports) != 1 || reports[0].scan.unread != leakReasonNotEnvelopes || reports[0].scan.scope != leakScopeRequest {
		t.Fatalf("its report: %+v", reports)
	}
	// Every flag Connect, gRPC and gRPC-Web use is an envelope's.
	for _, flags := range []byte{0x00, 0x01, 0x02, 0x03, 0x80, 0x81} {
		if _, err := io.ReadAll(newStream(bytes.NewReader(connectEnvelope(flags, []byte("{}"))))); err != nil {
			t.Fatal(err)
		}
		for _, report := range reported() {
			if report.scan.unread == leakReasonNotEnvelopes {
				t.Fatalf("flags %#x were taken for no envelope", flags)
			}
		}
	}
}

// The same over a tunnel: each is an event that says why, and the stream is
// neither changed nor stopped.
func TestCursorStreamEdgesAreReportedAsUnread(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.clientOffering(rig.phaseRoots, false, true)
	secret := agentMessage("the key is " + leakSecretOne)

	stream := openConnectStream(t, client, "end-flag", nil)
	marked := connectEnvelope(connectEndStream, secret)
	stream.send(marked)
	stream.mustAnswer(fmt.Sprintf("answer 1 to %d bytes", len(secret)))
	stream.end()
	if got := service.stream(t, "end-flag", 1).envelopes[0]; !bytes.Equal(got, marked) {
		t.Fatalf("an envelope marked as the end of a stream arrived changed: %q", got)
	}

	stream = openConnectStream(t, client, "cut", nil)
	stream.send(connectEnvelope(0, secret)[:connectEnvelopePrefix+7])
	stream.end()
	service.waitFor(t, "the cut stream", func(call *connectCall) bool { return call.header.Get("X-Stream-Id") == "cut" && call.gone })

	stream = openConnectStream(t, client, "no-envelopes", nil)
	stream.send(append([]byte{0x0a, 0x00, 0x12, 0x34, 0x56}, secret...))
	stream.end()
	service.waitFor(t, "the stream of no envelopes", func(call *connectCall) bool { return call.header.Get("X-Stream-Id") == "no-envelopes" && call.gone })

	reasons := map[string]string{}
	for _, event := range rig.distinctLeakEvents(t, 3) {
		if event.Outcome != outcomeUnread || event.ProxyDecision != "allow" || event.Protocol != leakProtocolHTTP2 || event.Detail["severity"] != nil {
			t.Fatalf("event: %+v", event)
		}
		reasons[event.Reason] = fmt.Sprint(event.Detail["scope"], " ", event.Detail["placeholderCount"])
	}
	want := map[string]string{
		leakReasonMessageFlags: leakScopeMessage + " 1", leakReasonMessageTruncated: leakScopeMessage + " <nil>", leakReasonNotEnvelopes: leakScopeRequest + " <nil>",
	}
	if fmt.Sprint(reasons) != fmt.Sprint(want) {
		t.Fatalf("what was reported as unread: %v, want %v", reasons, want)
	}
}

// A client that spoke HTTP/2 and said it takes trailers has that said to the
// service: gRPC refuses a call without it. Over HTTP/1.1 TE stays on its hop.
func TestTETrailersIsKeptForHTTP2Clients(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	target := "https://" + cursorAPIHost + cursorUnaryPath
	for name, c := range map[string]struct {
		http1, http2 bool
		sent, want   string
	}{
		"HTTP/2":                {false, true, "trailers", "trailers"},
		"HTTP/2 without it":     {false, true, "", ""},
		"HTTP/1.1":              {true, false, "trailers", ""},
		"HTTP/1.1 with another": {true, false, "trailers, deflate", ""},
	} {
		headers := map[string]string{}
		if c.sent != "" {
			headers["TE"] = c.sent
		}
		response, _ := postConnect(t, rig.clientOffering(rig.phaseRoots, c.http1, c.http2), target, "application/proto", agentMessage("hello"), headers)
		if got := service.last(t).header.Values("Te"); response.StatusCode != http.StatusOK || strings.Join(got, ",") != c.want {
			t.Fatalf("%s: status %d, TE at the service is %q, want %q", name, response.StatusCode, got, c.want)
		}
	}
}

// strictHTTP2Client speaks HTTP/2 over one tunnel at a time and, unlike
// net/http's client, opens no second one when the first is full.
func (r *leakRig) strictHTTP2Client(t *testing.T, host string) (*http.Client, *atomic.Int32) {
	t.Helper()
	tunnels := new(atomic.Int32)
	transport := &http2.Transport{
		StrictMaxConcurrentStreams: true,
		DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			tunnels.Add(1)
			conn, _ := r.connectTLS(t, host, &tls.Config{RootCAs: r.phaseRoots, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
			return conn, conn.SetDeadline(time.Time{})
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}, tunnels
}

// A tunnel carries a hundred streams at a time. The next one waits until one
// of them ends, and is then served like any other.
func TestTheStreamPastATunnelsLimitWaitsForOneToEnd(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client, tunnels := rig.strictHTTP2Client(t, cursorStreamHost)
	message := agentMessage("the key is " + leakSecretOne)
	open := make([]*openStream, maxTunnelStreams)
	for i := range open {
		open[i] = openConnectStream(t, client, fmt.Sprint("stream-", i), nil)
	}
	for _, i := range []int{0, maxTunnelStreams - 1} {
		open[i].send(connectEnvelope(0, message))
		open[i].mustAnswer(fmt.Sprintf("answer 1 to %d bytes", len(message)))
	}
	reader, writer := io.Pipe()
	request, _ := http.NewRequest(http.MethodPost, "https://"+cursorStreamHost+cursorStreamPath, reader)
	request.Header.Set("Content-Type", "application/connect+proto")
	request.Header.Set("X-Stream-Id", "one-more")
	type result struct {
		response *http.Response
		err      error
	}
	served := make(chan result, 1)
	go func() {
		response, err := client.Do(request)
		served <- result{response, err}
	}()
	select {
	case <-served:
		t.Fatal("a stream past the tunnel's limit did not wait")
	case <-time.After(300 * time.Millisecond):
	}
	if service.count() != maxTunnelStreams {
		t.Fatalf("%d streams reached the service", service.count())
	}
	open[7].end()
	var last result
	select {
	case last = <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("the waiting stream was never served")
	}
	if last.err != nil || last.response.StatusCode != http.StatusOK {
		t.Fatalf("the waiting stream: %v", last.err)
	}
	defer last.response.Body.Close()
	if _, err := writer.Write(connectEnvelope(0, message)); err != nil {
		t.Fatal(err)
	}
	padded := bytes.Replace(message, []byte(leakSecretOne), []byte(overwritten("ph:secret:stripe", len(leakSecretOne))), 1)
	if got := service.stream(t, "one-more", 1).envelopes[0]; !bytes.Equal(got, connectEnvelope(0, padded)) || tunnels.Load() != 1 {
		t.Fatalf("the stream that waited, over %d tunnels: %q", tunnels.Load(), got)
	}
	_ = writer.Close()
	for i, stream := range open {
		if i != 7 {
			stream.end()
		}
	}
}

// A client that does not read one stream's answer holds that stream only:
// another on the same tunnel goes on, and the answer is whole when it is read.
func TestAClientThatReadsSlowlyHoldsOnlyItsOwnStream(t *testing.T) {
	rig, _ := newConnectRig(t, leakModeCensor)
	client := rig.clientOffering(rig.phaseRoots, false, true)
	const size = 8 << 20
	message := agentMessage("send a lot")
	slow := openConnectStream(t, client, "slow", map[string]string{"X-Answer-Bytes": fmt.Sprint(size)})
	slow.send(connectEnvelope(0, message))

	quick := openConnectStream(t, client, "quick", nil)
	for count := 1; count <= 20; count++ {
		quick.send(connectEnvelope(0, message))
		quick.mustAnswer(fmt.Sprintf("answer %d to %d bytes", count, len(message)))
	}

	prefix := make([]byte, connectEnvelopePrefix)
	if _, err := io.ReadFull(slow.reader, prefix); err != nil || binary.BigEndian.Uint32(prefix[1:]) != size {
		t.Fatalf("the long answer's envelope: %v %v", prefix, err)
	}
	got := make([]byte, 0, size)
	piece := make([]byte, 256<<10)
	for len(got) < size {
		n, err := slow.reader.Read(piece[:min(len(piece), size-len(got))])
		if got = append(got, piece[:n]...); err != nil {
			t.Fatalf("the long answer broke off after %d bytes: %v", len(got), err)
		}
		if len(got) < 1<<20 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if !bytes.Equal(got, answerOfSize(size)) {
		t.Fatal("the long answer did not arrive as the service sent it")
	}
	quick.send(connectEnvelope(0, message))
	quick.mustAnswer(fmt.Sprintf("answer 21 to %d bytes", len(message)))
	slow.end()
	quick.end()
}
