package aiproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/pkg/censor"
)

// The tests of Cursor's traffic: Connect over protobuf, a stream that stays
// open over HTTP/2, and unary calls over HTTP/1.1. The service is a fake one
// in this process; nothing here leaves the machine.

const (
	// Cursor's agent sends its stream to a host named per session and region,
	// and its unary calls to another name of the same domain.
	cursorStreamHost = "agentn.global.api5.cursor.sh"
	cursorAPIHost    = "api2.cursor.sh"
	cursorStreamPath = "/agent.v1.AgentService/Run"
	cursorUnaryPath  = "/aiserver.v1.InferenceService/RunInference"
)

func protoBytesField(b []byte, number int, payload []byte) []byte {
	b = binary.AppendUvarint(b, uint64(number)<<3|2)
	b = binary.AppendUvarint(b, uint64(len(payload)))
	return append(b, payload...)
}

func protoVarintField(b []byte, number int, value uint64) []byte {
	return binary.AppendUvarint(binary.AppendUvarint(b, uint64(number)<<3), value)
}

// agentMessage is a message of the shape an agent sends: ids and numbers
// around a string, two messages deep.
func agentMessage(text string) []byte {
	inner := protoBytesField(protoVarintField(nil, 1, 3), 2, []byte(text))
	return protoBytesField(protoBytesField(protoVarintField(nil, 1, 42), 2, []byte("conversation-7f3a")), 5, inner)
}

func connectEnvelope(flags byte, payload []byte) []byte {
	prefix := binary.BigEndian.AppendUint32([]byte{flags}, uint32(len(payload)))
	return append(prefix, payload...)
}

// overwritten is what a value of length bytes is overwritten with.
func overwritten(placeholder string, length int) string {
	if len(placeholder) >= length {
		return placeholder[:length]
	}
	return placeholder + strings.Repeat("*", length-len(placeholder))
}

// connectCall is one request as the fake service got it.
type connectCall struct {
	proto, host, path string
	header            http.Header
	// body is a unary call's body, and envelopes a stream's envelopes, each
	// with its prefix, as they arrived.
	body      []byte
	envelopes [][]byte
	// trailer is what the request's trailers held once its stream had ended.
	trailer http.Header
	// ended says the request's stream ended as a stream does; gone that it
	// broke off instead.
	ended, gone bool
}

// connectService is a fake Connect service. It answers a unary call once it
// has the body, and each envelope of a stream as it arrives, while the stream
// stays open.
type connectService struct {
	mu    sync.Mutex
	calls []*connectCall
	// breakAfter makes a stream break off once it has had that many envelopes.
	breakAfter int
}

func (s *connectService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call := &connectCall{proto: r.Proto, host: r.Host, path: r.URL.Path, header: r.Header.Clone()}
	s.mu.Lock()
	s.calls = append(s.calls, call)
	s.mu.Unlock()
	contentType := r.Header.Get("Content-Type")
	w.Header().Set("Content-Type", contentType)
	// gRPC frames its messages as Connect does, and X-Envelopes says the same
	// of a body whose type does not.
	if !strings.HasPrefix(contentType, "application/connect+") && !strings.HasPrefix(contentType, "application/grpc") && r.Header.Get("X-Envelopes") == "" {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		call.body, call.ended = body, true
		s.mu.Unlock()
		_, _ = w.Write(protoBytesField(nil, 1, []byte("answer")))
		return
	}
	// Over HTTP/1.1 an answer may only begin before the request ends when the
	// handler says so; over HTTP/2 it always may.
	_ = http.NewResponseController(w).EnableFullDuplex()
	w.Header().Set("Trailer", "X-Stream-Status")
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	reader := bufio.NewReaderSize(r.Body, 64<<10)
	for count := 1; ; count++ {
		prefix := make([]byte, connectEnvelopePrefix)
		if _, err := io.ReadFull(reader, prefix); err != nil {
			s.mu.Lock()
			call.ended, call.gone, call.trailer = err == io.EOF, err != io.EOF, r.Trailer.Clone()
			s.mu.Unlock()
			break
		}
		// What does not read as an envelope is no stream: the service gives
		// up on it, as a real one refuses it.
		length := binary.BigEndian.Uint32(prefix[1:])
		var payload []byte
		if length <= 2*maxLeakBody {
			payload = make([]byte, length)
		}
		if _, err := io.ReadFull(reader, payload); err != nil || length > 2*maxLeakBody {
			s.mu.Lock()
			call.gone = true
			s.mu.Unlock()
			break
		}
		s.mu.Lock()
		call.envelopes = append(call.envelopes, append(prefix, payload...))
		breakNow := s.breakAfter > 0 && count == s.breakAfter
		s.mu.Unlock()
		if breakNow {
			panic(http.ErrAbortHandler)
		}
		answer := []byte(fmt.Sprintf("answer %d to %d bytes", count, len(payload)))
		if size, _ := strconv.Atoi(r.Header.Get("X-Answer-Bytes")); size > 0 {
			answer = answerOfSize(size)
		}
		_, _ = w.Write(connectEnvelope(0, answer))
		w.(http.Flusher).Flush()
	}
	w.Header().Set("X-Stream-Status", "complete")
	// A trailer that was never announced, as gRPC sends its status.
	w.Header().Set(http.TrailerPrefix+"X-Stream-Count", fmt.Sprint(len(call.envelopes)))
}

// answerOfSize is an answer of size bytes that shows where a byte went missing.
func answerOfSize(size int) []byte {
	answer := make([]byte, size)
	for i := range answer {
		answer[i] = byte(i % 251)
	}
	return answer
}

// waitFor returns the call for which found holds, once there is one.
func (s *connectService) waitFor(t *testing.T, what string, found func(*connectCall) bool) *connectCall {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(2 * time.Millisecond) {
		s.mu.Lock()
		for _, call := range s.calls {
			if found(call) {
				copied := *call
				copied.envelopes = append([][]byte(nil), call.envelopes...)
				s.mu.Unlock()
				return &copied
			}
		}
		s.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("the service never saw %s", what)
		}
	}
}

// stream returns the stream marked id once it has had count envelopes.
func (s *connectService) stream(t *testing.T, id string, count int) *connectCall {
	t.Helper()
	return s.waitFor(t, fmt.Sprintf("%d envelopes of stream %s", count, id), func(call *connectCall) bool {
		return call.header.Get("X-Stream-Id") == id && len(call.envelopes) >= count
	})
}

func (s *connectService) last(t *testing.T) *connectCall {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		t.Fatal("the service was not called")
	}
	copied := *s.calls[len(s.calls)-1]
	return &copied
}

func (s *connectService) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// newConnectRig is the proxy in front of a fake provider that also is a
// Connect service for every name under cursor.sh, and speaks HTTP/2 as well
// as HTTP/1.1.
func newConnectRig(t *testing.T, mode string) (*leakRig, *connectService) {
	t.Helper()
	service := &connectService{}
	rig := newLeakRigWith(t, mode, func(provider *httptest.Server) {
		other := provider.Config.Handler
		provider.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if host, _, _ := strings.Cut(r.Host, ":"); host == "cursor.sh" || strings.HasSuffix(host, ".cursor.sh") {
				service.ServeHTTP(w, r)
				return
			}
			other.ServeHTTP(w, r)
		})
		provider.TLS.NextProtos = []string{"h2", "http/1.1"}
	})
	return rig, service
}

// clientOffering goes through the proxy and offers the service only the
// given protocols. It adds no header of its own to a request.
func (r *leakRig) clientOffering(roots *x509.CertPool, http1, http2 bool) *http.Client {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(http1)
	protocols.SetHTTP2(http2)
	transport := &http.Transport{
		Proxy:              http.ProxyURL(r.proxyURL),
		TLSClientConfig:    &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		Protocols:          protocols,
		DisableCompression: true,
	}
	r.t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

// openStream is one end of a Connect stream a test holds open.
type openStream struct {
	t        *testing.T
	writer   *io.PipeWriter
	response *http.Response
	reader   *bufio.Reader
	cancel   context.CancelFunc
}

// openConnectStream starts a stream to the agent's host and returns once the
// service has answered with its headers. The request stays open.
func openConnectStream(t *testing.T, client *http.Client, id string, headers map[string]string) *openStream {
	t.Helper()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+cursorStreamHost+cursorStreamPath, reader)
	request.Header.Set("Content-Type", "application/connect+proto")
	request.Header.Set("Connect-Protocol-Version", "1")
	request.Header.Set("X-Stream-Id", id)
	// Present and empty: the client names no agent, so the service sees
	// whether the proxy named one.
	request.Header["User-Agent"] = []string{""}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("stream %s: %v", id, err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	if response.StatusCode != http.StatusOK {
		t.Fatalf("stream %s: status %d", id, response.StatusCode)
	}
	return &openStream{t: t, writer: writer, response: response, reader: bufio.NewReader(response.Body), cancel: cancel}
}

func (s *openStream) send(envelope []byte) {
	s.t.Helper()
	if _, err := s.writer.Write(envelope); err != nil {
		s.t.Fatalf("the stream took no more: %v", err)
	}
}

// answer reads one envelope of the service's answer.
func (s *openStream) answer() (string, error) {
	prefix := make([]byte, connectEnvelopePrefix)
	if _, err := io.ReadFull(s.reader, prefix); err != nil {
		return "", err
	}
	payload := make([]byte, binary.BigEndian.Uint32(prefix[1:]))
	if _, err := io.ReadFull(s.reader, payload); err != nil {
		return "", err
	}
	return string(payload), nil
}

func (s *openStream) mustAnswer(want string) {
	s.t.Helper()
	if got, err := s.answer(); err != nil || got != want {
		s.t.Fatalf("the service's answer: %q %v, want %q", got, err, want)
	}
}

// end ends the request, reads what is left of the answer to its end and
// returns its trailers.
func (s *openStream) end() http.Header {
	s.t.Helper()
	_ = s.writer.Close()
	if _, err := io.Copy(io.Discard, s.reader); err != nil {
		s.t.Fatalf("the answer did not end with the request: %v", err)
	}
	return s.response.Trailer
}

// abandon gives the call up the way a client does that no longer wants its
// answer: it resets the stream.
func (s *openStream) abandon() {
	_ = s.response.Body.Close()
	s.cancel()
}

// A client that offers h2 alone is served, its stream stays open while
// envelopes go both ways, and each envelope reaches the service as it is
// sent. A registered value is overwritten where it sits; every other byte of
// the stream arrives as the client sent it.
func TestCursorAgentStreamIsReadOverHTTP2(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne, "db": leakSecretTwo})
	client := rig.clientOffering(rig.phaseRoots, false, true)
	stream := openConnectStream(t, client, "one", map[string]string{"Connect-Content-Encoding": "gzip", "Connect-Accept-Encoding": "gzip"})
	if stream.response.Proto != "HTTP/2.0" {
		t.Fatalf("the client was answered over %s", stream.response.Proto)
	}

	// The first envelope is at the service, and answered, before the client
	// sends a second one.
	clean := connectEnvelope(0, agentMessage("list the files in the repository"))
	stream.send(clean)
	stream.mustAnswer(fmt.Sprintf("answer 1 to %d bytes", len(clean)-connectEnvelopePrefix))
	if got := service.stream(t, "one", 1); len(got.envelopes) != 1 || !bytes.Equal(got.envelopes[0], clean) || got.ended {
		t.Fatalf("after one envelope the service has %d and the stream ended = %v", len(got.envelopes), got.ended)
	}

	// A value in an envelope that is not compressed: overwritten in place.
	plain := agentMessage("STRIPE_KEY=" + leakSecretOne + "\nLOG_LEVEL=debug\n")
	stream.send(connectEnvelope(0, plain))
	stream.mustAnswer(fmt.Sprintf("answer 2 to %d bytes", len(plain)))
	wantPlain := bytes.Replace(plain, []byte(leakSecretOne), []byte(overwritten("ph:secret:stripe", len(leakSecretOne))), 1)
	if got := service.stream(t, "one", 2).envelopes[1]; !bytes.Equal(got, connectEnvelope(0, wantPlain)) {
		t.Fatalf("the envelope did not arrive with the value overwritten and nothing else changed:\n%q\n%q", got, connectEnvelope(0, wantPlain))
	}

	// The same in a compressed envelope: it arrives as gzip of the message
	// with the value overwritten, under a prefix that states its new length.
	zipped := agentMessage("DATABASE_URL=" + leakSecretTwo + "\n")
	stream.send(connectEnvelope(connectCompressed, gzipBytes(t, zipped)))
	if _, err := stream.answer(); err != nil {
		t.Fatal(err)
	}
	arrived := service.stream(t, "one", 3).envelopes[2]
	wantZipped := bytes.Replace(zipped, []byte(leakSecretTwo), []byte(overwritten("ph:secret:db", len(leakSecretTwo))), 1)
	if arrived[0] != connectCompressed || int(binary.BigEndian.Uint32(arrived[1:])) != len(arrived)-connectEnvelopePrefix {
		t.Fatalf("the compressed envelope's prefix is wrong: % x for %d bytes", arrived[:connectEnvelopePrefix], len(arrived)-connectEnvelopePrefix)
	}
	if inflated := gunzipBytes(t, arrived[connectEnvelopePrefix:]); !bytes.Equal(inflated, wantZipped) || len(inflated) != len(zipped) {
		t.Fatalf("the compressed envelope does not hold the message with the value overwritten:\n%q\n%q", inflated, wantZipped)
	}

	// Envelopes with nothing in them go on byte for byte, compressed ones
	// too, and so does the one that ends a stream.
	untouched := [][]byte{
		connectEnvelope(connectCompressed, gzipBytes(t, agentMessage("nothing to see here"))),
		connectEnvelope(0, nil),
		connectEnvelope(0, []byte{0x08, 0x01}),
		connectEnvelope(connectEndStream, []byte(`{"metadata":{"note":["`+leakSecretOne+`"]}}`)),
	}
	for i, envelope := range untouched {
		stream.send(envelope)
		if _, err := stream.answer(); err != nil {
			t.Fatal(err)
		}
		if got := service.stream(t, "one", 4+i).envelopes[3+i]; !bytes.Equal(got, envelope) {
			t.Fatalf("envelope %d did not arrive as it was sent", 4+i)
		}
	}

	// The request ends, the service's answer ends with it, and its trailers
	// reach the client, announced or not.
	trailers := stream.end()
	if trailers.Get("X-Stream-Status") != "complete" || trailers.Get("X-Stream-Count") != "7" {
		t.Fatalf("the trailers: %v", trailers)
	}
	call := service.stream(t, "one", 7)
	if !call.ended || call.gone || call.proto != "HTTP/2.0" || call.host != cursorStreamHost || call.path != cursorStreamPath {
		t.Fatalf("the call as the service saw it: %+v", call)
	}
	// What was sent is what was forwarded: the same headers, and none of the
	// proxy's or its transport's own.
	if call.header.Get("Content-Type") != "application/connect+proto" || call.header.Get("Connect-Protocol-Version") != "1" ||
		call.header.Get("Connect-Content-Encoding") != "gzip" || call.header.Get("Connect-Accept-Encoding") != "gzip" {
		t.Fatalf("the stream's headers changed: %v", call.header)
	}
	for _, added := range []string{"User-Agent", "Accept-Encoding", "Content-Length", "Proxy-Authorization", "Via", "X-Forwarded-For"} {
		if _, present := call.header[added]; present {
			t.Errorf("the service was sent %s: %v", added, call.header[added])
		}
	}

	// One event for each envelope in which something new was found: what it
	// is about and how many, never what it was. The envelope a client marked
	// as the end of a stream was not read, and its event says so.
	events := rig.leakEvents(3)
	placeholders := map[string]bool{}
	unread := 0
	for _, event := range events {
		if event.Outcome == outcomeUnread && event.Reason == leakReasonMessageFlags && event.Detail["scope"] == leakScopeMessage && event.Detail["replacedCount"] == float64(0) {
			unread++
			continue
		}
		if event.Outcome != outcomeCensored || event.Protocol != leakProtocolHTTP2 || event.Method != http.MethodPost || event.Host != cursorStreamHost ||
			event.Path != cursorStreamPath || event.Detail["where"] != "message" || event.Detail["harness"] != "cursor" || event.Detail["mode"] != "censor" ||
			event.Detail["inventoryHits"] != float64(1) || event.Detail["replacedCount"] != float64(1) || event.Detail["severity"] != "medium" {
			t.Fatalf("event: %+v", event)
		}
		placeholders[fmt.Sprint(event.Detail["placeholders"])] = true
	}
	if len(events) != 3 || unread != 1 || !placeholders["ph:secret:stripe"] || !placeholders["ph:secret:db"] {
		t.Fatalf("%d events for %v", len(events), placeholders)
	}
	shipped := rig.shippedPayloads()
	for _, value := range []string{leakSecretOne, leakSecretTwo, "LOG_LEVEL"} {
		if bytes.Contains(shipped, []byte(value)) {
			t.Fatal("an event carries content of the stream")
		}
	}
}

func postConnect(t *testing.T, client *http.Client, target, contentType string, body []byte, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Connect-Protocol-Version", "1")
	for name, value := range headers {
		// Said through the request, so the client itself knows not to use
		// the connection again.
		if name == "Connection" && value == "close" {
			request.Close = true
			continue
		}
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, answer
}

// A unary call is one protobuf message: a value in it is overwritten in
// place, in a gzip body too, over HTTP/1.1 as well as over HTTP/2.
func TestCursorUnaryCallsAreOverwrittenInPlace(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	target := "https://" + cursorAPIHost + cursorUnaryPath
	message := agentMessage("the key is " + leakSecretOne + " in .env")
	want := bytes.Replace(message, []byte(leakSecretOne), []byte(overwritten("ph:secret:stripe", len(leakSecretOne))), 1)
	answer := protoBytesField(nil, 1, []byte("answer"))
	for name, client := range map[string]*http.Client{
		// Cursor's own unary calls offer no protocol at all, which is HTTP/1.1.
		"HTTP/1.1": rig.clientOffering(rig.phaseRoots, true, false),
		"HTTP/2":   rig.clientOffering(rig.phaseRoots, false, true),
	} {
		response, got := postConnect(t, client, target, "application/proto", message, map[string]string{"Connection": "close", "Keep-Alive": "timeout=5"})
		call := service.last(t)
		if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Proto, name) || !bytes.Equal(got, answer) {
			t.Fatalf("%s: status %d over %s, answer %q", name, response.StatusCode, response.Proto, got)
		}
		if !bytes.Equal(call.body, want) || call.header.Get("Content-Length") != fmt.Sprint(len(message)) {
			t.Fatalf("%s: the body did not arrive with the value overwritten, as long as it was:\n%q\n%q", name, call.body, want)
		}
		// What belongs to one hop stays on it.
		if call.header.Get("Connection") != "" || call.header.Get("Keep-Alive") != "" || call.header.Get("Proxy-Authorization") != "" {
			t.Fatalf("%s: a header of the client's own connection was forwarded: %v", name, call.header)
		}

		// The same body in gzip: what arrives is gzip of the overwritten
		// message, and says how long it is.
		postConnect(t, client, target, "application/proto; charset=binary", gzipBytes(t, message), map[string]string{"Content-Encoding": "gzip"})
		call = service.last(t)
		if call.header.Get("Content-Encoding") != "gzip" || call.header.Get("Content-Length") != fmt.Sprint(len(call.body)) || !bytes.Equal(gunzipBytes(t, call.body), want) {
			t.Fatalf("%s: the gzip body did not arrive as gzip of the overwritten message", name)
		}

		// A body with nothing in it is not touched, compressed or not.
		for _, body := range [][]byte{agentMessage("nothing to see here"), gzipBytes(t, agentMessage("nothing here either"))} {
			headers := map[string]string{}
			if body[0] == 0x1f {
				headers["Content-Encoding"] = "gzip"
			}
			postConnect(t, client, target, "application/proto", body, headers)
			if call = service.last(t); !bytes.Equal(call.body, body) {
				t.Fatalf("%s: a body with nothing to change arrived changed", name)
			}
		}
	}
	// The first call found the value; the others on that host said nothing new.
	if events := rig.leakEvents(1); len(rig.leakEventsNow()) != 1 || events[0].Outcome != outcomeCensored || events[0].Detail["where"] != "body" ||
		events[0].Host != cursorAPIHost || events[0].Path != cursorUnaryPath || events[0].Detail["harness"] != "cursor" {
		t.Fatalf("events: %+v", rig.leakEventsNow())
	}
}

// Every Connect call carries conversation content, whatever its path, so
// every pattern rule applies to it. Anything else Cursor's hosts take is read
// for registered values and Phase's own tokens only.
func TestCursorConnectCallsAreConversationContent(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.clientOffering(rig.phaseRoots, true, false)
	token := "ghp_" + strings.Repeat("Ab3dEf6hIj9lMn2pQr5t", 2)[:36]
	phase := phaseServiceToken()
	text := "git token " + token + " and " + leakSecretOne + " and " + phase
	replaced := func(text string, rules bool) string {
		text = strings.Replace(text, leakSecretOne, overwritten("ph:secret:stripe", len(leakSecretOne)), 1)
		if rules {
			text = strings.Replace(text, token, overwritten("ph:github_token:1", len(token)), 1)
		}
		return text
	}

	postConnect(t, client, "https://"+cursorAPIHost+"/aiserver.v1.AnyService/AnyCall", "application/proto", agentMessage(text), nil)
	body := string(service.last(t).body)
	if !strings.Contains(body, replaced("git token "+token+" and "+leakSecretOne, true)) || strings.Contains(body, phase) {
		t.Fatalf("a Connect call was not read with every rule: %q", body)
	}

	// Traces are JSON, and no conversation: the token format is left, the
	// registered value and Phase's own token are not.
	traces := []byte(`{"resourceSpans":[{"attributes":{"note":"` + text + `"}}]}`)
	postConnect(t, client, "https://"+cursorAPIHost+"/v1/traces", "application/json", traces, nil)
	body = string(service.last(t).body)
	if !strings.Contains(body, token) || strings.Contains(body, leakSecretOne) || strings.Contains(body, phase) || !strings.Contains(body, "ph:secret:stripe and ph:phase_service_token:") {
		t.Fatalf("traces were not read for registered values and Phase's tokens only: %q", body)
	}

	// The kinds the table knows, and that only a host that speaks Connect is
	// asked what its Content-Type says.
	cursor := rig.guard.inspects(envFlow, cursorAPIHost, 443)
	for contentType, want := range map[string]leakBody{
		"application/proto":                        leakBodyProtobuf,
		"Application/Proto":                        leakBodyProtobuf,
		"application/proto; charset=utf-8":         leakBodyProtobuf,
		"application/connect+proto":                leakBodyProtobufStream,
		" application/connect+proto ;charset=utf8": leakBodyProtobufStream,
		"application/connect+json":                 leakBodyJSONStream,
		"application/json":                         leakBodyText,
		"application/problem+json; charset=utf-8":  leakBodyText,
		"text/plain":                               leakBodyText,
		"application/x-www-form-urlencoded":        leakBodyText,
		"application/x-protobuf":                   leakBodyBinary,
		"application/protobuf":                     leakBodyBinary,
		"application/octet-stream":                 leakBodyUnframed,
		"application/protobuf-x":                   leakBodyUnframed,
		"":                                         leakBodyUnframed,
		"application/grpc":                         leakBodyGRPC,
		"application/grpc+proto":                   leakBodyGRPC,
		"Application/gRPC-Web+proto; charset=utf8": leakBodyGRPC,
		"application/grpc-web":                     leakBodyGRPC,
		"application/grpc+json":                    leakBodyGRPCJSON,
		"application/grpc-web+json":                leakBodyGRPCJSON,
		// Envelopes in base64 show no envelope, and "grpcx" is not gRPC.
		"application/grpc-web-text":       leakBodyUnframed,
		"application/grpc-web-text+proto": leakBodyUnframed,
		"application/grpcx":               leakBodyUnframed,
	} {
		header := http.Header{"Content-Type": {contentType}}
		if got := cursor.body(header); got != want {
			t.Errorf("%q on Cursor's host is read as %d, want %d", contentType, got, want)
		}
		if got := rig.guard.inspects(envFlow, "api.anthropic.com", 443).body(header); got != leakBodyAsItReads {
			t.Errorf("%q on a host that does not speak Connect is read as %d", contentType, got)
		}
	}
	if !leakBodyProtobuf.conversation() || !leakBodyProtobufStream.conversation() || !leakBodyGRPC.conversation() || leakBodyJSONStream.conversation() ||
		leakBodyGRPCJSON.conversation() || leakBodyAsItReads.conversation() || leakBodyText.conversation() || leakBodyBinary.conversation() || leakBodyUnframed.conversation() {
		t.Fatal("which bodies carry conversation content")
	}
	for kind, want := range map[leakBody][3]bool{
		leakBodyAsItReads: {false, false, true}, leakBodyText: {false, false, true}, leakBodyBinary: {false, true, true}, leakBodyProtobuf: {false, true, true},
		leakBodyUnframed:       {false, true, false},
		leakBodyProtobufStream: {true, false, false}, leakBodyJSONStream: {true, false, false}, leakBodyGRPC: {true, false, false}, leakBodyGRPCJSON: {true, false, false},
	} {
		if kind.stream() != want[0] || kind.inPlace() != want[1] || kind.unary() != want[2] {
			t.Errorf("kind %d: read as a stream = %v, overwritten in place = %v", kind, kind.stream(), kind.inPlace())
		}
	}
	if leakBodyGRPC.encodingHeader() != "Grpc-Encoding" || leakBodyGRPCJSON.encodingHeader() != "Grpc-Encoding" || leakBodyJSONStream.encodingHeader() != "Connect-Content-Encoding" {
		t.Fatal("which header names a stream's encoding")
	}

	// On a host that does not speak Connect the same body is what its bytes
	// say, and a value in bytes that are not text still stops the request.
	response, _ := postConnect(t, client, "https://api.anthropic.com/v1/messages", "application/proto", agentMessage(text), nil)
	if response.StatusCode != http.StatusForbidden || response.Header.Get("X-Phase-Error-Code") != codeSecretInRequest {
		t.Fatalf("a binary body on another host: status %d", response.StatusCode)
	}
}

// A message the proxy cannot read goes on exactly as it came and is reported
// as unread, with why. What follows it in the stream is read as before.
func TestCursorMessagesThatCannotBeReadPassAndAreReported(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.clientOffering(rig.phaseRoots, false, true)
	secret := agentMessage("the key is " + leakSecretOne)
	overwrittenSecret := bytes.Replace(secret, []byte(leakSecretOne), []byte(overwritten("ph:secret:stripe", len(leakSecretOne))), 1)

	// Compressed with an encoding the proxy does not undo.
	stream := openConnectStream(t, client, "brotli", map[string]string{"Connect-Content-Encoding": "br"})
	unknown := connectEnvelope(connectCompressed, append([]byte{0x1b, 0x03}, secret...))
	stream.send(unknown)
	stream.send(connectEnvelope(0, secret))
	stream.end()
	if got := service.stream(t, "brotli", 2).envelopes; !bytes.Equal(got[0], unknown) || !bytes.Equal(got[1], connectEnvelope(0, overwrittenSecret)) {
		t.Fatal("an envelope in an unknown encoding was changed, or the one after it was not read")
	}

	// Marked compressed, with no encoding named at all.
	stream = openConnectStream(t, client, "unnamed", nil)
	stream.send(unknown)
	stream.end()
	if got := service.stream(t, "unnamed", 1).envelopes; !bytes.Equal(got[0], unknown) {
		t.Fatal("an envelope whose encoding is not named was changed")
	}

	// Marked gzip, and not gzip.
	stream = openConnectStream(t, client, "broken", map[string]string{"Connect-Content-Encoding": "gzip"})
	broken := connectEnvelope(connectCompressed, secret)
	stream.send(broken)
	stream.send(connectEnvelope(connectCompressed, gzipBytes(t, secret)))
	stream.end()
	got := service.stream(t, "broken", 2).envelopes
	if !bytes.Equal(got[0], broken) || !bytes.Equal(gunzipBytes(t, got[1][connectEnvelopePrefix:]), overwrittenSecret) {
		t.Fatal("an envelope that does not inflate was changed, or the one after it was not read")
	}

	// Longer than the proxy holds: it goes on as it comes.
	stream = openConnectStream(t, client, "large", nil)
	large := connectEnvelope(0, append(bytes.Repeat([]byte{0x2e}, maxLeakBody), secret...))
	go stream.send(large)
	if answer, err := stream.answer(); err != nil || answer != fmt.Sprintf("answer 1 to %d bytes", len(large)-connectEnvelopePrefix) {
		t.Fatalf("the large envelope: %q %v", answer, err)
	}
	stream.send(connectEnvelope(0, secret))
	stream.end()
	got = service.stream(t, "large", 2).envelopes
	if !bytes.Equal(got[0], large) || !bytes.Equal(got[1], connectEnvelope(0, overwrittenSecret)) {
		t.Fatal("an envelope over the limit was changed, or the one after it was not read")
	}

	// A stream compressed as a whole shows no envelopes: all of it is unread.
	whole := gzipBytes(t, connectEnvelope(0, secret))
	postConnect(t, client, "https://"+cursorStreamHost+cursorStreamPath, "application/connect+proto", whole, map[string]string{"Content-Encoding": "gzip", "X-Stream-Id": "whole"})
	// It reached the service as the client sent it, for the service to refuse.
	service.waitFor(t, "the stream compressed as a whole", func(call *connectCall) bool {
		return call.header.Get("X-Stream-Id") == "whole" && call.header.Get("Content-Encoding") == "gzip" && (call.gone || call.ended)
	})

	reasons := map[string]string{}
	for _, event := range rig.distinctLeakEvents(t, 5) {
		if event.Outcome != outcomeUnread {
			continue
		}
		if event.ProxyDecision != "allow" || event.Protocol != leakProtocolHTTP2 || event.Host != cursorStreamHost || event.Detail["harness"] != "cursor" || event.Detail["severity"] != nil {
			t.Fatalf("unread event: %+v", event)
		}
		reasons[event.Reason] = fmt.Sprint(event.Detail["scope"])
	}
	want := map[string]string{
		leakReasonMessageEncoding: leakScopeMessage, leakReasonMessageUndecodable: leakScopeMessage,
		leakReasonOverLimit: leakScopeMessage, leakReasonUndecodable: leakScopeRequest,
	}
	if !reflect.DeepEqual(reasons, want) {
		t.Fatalf("what was reported as unread: %v, want %v", reasons, want)
	}
	// Two streams met an encoding the proxy does not undo, a minute apart at
	// most: one event, as for every unread reason.
	unread := 0
	for _, event := range rig.leakEventsNow() {
		if event.Reason == leakReasonMessageEncoding {
			unread++
		}
	}
	if unread != 1 {
		t.Fatalf("%d events for one reason within a minute", unread)
	}
}

// observe mode reads the same and changes nothing; off leaves the tunnel alone.
func TestCursorObserveModeChangesNothingAndOffIsARawTunnel(t *testing.T) {
	rig, service := newConnectRig(t, leakModeObserve)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne, "db": leakSecretTwo})
	client := rig.clientOffering(rig.phaseRoots, false, true)
	stream := openConnectStream(t, client, "observed", map[string]string{"Connect-Content-Encoding": "gzip"})
	sent := [][]byte{
		connectEnvelope(0, agentMessage("the key is "+leakSecretOne)),
		connectEnvelope(connectCompressed, gzipBytes(t, agentMessage("the url is "+leakSecretTwo))),
	}
	for _, envelope := range sent {
		stream.send(envelope)
	}
	stream.end()
	if got := service.stream(t, "observed", 2).envelopes; !bytes.Equal(got[0], sent[0]) || !bytes.Equal(got[1], sent[1]) {
		t.Fatal("observe mode changed an envelope")
	}
	unary := agentMessage("again " + leakSecretOne)
	postConnect(t, client, "https://"+cursorAPIHost+cursorUnaryPath, "application/proto", unary, nil)
	if !bytes.Equal(service.last(t).body, unary) {
		t.Fatal("observe mode changed a body")
	}
	for _, event := range rig.leakEvents(3) {
		if event.Outcome != outcomeObserved || event.Detail["mode"] != "observe" || event.Detail["replacedCount"] != float64(0) {
			t.Fatalf("event: %+v", event)
		}
	}

	// With leak protection off the client's TLS is the service's own: over
	// whichever protocol the two of them choose.
	off, service := newConnectRig(t, leakModeOff)
	registerLeakValues(t, off.guard, map[string]string{"stripe": leakSecretOne})
	response, _ := postConnect(t, off.clientOffering(off.providerRoots, true, true), "https://"+cursorAPIHost+cursorUnaryPath, "application/proto", unary, nil)
	if response.Proto != "HTTP/2.0" || !bytes.Equal(service.last(t).body, unary) {
		t.Fatalf("the raw tunnel: %s", response.Proto)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://"+cursorAPIHost+"/", nil)
	if _, err := off.clientOffering(off.phaseRoots, true, true).Do(request); err == nil {
		t.Fatal("the client was given Phase's certificate: the tunnel was read")
	}
	if status := off.guard.status(); len(status.InspectedHosts) != 0 || !containsString(status.UnreadHosts, "*.cursor.sh") {
		t.Fatalf("off mode says it reads: %+v", status)
	}
}

// When either end of a stream goes away the other is told, and nothing of it
// is left running in the proxy.
func TestCursorStreamCancellationReachesTheOtherEnd(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	client := rig.clientOffering(rig.phaseRoots, false, true)
	message := connectEnvelope(0, agentMessage("first"))

	// The client gives up: the service's stream breaks off.
	stream := openConnectStream(t, client, "client-gone", nil)
	stream.send(message)
	stream.mustAnswer(fmt.Sprintf("answer 1 to %d bytes", len(message)-connectEnvelopePrefix))
	stream.abandon()
	service.waitFor(t, "the client's stream break off", func(call *connectCall) bool { return call.header.Get("X-Stream-Id") == "client-gone" && call.gone })
	if _, err := stream.answer(); err == nil {
		t.Fatal("a cancelled stream still answered")
	}

	// The service breaks off: the client's stream is reset, not ended as if
	// the answer were whole.
	service.mu.Lock()
	service.breakAfter = 2
	service.mu.Unlock()
	stream = openConnectStream(t, client, "service-gone", nil)
	stream.send(message)
	stream.mustAnswer(fmt.Sprintf("answer 1 to %d bytes", len(message)-connectEnvelopePrefix))
	stream.send(message)
	if answer, err := stream.answer(); err == nil || err == io.EOF {
		t.Fatalf("the service's stream broke off and the client's ended with %q, %v", answer, err)
	}
	service.mu.Lock()
	service.breakAfter = 0
	service.mu.Unlock()

	// The same tunnel still carries a new stream.
	stream = openConnectStream(t, client, "after", nil)
	stream.send(message)
	stream.mustAnswer(fmt.Sprintf("answer 1 to %d bytes", len(message)-connectEnvelopePrefix))

	// The proxy lets go of its tunnels while that stream is open: it does
	// not wait for the stream, and both ends see it go.
	released := make(chan struct{})
	go func() {
		rig.proxy.CloseHijacked()
		close(released)
	}()
	select {
	case <-released:
	case <-time.After(10 * time.Second):
		t.Fatal("the proxy still holds a tunnel whose streams should have ended")
	}
	service.waitFor(t, "the last stream break off", func(call *connectCall) bool { return call.header.Get("X-Stream-Id") == "after" && call.gone })
	if _, err := stream.answer(); err == nil {
		t.Fatal("a stream outlived its tunnel")
	}
	rig.proxy.mu.Lock()
	held := len(rig.proxy.hijacked)
	rig.proxy.mu.Unlock()
	if held != 0 {
		t.Fatalf("%d tunnels are still held", held)
	}
}

// Streams of one tunnel are independent: many at once, each carrying its own
// messages, arrive each as it was sent with its values overwritten.
func TestCursorStreamsAreMultiplexedAndIndependent(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.clientOffering(rig.phaseRoots, false, true)
	// More than one tunnel carries at a time: the client waits its turn.
	const streams, messages = maxTunnelStreams + 20, 6
	var group sync.WaitGroup
	failures := make(chan string, streams)
	for index := 0; index < streams; index++ {
		group.Add(1)
		go func(id string) {
			defer group.Done()
			stream := openConnectStream(t, client, id, map[string]string{"Connect-Content-Encoding": "gzip"})
			var sent, want [][]byte
			for m := 0; m < messages; m++ {
				text := fmt.Sprintf("stream %s message %d holds %s and nothing more", id, m, leakSecretOne)
				message := agentMessage(text)
				changed := bytes.Replace(message, []byte(leakSecretOne), []byte(overwritten("ph:secret:stripe", len(leakSecretOne))), 1)
				if m%2 == 1 {
					sent, want = append(sent, connectEnvelope(connectCompressed, gzipBytes(t, message))), append(want, changed)
				} else {
					sent, want = append(sent, connectEnvelope(0, message)), append(want, changed)
				}
				stream.send(sent[m])
				if _, err := stream.answer(); err != nil {
					failures <- fmt.Sprintf("stream %s: answer %d: %v", id, m, err)
					return
				}
			}
			if trailers := stream.end(); trailers.Get("X-Stream-Count") != fmt.Sprint(messages) {
				failures <- fmt.Sprintf("stream %s: trailers %v", id, trailers)
				return
			}
			for m, envelope := range service.stream(t, id, messages).envelopes {
				payload := envelope[connectEnvelopePrefix:]
				if envelope[0]&connectCompressed != 0 {
					payload = gunzipBytes(t, payload)
				}
				if !bytes.Equal(payload, want[m]) {
					failures <- fmt.Sprintf("stream %s: message %d arrived as %q", id, m, payload)
					return
				}
			}
		}(fmt.Sprint(index))
	}
	group.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	if service.count() != streams {
		t.Fatalf("the service saw %d streams, want %d", service.count(), streams)
	}
}

// A stream is also sent over HTTP/1.1, with a body that ends before any
// answer: one whose length the client states is read whole, so what is sent
// states the length it then has; one sent in chunks goes on as it comes.
func TestCursorStreamsOverHTTP1(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.clientOffering(rig.phaseRoots, true, false)
	message := agentMessage("the key is " + leakSecretOne)
	changed := bytes.Replace(message, []byte(leakSecretOne), []byte(overwritten("ph:secret:stripe", len(leakSecretOne))), 1)
	target := "https://" + cursorAPIHost + "/aiserver.v1.ChatService/StreamChat"
	body := append(connectEnvelope(connectCompressed, gzipBytes(t, message)), connectEnvelope(0, message)...)

	response, answer := postConnect(t, client, target, "application/connect+proto", body, map[string]string{"Connect-Content-Encoding": "gzip", "X-Stream-Id": "stated"})
	call := service.stream(t, "stated", 2)
	if response.StatusCode != http.StatusOK || response.Proto != "HTTP/1.1" || !bytes.Contains(answer, []byte("answer 2 to")) {
		t.Fatalf("status %d over %s: %q", response.StatusCode, response.Proto, answer)
	}
	arrived := len(call.envelopes[0]) + len(call.envelopes[1])
	if !bytes.Equal(gunzipBytes(t, call.envelopes[0][connectEnvelopePrefix:]), changed) || !bytes.Equal(call.envelopes[1], connectEnvelope(0, changed)) ||
		call.header.Get("Content-Length") != fmt.Sprint(arrived) {
		t.Fatalf("a stream of a stated length: %d bytes arrived under Content-Length %q", arrived, call.header.Get("Content-Length"))
	}

	// In chunks: the client states no length, and none is made up for it.
	request, _ := http.NewRequest(http.MethodPost, target, io.MultiReader(bytes.NewReader(body[:7]), bytes.NewReader(body[7:])))
	request.Header.Set("Content-Type", "application/connect+proto")
	request.Header.Set("Connect-Content-Encoding", "gzip")
	request.Header.Set("X-Stream-Id", "chunked")
	chunked, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, chunked.Body)
	_ = chunked.Body.Close()
	call = service.stream(t, "chunked", 2)
	if !bytes.Equal(gunzipBytes(t, call.envelopes[0][connectEnvelopePrefix:]), changed) || !bytes.Equal(call.envelopes[1], connectEnvelope(0, changed)) || call.header.Get("Content-Length") != "" {
		t.Fatalf("a stream sent in chunks: Content-Length %q", call.header.Get("Content-Length"))
	}

	// JSON messages are read as JSON is anywhere: the value is replaced by
	// its placeholder, and the envelope says how long the message then is.
	json := []byte(`{"text":"the key is ` + leakSecretOne + `"}`)
	postConnect(t, client, target, "application/connect+json", connectEnvelope(0, json), map[string]string{"X-Stream-Id": "json"})
	want := connectEnvelope(0, bytes.Replace(json, []byte(leakSecretOne), []byte("ph:secret:stripe"), 1))
	if got := service.stream(t, "json", 1).envelopes[0]; !bytes.Equal(got, want) {
		t.Fatalf("a JSON message: %q, want %q", got, want)
	}
	// A JSON stream's message that is not text is overwritten where the
	// value sits, like any bytes of this host that are not text.
	response, _ = postConnect(t, client, target, "application/connect+json", connectEnvelope(0, append([]byte{0xff, 0x00}, leakSecretOne...)), map[string]string{"X-Stream-Id": "not-text"})
	want = connectEnvelope(0, append([]byte{0xff, 0x00}, overwritten("ph:secret:stripe", len(leakSecretOne))...))
	if got := service.stream(t, "not-text", 1).envelopes[0]; response.StatusCode != http.StatusOK || !bytes.Equal(got, want) {
		t.Fatalf("a message that is not text: status %d, %q, want %q", response.StatusCode, got, want)
	}
}

// A host whose rule does not say its clients speak HTTP/2 is answered as it
// was: with HTTP/1.1, whatever the client offers. So is a host a Connection
// covers, whatever its rule says.
func TestHTTP2IsOfferedOnlyWhereTheTableSaysAndNoConnectionCovers(t *testing.T) {
	rig, _ := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	both := rig.clientOffering(rig.phaseRoots, true, true)
	body := anthropicBody("the key is " + leakSecretOne)
	response, _ := postConnect(t, both, "https://api.anthropic.com/v1/messages", "application/json", body, nil)
	if response.StatusCode != http.StatusOK || response.Proto != "HTTP/1.1" || bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) {
		t.Fatalf("a host without the flag: status %d over %s", response.StatusCode, response.Proto)
	}
	// A client that offers h2 alone was never served there, and is not now.
	request, _ := http.NewRequest(http.MethodGet, "https://api.anthropic.com/v1/models", nil)
	if _, err := rig.clientOffering(rig.phaseRoots, false, true).Do(request); err == nil {
		t.Fatal("a host without the flag answered a client that speaks only HTTP/2")
	}
	// On a flagged host the same client that offers both gets HTTP/2.
	response, _ = postConnect(t, both, "https://"+cursorAPIHost+cursorUnaryPath, "application/proto", agentMessage("hello"), nil)
	if response.Proto != "HTTP/2.0" {
		t.Fatalf("a flagged host answered over %s", response.Proto)
	}

	// A Connection's own host: flagged or not, its tunnel is HTTP/1.1 and its
	// credential is attached as before.
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-custom", 1,
		customConnectionPayload(customDecoyToken, customLiveToken)), "runtime-custom")
	defer state.destroy()
	bound, _ := newConnectRig(t, leakModeCensor)
	bound.guard.hosts = leakHostTable{{Harness: "test", Hosts: []leakHostRule{{Host: "api.example.test", Treatment: leakTreatmentInspect, HTTP2: true, Connect: true}}}}
	registerLeakValues(t, bound.guard, map[string]string{"stripe": leakSecretOne})
	bound.proxy.state = state
	bound.proxyURL.User = url.UserPassword("phase", "runtime-custom")
	response, _ = postConnect(t, bound.clientOffering(bound.phaseRoots, true, true), "https://api.example.test/v1/items", "application/json", body, nil)
	received := bound.lastReceived()
	if response.StatusCode != http.StatusOK || response.Proto != "HTTP/1.1" || received.header.Get("Authorization") != "Bearer "+customLiveToken ||
		bytes.Contains(received.body, []byte(leakSecretOne)) {
		t.Fatalf("a Connection's host: status %d over %s", response.StatusCode, response.Proto)
	}
	request, _ = http.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
	if _, err := bound.clientOffering(bound.phaseRoots, false, true).Do(request); err == nil {
		t.Fatal("a Connection's host answered a client that speaks only HTTP/2")
	}
}

// Cursor's desktop app has processes that refuse the proxy's certificate. A
// window is kept per tool and host: one name of the domain being refused
// leaves every other name of it read, and status names the one.
func TestRefusalsOnOneCursorHostLeaveItsOtherHostsRead(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	refused := leakStateKey{tool: "cursor", host: cursorAPIHost}
	message := agentMessage("the key is " + leakSecretOne)
	for refusals := 1; refusals <= 2; refusals++ {
		request, _ := http.NewRequest(http.MethodGet, "https://"+cursorAPIHost+"/", nil)
		if _, err := rig.clientOffering(rig.providerRoots, true, false).Do(request); err == nil {
			t.Fatal("a client that does not trust Phase completed TLS with the proxy")
		}
		for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			rig.guard.handshakes.mu.Lock()
			state := rig.guard.handshakes.hosts[refused]
			counted := state != nil && state.failures >= refusals
			rig.guard.handshakes.mu.Unlock()
			if counted {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("refusal %d was not counted for %+v", refusals, refused)
			}
		}
	}
	if !rig.guard.handshakes.bypassed(refused) || rig.guard.handshakes.bypassed(leakStateKey{tool: "cursor", host: cursorStreamHost}) ||
		rig.guard.handshakes.bypassed(leakStateKey{tool: "cursor", host: "cursor.sh"}) {
		t.Fatal("two refusals on one name did not open a window for that name alone")
	}
	// The agent's stream, on another name of the domain, is read.
	stream := openConnectStream(t, rig.clientOffering(rig.phaseRoots, false, true), "read", nil)
	stream.send(connectEnvelope(0, message))
	stream.end()
	if got := service.stream(t, "read", 1).envelopes[0]; bytes.Contains(got, []byte(leakSecretOne)) {
		t.Fatal("a refusal on one name stopped another name of the domain being read")
	}
	// The refused name is passed through meanwhile, to the process that
	// refuses and to any other.
	postConnect(t, rig.clientOffering(rig.providerRoots, true, false), "https://"+cursorAPIHost+cursorUnaryPath, "application/proto", message, nil)
	if !bytes.Equal(service.last(t).body, message) {
		t.Fatal("the name in a window was read")
	}
	status := rig.guard.status()
	if !containsString(status.UnreadHosts, cursorAPIHost) || !reflect.DeepEqual(status.UnreadReasons, map[string][]string{cursorAPIHost: {leakReasonTLSRefused}}) ||
		!containsString(status.InspectedHosts, "*.cursor.sh") || !containsString(status.InspectedHosts, "cursor.sh") || containsString(status.UnreadHosts, cursorStreamHost) {
		t.Fatalf("status: inspected %v, not inspected %v for %v", status.InspectedHosts, status.UnreadHosts, status.UnreadReasons)
	}
	var window []agentapi.Event
	for _, event := range rig.leakEvents(2) {
		if event.Outcome == outcomeBypass {
			window = append(window, event)
		}
	}
	if len(window) != 1 || window[0].Host != cursorAPIHost || window[0].Reason != leakReasonTLSRefused || window[0].Detail["harness"] != "cursor" || window[0].Detail["windowSeconds"] != float64(20) {
		t.Fatalf("the window's event: %+v", window)
	}
}

// brokenReader hands out what it holds and then fails.
type brokenReader struct {
	data []byte
	err  error
}

func (r *brokenReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// The stream's reader on its own: whatever the client sends, and however it
// arrives, what goes on is what came, with only what was found replaced.
func TestConnectStreamHandsOnEverythingItIsSent(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	registerLeakValues(t, guard, map[string]string{"stripe": leakSecretOne})
	proxy := &httpProxy{leak: guard}
	match := guard.inspects(envFlow, cursorStreamHost, 443)
	request := httptest.NewRequest(http.MethodPost, "https://"+cursorStreamHost+cursorStreamPath, nil)
	through := func(source io.Reader, buffer int) ([]byte, error) {
		stream := &connectStream{
			proxy: proxy, source: io.NopCloser(source), request: request, host: cursorStreamHost, port: 443,
			match: match, opts: censor.ScanOptions{}, protocol: leakProtocolHTTP2, encoding: "gzip",
		}
		var out []byte
		piece := make([]byte, buffer)
		for {
			n, err := stream.Read(piece)
			out = append(out, piece[:n]...)
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				return out, err
			}
		}
	}
	secret := agentMessage("the key is " + leakSecretOne)
	changed := bytes.Replace(secret, []byte(leakSecretOne), []byte(overwritten("ph:secret:stripe", len(leakSecretOne))), 1)
	sent := bytes.Join([][]byte{
		connectEnvelope(0, agentMessage("nothing")), connectEnvelope(0, secret), connectEnvelope(0, nil),
		connectEnvelope(connectEndStream, []byte(`{}`)), connectEnvelope(0x80, secret),
	}, nil)
	want := bytes.Join([][]byte{
		connectEnvelope(0, agentMessage("nothing")), connectEnvelope(0, changed), connectEnvelope(0, nil),
		connectEnvelope(connectEndStream, []byte(`{}`)), connectEnvelope(0x80, changed),
	}, nil)
	for _, buffer := range []int{1, 3, 5, 64, 32 << 10} {
		for name, source := range map[string]io.Reader{
			"at once": bytes.NewReader(sent), "a byte at a time": iotest.OneByteReader(bytes.NewReader(sent)), "in halves": iotest.HalfReader(bytes.NewReader(sent)),
		} {
			if got, err := through(source, buffer); err != nil || !bytes.Equal(got, want) {
				t.Fatalf("read %d bytes at a time, sent %s: %v\n%q\n%q", buffer, name, err, got, want)
			}
		}
	}
	// A stream that ends inside an envelope ends there: what came of it goes
	// on as it came, and nothing is made up.
	for cut := 0; cut < len(sent); cut++ {
		got, err := through(bytes.NewReader(sent[:cut]), 7)
		if err != nil || len(got) != cut {
			t.Fatalf("cut at %d: %d bytes went on, %v", cut, len(got), err)
		}
		// Whole envelopes before the cut were read; the cut one was not.
		if whole := len(connectEnvelope(0, agentMessage("nothing"))) + len(connectEnvelope(0, secret)); cut >= whole && !bytes.Equal(got[:whole], want[:whole]) {
			t.Fatalf("cut at %d: the envelopes before the cut were not read", cut)
		}
		if cut < len(connectEnvelope(0, agentMessage("nothing")))+len(connectEnvelope(0, secret)) && !bytes.Equal(got, sent[:cut]) {
			t.Fatalf("cut at %d: an envelope that never ended was changed", cut)
		}
	}
	// A stream that breaks is broken for the service too, after what came.
	broken := fmt.Errorf("the client's stream was reset")
	if got, err := through(&brokenReader{data: sent[:len(sent)-3], err: broken}, 16); err != broken || !bytes.HasPrefix(want, got[:len(got)-len(secret)]) {
		t.Fatalf("a broken stream: %v after %d bytes", err, len(got))
	}
	// So is a body that ends before the length its client stated: that is
	// no end of a stream, and is never passed on as one.
	for _, cut := range []int{2, 9, len(sent) - 20} {
		if got, err := through(&brokenReader{data: sent[:cut], err: io.ErrUnexpectedEOF}, 16); err != io.ErrUnexpectedEOF || len(got) > cut {
			t.Fatalf("a body cut short at %d: %v after %d bytes", cut, err, len(got))
		}
	}
	// An envelope too long to hold goes on as it comes, in pieces of any size.
	long := connectEnvelope(0, append(bytes.Repeat([]byte("x"), maxLeakBody+1), leakSecretOne...))
	if got, err := through(io.MultiReader(bytes.NewReader(long), bytes.NewReader(connectEnvelope(0, secret))), 64<<10); err != nil ||
		!bytes.Equal(got[:len(long)], long) || !bytes.Equal(got[len(long):], connectEnvelope(0, changed)) {
		t.Fatalf("an envelope over the limit: %v, %d bytes", err, len(got))
	}
	if got, err := through(bytes.NewReader(long[:len(long)-9]), 64<<10); err != nil || !bytes.Equal(got, long[:len(long)-9]) {
		t.Fatalf("an envelope over the limit that never ended: %v, %d bytes", err, len(got))
	}
}

// The tunnel's own count of its streams: one that starts once the tunnel is
// being let go of is not served, and letting go waits for those that are.
func TestStreamCountLetsNoStreamOutliveItsTunnel(t *testing.T) {
	streams := &streamCount{idle: make(chan struct{})}
	if !streams.enter() || !streams.enter() {
		t.Fatal("a stream was turned away from an open tunnel")
	}
	waited := make(chan struct{})
	go func() {
		streams.wait()
		close(waited)
	}()
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(time.Millisecond) {
		streams.mu.Lock()
		closed := streams.closed
		streams.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the tunnel never began to be let go of")
		}
	}
	if streams.enter() {
		t.Fatal("a stream began on a tunnel that is being let go of")
	}
	streams.leave()
	select {
	case <-waited:
		t.Fatal("the tunnel was let go of with a stream still served")
	case <-time.After(20 * time.Millisecond):
	}
	streams.leave()
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("the tunnel was never let go of")
	}
	(&streamCount{idle: make(chan struct{})}).wait()
}

// A tunnel's connection that ends without a request is let go of at once.
func TestAnHTTP2TunnelWithNoStreamsEndsWithItsConnection(t *testing.T) {
	rig, _ := newConnectRig(t, leakModeCensor)
	raw := rig.connectAs(t, cursorStreamHost, nil)
	conn := tls.Client(raw, &tls.Config{ServerName: cursorStreamHost, RootCAs: rig.phaseRoots, NextProtos: []string{"h2"}})
	if err := conn.Handshake(); err != nil || conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("the handshake: %v, %q", err, conn.ConnectionState().NegotiatedProtocol)
	}
	_ = conn.Close()
	_ = raw.(net.Conn).Close()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		rig.proxy.mu.Lock()
		held := len(rig.proxy.hijacked)
		rig.proxy.mu.Unlock()
		if held == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d tunnels are still held after their client left", held)
		}
	}
}

// The live harness measures a Connect stream message by message: the verifier
// looks in what goes on to the service, inflated where it is compressed. A
// message gets a line when a registered value was sent in it, when the proxy
// found something in it, or when it was not read; the rest are counted.
func TestLiveMeterMeasuresStreamMessages(t *testing.T) {
	for mode, want := range map[string][]string{
		leakModeCensor: {
			"request host=agentn.global.api5.cursor.sh path=/agent.v1.AgentService/Run conversation=true bytes=N replaced=1 seen=stripe-key missed= expected_missed= protocol=http2 micros=N",
			"request host=agentn.global.api5.cursor.sh path=/agent.v1.AgentService/Run conversation=true bytes=N replaced=1 seen=database-url missed= expected_missed= protocol=http2 micros=N",
			// A piece of a value the matcher cannot be sure of got through,
			// and the line says so.
			"request host=agentn.global.api5.cursor.sh path=/agent.v1.AgentService/Run conversation=true bytes=N replaced=0 seen=stripe-key missed=stripe-key expected_missed= protocol=http2 micros=N",
			"request host=agentn.global.api5.cursor.sh path=/agent.v1.AgentService/Run conversation=true bytes=N replaced=0 seen=admin-pin missed= expected_missed=admin-pin protocol=http2 micros=N",
			"request host=agentn.global.api5.cursor.sh path=/agent.v1.AgentService/Run conversation=true bytes=N replaced=0 seen= missed= expected_missed= protocol=http2 micros=N unread=message_undecodable",
			"request host=agentn.global.api5.cursor.sh path=/agent.v1.AgentService/Run conversation=true bytes=N replaced=0 seen= missed= expected_missed= protocol=http2 micros=N unread=message_flags_unexpected",
			"request host=api2.cursor.sh path=/aiserver.v1.InferenceService/RunInference conversation=true bytes=N replaced=1 seen=stripe-key missed= expected_missed= protocol=http micros=N",
			"summary requests_with_body=9 conversation_requests=9 requests_rewritten=3 requests_blocked=0 websocket_messages=0",
			"summary ids_seen=3 seen=admin-pin,database-url,stripe-key",
			"summary ids_missed=1 missed=stripe-key",
			"summary ids_expected_missed=1 expected_missed=admin-pin",
			"summary inventory_hits=3 rule_hits=0 rule_redactions=0 rule_alerts=0 signed_findings=0",
			"summary unread message_flags_unexpected=1 message_undecodable=1",
			"summary bypass none",
			"summary inspect_micros p50=N max=N inspected=7",
			"summary stream_messages=8 listed=6",
		},
		leakModeObserve: {
			"request host=agentn.global.api5.cursor.sh path=/agent.v1.AgentService/Run conversation=true bytes=N replaced=0 seen=stripe-key missed=stripe-key expected_missed= protocol=http2 micros=N",
			"request host=agentn.global.api5.cursor.sh path=/agent.v1.AgentService/Run conversation=true bytes=N replaced=0 seen=database-url missed=database-url expected_missed= protocol=http2 micros=N",
			"request host=agentn.global.api5.cursor.sh path=/agent.v1.AgentService/Run conversation=true bytes=N replaced=0 seen=stripe-key missed=stripe-key expected_missed= protocol=http2 micros=N",
			"request host=agentn.global.api5.cursor.sh path=/agent.v1.AgentService/Run conversation=true bytes=N replaced=0 seen=admin-pin missed= expected_missed=admin-pin protocol=http2 micros=N",
			"request host=agentn.global.api5.cursor.sh path=/agent.v1.AgentService/Run conversation=true bytes=N replaced=0 seen= missed= expected_missed= protocol=http2 micros=N unread=message_undecodable",
			"request host=agentn.global.api5.cursor.sh path=/agent.v1.AgentService/Run conversation=true bytes=N replaced=0 seen= missed= expected_missed= protocol=http2 micros=N unread=message_flags_unexpected",
			"request host=api2.cursor.sh path=/aiserver.v1.InferenceService/RunInference conversation=true bytes=N replaced=0 seen=stripe-key missed=stripe-key expected_missed= protocol=http micros=N",
			"summary requests_with_body=9 conversation_requests=9 requests_rewritten=0 requests_blocked=0 websocket_messages=0",
			"summary ids_seen=3 seen=admin-pin,database-url,stripe-key",
			"summary ids_missed=2 missed=database-url,stripe-key",
			"summary ids_expected_missed=1 expected_missed=admin-pin",
			"summary inventory_hits=3 rule_hits=0 rule_redactions=0 rule_alerts=0 signed_findings=0",
			"summary unread message_flags_unexpected=1 message_undecodable=1",
			"summary bypass none",
			"summary inspect_micros p50=N max=N inspected=7",
			"summary stream_messages=8 listed=6",
		},
	} {
		rig, _ := newConnectRig(t, mode)
		values := []liveValue{
			{ID: "stripe-key", Type: "secret", Value: leakSecretOne},
			{ID: "database-url", Type: "sealed", Value: leakSecretTwo},
			// Too short to protect: it is expected to get through.
			{ID: "admin-pin", Type: "secret", Value: "hunter2!"},
		}
		entries, _ := liveRegister(t, rig.guard, values)
		output := &lockedBuffer{}
		meter := newLiveMeter(&liveOutput{w: output}, rig.guard, entries)
		rig.proxy.observe = meter.observe

		stream := openConnectStream(t, rig.clientOffering(rig.phaseRoots, false, true), "live", map[string]string{"Connect-Content-Encoding": "gzip"})
		first := agentMessage("the key is " + leakSecretOne)
		for _, envelope := range [][]byte{
			connectEnvelope(0, agentMessage("list the files")),
			connectEnvelope(0, first),
			connectEnvelope(connectCompressed, gzipBytes(t, agentMessage("the url is "+leakSecretTwo))),
			connectEnvelope(connectCompressed, gzipBytes(t, agentMessage("nothing in this one"))),
			connectEnvelope(0, agentMessage("it ends in "+liveFragment)),
			connectEnvelope(0, agentMessage("the pin is hunter2!")),
			connectEnvelope(connectCompressed, agentMessage("marked as gzip, and not gzip")),
			connectEnvelope(connectEndStream, []byte(`{}`)),
		} {
			stream.send(envelope)
			if _, err := stream.answer(); err != nil {
				t.Fatal(err)
			}
		}
		stream.end()
		postConnect(t, rig.clientOffering(rig.phaseRoots, true, false), "https://"+cursorAPIHost+cursorUnaryPath, "application/proto", first, nil)

		meter.finish()
		printed := strings.Split(strings.TrimRight(string(output.bytes()), "\n"), "\n")
		printed = append(printed, meter.summary()...)
		if got := liveNormalised(printed); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s mode:\n%s\nwant:\n%s", mode, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
		// A message goes on exactly as long as it came, whatever was
		// overwritten in it; one that was not read is not measured.
		if !strings.Contains(printed[0], fmt.Sprintf(" bytes=%d ", len(first))) || !strings.Contains(printed[4], " bytes=0 ") {
			t.Fatalf("%s mode: the sizes: %s | %s", mode, printed[0], printed[4])
		}
		everything := strings.Join(printed, "\n")
		for _, value := range values {
			if strings.Contains(everything, value.Value) {
				t.Fatalf("%s mode: what the harness printed holds the value of %s", mode, value.ID)
			}
		}
	}
}

// Cursor's unary calls offer no protocol in their TLS hello at all, send
// "Connection: close", and send some bodies in chunks. Such a client is served
// over HTTP/1.1 on the same host that also answers HTTP/2.
func TestCursorClientsThatOfferNoProtocolSpeakHTTP1(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	message := agentMessage("the key is " + leakSecretOne)
	want := bytes.Replace(message, []byte(leakSecretOne), []byte(overwritten("ph:secret:stripe", len(leakSecretOne))), 1)
	for name, framing := range map[string]func([]byte) string{
		"a stated length": func(body []byte) string { return fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body) },
		"chunks": func(body []byte) string {
			return fmt.Sprintf("Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n%x\r\n%s\r\n0\r\n\r\n", 9, body[:9], len(body)-9, body[9:])
		},
	} {
		conn := tls.Client(rig.connectAs(t, cursorAPIHost, nil), &tls.Config{ServerName: cursorAPIHost, RootCAs: rig.phaseRoots, MinVersion: tls.VersionTLS12})
		if err := conn.Handshake(); err != nil || conn.ConnectionState().NegotiatedProtocol != "" {
			t.Fatalf("%s: the handshake: %v, protocol %q", name, err, conn.ConnectionState().NegotiatedProtocol)
		}
		request := "POST " + cursorUnaryPath + " HTTP/1.1\r\nHost: " + cursorAPIHost + "\r\nContent-Type: application/proto\r\nConnect-Protocol-Version: 1\r\nConnection: close\r\n" + framing(message)
		response, answer := exchange(t, conn, bufio.NewReader(conn), request)
		_ = conn.Close()
		call := service.last(t)
		if response.StatusCode != http.StatusOK || !bytes.Equal(answer, protoBytesField(nil, 1, []byte("answer"))) || !bytes.Equal(call.body, want) || call.header.Get("Connection") != "" {
			t.Fatalf("%s: status %d, the body arrived as %q", name, response.StatusCode, call.body)
		}
	}
}

// Trailers a client announced for its request reach the service once the
// request's stream has ended.
func TestCursorStreamRequestTrailersAreForwarded(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	client := rig.clientOffering(rig.phaseRoots, false, true)
	reader, writer := io.Pipe()
	request, _ := http.NewRequest(http.MethodPost, "https://"+cursorStreamHost+cursorStreamPath, reader)
	request.Header.Set("Content-Type", "application/connect+proto")
	request.Header.Set("X-Stream-Id", "trailers")
	request.Trailer = http.Header{"X-Request-Checksum": nil}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := writer.Write(connectEnvelope(0, agentMessage("one message"))); err != nil {
		t.Fatal(err)
	}
	request.Trailer.Set("X-Request-Checksum", "abc123")
	_ = writer.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	call := service.waitFor(t, "the stream's end", func(call *connectCall) bool { return call.header.Get("X-Stream-Id") == "trailers" && call.ended })
	if call.trailer.Get("X-Request-Checksum") != "abc123" || len(call.envelopes) != 1 {
		t.Fatalf("the request's trailers at the service: %v", call.trailer)
	}
}

// The policy's row for protobuf: what is found is overwritten where it sits,
// the same whether the bytes come as a call's body or as a message of a
// stream, compressed or not, and nothing found in them stops the request. A
// value in the URL or in a header of such a call keeps the rules those have.
func TestProtobufMeetsTheSameEndAsABodyAndAsAMessage(t *testing.T) {
	if rule := leakPartRules[leakPartProtobuf]; !rule.read || !rule.rewrite || rule.block {
		t.Fatalf("the row for protobuf: %+v", rule)
	}
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	client := rig.clientOffering(rig.phaseRoots, false, true)
	token := phaseServiceToken()
	padded := overwritten("ph:secret:stripe", len(leakSecretOne))
	for _, c := range []struct {
		name          string
		payload, want []byte
	}{
		{"a value in a message", agentMessage("key " + leakSecretOne), agentMessage("key " + padded)},
		{"a value alone in a field", protoBytesField(nil, 2, []byte(leakSecretOne)), protoBytesField(nil, 2, []byte(padded))},
		{"a Phase token in a message", agentMessage("token " + token), nil},
		// Bytes that would stop the request anywhere else.
		{"a value in bytes that are no message", append([]byte{0xff, 0x00, 0xfe}, leakSecretOne...), append([]byte{0xff, 0x00, 0xfe}, padded...)},
		{"a message with nothing in it", agentMessage("nothing to see"), agentMessage("nothing to see")},
		{"bytes with nothing in them", []byte{0xff, 0x00, 0xfe, 0x01}, []byte{0xff, 0x00, 0xfe, 0x01}},
	} {
		check := func(how string, got []byte) {
			t.Helper()
			switch {
			case len(got) != len(c.payload):
				t.Fatalf("%s, %s: %d bytes arrived for %d sent", c.name, how, len(got), len(c.payload))
			case c.want != nil && !bytes.Equal(got, c.want):
				t.Fatalf("%s, %s: arrived as %q, want %q", c.name, how, got, c.want)
			case c.want == nil && (bytes.Contains(got, []byte(token)) || !bytes.Contains(got, []byte("ph:phase_service_token:"))):
				t.Fatalf("%s, %s: the token was not overwritten: %q", c.name, how, got)
			}
		}
		target := "https://" + cursorAPIHost + cursorUnaryPath
		response, _ := postConnect(t, client, target, "application/proto", c.payload, nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s, as a body: status %d", c.name, response.StatusCode)
		}
		check("as a body", service.last(t).body)
		postConnect(t, client, target, "application/proto", gzipBytes(t, c.payload), map[string]string{"Content-Encoding": "gzip"})
		check("as a gzip body", gunzipBytes(t, service.last(t).body))

		stream := openConnectStream(t, client, c.name, map[string]string{"Connect-Content-Encoding": "gzip"})
		stream.send(connectEnvelope(0, c.payload))
		stream.send(connectEnvelope(connectCompressed, gzipBytes(t, c.payload)))
		stream.end()
		envelopes := service.stream(t, c.name, 2).envelopes
		check("as a message", envelopes[0][connectEnvelopePrefix:])
		check("as a compressed message", gunzipBytes(t, envelopes[1][connectEnvelopePrefix:]))
	}

	// The URL of a call: a known value there stops it, as on any host.
	before := service.count()
	response, _ := postConnect(t, client, "https://"+cursorAPIHost+cursorUnaryPath+"?key="+url.QueryEscape(leakSecretOne), "application/proto", agentMessage("hello"), nil)
	if response.StatusCode != http.StatusForbidden || response.Header.Get("X-Phase-Error-Code") != codeSecretInRequest || service.count() != before {
		t.Fatalf("a known value in the URL of a call: status %d", response.StatusCode)
	}
	request, _ := http.NewRequest(http.MethodPost, "https://"+cursorStreamHost+cursorStreamPath+"?key="+url.QueryEscape(leakSecretOne), bytes.NewReader(connectEnvelope(0, agentMessage("hello"))))
	request.Header.Set("Content-Type", "application/connect+proto")
	if status := doRequest(t, client, request); status != http.StatusForbidden || service.count() != before {
		t.Fatalf("a known value in the URL of a stream: status %d", status)
	}
	// A header: reported, and the call goes out as it was.
	response, _ = postConnect(t, client, "https://"+cursorAPIHost+cursorUnaryPath, "application/proto", agentMessage("hello"), map[string]string{"X-Note": leakSecretOne})
	if response.StatusCode != http.StatusOK || service.last(t).header.Get("X-Note") != leakSecretOne {
		t.Fatalf("a known value in a header of a call: status %d", response.StatusCode)
	}
}

// A message of a JSON stream that is not text does not stop the stream: the
// value in it is overwritten where it sits, and the stream goes on.
func TestCursorJSONStreamMessageThatIsNotTextIsOverwrittenInPlace(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	stream := openConnectStream(t, rig.clientOffering(rig.phaseRoots, false, true), "json", map[string]string{"Content-Type": "application/connect+json"})
	first := connectEnvelope(0, []byte(`{"text":"the key is `+leakSecretOne+`"}`))
	stream.send(first)
	if _, err := stream.answer(); err != nil {
		t.Fatal(err)
	}
	stream.send(connectEnvelope(0, append([]byte{0xff, 0x00}, leakSecretOne...)))
	if answer, err := stream.answer(); err != nil {
		t.Fatalf("the stream did not go on after a message that is not text: %q, %v", answer, err)
	}
	stream.send(first)
	stream.end()
	call := service.waitFor(t, "the stream's end", func(call *connectCall) bool { return call.header.Get("X-Stream-Id") == "json" && call.ended })
	replaced := connectEnvelope(0, []byte(`{"text":"the key is ph:secret:stripe"}`))
	inPlace := connectEnvelope(0, append([]byte{0xff, 0x00}, overwritten("ph:secret:stripe", len(leakSecretOne))...))
	if len(call.envelopes) != 3 || !bytes.Equal(call.envelopes[0], replaced) || !bytes.Equal(call.envelopes[1], inPlace) || !bytes.Equal(call.envelopes[2], replaced) {
		t.Fatalf("the service got %q", call.envelopes)
	}
	for _, event := range rig.leakEventsNow() {
		if event.ProxyDecision == "block" {
			t.Fatalf("something in a message stopped the stream: %+v", event)
		}
	}
}

// Streams that ended, were given up, or broke off leave nothing running in
// the proxy once their tunnel is let go of.
func TestCursorStreamsLeaveNoGoroutineBehind(t *testing.T) {
	rig, service := newConnectRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	settled := func() int {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
		return runtime.NumGoroutine()
	}
	release := func() {
		rig.proxy.CloseHijacked()
		rig.proxy.transport.(*http.Transport).CloseIdleConnections()
	}
	// One call first, so that what the rig keeps for itself from then on (its
	// connection to the stand-in for the Console) is there before anything is
	// counted. Everything the test starts after that is closed again below,
	// so what is left over is the proxy's.
	unary := rig.clientOffering(rig.phaseRoots, true, false)
	postConnect(t, unary, "https://"+cursorAPIHost+cursorUnaryPath, "application/proto", agentMessage("the key is "+leakSecretOne), map[string]string{"Connection": "close"})
	rig.leakEvents(1)
	release()
	before := settled()
	client := rig.clientOffering(rig.phaseRoots, false, true)
	message := connectEnvelope(0, agentMessage("the key is "+leakSecretOne))
	var open []*openStream
	for i := 0; i < 12; i++ {
		stream := openConnectStream(t, client, fmt.Sprint("stream-", i), nil)
		stream.send(message)
		if _, err := stream.answer(); err != nil {
			t.Fatal(err)
		}
		switch i % 3 {
		case 0:
			stream.end()
		case 1:
			stream.abandon()
		default:
			// Left open: its tunnel goes away under it.
			open = append(open, stream)
		}
	}
	service.mu.Lock()
	service.breakAfter = 1
	service.mu.Unlock()
	broken := openConnectStream(t, client, "broken", nil)
	broken.send(message)
	if _, err := broken.answer(); err == nil {
		t.Fatal("a stream the service broke off answered")
	}
	postConnect(t, unary, "https://"+cursorAPIHost+cursorUnaryPath, "application/proto", agentMessage("hello"), map[string]string{"Connection": "close"})

	release()
	for _, stream := range open {
		stream.abandon()
	}
	client.Transport.(*http.Transport).CloseIdleConnections()
	for deadline := time.Now().Add(10 * time.Second); ; {
		after := settled()
		if after <= before {
			return
		}
		if time.Now().After(deadline) {
			stacks := make([]byte, 1<<20)
			t.Fatalf("%d goroutines before, %d after:\n%s", before, after, stacks[:runtime.Stack(stacks, true)])
		}
	}
}
