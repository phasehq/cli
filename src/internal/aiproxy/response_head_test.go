package aiproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

var errHandshakeRefused = errors.New("attack attempt detected")

// readHeadAsTungstenite reads a response head under the limits of Codex's
// WebSocket client: 65536 bytes, 512 reads, 128 bytes a read past the 64th.
func readHeadAsTungstenite(connection io.Reader) (head, tail []byte, reads int, err error) {
	var received []byte
	chunk := make([]byte, 4096)
	for {
		n, readErr := connection.Read(chunk)
		if n == 0 {
			if readErr == nil {
				continue
			}
			return nil, nil, reads, readErr
		}
		reads++
		received = append(received, chunk[:n]...)
		if len(received) > 65536 || reads > 512 || (reads > 64 && reads*128 > len(received)) {
			return nil, nil, reads, errHandshakeRefused
		}
		if end := bytes.Index(received, []byte("\r\n\r\n")); end >= 0 {
			return received[:end+4], received[end+4:], reads, nil
		}
	}
}

// codexUpgradeAnswer is the head chatgpt.com answers Codex's upgrade with:
// its header names and the lengths of their values, on top of the handshake's.
func codexUpgradeAnswer() http.Header {
	header := http.Header{}
	for name, length := range map[string]int{
		"Cf-Cache-Status": 7, "Cf-Ray": 20, "Cross-Origin-Opener-Policy": 24, "Date": 29, "Nel": 63, "Referrer-Policy": 31,
		"Report-To": 229, "Server": 10, "Strict-Transport-Security": 44, "X-Codex-Websocket-Max-Message-Bytes": 9,
		"X-Content-Type-Options": 7, "X-Models-Etag": 36, "X-Oai-Request-Id": 36, "X-Openai-Proxy-Wasm": 4,
	} {
		header.Set(name, strings.Repeat("v", length))
	}
	return header
}

// Codex's WebSocket client gives up on an upgrade whose answer reaches it in
// small pieces, so the answer the service gave has to arrive in one.
func TestWebSocketUpgradeAnswerReachesAClientThatCountsItsReads(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	fromClient := make(chan wsMessage, 1)
	rig.upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		answer := codexUpgradeAnswer()
		answer.Set("Connection", "upgrade")
		answer.Set("Upgrade", "websocket")
		answer.Set("Sec-WebSocket-Accept", webSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
		_, _ = io.WriteString(buffered, "HTTP/1.1 101 Switching Protocols\r\n")
		_ = answer.Write(buffered)
		_, _ = io.WriteString(buffered, "\r\n")
		// The service's first frame leaves with its answer.
		_, _ = buffered.Write([]byte{0x80 | wsOpText, 5, 'h', 'e', 'l', 'l', 'o'})
		_ = buffered.Flush()
		if _, opcode, payload, err := readFrame(buffered.Reader); err == nil {
			fromClient <- wsMessage{opcode: opcode, payload: payload}
		}
		_, _ = io.Copy(io.Discard, buffered)
	})
	conn := connectThroughProxy(t, rig, "chatgpt.com", rig.phaseRoots)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\nSec-WebSocket-Key: %s\r\n\r\n", codexSocketPath, key)

	// A read of a TLS connection returns one record, so the reads counted are
	// the writes the proxy made.
	head, tail, reads, err := readHeadAsTungstenite(conn)
	if err != nil {
		t.Fatalf("the client gave up on the answer after %d reads: %v", reads, err)
	}
	if reads != 1 {
		t.Fatalf("the answer took %d reads", reads)
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(head)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols || response.Header.Get("Sec-WebSocket-Accept") != webSocketAccept(key) ||
		!strings.EqualFold(response.Header.Get("Upgrade"), "websocket") || !headerContainsToken(response.Header, "Connection", "upgrade") {
		t.Fatalf("the answer: %d %v", response.StatusCode, response.Header)
	}
	for name, values := range codexUpgradeAnswer() {
		if !reflect.DeepEqual(response.Header.Values(name), values) {
			t.Fatalf("the service's %s did not reach the client", name)
		}
	}

	// Both directions carry frames after it, starting with what the service
	// sent along with its answer.
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(tail), conn))
	if _, opcode, payload, err := readFrame(reader); err != nil || opcode != wsOpText || string(payload) != "hello" {
		t.Fatalf("the service's first frame: %d %q %v", opcode, payload, err)
	}
	if _, err := conn.Write(clientFrame(true, wsOpText, []byte(`{"type":"response.create"}`))); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-fromClient:
		if message.opcode != wsOpText || string(message.payload) != `{"type":"response.create"}` {
			t.Fatalf("the service got %d %q", message.opcode, message.payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the client's message did not reach the service")
	}
}

// A service that refuses the upgrade says why in an ordinary response, and
// the same client has to be able to read that too: a 401 is its cue to log in.
func TestRefusedWebSocketUpgradeReachesAClientThatCountsItsReads(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	const refusal = `{"detail":"the token is expired"}`
	rig.upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, values := range codexUpgradeAnswer() {
			w.Header()[name] = values
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Www-Authenticate", "Bearer")
		w.Header().Add("Set-Cookie", "a=b; Path=/; Secure; HttpOnly")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, refusal)
	})
	conn := connectThroughProxy(t, rig, "chatgpt.com", rig.phaseRoots)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n", codexSocketPath, key)
	head, tail, reads, err := readHeadAsTungstenite(conn)
	if err != nil {
		t.Fatalf("the client gave up on the refusal after %d reads: %v", reads, err)
	}
	if reads != 1 {
		t.Fatalf("the refusal's head took %d reads", reads)
	}
	response, err := http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(head), bytes.NewReader(tail), conn)), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusUnauthorized || string(body) != refusal {
		t.Fatalf("the refusal: %d %q %v", response.StatusCode, body, err)
	}
}

// recordedWrites keeps each write it is given apart.
type recordedWrites struct {
	writes []string
	fail   error
}

func (r *recordedWrites) Write(data []byte) (int, error) {
	if r.fail != nil {
		return 0, r.fail
	}
	r.writes = append(r.writes, string(data))
	return len(data), nil
}

// The head goes out whole however it was written, and nothing after it is
// held: a streamed body reaches the client as each piece of it is written.
func TestHeadWriterSendsTheHeadWholeAndTheBodyAsItComes(t *testing.T) {
	for name, c := range map[string]struct {
		written []string
		want    []string
	}{
		"a head in pieces, then a body": {
			written: []string{"HTTP/1.1 200 OK\r\n", "Content-Type", ": ", "text/event-stream", "\r\n", "\r\n", "data: 1\n\n", "data: 2\n\n"},
			want:    []string{"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n", "data: 1\n\n", "data: 2\n\n"},
		},
		"the blank line split between writes": {
			written: []string{"HTTP/1.1 204 No Content\r\nA: b\r", "\n\r", "\n", "next"},
			want:    []string{"HTTP/1.1 204 No Content\r\nA: b\r\n\r\n", "next"},
		},
		"the start of the body in the write that ends the head": {
			written: []string{"HTTP/1.1 200 OK\r\n", "\r\nbody", " more"},
			want:    []string{"HTTP/1.1 200 OK\r\n\r\nbody", " more"},
		},
		"a blank line in the body": {
			written: []string{"HTTP/1.1 200 OK\r\n\r\n", "a\r\n\r\n", "b"},
			want:    []string{"HTTP/1.1 200 OK\r\n\r\n", "a\r\n\r\n", "b"},
		},
	} {
		client := &recordedWrites{}
		writer := &headWriter{client: client}
		for _, piece := range c.written {
			if n, err := writer.Write([]byte(piece)); n != len(piece) || err != nil {
				t.Fatalf("%s: writing %q: %d %v", name, piece, n, err)
			}
		}
		if err := writer.flush(); err != nil || !reflect.DeepEqual(client.writes, c.want) {
			t.Fatalf("%s: the client was written %q, %v", name, client.writes, err)
		}
	}

	// A head that never ends is still sent, and a client that is gone is an
	// error to whoever writes the response.
	client := &recordedWrites{}
	writer := &headWriter{client: client}
	_, _ = writer.Write([]byte("HTTP/1.1 200 OK\r\n"))
	if err := writer.flush(); err != nil || !reflect.DeepEqual(client.writes, []string{"HTTP/1.1 200 OK\r\n"}) {
		t.Fatalf("a head cut short: %q %v", client.writes, err)
	}
	gone := errors.New("the client is gone")
	response := &http.Response{StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"A": {"b"}}, Body: http.NoBody}
	if err := writeTunnelResponse(&recordedWrites{fail: gone}, response); !errors.Is(err, gone) {
		t.Fatalf("writing to a client that is gone: %v", err)
	}
}
