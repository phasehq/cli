package aiproxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/censortest"
	"github.com/phasehq/cli/internal/leakguard"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// receivedRequest is what the fake model provider saw.
type receivedRequest struct {
	host, path, rawQuery string
	header               http.Header
	body                 []byte
	// wire is the connection that carried the request.
	wire *wireConn
}

// leakRig is the real proxy in front of a fake model provider: every name the
// proxy dials reaches the provider, which answers with a certificate of its
// own CA for whatever name the client asked for. A client that gets the
// provider's certificate went through a raw tunnel; one that gets Phase's was
// read by the proxy.
type leakRig struct {
	t             *testing.T
	guard         *leakGuard
	proxy         *httpProxy
	proxyURL      *url.URL
	phaseRoots    *x509.CertPool
	providerRoots *x509.CertPool
	// bothRoots trusts Phase and the provider: a client that has talked to
	// the provider itself and is then read by the proxy.
	bothRoots *x509.CertPool
	events    *eventBuffer
	// provider is the fake model provider, and wire what each connection to it
	// carried before any TLS: the tests of hosts whose hello is copied read
	// the hellos it was sent.
	provider *httptest.Server
	wire     *wireLog

	mu        sync.Mutex
	received  []receivedRequest
	shipped   []agentapi.Event
	shippedJS [][]byte
	upstream  http.Handler
}

func newLeakRig(t *testing.T, mode string) *leakRig {
	t.Helper()
	return newLeakRigWith(t, mode, nil)
}

// newLeakRigWith lets a test change the fake provider before it starts.
func newLeakRigWith(t *testing.T, mode string, configure func(provider *httptest.Server)) *leakRig {
	t.Helper()
	rig := &leakRig{t: t, guard: newTestLeakGuard(t, mode), wire: &wireLog{}}

	phaseCA, phasePEM, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rig.phaseRoots = x509.NewCertPool()
	rig.phaseRoots.AppendCertsFromPEM(phasePEM)
	providerCA, providerPEM, _, err := phaseproxy.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rig.providerRoots = x509.NewCertPool()
	rig.providerRoots.AppendCertsFromPEM(providerPEM)
	rig.bothRoots = x509.NewCertPool()
	rig.bothRoots.AppendCertsFromPEM(phasePEM)
	rig.bothRoots.AppendCertsFromPEM(providerPEM)

	provider := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.mu.Lock()
		handler := rig.upstream
		rig.mu.Unlock()
		if handler != nil && (r.Header.Get("Upgrade") != "" || r.Header.Get("X-Test-Handler") != "") {
			handler.ServeHTTP(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		wire, _ := r.Context().Value(wireKey{}).(*wireConn)
		rig.mu.Lock()
		rig.received = append(rig.received, receivedRequest{host: r.Host, path: r.URL.Path, rawQuery: r.URL.RawQuery, header: r.Header.Clone(), body: body, wire: wire})
		rig.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"message","content":[]}`)
	}))
	provider.Config.ConnContext = keepWire
	provider.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return providerCA.CertificateForHost(hello.ServerName)
	}}
	provider.Listener = &wireListener{Listener: provider.Listener, log: rig.wire}
	if configure != nil {
		configure(provider)
	}
	provider.StartTLS()
	t.Cleanup(provider.Close)
	rig.provider = provider
	providerAddress := provider.Listener.Addr().String()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, providerAddress)
	}

	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/events/") {
			body, _ := io.ReadAll(r.Body)
			var batch agentapi.EventBatchRequest
			_ = json.Unmarshal(body, &batch)
			rig.mu.Lock()
			rig.shipped = append(rig.shipped, batch.Events...)
			rig.shippedJS = append(rig.shippedJS, body)
			rig.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(console.Close)
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := selectionState(t)
	state.hints = &hintLog{}
	state.client = client
	rig.events, err = newEventBuffer(state, 5*time.Millisecond, t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: rig.providerRoots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	rig.proxy = &httpProxy{
		state: state, ca: phaseCA, transport: transport, dial: dial, events: rig.events, leak: rig.guard,
		control: &controlHandler{state: state, leak: rig.guard},
	}
	server := httptest.NewServer(rig.proxy)
	t.Cleanup(func() {
		rig.proxy.CloseHijacked()
		server.Close()
		_ = rig.events.Stop()
	})
	rig.proxyURL, _ = url.Parse(server.URL)
	rig.proxyURL.User = url.UserPassword("phase", "runtime-test")
	return rig
}

// client goes through the proxy and trusts roots.
func (r *leakRig) client(roots *x509.CertPool) *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyURL(r.proxyURL),
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ExpectContinueTimeout: 10 * time.Second,
	}
	r.t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func (r *leakRig) lastReceived() receivedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.received) == 0 {
		r.t.Fatal("the provider received nothing")
	}
	return r.received[len(r.received)-1]
}

func (r *leakRig) receivedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.received)
}

// leakEvents waits for the shipped leak protection events.
func (r *leakRig) leakEvents(want int) []agentapi.Event {
	r.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		r.mu.Lock()
		var events []agentapi.Event
		for _, event := range r.shipped {
			if event.EventType == leakEventType {
				events = append(events, event)
			}
		}
		r.mu.Unlock()
		if len(events) >= want || time.Now().After(deadline) {
			if len(events) < want {
				r.t.Fatalf("%d leak protection events shipped, want %d", len(events), want)
			}
			return events
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (r *leakRig) shippedPayloads() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Join(r.shippedJS, []byte("\n"))
}

func anthropicBody(content string) []byte {
	body, _ := json.Marshal(map[string]any{
		"model": "claude-test", "max_tokens": 1024, "stream": false,
		"messages": []any{
			map[string]any{"role": "user", "content": "read the config"},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "toolu_01", "content": content}}},
		},
	})
	return body
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func gunzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func postMessages(t *testing.T, client *http.Client, target string, body []byte, encoding string) *http.Response {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Api-Key", "harness-login-value")
	if encoding != "" {
		request.Header.Set("Content-Encoding", encoding)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return response
}

func TestLeakProtectionRewritesAGzipAnthropicBodyAndNothingElse(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne, "db": leakSecretTwo})
	content := "STRIPE_KEY=" + leakSecretOne + "\nDATABASE_URL=" + leakSecretTwo + "\nLOG_LEVEL=debug\n"
	original := anthropicBody(content)
	response := postMessages(t, rig.client(rig.phaseRoots), "https://api.anthropic.com/v1/messages?beta=true", gzipBytes(t, original), "gzip")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	received := rig.lastReceived()
	if received.header.Get("Content-Encoding") != "gzip" || received.header.Get("X-Api-Key") != "harness-login-value" || received.rawQuery != "beta=true" {
		t.Fatalf("the request changed beyond its body: %v", received.header)
	}
	decoded := gunzipBytes(t, received.body)
	want := bytes.Replace(original, []byte(leakSecretOne), []byte("ph:secret:stripe"), 1)
	// The URL holds a slash, which JSON escapes nowhere here.
	want = bytes.Replace(want, []byte(leakSecretTwo), []byte("ph:secret:db"), 1)
	if !bytes.Equal(decoded, want) {
		t.Fatalf("the body is not the original with placeholders:\n%s\n%s", decoded, want)
	}
	events := rig.leakEvents(1)
	event := events[0]
	if event.Outcome != outcomeCensored || event.ProxyDecision != "allow" || event.Host != "api.anthropic.com" || event.Path != "/v1/messages" ||
		event.Detail["harness"] != "claude" || event.Detail["mode"] != "censor" || event.Detail["inventoryHits"] != float64(2) {
		t.Fatalf("event: %+v", event)
	}
	placeholders := strings.Split(event.Detail["placeholders"].(string), ",")
	sort.Strings(placeholders)
	if strings.Join(placeholders, ",") != "ph:secret:db,ph:secret:stripe" {
		t.Fatalf("placeholders: %v", placeholders)
	}
	shipped := rig.shippedPayloads()
	for _, value := range []string{leakSecretOne, leakSecretTwo, "harness-login-value"} {
		if bytes.Contains(shipped, []byte(value)) {
			t.Fatal("an event carries a value")
		}
	}
}

func TestLeakProtectionLeavesACleanBodyByteIdenticalAndSilent(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	// Odd spacing and escapes that a re-serialiser would change.
	original := []byte("{\"model\" : \"m\",\n \"messages\":[{\"role\":\"user\",\"content\":\"caf\\u00e9 \\/ ok\"}] }")
	compressed := gzipBytes(t, original)
	postMessages(t, rig.client(rig.phaseRoots), "https://api.anthropic.com/v1/messages", compressed, "gzip")
	if received := rig.lastReceived(); !bytes.Equal(received.body, compressed) {
		t.Fatal("a body with nothing to change did not reach the provider byte for byte")
	}
	time.Sleep(30 * time.Millisecond)
	rig.mu.Lock()
	shipped := len(rig.shipped)
	rig.mu.Unlock()
	if shipped != 0 {
		t.Fatal("a clean request produced an event")
	}
}

func TestLeakProtectionRewritesAZstdBody(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	original := []byte(`{"model":"gpt","input":[{"role":"user","content":[{"type":"input_text","text":"key ` + leakSecretOne + `"}]}]}`)
	encoder, _ := zstd.NewWriter(nil)
	compressed := encoder.EncodeAll(original, nil)
	_ = encoder.Close()
	postMessages(t, rig.client(rig.phaseRoots), "https://chatgpt.com/backend-api/codex/responses", compressed, "zstd")
	received := rig.lastReceived()
	if received.header.Get("Content-Encoding") != "zstd" {
		t.Fatal("the encoding changed")
	}
	decoder, _ := zstd.NewReader(nil)
	defer decoder.Close()
	decoded, err := decoder.DecodeAll(received.body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := bytes.Replace(original, []byte(leakSecretOne), []byte("ph:secret:stripe"), 1); !bytes.Equal(decoded, want) {
		t.Fatalf("zstd body: %s", decoded)
	}
	// Outside /backend-api/ the same host is forwarded unread.
	postMessages(t, rig.client(rig.phaseRoots), "https://chatgpt.com/other", original, "")
	if received := rig.lastReceived(); !bytes.Equal(received.body, original) {
		t.Fatal("a path outside the rule was read")
	}
}

func TestLeakProtectionBlocksASecretInTheURL(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	request, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages?key="+url.QueryEscape(leakSecretOne), bytes.NewReader(anthropicBody("hello")))
	request.Header.Set("Content-Type", "application/json")
	response, err := rig.client(rig.phaseRoots).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || response.Header.Get("X-Phase-Error-Code") != codeSecretInRequest ||
		!strings.Contains(string(body), `"code":"secret_in_request"`) || strings.Contains(string(body), leakSecretOne) {
		t.Fatalf("not blocked: %d %s", response.StatusCode, body)
	}
	if rig.receivedCount() != 0 {
		t.Fatal("the blocked request reached the provider")
	}
	event := rig.leakEvents(1)[0]
	if event.ProxyDecision != "block" || event.Outcome != "denied" || event.Detail["where"] != "url" || event.Detail["placeholders"] != "ph:secret:stripe" {
		t.Fatalf("event: %+v", event)
	}
	// The same value in a header that is not a login header is reported and
	// goes out: a header is never a reason to block.
	request, _ = http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(anthropicBody("hello")))
	request.Header.Set("X-Debug", leakSecretOne)
	response, err = rig.client(rig.phaseRoots).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || rig.lastReceived().header.Get("X-Debug") != leakSecretOne {
		t.Fatalf("a value in a header was blocked or changed: %d", response.StatusCode)
	}
}

func TestLeakProtectionNeverJudgesLoginHeaders(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"login": leakSecretOne})
	request, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(anthropicBody("hello")))
	request.Header.Set("Authorization", "Bearer "+leakSecretOne)
	request.Header.Set("X-Api-Key", leakSecretOne)
	request.Header.Set("Cookie", "session="+leakSecretOne)
	response, err := rig.client(rig.phaseRoots).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	received := rig.lastReceived()
	if response.StatusCode != http.StatusOK || received.header.Get("Authorization") != "Bearer "+leakSecretOne ||
		received.header.Get("X-Api-Key") != leakSecretOne || received.header.Get("Cookie") != "session="+leakSecretOne {
		t.Fatalf("a login header was judged or changed: %d", response.StatusCode)
	}
}

func TestLeakProtectionObserveModeChangesNothing(t *testing.T) {
	rig := newLeakRig(t, leakModeObserve)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne, "db": leakSecretTwo})
	original := anthropicBody("key " + leakSecretOne)
	postMessages(t, rig.client(rig.phaseRoots), "https://api.anthropic.com/v1/messages", original, "")
	if received := rig.lastReceived(); !bytes.Equal(received.body, original) {
		t.Fatal("observe mode changed the body")
	}
	// Even what censor mode would block goes out.
	request, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages?key="+url.QueryEscape(leakSecretTwo), bytes.NewReader(original))
	response, err := rig.client(rig.phaseRoots).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || rig.receivedCount() != 2 {
		t.Fatalf("observe mode blocked: %d", response.StatusCode)
	}
	events := rig.leakEvents(2)
	for _, event := range events {
		if event.Outcome != outcomeObserved || event.Detail["mode"] != "observe" {
			t.Fatalf("event: %+v", event)
		}
	}
}

// rawTunnelHandshake checks that a CONNECT to host is a raw tunnel: the client
// completes TLS with the provider's own certificate and its request arrives.
func rawTunnelHandshake(t *testing.T, rig *leakRig, host string) {
	t.Helper()
	original := anthropicBody("key " + leakSecretOne)
	postMessages(t, rig.client(rig.providerRoots), "https://"+host+"/v1/messages", original, "")
	if received := rig.lastReceived(); !bytes.Equal(received.body, original) {
		t.Fatal("the raw tunnel changed the body")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://"+host+"/v1/models", nil)
	if _, err := rig.client(rig.phaseRoots).Do(request); err == nil {
		t.Fatal("the client was given Phase's certificate: the tunnel was read")
	}
}

func TestLeakProtectionOffLeavesTheConnectARawTunnel(t *testing.T) {
	rig := newLeakRig(t, leakModeOff)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	rawTunnelHandshake(t, rig, "api.anthropic.com")
}

func TestLeakProtectionLeavesHostsOutsideTheTableAlone(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	rawTunnelHandshake(t, rig, "api.example.com")
	// A name beside a listed host is not that host, and one that only ends
	// like a listed domain is not under it.
	rawTunnelHandshake(t, rig, "api.opencode.ai")
	rawTunnelHandshake(t, rig, "mycursor.sh")
}

func TestLeakProtectionPassesThroughAfterTwoRefusedHandshakes(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	now := time.Now()
	var clockMu sync.Mutex
	rig.guard.handshakes.now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	advance := func(d time.Duration) { clockMu.Lock(); now = now.Add(d); clockMu.Unlock() }
	host := "api.anthropic.com"
	refuse := func() {
		t.Helper()
		request, _ := http.NewRequest(http.MethodGet, "https://"+host+"/v1/models", nil)
		if _, err := rig.client(rig.providerRoots).Do(request); err == nil {
			t.Fatal("a client that does not trust Phase completed TLS with the proxy")
		}
	}
	waitFailures := func(want int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			rig.guard.handshakes.mu.Lock()
			state := rig.guard.handshakes.hosts[hostKey(host)]
			got := 0
			if state != nil {
				got = state.failures
			}
			rig.guard.handshakes.mu.Unlock()
			if got >= want || time.Now().After(deadline) {
				if got < want {
					t.Fatalf("%d failed handshakes recorded, want %d", got, want)
				}
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	refuse()
	waitFailures(1)
	if rig.guard.handshakes.bypassed(hostKey(host)) {
		t.Fatal("one refusal opened a window")
	}
	refuse()
	waitFailures(2)
	if !rig.guard.handshakes.bypassed(hostKey(host)) {
		t.Fatal("two refusals in a row did not open a window")
	}
	// Inside the window the client is passed through unread.
	original := anthropicBody("key " + leakSecretOne)
	postMessages(t, rig.client(rig.providerRoots), "https://"+host+"/v1/messages", original, "")
	if received := rig.lastReceived(); !bytes.Equal(received.body, original) {
		t.Fatal("the pass-through changed the body")
	}
	event := rig.leakEvents(1)[0]
	if event.Outcome != outcomeBypass || event.Method != http.MethodConnect || event.Reason != leakReasonTLSRefused ||
		event.Detail["windowSeconds"] != float64(20) || event.Detail["harness"] != "claude" {
		t.Fatalf("window event: %+v", event)
	}
	if status := rig.guard.status(); !containsString(status.UnreadHosts, host) {
		t.Fatalf("status lists the host as inspected during the window: %+v", status)
	}
	// After the window a client that trusts Phase is read again, and its
	// success clears the count.
	advance(21 * time.Second)
	postMessages(t, rig.client(rig.phaseRoots), "https://"+host+"/v1/messages", original, "")
	if received := rig.lastReceived(); bytes.Contains(received.body, []byte(leakSecretOne)) {
		t.Fatal("the host was not read after the window")
	}
	rig.guard.handshakes.mu.Lock()
	cleared := rig.guard.handshakes.hosts[hostKey(host)] == nil
	rig.guard.handshakes.mu.Unlock()
	if !cleared {
		t.Fatal("a successful handshake did not clear the count")
	}
	refuse()
	waitFailures(1)
	if rig.guard.handshakes.bypassed(hostKey(host)) {
		t.Fatal("one refusal after a success opened a window")
	}
}

func TestLeakProtectionKeepsTheTunnelAliveExpectContinueAndStreaming(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	firstRead := make(chan struct{})
	rig.upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rig.mu.Lock()
		rig.received = append(rig.received, receivedRequest{path: r.URL.Path, header: r.Header.Clone(), body: body})
		rig.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message_start\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-firstRead:
		case <-time.After(5 * time.Second):
			return
		}
		_, _ = io.WriteString(w, "event: message_stop\ndata: {}\n\n")
	})
	client := rig.client(rig.phaseRoots)
	var reused []bool
	for i := 0; i < 2; i++ {
		request, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(anthropicBody("key "+leakSecretOne)))
		request.Header.Set("X-Test-Handler", "stream")
		if i == 1 {
			request.Header.Set("Expect", "100-continue")
		}
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { reused = append(reused, info.Reused) },
		}))
		started := time.Now()
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(response.Body)
		line, err := reader.ReadString('\n')
		if err != nil || line != "event: message_start\n" {
			t.Fatalf("the first event did not stream: %q %v", line, err)
		}
		firstRead <- struct{}{}
		rest, _ := io.ReadAll(reader)
		_ = response.Body.Close()
		if !strings.Contains(string(rest), "message_stop") {
			t.Fatalf("the stream did not finish: %q", rest)
		}
		if i == 1 && time.Since(started) > 5*time.Second {
			t.Fatal("100-continue was not answered: the client waited out its timeout")
		}
		if bytes.Contains(rig.lastReceived().body, []byte(leakSecretOne)) {
			t.Fatal("the value reached the provider")
		}
	}
	if len(reused) != 2 || !reused[1] {
		t.Fatalf("the second request did not reuse the tunnel: %v", reused)
	}
}

// clientFrame builds a masked client frame, fragment or whole.
func clientFrame(fin bool, opcode byte, payload []byte) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}
	frame := []byte{first}
	switch {
	case len(payload) < 126:
		frame = append(frame, 0x80|byte(len(payload)))
	case len(payload) <= 0xffff:
		frame = append(frame, 0x80|126)
		frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	default:
		frame = append(frame, 0x80|127)
		frame = binary.BigEndian.AppendUint64(frame, uint64(len(payload)))
	}
	mask := [4]byte{0x11, 0x22, 0x33, 0x44}
	frame = append(frame, mask[:]...)
	start := len(frame)
	frame = append(frame, payload...)
	unmaskWS(frame[start:], mask)
	return frame
}

type wsMessage struct {
	opcode  byte
	payload []byte
}

// readServerSide reads one frame as the provider would, unmasking it.
func readFrame(reader *bufio.Reader) (bool, byte, []byte, error) {
	header, err := readWSFrameHeader(reader)
	if err != nil {
		return false, 0, nil, err
	}
	payload := make([]byte, header.length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return false, 0, nil, err
	}
	if header.masked {
		unmaskWS(payload, header.mask)
	}
	return header.fin, header.opcode, payload, nil
}

func TestLeakProtectionRewritesCodexWebSocketMessages(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	registerLeakValues(t, rig.guard, map[string]string{"stripe": leakSecretOne})
	messages := make(chan wsMessage, 16)
	extensions := make(chan string, 1)
	rig.upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extensions <- r.Header.Get("Sec-WebSocket-Extensions")
		connection, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = fmt.Fprintf(buffered, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", webSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
		_ = buffered.Flush()
		var message []byte
		var opcode byte
		for {
			fin, op, payload, err := readFrame(buffered.Reader)
			if err != nil {
				close(messages)
				return
			}
			if op >= wsOpClose {
				messages <- wsMessage{opcode: op, payload: payload}
				if op == wsOpClose {
					_, _ = buffered.Write([]byte{0x88, 0x00})
					_ = buffered.Flush()
					close(messages)
					return
				}
				continue
			}
			if op != 0 {
				opcode = op
			}
			message = append(message, payload...)
			if fin {
				messages <- wsMessage{opcode: opcode, payload: message}
				// Echo text messages back, unmasked as a server sends them.
				if opcode == wsOpText {
					_, _ = buffered.Write(append([]byte{0x81, byte(len("ok"))}, "ok"...))
					_ = buffered.Flush()
				}
				message = nil
			}
		}
	})

	conn := connectThroughProxy(t, rig, "chatgpt.com", rig.phaseRoots)
	defer conn.Close()
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, _ = fmt.Fprintf(conn, "GET /backend-api/codex/responses HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n", key)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", response, err)
	}
	if offered := <-extensions; offered != "" {
		t.Fatalf("the compression offer reached the provider: %q", offered)
	}

	create := []byte(`{"type":"response.create","model":"gpt-5","input":[{"type":"function_call_output","call_id":"c1","output":"STRIPE_KEY=` + leakSecretOne + `\n"}]}`)
	half := len(create) / 2
	// Bytes that are not text and hold nothing known. A binary message that
	// holds a known value is blocked: see the WebSocket tests of the policy.
	binaryPayload := []byte{0, 1, 2, 0xff, 0xfe, 0x80, 'f', 'r', 'a', 'm', 'e'}
	for _, frame := range [][]byte{
		clientFrame(false, wsOpText, create[:half]),
		clientFrame(true, 0x9, []byte("ping")),
		clientFrame(true, wsOpContinuation, create[half:]),
		clientFrame(true, 0x2, binaryPayload),
		clientFrame(true, 0x2, binaryPayload),
		clientFrame(true, wsOpText, []byte("plain text, not json")),
		clientFrame(true, wsOpText, []byte(`{"type":"response.create","input":"nothing here"}`)),
	} {
		if _, err := conn.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
	// The server's echo comes back through untouched.
	if fin, op, payload, err := readFrame(reader); err != nil || !fin || op != wsOpText || string(payload) != "ok" {
		t.Fatalf("echo: %v %v %q %v", fin, op, payload, err)
	}
	next := func() wsMessage {
		select {
		case message := <-messages:
			return message
		case <-time.After(3 * time.Second):
			t.Fatal("the provider did not get a message")
		}
		return wsMessage{}
	}
	if ping := next(); ping.opcode != 0x9 || string(ping.payload) != "ping" {
		t.Fatalf("the ping between fragments was not passed on: %+v", ping)
	}
	text := next()
	want := bytes.Replace(create, []byte(leakSecretOne), []byte("ph:secret:stripe"), 1)
	if text.opcode != wsOpText || !bytes.Equal(text.payload, want) {
		t.Fatalf("the response.create message: %s", text.payload)
	}
	for i := 0; i < 2; i++ {
		if binary := next(); binary.opcode != 0x2 || !bytes.Equal(binary.payload, binaryPayload) {
			t.Fatal("a binary message was changed")
		}
	}
	if plain := next(); string(plain.payload) != "plain text, not json" {
		t.Fatalf("a non-JSON message was changed: %q", plain.payload)
	}
	if clean := next(); string(clean.payload) != `{"type":"response.create","input":"nothing here"}` {
		t.Fatal("a clean message was changed")
	}
	if _, err := conn.Write(clientFrame(true, wsOpClose, []byte{0x03, 0xe8})); err != nil {
		t.Fatal(err)
	}
	if closing := next(); closing.opcode != wsOpClose {
		t.Fatalf("the close frame was not passed on: %+v", closing)
	}
	// Binary messages and text that is not JSON are read like a request body
	// of the same kind, so a clean one is no event: only the replaced value is
	// reported.
	rig.leakEvents(1)
	events := rig.leakEventsNow()
	if len(events) != 1 {
		t.Fatalf("events: %+v", events)
	}
	if event := events[0]; event.Protocol != "websocket" || event.Path != "/backend-api/codex/responses" || event.Detail["harness"] != "codex" ||
		event.Outcome != outcomeCensored || event.Detail["placeholders"] != "ph:secret:stripe" || event.Detail["where"] != "message" {
		t.Fatalf("event: %+v", event)
	}
}

func connectThroughProxy(t *testing.T, rig *leakRig, host string, roots *x509.CertPool) *tls.Conn {
	t.Helper()
	raw, err := net.Dial("tcp", rig.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	authorization := base64.StdEncoding.EncodeToString([]byte("phase:runtime-test"))
	_, _ = fmt.Fprintf(raw, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: Basic %s\r\n\r\n", host, host, authorization)
	reader := bufio.NewReader(raw)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %v %v", response, err)
	}
	conn := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	return conn
}

// TestLeakProtectionFixtureEndToEnd sends every file of the fake-secret
// repository as a tool result through the real proxy, and checks what the
// provider received with the independent verifier.
func TestLeakProtectionFixtureEndToEnd(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	fixture := censortest.NewFixture()
	values := map[string]string{}
	types := map[string]string{}
	for _, entry := range fixture.Entries {
		if entry.Expect != "rule" {
			values[entry.ID] = entry.Value
			types[entry.ID] = entry.Type
		}
	}
	for id, value := range values {
		entry, err := censorIndex(rig.guard, types[id], id, value)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := rig.guard.add(entry, nil); err != nil {
			t.Fatal(err)
		}
	}
	verifier := censortest.NewVerifier(fixture.Entries)
	client := rig.client(rig.phaseRoots)
	names := make([]string, 0, len(fixture.Files))
	for name := range fixture.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := anthropicBody(fixture.Files[name])
		response := postMessages(t, client, "https://api.anthropic.com/v1/messages", gzipBytes(t, body), "gzip")
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", name, response.StatusCode)
		}
		received := gunzipBytes(t, rig.lastReceived().body)
		if !json.Valid(received) {
			t.Fatalf("%s: the provider got invalid JSON", name)
		}
		for _, miss := range verifier.Check(received) {
			if !miss.Expected {
				t.Errorf("%s: %s reached the provider (%s %s)", name, miss.ID, miss.Form, miss.Part)
			}
		}
	}
	shipped := rig.shippedPayloads()
	if misses := verifier.Check(shipped); len(misses) > 0 {
		for _, miss := range misses {
			if !miss.Expected {
				t.Errorf("an event carries %s", miss.ID)
			}
		}
	}
}

// TestLeakProtectionRegistrationRoundTrip registers values the way the CLI
// does, through the control API of a running proxy, and checks that nothing
// the proxy holds or reports carries them.
func TestLeakProtectionRegistrationRoundTrip(t *testing.T) {
	rig := newLeakRig(t, leakModeCensor)
	environment := map[string]string{"PHASE_AI_ENABLED": "1", "HTTPS_PROXY": rig.proxyURL.String()}
	previous := leakguard.Environment
	leakguard.Environment = func(key string) string { return environment[key] }
	defer func() { leakguard.Environment = previous }()

	result, err := leakguard.Register(context.Background(), []leakguard.Value{
		{Type: "secret", ID: "secret-id-1", Value: leakSecretOne},
		{Type: "sealed", ID: "secret-id-2", Value: leakSecretTwo},
		{Type: "config", ID: "secret-id-3", Value: "a-config-value-that-is-public-0001"},
		{Type: "secret", ID: "secret-id-4", Value: "short"},
	})
	if err != nil || result.Added != 2 || result.Unprotected != 1 {
		t.Fatalf("registration: %+v %v", result, err)
	}
	if status := rig.guard.status(); status.SecretsKnown != 2 || status.Unprotected != 1 {
		t.Fatalf("status after registration: %+v", status)
	}
	postMessages(t, rig.client(rig.phaseRoots), "https://api.anthropic.com/v1/messages", anthropicBody(leakSecretOne+" "+leakSecretTwo), "")
	received := rig.lastReceived()
	if !bytes.Contains(received.body, []byte("ph:secret:secret-id-1")) || !bytes.Contains(received.body, []byte("ph:sealed:secret-id-2")) {
		t.Fatalf("registered values were not replaced: %s", received.body)
	}
	rig.leakEvents(1)
	verifier := censortest.NewVerifier([]censortest.Entry{{ID: "one", Value: leakSecretOne}, {ID: "two", Value: leakSecretTwo}})
	if misses := verifier.Check(received.body); len(misses) > 0 {
		t.Fatalf("values reached the provider: %+v", misses)
	}
	if misses := verifier.Check(rig.shippedPayloads()); len(misses) > 0 {
		t.Fatalf("an event carries a value: %+v", misses)
	}
	// The index holds keyed hashes only.
	dump := []byte(fmt.Sprintf("%+v", rig.guard.index))
	if misses := verifier.Check(dump); len(misses) > 0 {
		t.Fatalf("the index holds a value: %+v", misses)
	}
	// So do the entries the client sends.
	entry, err := censorIndex(rig.guard, "secret", "one", leakSecretOne)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := entry[0].Marshal()
	if misses := verifier.Check(encoded); len(misses) > 0 {
		t.Fatalf("the entries hold a value: %+v", misses)
	}
	// A client of another session cannot register: the proxy wants its
	// capability.
	environment["HTTPS_PROXY"] = strings.Replace(rig.proxyURL.String(), "runtime-test", "another-capability", 1)
	if _, err := leakguard.Register(context.Background(), []leakguard.Value{{Type: "secret", ID: "x", Value: leakSecretOne}}); err == nil {
		t.Fatal("a registration with the wrong capability succeeded")
	}
}
