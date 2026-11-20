package aiproxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// rawTunnel is one CONNECT tunnel through a running engine, for requests
// whose request line a normal HTTP client would never write.
type rawTunnel struct {
	connection *tls.Conn
	reader     *bufio.Reader
	authority  string
}

func openRawTunnel(t *testing.T, running *runningEngine, authority string) *rawTunnel {
	t.Helper()
	proxyURL, err := url.Parse(running.endpoints.ProxyURL.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	password, _ := proxyURL.User.Password()
	credentials := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
	plain, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { plain.Close() })
	fmt.Fprintf(plain, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", authority, authority, credentials)
	established, err := http.ReadResponse(bufio.NewReader(plain), &http.Request{Method: http.MethodConnect})
	if err != nil || established.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT was not established: %v", err)
	}
	host, _, _ := net.SplitHostPort(authority)
	secured := tls.Client(plain, &tls.Config{RootCAs: running.roots, ServerName: host, MinVersion: tls.VersionTLS12})
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	return &rawTunnel{connection: secured, reader: bufio.NewReader(secured), authority: authority}
}

// send writes one request with the given request line and returns the answer.
func (tunnel *rawTunnel) send(t *testing.T, requestLine string) (*http.Response, string) {
	t.Helper()
	method, _, _ := strings.Cut(requestLine, " ")
	if _, err := io.WriteString(tunnel.connection, requestLine+" HTTP/1.1\r\nHost: "+tunnel.authority+"\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(tunnel.reader, &http.Request{Method: method})
	if err != nil {
		t.Fatalf("%s: %v", requestLine, err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	return response, string(body)
}

// A request-target of the form "scheme:opaque" has no path for the proxy to
// judge, while the transport would send the opaque text upstream as written.
// The tunnel refuses it before a rule, an override or the secret guard is
// consulted, and nothing reaches the upstream.
func TestTunnelRefusesARequestTargetThatIsNotAPath(t *testing.T) {
	var mu sync.Mutex
	var forwarded []string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		forwarded = append(forwarded, r.Method+" "+r.RequestURI+" host="+r.Host+" authorization="+r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	host, port, _ := net.SplitHostPort(parsed.Host)
	authority := parsed.Host

	// One packaged service with a path rule, a class override and, being
	// GitHub, a path rule of the secret guard.
	policy := policyDocument("allow", []any{matchRule("block", "/admin/*"), classRule("update", "block")})
	connection := packagedHTTPPayload(policy, githubGraphQLUpdate)
	connection["hosts"] = []any{map[string]any{"match": "exact", "value": host, "port": mustPort(t, port)}}
	client, shipped := eventConsole(t)
	payload := customSessionPayload("psx_sess_request_target_0123456789", 1, connection)
	running := serveCustomEngine(t, client, decodeTestSession(t, payload), upstream.Client().Transport)
	defer running.stop()

	seen := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(forwarded)
	}
	tunnel := openRawTunnel(t, running, authority)

	// The same calls with an ordinary path are judged as written.
	for requestLine, code := range map[string]string{
		"DELETE /admin/users/1":                   "agent_access_policy_blocked",
		"POST /graphql":                           "agent_access_policy_blocked",
		"POST /app/installations/1/access_tokens": "agent_access_policy_blocked",
	} {
		response, _ := tunnel.send(t, requestLine)
		if response.StatusCode != http.StatusForbidden || response.Header.Get("X-Phase-Error-Code") != code {
			t.Fatalf("%s: status=%d code=%s", requestLine, response.StatusCode, response.Header.Get("X-Phase-Error-Code"))
		}
	}
	if response, body := tunnel.send(t, "GET /user"); response.StatusCode != http.StatusOK || body != "ok" || seen() != 1 {
		t.Fatalf("an ordinary request: status=%d forwarded=%d", response.StatusCode, seen())
	}

	for name, requestLine := range map[string]string{
		"a path rule":                     "DELETE x:https://" + authority + "/admin/users/1",
		"a class override":                "POST x:https://" + authority + "/graphql",
		"the secret guard's path rule":    "POST x:https://" + authority + "/app/installations/1/access_tokens",
		"an absolute URL of another host": "GET x:https://attacker.example.net/collect",
		"an opaque target under https":    "GET https:admin/users/1",
		"an opaque target with a query":   "GET x:https://" + authority + "/admin/users?page=2",
	} {
		response, body := tunnel.send(t, requestLine)
		if response.StatusCode != http.StatusBadRequest || response.Header.Get("X-Phase-Error-Code") != "invalid_proxy_request" ||
			response.Header.Get("X-Phase-Event-Id") == "" || strings.Contains(body, packagedLive) {
			t.Errorf("%s: status=%d code=%s body=%s", name, response.StatusCode, response.Header.Get("X-Phase-Error-Code"), body)
		}
		if seen() != 1 {
			t.Fatalf("%s reached the upstream: %v", name, forwarded)
		}
	}
	// The refusal leaves the tunnel in step: the next request is served.
	if response, _ := tunnel.send(t, "GET /user"); response.StatusCode != http.StatusOK || seen() != 2 {
		t.Fatalf("a request after the refusals: status=%d forwarded=%d", response.StatusCode, seen())
	}
	mu.Lock()
	for _, request := range forwarded {
		if !strings.HasPrefix(request, "GET /user host="+authority+" authorization=Bearer "+packagedLive) {
			t.Errorf("unexpected upstream request: %s", request)
		}
	}
	mu.Unlock()

	running.stop()
	// A denial is kept until the Console has it, so one may be shipped twice.
	refused := map[string]bool{}
	for _, event := range shipped() {
		if event.StatusCode != http.StatusBadRequest {
			continue
		}
		refused[event.EventID] = true
		if event.Reason != "unclassifiable_request" || event.ProxyDecision != "block" || event.Outcome != "denied" || event.Host != host {
			t.Errorf("event for a refused request target = %+v", event)
		}
	}
	if len(refused) != 6 {
		t.Fatalf("events for refused request targets = %d, want 6", len(refused))
	}
}

// The same refusal on the explicit-proxy path, where the request arrives in
// absolute form without a tunnel.
func TestProxyRefusesAnOpaqueRequestTargetOutsideATunnel(t *testing.T) {
	policy := policyDocument("allow", []any{matchRule("block", "/v1/admin/*")})
	_, proxy, upstream := policyProxy(t, customPolicyConnection(policy))
	for _, target := range []string{"https:v1/admin/users", "http:v1/admin/users"} {
		request := httptest.NewRequest(http.MethodDelete, target, nil)
		request.Host = "api.example.test"
		result := processThrough(proxy, request)
		if result.failure == nil || result.failure.status != http.StatusBadRequest || result.failure.code != "invalid_proxy_request" ||
			result.event.Reason != "unclassifiable_request" || result.event.ProxyDecision != "block" || result.event.EventID == "" {
			t.Fatalf("%s: failure=%+v event=%+v", target, result.failure, result.event)
		}
	}
	// Built by hand, as a caller inside the process could: a URL with a host
	// and an opaque part is refused as well and never cloned for forwarding.
	crafted := httptest.NewRequest(http.MethodDelete, "https://api.example.test/v1/items", nil)
	crafted.URL.Opaque, crafted.URL.Path = "https://api.example.test/v1/admin/users", ""
	if result := processThrough(proxy, crafted); result.failure == nil || result.failure.status != http.StatusBadRequest {
		t.Fatalf("a hand-built opaque URL: %+v", result.failure)
	}
	if _, err := cloneUpstreamRequest(crafted); err == nil {
		t.Fatal("an opaque URL was cloned for forwarding")
	}
	if upstream.calls.Load() != 0 {
		t.Fatalf("upstream calls = %d", upstream.calls.Load())
	}
}
