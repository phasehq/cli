package aiproxy

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- required by RFC 6455 for Sec-WebSocket-Accept.
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

type httpProxy struct {
	state *runtimeState
	ca    interface {
		CertificateForHost(string) (*tls.Certificate, error)
	}
	transport        http.RoundTripper
	unboundTransport http.RoundTripper
	dial             func(context.Context, string, string) (net.Conn, error)
	unboundDial      func(context.Context, string, string) (net.Conn, error)
	lockdown         bool
	remote           bool
	events           *eventBuffer
	manifest         *manifestHandler
	control          *controlHandler
	// lifecycle ends with the engine run. Requests read off a hijacked CONNECT
	// tunnel have no context of their own, so they borrow this one and their
	// upstream round trips stop when the proxy does.
	lifecycle context.Context
	mu        sync.Mutex
	hijacked  map[net.Conn]struct{}
	wg        sync.WaitGroup
}

type requestFailure struct {
	status   int
	code     string
	message  string
	decision string
	reason   string
	binding  *binding
	// eventID is the credential-free ID of the event recorded for this
	// request, returned to the client so a human can find it in the Console.
	eventID string
}

// eventIDHeader carries the proxy's per-request event ID back to the client.
// It contains no credential material and matches the event the proxy reports
// to the Console, so a CLI invocation can be correlated with its upstream
// forwarding, decision, and completion.
const eventIDHeader = "X-Phase-Event-Id"

type tunnelAuthentication struct{ connectionID string }
type selectedConnectionContextKey struct{}

func selectedConnection(req *http.Request) string {
	value, _ := req.Context().Value(selectedConnectionContextKey{}).(string)
	return value
}

const awsSSMTokenCredentialAction = "aws_ssm_token"

type processedResponse struct {
	response *http.Response
	event    agentEvent
	failure  *requestFailure
	snapshot protocolBindingSnapshot
}

type bufferedReadWriteCloser struct {
	io.Reader
	io.Writer
	io.Closer
}

func (e *requestFailure) Error() string { return e.message }

func (p *httpProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !p.authenticateProxyRequest(w, req) {
		return
	}
	if req != nil && req.URL != nil && req.URL.IsAbs() && strings.EqualFold(req.URL.Hostname(), ManifestHost) {
		if p.manifest != nil && p.manifest.matchesManifest(req) {
			p.manifest.ServeManifestHTTP(w, req)
			return
		}
		if p.control != nil && strings.HasPrefix(req.URL.Path, "/v1/") {
			p.control.ServeProxyHTTP(w, req, p.remote)
			return
		}
		writeProxyError(w, &requestFailure{status: http.StatusNotFound, code: "agent_manifest_route_not_found", message: "The Phase Agent proxy route was not found."})
		return
	}
	if req.Method == http.MethodConnect {
		p.handleConnect(w, req)
		return
	}
	result := p.process(req, nil)
	if result.failure != nil {
		result.failure.eventID = result.event.EventID
		p.events.Emit(result.event)
		writeProxyError(w, result.failure)
		return
	}
	if result.event.EventID != "" {
		p.events.Emit(result.event)
	}
	defer result.response.Body.Close()
	copyResponse(w, result.response, result.event.EventID)
}

func (p *httpProxy) process(req *http.Request, tunnelAuth *tunnelAuthentication) processedResponse {
	started := time.Now()
	host, port, err := requestAuthority(req)
	if err != nil || req.URL == nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
		failure := &requestFailure{status: http.StatusBadRequest, code: "invalid_proxy_request", message: "The proxy request target is invalid.", decision: "block", reason: "unclassifiable_request"}
		return processedResponse{event: makeEvent(nil, req, "block", "denied", failure.reason, failure.status, time.Since(started), ""), failure: failure}
	}
	selection := selectedConnection(req)
	if tunnelAuth != nil {
		selection = tunnelAuth.connectionID
	}
	binding, matchErr := p.state.findBinding(host, port, req.URL.EscapedPath(), selection)
	if matchErr != nil {
		failure := &requestFailure{status: http.StatusForbidden, code: "ambiguous_agent_binding", message: "The request matches more than one Agent binding.", decision: "block", reason: "ambiguous_binding"}
		return processedResponse{event: makeEvent(nil, req, "block", "denied", failure.reason, failure.status, time.Since(started), ""), failure: failure}
	}
	if binding == nil {
		if p.lockdown {
			failure := &requestFailure{status: http.StatusForbidden, code: "unbound_host_blocked", message: "The host is not bound to this Agent Workflow.", decision: "block", reason: "lockdown_unbound_host"}
			return processedResponse{event: makeEvent(nil, req, "block", "denied", failure.reason, failure.status, time.Since(started), ""), failure: failure}
		}
		upstream, cloneErr := cloneUpstreamRequest(req)
		if cloneErr != nil {
			failure := &requestFailure{status: http.StatusBadRequest, code: "invalid_proxy_request", message: "The proxy request could not be forwarded.", decision: "block", reason: "unclassifiable_request"}
			return processedResponse{failure: failure}
		}
		roundTripper := p.unboundTransport
		if roundTripper == nil {
			roundTripper = p.transport
		}
		response, roundTripErr := roundTripper.RoundTrip(upstream)
		if roundTripErr != nil {
			if errors.Is(roundTripErr, errUnsafeRemoteDestination) {
				failure := &requestFailure{status: http.StatusForbidden, code: "unsafe_remote_destination", message: "The remote proxy target is not publicly routable.", decision: "block", reason: "unsafe_remote_destination"}
				return processedResponse{event: makeEvent(nil, req, "block", "denied", failure.reason, failure.status, time.Since(started), ""), failure: failure}
			}
			return processedResponse{failure: &requestFailure{status: http.StatusBadGateway, code: "upstream_unavailable", message: "The upstream service is unavailable."}}
		}
		return processedResponse{response: response}
	}
	snapshot, snapshotErr := p.state.snapshotForBinding(binding, "http")
	if snapshotErr != nil {
		failure := &requestFailure{status: http.StatusServiceUnavailable, code: "agent_binding_unavailable", message: "The Agent binding is not currently validated.", decision: "error", reason: "binding_unavailable", binding: binding}
		return processedResponse{event: makeEvent(binding, req, "error", "error", failure.reason, failure.status, time.Since(started), ""), failure: failure}
	}
	binding = snapshot.binding
	defer snapshot.release()
	authorization := binding.authorizationDecision(time.Now())
	if !authorization.allowed {
		failure := &requestFailure{status: authorization.status, code: authorization.code, message: authorization.message, decision: "block", reason: authorization.reason, binding: binding}
		return processedResponse{event: makeEvent(binding, req, "block", "denied", authorization.reason, authorization.status, time.Since(started), ""), failure: failure}
	}
	upstream, cloneErr := cloneUpstreamRequest(req)
	if cloneErr != nil {
		failure := &requestFailure{status: http.StatusBadRequest, code: "invalid_proxy_request", message: "The proxy request could not be classified.", decision: "block", reason: "unclassifiable_request", binding: binding}
		return processedResponse{event: makeEvent(binding, req, "block", "denied", failure.reason, failure.status, time.Since(started), ""), failure: failure}
	}
	if tunnelAuth != nil {
		restoreWebSocketUpgrade(req, upstream)
	}
	// Refuse calls that would mint a new credential before anything is
	// re-signed or injected. See pkg/proxy/minting.go for the rule table.
	if blocked, inspectErr := phaseproxy.CredentialMintingBlocked(upstream, binding.connection); blocked != nil || inspectErr != nil {
		failure := &requestFailure{status: http.StatusForbidden, code: "credential_minting_blocked", decision: "block", reason: "credential_minting_blocked", binding: binding}
		event := makeEvent(binding, req, "block", "denied", failure.reason, failure.status, time.Since(started), binding.connection.Injection.Action)
		if blocked != nil {
			failure.message = blocked.Message()
			event.Detail["blocked_operation"] = blocked.Operation
		} else {
			failure.code = "credential_minting_uninspectable"
			failure.message = "Phase could not inspect this request to rule out credential minting (the body is too large or unreadable). Split the request or use a smaller body."
		}
		return processedResponse{event: event, failure: failure}
	}
	if binding.connection.Injection.Action == "aws_sigv4" {
		// Keep the response representation inspectable so a live AWS identity
		// can never bypass the exact response redaction boundary via compression.
		upstream.Header.Set("Accept-Encoding", "identity")
	}
	injection := phaseproxy.InjectionResult{Action: awsSSMTokenCredentialAction}
	var injectionErr error
	if !isPresignedSSMDataChannelWebSocket(req, upstream, tunnelAuth, binding.connection, time.Now()) {
		injection, injectionErr = applyHTTPInjectionWithHistory(upstream, binding.connection, p.state.previousDecoyViews(binding.connection))
	}
	if injectionErr != nil {
		failure := &requestFailure{status: http.StatusForbidden, code: "agent_credential_injection_failed", message: injectionErr.Error(), decision: "block", reason: "credential_swap_failed", binding: binding}
		event := makeEvent(binding, req, "block", "denied", failure.reason, failure.status, time.Since(started), binding.connection.Injection.Action)
		var typed *phaseproxy.InjectionError
		if errors.As(injectionErr, &typed) && typed.AWSSigV4Failure != "" {
			event.Detail["aws_sigv4_failure"] = string(typed.AWSSigV4Failure)
		}
		return processedResponse{event: event, failure: failure}
	}
	if err := p.state.validateProtocolBinding(snapshot); err != nil {
		failure := &requestFailure{status: http.StatusServiceUnavailable, code: "agent_binding_changed", message: "The Agent binding changed while the request was evaluated; retry it.", decision: "error", reason: "binding_changed", binding: binding}
		return processedResponse{event: makeEvent(binding, req, "error", "error", failure.reason, failure.status, time.Since(started), injection.Action), failure: failure}
	}
	response, roundTripErr := p.transport.RoundTrip(upstream)
	if roundTripErr != nil {
		failure := &requestFailure{status: http.StatusBadGateway, code: "upstream_unavailable", message: "The upstream service is unavailable.", decision: "error", reason: "upstream_error", binding: binding}
		return processedResponse{event: makeEvent(binding, req, "error", "error", failure.reason, failure.status, time.Since(started), injection.Action), failure: failure}
	}
	if binding.connection.Injection.Action == "aws_sigv4" {
		if err := phaseproxy.SanitizeAWSSigV4Response(response, binding.connection); err != nil {
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			failure := &requestFailure{status: http.StatusBadGateway, code: "unsafe_aws_response", message: "The AWS response could not be safely returned.", decision: "error", reason: "upstream_response_redaction_failed", binding: binding}
			return processedResponse{event: makeEvent(binding, req, "error", "error", failure.reason, failure.status, time.Since(started), injection.Action), failure: failure}
		}
		phaseproxy.LowercaseAmazonMetadataHeaders(response.Header)
		phaseproxy.LowercaseAmazonMetadataHeaders(response.Trailer)
	}
	event := makeEvent(binding, req, "allow", "ok", authorization.reason, response.StatusCode, time.Since(started), injection.Action)
	return processedResponse{response: response, event: event, snapshot: snapshot}
}

func (p *httpProxy) authenticateProxyRequest(w http.ResponseWriter, req *http.Request) bool {
	credential, selection, ok := selectedProxyAuthorization(req.Header)
	if ok && p.state.authenticateRuntimeCapability(credential) {
		if selection != "" && p.state.connectionByID(selection) == nil {
			writeProxyError(w, &requestFailure{status: http.StatusForbidden, code: "unknown_connection", message: "The selected Connection is unavailable."})
			return false
		}
		*req = *req.WithContext(context.WithValue(req.Context(), selectedConnectionContextKey{}, selection))
		return true
	}
	w.Header().Set("Proxy-Authenticate", `Basic realm="Phase Agent session"`)
	failure := &requestFailure{
		status: http.StatusProxyAuthRequired, code: "invalid_runtime_capability",
		message: "A valid Phase AI runtime capability is required.", decision: "auth_deny", reason: "invalid_runtime_capability",
	}
	if p.events != nil {
		p.events.Emit(makeEvent(nil, req, failure.decision, "denied", failure.reason, failure.status, 0, ""))
	}
	writeProxyError(w, failure)
	return false
}

// agentEvent is an alias boundary that keeps the HTTP worker independent of
// the wire package in its signatures.
type agentEvent = agentapi.Event

func makeEvent(binding *binding, req *http.Request, decision, outcome, reason string, status int, latency time.Duration, action string) agentEvent {
	method, host, requestPath, port := "UNKNOWN", "invalid", "/", 0
	if req != nil {
		method = req.Method
		if req.URL != nil {
			host = req.URL.Hostname()
			requestPath = req.URL.EscapedPath()
		}
		if host == "" {
			host = req.Host
		}
		if observedHost, observedPort, err := requestAuthority(req); err == nil {
			host, port = observedHost, observedPort
		}
	}
	return newRequestEvent(binding, method, host, port, requestPath, decision, outcome, reason, status, latency, action)
}

func (p *httpProxy) handleConnect(w http.ResponseWriter, req *http.Request) {
	p.wg.Add(1)
	defer p.wg.Done()
	host, port, err := phaseproxy.ParseAuthority(req.Host, 443)
	if err != nil {
		writeProxyError(w, &requestFailure{status: http.StatusBadRequest, code: "invalid_connect_target", message: "The CONNECT target is invalid."})
		return
	}
	if strings.EqualFold(host, ManifestHost) {
		writeProxyError(w, &requestFailure{status: http.StatusForbidden, code: "reserved_proxy_origin", message: "The CONNECT target is reserved by the Phase Agent proxy."})
		return
	}
	bound, matchErr := p.state.hasBoundHost(host, port, selectedConnection(req))
	if matchErr != nil {
		writeProxyError(w, &requestFailure{status: http.StatusForbidden, code: "ambiguous_agent_binding", message: "The CONNECT target is ambiguous."})
		return
	}
	if !bound {
		if p.lockdown {
			failure := &requestFailure{
				status: http.StatusForbidden, code: "unbound_host_blocked", message: "The CONNECT target is not bound.",
				decision: "block", reason: "lockdown_unbound_host",
			}
			if p.events != nil {
				p.events.Emit(newRequestEvent(nil, http.MethodConnect, host, port, "/", failure.decision, "denied", failure.reason, failure.status, 0, ""))
			}
			writeProxyError(w, failure)
			return
		}
		p.tunnelUnbound(w, req, host, port)
		return
	}
	if err := p.state.availability(); err != nil {
		writeProxyError(w, &requestFailure{status: http.StatusServiceUnavailable, code: "agent_session_unavailable", message: "The Agent session is unavailable."})
		return
	}
	p.mitmConnect(w, req, host, port, tunnelAuthentication{connectionID: selectedConnection(req)})
}

func (p *httpProxy) tunnelUnbound(w http.ResponseWriter, req *http.Request, host string, port int) {
	dial := p.unboundDial
	if dial == nil {
		dial = p.dial
	}
	upstream, err := dial(req.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		if errors.Is(err, errUnsafeRemoteDestination) {
			writeProxyError(w, &requestFailure{status: http.StatusForbidden, code: "unsafe_remote_destination", message: "The remote proxy target is not publicly routable."})
			return
		}
		writeProxyError(w, &requestFailure{status: http.StatusBadGateway, code: "upstream_unavailable", message: "The CONNECT target is unavailable."})
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		writeProxyError(w, &requestFailure{status: http.StatusInternalServerError, code: "proxy_hijack_unavailable", message: "CONNECT is unavailable."})
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	p.track(client, true)
	defer p.track(client, false)
	defer client.Close()
	defer upstream.Close()
	stateWatchDone := make(chan struct{})
	defer close(stateWatchDone)
	go p.watchUnboundTunnel(req.Context(), client, upstream, stateWatchDone)
	_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if buffered.Flush() != nil {
		return
	}
	copyBidirectional(client, upstream)
}

// watchUnboundTunnel closes an already-established pass-through tunnel as
// soon as Phase can no longer validate the active session. New requests are
// rejected by the normal authentication/availability gate; this watcher makes
// the same fail-closed guarantee apply to idle raw CONNECT streams.
func (p *httpProxy) watchUnboundTunnel(ctx context.Context, client, upstream net.Conn, stop <-chan struct{}) {
	for {
		changed := p.state.changeSignal()
		if p.state.availability() != nil {
			_ = client.Close()
			_ = upstream.Close()
			return
		}
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = upstream.Close()
			return
		case <-stop:
			return
		case <-changed:
		}
	}
}

func (p *httpProxy) mitmConnect(w http.ResponseWriter, req *http.Request, host string, port int, authentication tunnelAuthentication) {
	certificate, err := p.ca.CertificateForHost(host)
	if err != nil {
		writeProxyError(w, &requestFailure{status: http.StatusBadGateway, code: "certificate_generation_failed", message: "The proxy could not establish a protected tunnel."})
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeProxyError(w, &requestFailure{status: http.StatusInternalServerError, code: "proxy_hijack_unavailable", message: "CONNECT is unavailable."})
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	p.track(client, true)
	defer p.track(client, false)
	defer client.Close()
	_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if buffered.Flush() != nil {
		return
	}
	tunnelContext, stopTunnel := context.WithCancel(req.Context())
	defer stopTunnel()
	if p.lifecycle != nil {
		defer context.AfterFunc(p.lifecycle, stopTunnel)()
	}
	tlsClient := tls.Server(client, &tls.Config{Certificates: []tls.Certificate{*certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err := tlsClient.HandshakeContext(tunnelContext); err != nil {
		return
	}
	reader := bufio.NewReader(tlsClient)
	for {
		inner, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		inner = inner.WithContext(tunnelContext)
		innerHost, innerPort, authorityErr := phaseproxy.ParseAuthority(inner.Host, port)
		if authorityErr != nil || innerHost != host || innerPort != port {
			_ = writeFailureResponse(tlsClient, inner, &requestFailure{status: http.StatusForbidden, code: "connect_authority_mismatch", message: "The tunneled request target differs from CONNECT."})
			inner.Body.Close()
			return
		}
		inner.URL.Scheme = "https"
		inner.URL.Host = net.JoinHostPort(host, strconv.Itoa(port))
		// http.ReadRequest does not implement Expect: 100-continue, unlike the
		// net/http server. Clients such as the AWS CLI hold the body back until
		// they see the 100, so answer it the moment the body is first read.
		var continueBody *expectContinueBody
		if inner.ProtoAtLeast(1, 1) && headerContainsToken(inner.Header, "Expect", "100-continue") &&
			inner.Body != nil && inner.Body != http.NoBody {
			continueBody = &expectContinueBody{ReadCloser: inner.Body, writer: tlsClient}
			inner.Body = continueBody
		}
		// A client still waiting for 100 Continue never sends its body. After a
		// final response without that 100 the connection cannot be reused, and
		// draining the body would block forever; closing keeps both sides in sync.
		bodyWithheld := func() bool { return continueBody != nil && !continueBody.sent.Load() }
		result := p.process(inner, &authentication)
		if result.failure != nil {
			result.failure.eventID = result.event.EventID
			p.events.Emit(result.event)
			_ = writeFailureResponse(tlsClient, inner, result.failure)
			if bodyWithheld() {
				return
			}
			inner.Body.Close()
			if inner.Close {
				return
			}
			continue
		}
		if result.response.StatusCode == http.StatusSwitchingProtocols {
			p.handleWebSocket(tunnelContext, tlsClient, reader, inner, result)
			return
		}
		if result.event.EventID != "" {
			p.events.Emit(result.event)
		}
		response := responseForMITMClient(result.response, inner)
		if result.event.EventID != "" {
			response.Header.Set(eventIDHeader, result.event.EventID)
		}
		writeErr := response.Write(tlsClient)
		result.response.Body.Close()
		if bodyWithheld() {
			return
		}
		inner.Body.Close()
		if writeErr != nil || inner.Close || response.Close {
			return
		}
	}
}

// expectContinueBody answers a tunnelled client's Expect: 100-continue the
// first time anything reads the request body, as net/http's server does.
// Requests the proxy rejects before forwarding never read the body, so the
// client never receives a 100 for them.
type expectContinueBody struct {
	io.ReadCloser
	writer io.Writer
	once   sync.Once
	sent   atomic.Bool
}

func (b *expectContinueBody) Read(destination []byte) (int, error) {
	b.once.Do(func() {
		if _, err := io.WriteString(b.writer, "HTTP/1.1 100 Continue\r\n\r\n"); err == nil {
			b.sent.Store(true)
		}
	})
	return b.ReadCloser.Read(destination)
}

// responseForMITMClient preserves message framing across the decrypted CONNECT
// tunnel. Streaming sanitizers intentionally make the final body length
// unknown; http.Response.Write otherwise adds "Connection: close" to delimit
// that body without updating the source Response.Close field. Explicit
// chunking keeps the inner HTTP/1.1 connection reusable and gives the client a
// prompt, unambiguous end of body.
func responseForMITMClient(upstream *http.Response, request *http.Request) *http.Response {
	response := new(http.Response)
	*response = *upstream
	response.Request = request
	response.Proto = request.Proto
	response.ProtoMajor = request.ProtoMajor
	response.ProtoMinor = request.ProtoMinor
	if response.ContentLength < 0 && response.Body != nil && response.Body != http.NoBody &&
		request.Method != http.MethodHead && response.StatusCode >= 200 && response.StatusCode != http.StatusNoContent &&
		response.StatusCode != http.StatusNotModified && !response.Close {
		if response.ProtoAtLeast(1, 1) && len(response.TransferEncoding) == 0 {
			response.TransferEncoding = []string{"chunked"}
		} else if len(response.TransferEncoding) == 0 {
			response.Close = true
		}
	}
	return response
}

func (p *httpProxy) handleWebSocket(ctx context.Context, client *tls.Conn, clientReader *bufio.Reader, request *http.Request, result processedResponse) {
	defer request.Body.Close()
	defer result.response.Body.Close()
	upstream, writable := result.response.Body.(io.ReadWriteCloser)
	if !validWebSocketResponse(request, result.response) || !writable || p.state.validateProtocolBinding(result.snapshot) != nil {
		failure := &requestFailure{status: http.StatusBadGateway, code: "invalid_websocket_upgrade", message: "The upstream WebSocket handshake was invalid.", decision: "error", reason: "upstream_error"}
		if result.snapshot.binding != nil {
			failure.binding = result.snapshot.binding
		}
		p.events.Emit(makeEvent(failure.binding, request, failure.decision, "error", failure.reason, failure.status, 0, result.event.CredentialAction))
		_ = writeFailureResponse(client, request, failure)
		return
	}
	if result.event.EventID != "" {
		p.events.Emit(result.event)
	}
	responseCopy := *result.response
	responseCopy.Request = request
	responseCopy.Body = nil
	responseCopy.ContentLength = 0
	responseCopy.Header = result.response.Header.Clone()
	removeHopHeaders(responseCopy.Header)
	responseCopy.Header.Set("Connection", "Upgrade")
	responseCopy.Header.Set("Upgrade", "websocket")
	if err := responseCopy.Write(client); err != nil {
		return
	}
	stop := make(chan struct{})
	defer close(stop)
	go p.watchWebSocket(ctx, client, upstream, result.snapshot, stop)
	copyBidirectional(&bufferedReadWriteCloser{Reader: clientReader, Writer: client, Closer: client}, upstream)
}

func (p *httpProxy) watchWebSocket(ctx context.Context, client, upstream io.Closer, snapshot protocolBindingSnapshot, stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		changed := p.state.changeSignal()
		if p.state.validateProtocolBinding(snapshot) != nil {
			_ = client.Close()
			_ = upstream.Close()
			return
		}
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = upstream.Close()
			return
		case <-stop:
			return
		case <-changed:
		case <-ticker.C:
		}
	}
}

func (p *httpProxy) track(connection net.Conn, add bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hijacked == nil {
		p.hijacked = make(map[net.Conn]struct{})
	}
	if add {
		p.hijacked[connection] = struct{}{}
	} else {
		delete(p.hijacked, connection)
	}
}

func (p *httpProxy) CloseHijacked() {
	p.mu.Lock()
	for connection := range p.hijacked {
		_ = connection.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
}

func selectedProxyAuthorization(header http.Header) (string, string, bool) {
	values := header.Values("Proxy-Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(values[0], "Basic "))
	if err != nil {
		return "", "", false
	}
	username, password, found := strings.Cut(string(decoded), ":")
	selection := strings.TrimPrefix(username, "phase.")
	if username == "phase" {
		selection = ""
	} else if selection == username || !controlIdentifier.MatchString(selection) {
		return "", "", false
	}
	return password, selection, found && password != ""
}

func cloneUpstreamRequest(req *http.Request) (*http.Request, error) {
	if req.URL == nil || req.URL.User != nil || req.URL.Host == "" {
		return nil, errors.New("invalid upstream request")
	}
	clone := req.Clone(req.Context())
	clone.URL = new(url.URL)
	*clone.URL = *req.URL
	clone.RequestURI = ""
	clone.Header = req.Header.Clone()
	removeHopHeaders(clone.Header)
	clone.Header.Del("Proxy-Authorization")
	// The proxy settles 100-continue with its own client (net/http server on
	// the explicit path, expectContinueBody inside a tunnel). Forwarding Expect
	// would only make the upstream transport wait for a second 100.
	clone.Header.Del("Expect")
	return clone, nil
}

func validWebSocketRequest(request *http.Request) bool {
	if request == nil || request.Method != http.MethodGet || request.ProtoMajor != 1 || request.ProtoMinor != 1 ||
		!headerContainsToken(request.Header, "Connection", "upgrade") || !singleHeaderEquals(request.Header, "Upgrade", "websocket") ||
		!singleHeaderEquals(request.Header, "Sec-WebSocket-Version", "13") {
		return false
	}
	keys := request.Header.Values("Sec-WebSocket-Key")
	if len(keys) != 1 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keys[0]))
	return err == nil && len(decoded) == 16
}

func restoreWebSocketUpgrade(source, target *http.Request) {
	if validWebSocketRequest(source) {
		target.Header.Set("Connection", "Upgrade")
		target.Header.Set("Upgrade", "websocket")
	}
}

// isPresignedSSMDataChannelWebSocket identifies the AWS-issued, short-lived
// StreamUrl used by Session Manager. Keep this exception at the authenticated
// MITM boundary; ordinary unsigned or merely SSM-shaped AWS requests must still
// fail SigV4 injection.
func isPresignedSSMDataChannelWebSocket(request, upstream *http.Request, authentication *tunnelAuthentication, connection agentapi.Connection, now time.Time) bool {
	if authentication == nil || request == nil || upstream == nil || request.URL == nil || upstream.URL == nil ||
		!strings.EqualFold(connection.ServiceType, "aws") || !strings.EqualFold(connection.Injection.Action, "aws_sigv4") ||
		!strings.EqualFold(connection.Protocol, "http") || connection.Injection.ServiceFrom != "host" || connection.Injection.RegionFrom != "host" ||
		!validWebSocketRequest(request) || hasHeader(request.Header, "Authorization") || hasHeader(upstream.Header, "Authorization") ||
		request.URL.Scheme != "https" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 ||
		(request.Body != nil && request.Body != http.NoBody) ||
		request.URL.RawQuery != upstream.URL.RawQuery || request.URL.EscapedPath() != upstream.URL.EscapedPath() {
		return false
	}
	region, ok := ssmMessagesRegion(request.URL.Hostname())
	if !ok || !strings.EqualFold(request.URL.Hostname(), upstream.URL.Hostname()) {
		return false
	}
	const prefix = "/v1/data-channel/"
	channelID, found := strings.CutPrefix(request.URL.EscapedPath(), prefix)
	if !found || channelID == "" || len(channelID) > 256 {
		return false
	}
	for _, character := range channelID {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return validSSMPresignedQuery(request.URL.RawQuery, region, now)
}

func hasHeader(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func ssmMessagesRegion(host string) (string, bool) {
	if host == "" || strings.HasSuffix(host, ".") || host != strings.ToLower(host) {
		return "", false
	}
	labels := strings.Split(host, ".")
	standard := len(labels) == 4 && labels[2] == "amazonaws" && labels[3] == "com"
	china := len(labels) == 5 && labels[2] == "amazonaws" && labels[3] == "com" && labels[4] == "cn"
	if (!standard && !china) || (labels[0] != "ssmmessages" && labels[0] != "ssmmessages-fips") {
		return "", false
	}
	parts := strings.Split(labels[1], "-")
	if len(parts) < 3 {
		return "", false
	}
	switch parts[0] {
	case "af", "ap", "ca", "cn", "eu", "eusc", "il", "me", "mx", "sa", "us":
	default:
		return "", false
	}
	if _, err := strconv.ParseUint(parts[len(parts)-1], 10, 8); err != nil {
		return "", false
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" {
			return "", false
		}
		for _, character := range part {
			if character < 'a' || character > 'z' {
				return "", false
			}
		}
	}
	return labels[1], true
}

func validSSMPresignedQuery(rawQuery, region string, now time.Time) bool {
	if rawQuery == "" || len(rawQuery) > 16<<10 {
		return false
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return false
	}
	for _, field := range strings.Split(rawQuery, "&") {
		key, _, found := strings.Cut(field, "=")
		if !found || key == "" || strings.ContainsAny(key, "%+") {
			return false
		}
	}
	allowed := map[string]struct{}{
		"role": {}, "cell-number": {}, "X-Amz-Algorithm": {}, "X-Amz-Credential": {}, "X-Amz-Date": {},
		"X-Amz-Expires": {}, "X-Amz-SignedHeaders": {}, "X-Amz-Signature": {}, "X-Amz-Security-Token": {},
	}
	for key, values := range query {
		if _, ok := allowed[key]; !ok || len(values) != 1 || values[0] == "" {
			return false
		}
	}
	single := func(key string) (string, bool) {
		values, found := query[key]
		if !found || len(values) != 1 {
			return "", false
		}
		return values[0], true
	}
	role, roleOK := single("role")
	cellNumber, cellOK := single("cell-number")
	algorithm, algorithmOK := single("X-Amz-Algorithm")
	credential, credentialOK := single("X-Amz-Credential")
	dateValue, dateOK := single("X-Amz-Date")
	expiresValue, expiresOK := single("X-Amz-Expires")
	signedHeaders, headersOK := single("X-Amz-SignedHeaders")
	signature, signatureOK := single("X-Amz-Signature")
	if !roleOK || !cellOK || !algorithmOK || !credentialOK || !dateOK || !expiresOK || !headersOK || !signatureOK ||
		role != "publish_subscribe" || algorithm != "AWS4-HMAC-SHA256" || signedHeaders != "host" ||
		len(cellNumber) > 4096 || !isPrintableASCIIWithSpace(cellNumber) || len(signature) != 64 || !isLowerHex(signature) {
		return false
	}
	securityToken, tokenOK := single("X-Amz-Security-Token")
	if !tokenOK || len(securityToken) > 8192 || !isPrintableASCII(securityToken) {
		return false
	}
	scope := strings.Split(credential, "/")
	if len(scope) != 5 || !validAWSAccessKeyID(scope[0]) || scope[2] != region || scope[3] != "ssmmessages" || scope[4] != "aws4_request" {
		return false
	}
	signingTime, err := time.Parse("20060102T150405Z", dateValue)
	if err != nil || scope[1] != dateValue[:8] {
		return false
	}
	expires, err := strconv.ParseUint(expiresValue, 10, 16)
	if err != nil || expires == 0 || expires > 300 || strconv.FormatUint(expires, 10) != expiresValue {
		return false
	}
	now = now.UTC()
	return !signingTime.After(now.Add(5*time.Minute)) && !now.After(signingTime.Add(time.Duration(expires)*time.Second).Add(5*time.Minute))
}

func validAWSAccessKeyID(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return false
	}
	return true
}

func isPrintableASCII(value string) bool {
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return value != ""
}

func isPrintableASCIIWithSpace(value string) bool {
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return value != ""
}

func validWebSocketResponse(request *http.Request, response *http.Response) bool {
	if !validWebSocketRequest(request) || response == nil || response.StatusCode != http.StatusSwitchingProtocols ||
		!headerContainsToken(response.Header, "Connection", "upgrade") || !singleHeaderEquals(response.Header, "Upgrade", "websocket") {
		return false
	}
	accept := response.Header.Values("Sec-WebSocket-Accept")
	if len(accept) != 1 {
		return false
	}
	return strings.TrimSpace(accept[0]) == webSocketAccept(request.Header.Get("Sec-WebSocket-Key"))
}

func webSocketAccept(key string) string {
	digest := sha1.Sum([]byte(strings.TrimSpace(key) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) // #nosec G401 -- RFC 6455 mandates SHA-1 here.
	return base64.StdEncoding.EncodeToString(digest[:])
}

func singleHeaderEquals(header http.Header, name, expected string) bool {
	values := header.Values(name)
	return len(values) == 1 && strings.EqualFold(strings.TrimSpace(values[0]), expected)
}

func headerContainsToken(header http.Header, name, expected string) bool {
	for _, value := range header.Values(name) {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), expected) {
				return true
			}
		}
	}
	return false
}

func removeHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

func copyResponse(w http.ResponseWriter, response *http.Response, eventID string) {
	removeHopHeaders(response.Header)
	// Assign keys directly so deliberately non-canonical names (S3 user
	// metadata) reach the client exactly as the upstream sent them.
	for key, values := range response.Header {
		w.Header()[key] = append(w.Header()[key], values...)
	}
	if eventID != "" {
		w.Header().Set(eventIDHeader, eventID)
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func writeProxyError(w http.ResponseWriter, failure *requestFailure) {
	if failure.status == 0 {
		failure.status = http.StatusBadGateway
	}
	contentType, body := proxyFailurePayload(failure)
	setProxyFailureHeaders(w.Header(), failure)
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(failure.status)
	_, _ = w.Write(body)
}

func writeFailureResponse(writer io.Writer, request *http.Request, failure *requestFailure) error {
	contentType, body := proxyFailurePayload(failure)
	response := &http.Response{
		StatusCode: failure.status, Status: fmt.Sprintf("%d %s", failure.status, http.StatusText(failure.status)),
		ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)), Request: request,
	}
	setProxyFailureHeaders(response.Header, failure)
	response.Header.Set("Content-Type", contentType)
	return response.Write(writer)
}

func proxyFailurePayload(failure *requestFailure) (string, []byte) {
	if failure != nil && failure.binding != nil && failure.binding.connection.Injection.Action == "aws_sigv4" {
		code := "PhaseProxyError"
		switch failure.code {
		case "agent_connection_denied":
			code = "PhaseAccessDenied"
		case "credential_minting_blocked", "credential_minting_uninspectable":
			code = "PhaseCredentialMintingBlocked"
		}
		message := failure.message
		if failure.binding.connection.ConnectionID != "" {
			message += " Connection: " + failure.binding.connection.ConnectionID + "."
		}
		if failure.binding.connection.GrantID != "" {
			message += " Grant: " + failure.binding.connection.GrantID + "."
		}
		payload, _ := xml.Marshal(struct {
			XMLName xml.Name `xml:"ErrorResponse"`
			XMLNS   string   `xml:"xmlns,attr"`
			Error   struct {
				Type    string `xml:"Type"`
				Code    string `xml:"Code"`
				Message string `xml:"Message"`
			} `xml:"Error"`
			RequestID string `xml:"RequestId"`
		}{
			XMLNS: "https://phase.dev/agent-proxy/errors/v1",
			Error: struct {
				Type    string `xml:"Type"`
				Code    string `xml:"Code"`
				Message string `xml:"Message"`
			}{Type: "Sender", Code: code, Message: message},
			RequestID: awsFailureRequestID(failure),
		})
		return "text/xml; charset=utf-8", append([]byte(xml.Header), payload...)
	}
	details := map[string]any{}
	if failure != nil && failure.binding != nil {
		details["connectionId"] = failure.binding.connection.ConnectionID
		details["grantId"] = failure.binding.connection.GrantID
	}
	payload, _ := json.Marshal(map[string]any{"error": map[string]any{
		"code": failure.code, "message": failure.message, "retryable": false, "details": details,
	}})
	return "application/json", payload
}

// awsFailureRequestID prefers the proxy event ID so an AWS-shaped error can be
// looked up in the Console like any other proxied request.
func awsFailureRequestID(failure *requestFailure) string {
	if failure.eventID != "" {
		return failure.eventID
	}
	return "phase-" + failure.binding.connection.ConnectionID
}

func setProxyFailureHeaders(header http.Header, failure *requestFailure) {
	if failure == nil {
		return
	}
	header.Set("X-Phase-Error-Code", failure.code)
	if failure.eventID != "" {
		header.Set(eventIDHeader, failure.eventID)
	}
	if failure.binding == nil {
		return
	}
	if controlIdentifier.MatchString(failure.binding.connection.ConnectionID) {
		header.Set("X-Phase-Connection-Id", failure.binding.connection.ConnectionID)
	}
	if controlIdentifier.MatchString(failure.binding.connection.GrantID) {
		header.Set("X-Phase-Grant-Id", failure.binding.connection.GrantID)
	}
}

func copyBidirectional(left, right io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(left, right); done <- struct{}{} }()
	go func() { _, _ = io.Copy(right, left); done <- struct{}{} }()
	<-done
	_ = left.Close()
	_ = right.Close()
	<-done
}
