package aiproxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/phasehq/cli/internal/agentapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type oneByteReader struct{ reader *strings.Reader }

func (reader *oneByteReader) Read(destination []byte) (int, error) {
	if len(destination) > 1 {
		destination = destination[:1]
	}
	return reader.reader.Read(destination)
}

func TestWebSocketUpgradeRestoresOnlyCanonicalHopHeaders(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "https://ssmmessages.eu-central-1.amazonaws.com/v1/data-channel/test", nil)
	request.Header.Set("Connection", "keep-alive, Upgrade, X-Remove")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Keep-Alive", "timeout=5")
	request.Header.Set("Proxy-Authorization", "secret")
	request.Header.Set("X-Remove", "nominated-hop-header")

	upstream, err := cloneUpstreamRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	restoreWebSocketUpgrade(request, upstream)
	if upstream.Header.Get("Connection") != "Upgrade" || upstream.Header.Get("Upgrade") != "websocket" {
		t.Fatalf("canonical upgrade headers missing: %v", upstream.Header)
	}
	for _, name := range []string{"Keep-Alive", "Proxy-Authorization", "X-Remove"} {
		if upstream.Header.Get(name) != "" {
			t.Fatalf("unsafe hop header %s survived: %v", name, upstream.Header)
		}
	}

	request.Header.Add("Upgrade", "h2c")
	malformed, err := cloneUpstreamRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	restoreWebSocketUpgrade(request, malformed)
	if malformed.Header.Get("Connection") != "" || malformed.Header.Get("Upgrade") != "" {
		t.Fatalf("ambiguous upgrade headers were restored: %v", malformed.Header)
	}
}

func TestPresignedSSMDataChannelWebSocketIsNarrowlyScoped(t *testing.T) {
	now := time.Date(2026, time.August, 13, 12, 34, 56, 0, time.UTC)
	connection := agentapi.Connection{
		ServiceType: "aws", Protocol: "http",
		Injection: agentapi.Injection{Action: "aws_sigv4", ServiceFrom: "host", RegionFrom: "host"},
	}
	newRequest := func(rawQuery string) (*http.Request, *http.Request) {
		request, err := http.NewRequest(http.MethodGet, "https://ssmmessages.eu-central-1.amazonaws.com/v1/data-channel/session-012345?"+rawQuery, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.ProtoMajor, request.ProtoMinor = 1, 1
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
		request.Header.Set("Sec-WebSocket-Version", "13")
		upstream, err := cloneUpstreamRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		restoreWebSocketUpgrade(request, upstream)
		return request, upstream
	}
	query := url.Values{
		"role":                 {"publish_subscribe"},
		"cell-number":          {"AAECAwQF cell"},
		"X-Amz-Algorithm":      {"AWS4-HMAC-SHA256"},
		"X-Amz-Credential":     {"ASIAPHASEEXAMPLE1/20260813/eu-central-1/ssmmessages/aws4_request"},
		"X-Amz-Date":           {"20260813T123456Z"},
		"X-Amz-Expires":        {"60"},
		"X-Amz-SignedHeaders":  {"host"},
		"X-Amz-Signature":      {strings.Repeat("a", 64)},
		"X-Amz-Security-Token": {"temporary/session+token="},
	}.Encode()
	query = strings.Replace(query, "cell-number=AAECAwQF+cell", "cell-number=AAECAwQF%20cell", 1)
	request, upstream := newRequest(query)
	if !isPresignedSSMDataChannelWebSocket(request, upstream, &tunnelAuthentication{}, connection, now) {
		t.Fatal("valid AWS presigned SSM data-channel WebSocket was rejected")
	}

	tests := map[string]func(*http.Request, *http.Request){
		"not authenticated MITM": func(*http.Request, *http.Request) {},
		"authorization header":   func(request, _ *http.Request) { request.Header.Set("Authorization", "AWS4-HMAC-SHA256 invalid") },
		"authorization smuggling": func(request, _ *http.Request) {
			request.Header.Set("Authorization", "AWS4-HMAC-SHA256 invalid")
			request.Header.Set("Connection", "Upgrade, Authorization")
		},
		"wrong host": func(request, upstream *http.Request) {
			request.URL.Host = "ssmmessages.eu-central-1.amazonaws.com.attacker.test"
			upstream.URL.Host = request.URL.Host
		},
		"wrong path": func(request, upstream *http.Request) {
			request.URL.Path = "/v1/data-channel/session-012345/extra"
			upstream.URL.Path = request.URL.Path
		},
		"wrong method":          func(request, _ *http.Request) { request.Method = http.MethodPost },
		"wrong service binding": func(*http.Request, *http.Request) {},
		"missing token": func(request, upstream *http.Request) {
			values := request.URL.Query()
			values.Del("X-Amz-Security-Token")
			request.URL.RawQuery = values.Encode()
			upstream.URL.RawQuery = request.URL.RawQuery
		},
		"duplicate signature": func(request, upstream *http.Request) {
			request.URL.RawQuery += "&X-Amz-Signature=" + strings.Repeat("b", 64)
			upstream.URL.RawQuery = request.URL.RawQuery
		},
		"case ambiguous auth field": func(request, upstream *http.Request) {
			request.URL.RawQuery += "&x-amz-signature=" + strings.Repeat("b", 64)
			upstream.URL.RawQuery = request.URL.RawQuery
		},
		"wrong credential region": func(request, upstream *http.Request) {
			values := request.URL.Query()
			values.Set("X-Amz-Credential", "ASIAPHASEEXAMPLE1/20260813/us-east-1/ssmmessages/aws4_request")
			request.URL.RawQuery = values.Encode()
			upstream.URL.RawQuery = request.URL.RawQuery
		},
		"excessive expiry": func(request, upstream *http.Request) {
			values := request.URL.Query()
			values.Set("X-Amz-Expires", "301")
			request.URL.RawQuery = values.Encode()
			upstream.URL.RawQuery = request.URL.RawQuery
		},
		"unknown query field": func(request, upstream *http.Request) {
			request.URL.RawQuery += "&debug=true"
			upstream.URL.RawQuery = request.URL.RawQuery
		},
		"query mutation": func(_ *http.Request, upstream *http.Request) {
			upstream.URL.RawQuery += "&debug=true"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request, upstream := newRequest(query)
			mutate(request, upstream)
			authentication := &tunnelAuthentication{}
			candidateConnection := connection
			if name == "not authenticated MITM" {
				authentication = nil
			}
			if name == "wrong service binding" {
				candidateConnection.ServiceType = "github"
			}
			if isPresignedSSMDataChannelWebSocket(request, upstream, authentication, candidateConnection, now) {
				t.Fatal("invalid presigned SSM WebSocket was accepted")
			}
		})
	}
}

func TestPresignedSSMDataChannelWebSocketBypassesOnlySigV4Injection(t *testing.T) {
	now := time.Now().UTC()
	streamAccessKeyID := "ASIAPHASEEXAMPLE1"
	fakeAccessKeyID := "AKIAPHASESSMDECOY00"
	liveAccessKeyID := "AKIALIVESSMEXAMPLE00"
	connection := map[string]any{
		"grantId": "grant-ssm", "connectionId": "aws", "credentialId": "aws-credential",
		"serviceType": "aws", "protocol": "http",
		"hosts": []any{map[string]any{"match": "exact", "value": "ssmmessages.eu-central-1.amazonaws.com", "port": 443}},
		"injection": map[string]any{
			"action": "aws_sigv4", "serviceFrom": "host", "regionFrom": "host",
			"valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"accessKeyId": "access_key_id", "secretAccessKey": "secret_access_key"}},
		},
		"identifiers":    map[string]string{"access_key_id": fakeAccessKeyID},
		"decoyMaterial":  map[string]string{"secret_access_key": "phaseSSMDecoySecret00000000000000000000"},
		"agentEnv":       map[string]string{"AWS_ACCESS_KEY_ID": fakeAccessKeyID, "AWS_SECRET_ACCESS_KEY": "phaseSSMDecoySecret00000000000000000000"},
		"secretMaterial": map[string]string{"access_key_id": liveAccessKeyID, "secret_access_key": "phaseSSMLiveSecret000000000000000000000"},
		"authorization":  map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
	}
	console := httptest.NewServer(http.NotFoundHandler())
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, map[string]any{
		"schemaVersion": 1, "sessionUid": "presigned-ssm-session", "sessionCredential": "ssm-backend-capability",
		"expiresAt": now.Add(time.Hour), "maxExpiresAt": now.Add(2 * time.Hour), "configGeneration": 1,
		"configEnv": map[string]string{}, "connections": []any{connection},
	}, "ssm-runtime-capability")
	defer state.destroy()
	var upstreamCalls atomic.Int32
	var upstreamQuery string
	proxy := &httpProxy{state: state, transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		upstreamQuery = request.URL.RawQuery
		return &http.Response{StatusCode: http.StatusBadRequest, Body: http.NoBody}, nil
	})}
	query := url.Values{
		"role": {"publish_subscribe"}, "cell-number": {"cell/example+value="},
		"X-Amz-Algorithm":  {"AWS4-HMAC-SHA256"},
		"X-Amz-Credential": {streamAccessKeyID + "/" + now.Format("20060102") + "/eu-central-1/ssmmessages/aws4_request"},
		"X-Amz-Date":       {now.Format("20060102T150405Z")}, "X-Amz-Expires": {"60"}, "X-Amz-SignedHeaders": {"host"},
		"X-Amz-Signature": {strings.Repeat("a", 64)}, "X-Amz-Security-Token": {"temporary/session+token="},
	}.Encode()
	request, _ := http.NewRequest(http.MethodGet, "https://ssmmessages.eu-central-1.amazonaws.com/v1/data-channel/session-012345?"+query, nil)
	request.ProtoMajor, request.ProtoMinor = 1, 1
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	request.Header.Set("Sec-WebSocket-Version", "13")
	result := proxy.process(request, &tunnelAuthentication{})
	if result.response != nil {
		result.response.Body.Close()
	}
	if result.failure != nil || upstreamCalls.Load() != 1 || result.event.CredentialAction != awsSSMTokenCredentialAction || upstreamQuery != query {
		t.Fatalf("presigned result failure=%v calls=%d action=%q query_mutated=%t", result.failure, upstreamCalls.Load(), result.event.CredentialAction, upstreamQuery != query)
	}

	unsigned, _ := http.NewRequest(http.MethodGet, "https://ssmmessages.eu-central-1.amazonaws.com/v1/data-channel/session-012345?role=publish_subscribe", nil)
	unsigned.ProtoMajor, unsigned.ProtoMinor = 1, 1
	unsigned.Header = request.Header.Clone()
	failed := proxy.process(unsigned, &tunnelAuthentication{})
	if failed.response != nil {
		failed.response.Body.Close()
	}
	if failed.failure == nil || failed.failure.reason != "credential_swap_failed" || upstreamCalls.Load() != 1 {
		t.Fatalf("generic unsigned SSM request failure=%v calls=%d", failed.failure, upstreamCalls.Load())
	}
}

func TestWebSocketClosesWhenBindingBecomesInvalid(t *testing.T) {
	console := httptest.NewServer(http.NotFoundHandler())
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, map[string]any{
		"schemaVersion": 1, "sessionUid": "websocket-session", "sessionCredential": "websocket-backend-capability",
		"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
		"configGeneration": 1, "configEnv": map[string]string{},
		"connections": []any{map[string]any{
			"grantId": "grant-websocket", "connectionId": "connection-websocket", "credentialId": "credential-websocket",
			"serviceType": "github", "protocol": "http", "hosts": []any{map[string]any{"match": "exact", "value": "example.test", "port": 443}},
			"injection":     map[string]any{"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}", "valueFrom": map[string]any{"source": "credential", "field": "access_token"}},
			"decoyMaterial": map[string]string{"access_token": "decoy-token"}, "agentEnv": map[string]string{}, "secretMaterial": map[string]string{"access_token": "live-token"},
		}},
	}, "websocket-runtime-capability")
	defer state.destroy()
	snapshot, err := state.protocolBinding("grant-websocket", "http")
	if err != nil {
		t.Fatal(err)
	}
	clientPeer, clientSide := net.Pipe()
	upstreamPeer, upstreamSide := net.Pipe()
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&httpProxy{state: state}).watchWebSocket(context.Background(), clientSide, upstreamSide, snapshot, make(chan struct{}))
	}()
	state.setUnhealthy()
	_ = clientPeer.SetReadDeadline(time.Now().Add(time.Second))
	_ = upstreamPeer.SetReadDeadline(time.Now().Add(time.Second))
	for name, connection := range map[string]net.Conn{"client": clientPeer, "upstream": upstreamPeer} {
		if _, err := connection.Read(make([]byte, 1)); err == nil {
			t.Fatalf("%s WebSocket side remained open", name)
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WebSocket watcher did not stop")
	}
}

func TestWebSocketRejectsHandshakeAcrossBindingGenerationChange(t *testing.T) {
	console := httptest.NewServer(http.NotFoundHandler())
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"schemaVersion": 1, "sessionUid": "websocket-generation", "sessionCredential": "websocket-backend-capability",
		"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
		"configGeneration": 1, "configEnv": map[string]string{},
		"connections": []any{map[string]any{
			"grantId": "grant-websocket", "connectionId": "connection-websocket", "credentialId": "credential-websocket",
			"serviceType": "github", "protocol": "http", "hosts": []any{map[string]any{"match": "exact", "value": "example.test", "port": 443}},
			"injection":     map[string]any{"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}", "valueFrom": map[string]any{"source": "credential", "field": "access_token"}},
			"decoyMaterial": map[string]string{"access_token": "decoy-token"}, "agentEnv": map[string]string{}, "secretMaterial": map[string]string{"access_token": "live-token"},
		}},
	}
	state := controlRuntimeState(t, client, payload, "websocket-runtime-capability")
	defer state.destroy()
	snapshot, err := state.protocolBinding("grant-websocket", "http")
	if err != nil {
		t.Fatal(err)
	}
	payload["configGeneration"] = 2
	refreshed := decodeTestSession(t, payload)
	if err = state.replaceConfig(&refreshed.SessionConfig); err != nil {
		t.Fatal(err)
	}
	if err = state.validateProtocolBinding(snapshot); err == nil {
		t.Fatal("pre-rotation WebSocket snapshot survived a generation change")
	}
}

func TestConnectionAuthorizationContractFailsClosed(t *testing.T) {
	base := agentapi.Connection{
		GrantID: "grant-1", ConnectionID: "connection-1", CredentialID: "credential-1",
		CredentialProvider: "github", CredentialName: "GitHub test credential", ServiceType: "github", Protocol: "http",
		Hosts:     []agentapi.HostRule{{Match: "exact", Value: "api.example.test", Port: 443}},
		Injection: agentapi.Injection{Action: "set_header"},
	}
	if _, err := parseBindings([]agentapi.Connection{base}); err == nil {
		t.Fatal("missing connection authorization was accepted")
	}
	unknown := base
	unknown.Authorization = agentapi.ConnectionAuthorization{Version: 1, Mode: "operation", AccessMode: "allow", State: "allowed"}
	if _, err := parseBindings([]agentapi.Connection{unknown}); err == nil {
		t.Fatal("unknown connection authorization mode was accepted")
	}
	unsupported := base
	unsupported.Authorization = agentapi.ConnectionAuthorization{Version: 1, Mode: "connection", AccessMode: "future_mode", State: "future_state"}
	if _, err := parseBindings([]agentapi.Connection{unsupported}); err == nil {
		t.Fatal("unsupported connection authorization was accepted")
	}
}

func TestAWSConnectionDeniedErrorUsesNativeXML(t *testing.T) {
	binding := &binding{connection: agentapi.Connection{
		GrantID: "grant-aws", ConnectionID: "connection-aws",
		Injection: agentapi.Injection{Action: "aws_sigv4"},
	}}
	recorder := httptest.NewRecorder()
	writeProxyError(recorder, &requestFailure{
		status: http.StatusForbidden, code: "agent_connection_denied",
		message: "This Agent is not authorized to use the connection.", binding: binding,
	})
	body := recorder.Body.String()
	if recorder.Code != http.StatusForbidden || !strings.HasPrefix(recorder.Header().Get("Content-Type"), "text/xml") ||
		!strings.Contains(body, "<Code>PhaseAccessDenied</Code>") ||
		!strings.Contains(body, "connection-aws") || !strings.Contains(body, "grant-aws") {
		t.Fatalf("AWS denial response status=%d headers=%v body=%s", recorder.Code, recorder.Header(), body)
	}
}

func TestAWSSigV4FailureSubtypeIsAudited(t *testing.T) {
	const (
		fakeAccessKeyID = "AKIAPHASEFAILURE0000"
		liveAccessKeyID = "AKIALIVEFAILURE00000"
		decoySecret     = "phaseFailureDecoySecret0000000000000000"
		liveSecret      = "phaseFailureLiveSecret00000000000000000"
	)
	console := httptest.NewServer(http.NotFoundHandler())
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, map[string]any{
		"schemaVersion": 1, "sessionUid": "sigv4-failure-session", "sessionCredential": "sigv4-backend-capability",
		"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
		"configGeneration": 1, "configEnv": map[string]string{},
		"connections": []any{map[string]any{
			"grantId": "grant-aws", "connectionId": "aws", "credentialId": "aws-credential",
			"serviceType": "aws", "protocol": "http",
			"hosts":            []any{map[string]any{"match": "exact", "value": "sts.example.test", "port": 443}},
			"connectionConfig": map[string]any{"service": "sts", "region": "us-east-1"},
			"injection": map[string]any{
				"action": "aws_sigv4", "serviceFrom": "config", "regionFrom": "config",
				"valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"accessKeyId": "access_key_id", "secretAccessKey": "secret_access_key"}},
			},
			"identifiers":    map[string]string{"access_key_id": fakeAccessKeyID},
			"decoyMaterial":  map[string]string{"secret_access_key": decoySecret},
			"agentEnv":       map[string]string{"AWS_ACCESS_KEY_ID": fakeAccessKeyID, "AWS_SECRET_ACCESS_KEY": decoySecret},
			"secretMaterial": map[string]string{"access_key_id": liveAccessKeyID, "secret_access_key": liveSecret},
			"authorization":  map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
		}},
	}, "sigv4-runtime-capability")
	defer state.destroy()
	var upstreamCalls atomic.Int32
	proxy := &httpProxy{state: state, transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
	})}
	request, _ := http.NewRequest(http.MethodGet, "https://sts.example.test/?Action=GetCallerIdentity", nil)
	result := proxy.process(request, nil)
	if result.failure == nil || result.failure.reason != "credential_swap_failed" {
		t.Fatalf("failure=%+v", result.failure)
	}
	if got := result.event.Detail["aws_sigv4_failure"]; got != string(phaseproxy.AWSSigV4MissingAuthorization) {
		t.Fatalf("AWS failure audit detail=%v", result.event.Detail)
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("unsigned AWS request reached upstream %d times", upstreamCalls.Load())
	}
}

func TestAWSSigV4UpstreamResponseRedactsAllLiveMaterial(t *testing.T) {
	const (
		fakeAccessKeyID = "AKIAPHASEDECOY000000"
		liveAccessKeyID = "AKIALIVEEXAMPLE00000"
		decoySecret     = "phaseResponseDecoySecret000000000000000"
		liveSecret      = "phaseResponseLiveSecret0000000000000000"
		decoyToken      = "phase-response-decoy-session-token"
		liveToken       = "phase-response-live-session-token"
	)
	console := httptest.NewServer(http.NotFoundHandler())
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, map[string]any{
		"schemaVersion": 1, "sessionUid": "response-redaction", "sessionCredential": "response-backend-capability",
		"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
		"configGeneration": 1, "configEnv": map[string]string{},
		"connections": []any{map[string]any{
			"grantId": "grant-aws", "connectionId": "aws", "credentialId": "aws-credential",
			"credentialName": "AWS response test", "credentialProvider": "aws", "serviceType": "aws", "protocol": "http",
			"hosts":            []any{map[string]any{"match": "exact", "value": "sts.example.test", "port": 443}},
			"connectionConfig": map[string]any{"service": "sts", "region": "us-east-1"},
			"injection": map[string]any{
				"action": "aws_sigv4", "serviceFrom": "config", "regionFrom": "config",
				"valueFrom": map[string]any{"source": "credential", "fields": map[string]string{
					"accessKeyId": "access_key_id", "secretAccessKey": "secret_access_key", "sessionToken": "session_token",
				}},
			},
			"identifiers":   map[string]string{"access_key_id": fakeAccessKeyID},
			"decoyMaterial": map[string]string{"secret_access_key": decoySecret, "session_token": decoyToken},
			"agentEnv": map[string]string{
				"AWS_ACCESS_KEY_ID": fakeAccessKeyID, "AWS_SECRET_ACCESS_KEY": decoySecret, "AWS_SESSION_TOKEN": decoyToken,
			},
			"secretMaterial": map[string]string{
				"access_key_id": liveAccessKeyID, "secret_access_key": liveSecret, "session_token": liveToken,
			},
			"authorization": map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
		}},
	}, "response-runtime-capability")
	defer state.destroy()
	emptyPayloadHash := sha256.Sum256(nil)
	emptyPayloadHashHex := hex.EncodeToString(emptyPayloadHash[:])

	newRequest := func() *http.Request {
		request, _ := http.NewRequest(http.MethodGet, "https://sts.example.test/?Action=GetCallerIdentity", nil)
		request.Header.Set("X-Amz-Content-Sha256", emptyPayloadHashHex)
		if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{
			AccessKeyID: fakeAccessKeyID, SecretAccessKey: decoySecret, SessionToken: decoyToken,
		}, request, emptyPayloadHashHex, "sts", "us-east-1", time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		return request
	}
	liveEcho := strings.Join([]string{liveAccessKeyID, liveSecret, liveToken}, "|")
	proxy := &httpProxy{state: state, transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Accept-Encoding") != "identity" ||
			!strings.Contains(request.Header.Get("Authorization"), "Credential="+liveAccessKeyID+"/") ||
			request.Header.Get("X-Amz-Security-Token") != liveToken {
			t.Errorf("upstream request was not safely re-signed: %v", request.Header)
		}
		return &http.Response{
			StatusCode: http.StatusForbidden, Status: "403 AccessDenied " + liveAccessKeyID,
			Header:  http.Header{"X-Aws-Echo": []string{liveEcho}, "Content-Type": []string{"application/xml"}},
			Trailer: http.Header{"X-Aws-Trailer": []string{liveToken + "|" + liveSecret}},
			Body:    io.NopCloser(&oneByteReader{reader: strings.NewReader("<Error>" + liveEcho + "</Error>")}),
		}, nil
	})}
	result := proxy.process(newRequest(), nil)
	if result.failure != nil {
		t.Fatalf("AWS response was rejected: %+v", result.failure)
	}
	body, err := io.ReadAll(result.response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = result.response.Body.Close()
	visible := result.response.Status + " " + result.response.Header.Get("X-Aws-Echo") + " " +
		result.response.Trailer.Get("X-Aws-Trailer") + " " + string(body)
	for _, live := range []string{liveAccessKeyID, liveSecret, liveToken} {
		if strings.Contains(visible, live) {
			t.Fatalf("AWS response leaked live material: %s", visible)
		}
	}
	for _, safe := range []string{fakeAccessKeyID, decoySecret, decoyToken} {
		if !strings.Contains(visible, safe) {
			t.Fatalf("AWS response did not preserve safe replacement %q: %s", safe, visible)
		}
	}

	proxy.transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusForbidden, Header: http.Header{"Content-Encoding": []string{"gzip"}},
			Body: io.NopCloser(strings.NewReader(liveEcho)),
		}, nil
	})
	encoded := proxy.process(newRequest(), nil)
	if encoded.failure == nil || encoded.failure.code != "unsafe_aws_response" || encoded.response != nil {
		t.Fatalf("encoded AWS response did not fail closed: %+v", encoded)
	}
}

func TestCopyResponseWritesHeaderNamesVerbatim(t *testing.T) {
	recorder := httptest.NewRecorder()
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"x-amz-meta-owner": {"claude"}, "Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("ok")),
	}
	copyResponse(recorder, response, "event-test-1234")
	if got := recorder.Header()["x-amz-meta-owner"]; len(got) != 1 || got[0] != "claude" {
		t.Fatalf("lowercase metadata header was not preserved: %#v", recorder.Header())
	}
	if got := recorder.Header().Get(eventIDHeader); got != "event-test-1234" {
		t.Fatalf("event ID header = %q", got)
	}
	if _, canonicalized := recorder.Header()["X-Amz-Meta-Owner"]; canonicalized {
		t.Fatalf("metadata header was canonicalized: %#v", recorder.Header())
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestAWSSigV4IsNotSentOverPlaintextHTTP(t *testing.T) {
	const (
		fakeAccessKeyID = "AKIAPHASEPLAINTEXT00"
		liveAccessKeyID = "AKIALIVEPLAINTEXT000"
		decoySecret     = "phasePlaintextDecoySecret00000000000000"
	)
	console := httptest.NewServer(http.NotFoundHandler())
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	state := controlRuntimeState(t, client, map[string]any{
		"schemaVersion": 1, "sessionUid": "plaintext-session", "sessionCredential": "plaintext-backend-capability",
		"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
		"configGeneration": 1, "configEnv": map[string]string{},
		"connections": []any{map[string]any{
			"grantId": "grant-aws", "connectionId": "aws", "credentialId": "aws-credential",
			"serviceType": "aws", "protocol": "http",
			"hosts":            []any{map[string]any{"match": "suffix", "value": ".example.test"}, map[string]any{"match": "exact", "value": "127.0.0.1"}},
			"connectionConfig": map[string]any{"service": "sts", "region": "us-east-1"},
			"injection": map[string]any{
				"action": "aws_sigv4", "serviceFrom": "config", "regionFrom": "config",
				"valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"accessKeyId": "access_key_id", "secretAccessKey": "secret_access_key"}},
			},
			"identifiers":    map[string]string{"access_key_id": fakeAccessKeyID},
			"decoyMaterial":  map[string]string{"secret_access_key": decoySecret},
			"agentEnv":       map[string]string{"AWS_ACCESS_KEY_ID": fakeAccessKeyID, "AWS_SECRET_ACCESS_KEY": decoySecret},
			"secretMaterial": map[string]string{"access_key_id": liveAccessKeyID, "secret_access_key": "phasePlaintextLiveSecret000000000000000"},
		}},
	}, "plaintext-runtime-capability")
	defer state.destroy()
	var sent []string
	proxy := &httpProxy{state: state, transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		sent = append(sent, request.URL.Scheme+"://"+request.URL.Host)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})}
	emptyPayloadHash := sha256.Sum256(nil)
	process := func(target string) processedResponse {
		request, _ := http.NewRequest(http.MethodGet, target+"/?Action=GetCallerIdentity", nil)
		request.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(emptyPayloadHash[:]))
		if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: fakeAccessKeyID, SecretAccessKey: decoySecret},
			request, hex.EncodeToString(emptyPayloadHash[:]), "sts", "us-east-1", time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		result := proxy.process(request, nil)
		if result.response != nil {
			result.response.Body.Close()
		}
		return result
	}
	for _, target := range []string{"http://sts.example.test:443", "http://sts.example.test"} {
		if result := process(target); result.failure == nil || result.failure.status != http.StatusForbidden || result.event.ProxyDecision != "block" {
			t.Fatalf("%s: plaintext AWS request was not refused: %+v", target, result.failure)
		}
	}
	if len(sent) != 0 {
		t.Fatalf("signed AWS requests were sent in plaintext: %v", sent)
	}
	for _, target := range []string{"https://sts.example.test", "http://127.0.0.1:4566"} {
		if result := process(target); result.failure != nil {
			t.Fatalf("%s: AWS request was refused: %+v", target, result.failure)
		}
	}
	if strings.Join(sent, " ") != "https://sts.example.test http://127.0.0.1:4566" {
		t.Fatalf("upstream requests=%v", sent)
	}
}
