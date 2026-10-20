package aiproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

func TestOneSessionHTTPAndPostgres(t *testing.T) {
	const (
		capability       = "one-session-capability"
		awsAgentAccessID = "AKIAPHASEDECOY000000"
		awsLiveAccessID  = "AKIALIVEEXAMPLE00000"
		decoyAWSKey      = "phaseTestDecoySecretKey000000000000000"
		liveAWSKey       = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		pgUser           = "agent_db_user"
		pgPassword       = "live-db-password"
		pgDecoy          = "decoy-db-password"
	)
	ca, certPEM, _, err := phaseproxy.GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("CA")
	}
	leaf, err := ca.CertificateForHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	pgListener, pgPasswordSeen, pgQuerySeen := startFakePostgres(t, leaf)
	defer pgListener.Close()
	var awsAuthorization, webSocketAuthorization atomic.Value
	webSocketResult := make(chan error, 1)
	httpUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/data-channel/") {
			webSocketAuthorization.Store(r.Header.Get("Authorization"))
			if !headerContainsToken(r.Header, "Connection", "upgrade") || !singleHeaderEquals(r.Header, "Upgrade", "websocket") {
				http.Error(w, "missing websocket upgrade", http.StatusBadRequest)
				return
			}
			connection, buffered, err := http.NewResponseController(w).Hijack()
			if err != nil {
				webSocketResult <- err
				return
			}
			defer connection.Close()
			_, _ = fmt.Fprintf(buffered, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", webSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
			if err = buffered.Flush(); err == nil {
				message := make([]byte, 4)
				if _, err = io.ReadFull(buffered, message); err == nil {
					_, err = buffered.Write(message)
					if err == nil {
						err = buffered.Flush()
					}
				}
			}
			webSocketResult <- err
			return
		}
		awsAuthorization.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, "<GetCallerIdentityResponse><AccessKeyId>"+awsLiveAccessID+"</AccessKeyId></GetCallerIdentityResponse>")
	}))
	defer httpUpstream.Close()
	httpURL, _ := url.Parse(httpUpstream.URL)
	httpHost, httpPortRaw, _ := net.SplitHostPort(httpURL.Host)
	_, pgPortRaw, _ := net.SplitHostPort(pgListener.Addr().String())

	var eventBodiesMu sync.Mutex
	var eventBodies [][]byte
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/events/") {
			body, _ := io.ReadAll(r.Body)
			eventBodiesMu.Lock()
			eventBodies = append(eventBodies, body)
			eventBodiesMu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := decodeTestSession(t, map[string]any{
		"schemaVersion": 1, "sessionUid": "one-session", "sessionCredential": capability, "expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(), "configGeneration": 1, "configEnv": map[string]string{},
		"connections": []any{
			map[string]any{
				"grantId": "grant-aws", "connectionId": "aws", "credentialId": "aws-cred", "serviceType": "aws", "protocol": "http",
				"hosts":            []any{map[string]any{"match": "exact", "value": httpHost, "port": mustPort(t, httpPortRaw)}},
				"connectionConfig": map[string]any{"service": "ssmmessages", "region": "eu-central-1"},
				"injection":        map[string]any{"action": "aws_sigv4", "serviceFrom": "config", "regionFrom": "config", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"accessKeyId": "access_key_id", "secretAccessKey": "secret_access_key"}}},
				"identifiers":      map[string]string{"access_key_id": awsAgentAccessID}, "decoyMaterial": map[string]string{"secret_access_key": decoyAWSKey},
				"configEnv": map[string]string{"AWS_REGION": "eu-central-1"}, "agentEnv": map[string]string{"AWS_ACCESS_KEY_ID": awsAgentAccessID, "AWS_SECRET_ACCESS_KEY": decoyAWSKey},
				"environmentBindings": []any{
					map[string]any{"name": "AWS_ACCESS_KEY_ID", "action": "set", "source": "identifier", "sourceField": "access_key_id", "sensitive": false, "systemManaged": true},
					map[string]any{"name": "AWS_SECRET_ACCESS_KEY", "action": "set", "source": "decoy", "sourceField": "secret_access_key", "sensitive": true, "systemManaged": true},
					map[string]any{"name": "AWS_REGION", "action": "set", "source": "connection_config", "sourceField": "region", "sensitive": false, "systemManaged": true},
				},
				"secretMaterial": map[string]string{"access_key_id": awsLiveAccessID, "secret_access_key": liveAWSKey},
			},
			map[string]any{
				"grantId": "grant-pg", "connectionId": "pg", "credentialId": "pg-cred", "serviceType": "postgres", "protocol": "postgres",
				"hosts":       []any{map[string]any{"match": "exact", "value": "127.0.0.1", "port": mustPort(t, pgPortRaw)}},
				"injection":   map[string]any{"action": "pg_handshake", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}}},
				"identifiers": map[string]string{"username": pgUser}, "decoyMaterial": map[string]string{"password": pgDecoy},
				"configEnv": map[string]string{}, "agentEnv": map[string]string{"PGUSER": pgUser},
				"environmentBindings": []any{map[string]any{"name": "PGUSER", "action": "set", "source": "identifier", "sourceField": "username", "sensitive": false, "systemManaged": true}},
				"secretMaterial":      map[string]string{"username": pgUser, "password": pgPassword},
			},
		},
	})
	engine := New()
	listenAddresses := unusedTestListenAddresses(t, "127.0.0.1", "127.0.0.1")
	engine.ListenAddress = listenAddresses[0]
	engine.PostgresListenAddress = listenAddresses[1]
	engine.RefreshInterval = time.Hour
	engine.EventFlushInterval = 10 * time.Millisecond
	engine.EventSpoolDirectory = t.TempDir()
	engine.Transport = httpUpstream.Client().Transport
	engine.UpstreamTLSConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	started := make(chan Endpoints, 1)
	engine.OnStarted = func(value Endpoints) { started <- value }
	engine.Stdout = io.Discard
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	caDirectory := t.TempDir()
	certificatePath := filepath.Join(caDirectory, "ca.pem")
	bundlePath := filepath.Join(caDirectory, "ca-bundle.pem")
	if err := os.WriteFile(certificatePath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		done <- engine.Serve(ctx, &airuntime.ProxySession{Config: session, Client: client, CA: ca, CAPaths: phaseproxy.CAPaths{Certificate: certificatePath, Bundle: bundlePath}})
	}()
	var endpoints Endpoints
	select {
	case endpoints = <-started:
	case err := <-done:
		t.Fatalf("engine stopped before protocol listeners started: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("engine did not start protocol listeners")
	}
	if endpoints.PostgresAddress == "" {
		t.Fatalf("protocol listeners missing: %+v", endpoints)
	}

	proxyURL, _ := url.Parse(endpoints.ProxyURL.Reveal())
	runtimeCapability, _ := proxyURL.User.Password()
	if runtimeCapability == capability || runtimeCapability == pgDecoy {
		t.Fatal("HTTP, PostgreSQL, and backend credentials must be pairwise distinct")
	}
	httpClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	request, _ := http.NewRequest(http.MethodGet, httpUpstream.URL+"/?Action=GetCallerIdentity&Version=2011-06-15", nil)
	requestContext, cancelRequest := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancelRequest()
	request = request.WithContext(requestContext)
	payloadHash := sha256.Sum256(nil)
	request.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(payloadHash[:]))
	signingTime := time.Now().UTC()
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: awsAgentAccessID, SecretAccessKey: decoyAWSKey}, request, hex.EncodeToString(payloadHash[:]), "ssmmessages", "eu-central-1", signingTime); err != nil {
		t.Fatal(err)
	}
	decoyAuthorization := request.Header.Get("Authorization")
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read framed AWS response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTP=%d", response.StatusCode)
	}
	if strings.Contains(string(responseBody), awsLiveAccessID) || !strings.Contains(string(responseBody), awsAgentAccessID) {
		t.Fatal("AWS response was not safely redacted before reaching the client")
	}
	if value, _ := awsAuthorization.Load().(string); value == "" || value == decoyAuthorization || !strings.Contains(value, "Credential="+awsLiveAccessID+"/") || strings.Contains(value, awsAgentAccessID) {
		t.Fatalf("AWS request was not re-signed with live material: %q", value)
	}

	webSocketRequest, _ := http.NewRequest(http.MethodGet, httpUpstream.URL+"/v1/data-channel/test", nil)
	webSocketRequest.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(payloadHash[:]))
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: awsAgentAccessID, SecretAccessKey: decoyAWSKey}, webSocketRequest, hex.EncodeToString(payloadHash[:]), "ssmmessages", "eu-central-1", signingTime); err != nil {
		t.Fatal(err)
	}
	decoyWebSocketAuthorization := webSocketRequest.Header.Get("Authorization")
	webSocketRequest.Header.Set("Connection", "Upgrade")
	webSocketRequest.Header.Set("Upgrade", "websocket")
	webSocketRequest.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	webSocketRequest.Header.Set("Sec-WebSocket-Version", "13")
	webSocketResponse, err := httpClient.Do(webSocketRequest)
	if err != nil {
		t.Fatal(err)
	}
	webSocket, ok := webSocketResponse.Body.(io.ReadWriteCloser)
	if !ok || webSocketResponse.StatusCode != http.StatusSwitchingProtocols {
		webSocketResponse.Body.Close()
		t.Fatalf("WebSocket response=%d writable=%t", webSocketResponse.StatusCode, ok)
	}
	if _, err = webSocket.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 4)
	if _, err = io.ReadFull(webSocket, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("WebSocket echo=%q err=%v", echo, err)
	}
	webSocket.Close()
	select {
	case err = <-webSocketResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream WebSocket did not close")
	}
	if value, _ := webSocketAuthorization.Load().(string); value == "" || value == decoyWebSocketAuthorization || !strings.Contains(value, "Credential="+awsLiveAccessID+"/") || strings.Contains(value, awsAgentAccessID) || !strings.Contains(value, "/eu-central-1/ssmmessages/aws4_request") {
		t.Fatalf("WebSocket request was not re-signed with live material: %q", value)
	}

	pgStatuses, pgBackendKey := runPostgresClient(t, endpoints.PostgresAddress, roots, pgUser, pgDecoy, "appdb", "SELECT * FROM reports")
	if pgStatuses["server_version"] != "16.3" {
		t.Fatalf("client did not see the upstream server_version: %v", pgStatuses)
	}
	if !bytes.Equal(pgBackendKey, make([]byte, 8)) {
		t.Fatalf("upstream backend key reached the client: %x", pgBackendKey)
	}
	select {
	case value := <-pgPasswordSeen:
		if value != pgPassword {
			t.Fatalf("PG password=%q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("PG password not seen")
	}
	select {
	case value := <-pgQuerySeen:
		if value != "SELECT * FROM reports" {
			t.Fatalf("PG query=%q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("PG query not seen")
	}

	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	eventBodiesMu.Lock()
	batches := append([][]byte(nil), eventBodies...)
	eventBodiesMu.Unlock()
	for _, body := range batches {
		var batch agentapi.EventBatchRequest
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{capability, runtimeCapability, pgDecoy, pgPassword, awsLiveAccessID, liveAWSKey} {
			if strings.Contains(string(body), forbidden) {
				t.Fatalf("audit event leaked credential %q: %s", forbidden, body)
			}
		}
	}
}

func startFakePostgres(t *testing.T, certificate *tls.Certificate) (net.Listener, <-chan string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	passwords := make(chan string, 1)
	queries := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		request := make([]byte, 8)
		if _, err = io.ReadFull(connection, request); err != nil {
			return
		}
		_, _ = connection.Write([]byte{'S'})
		secure := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{*certificate}, MinVersion: tls.VersionTLS12})
		if secure.Handshake() != nil {
			return
		}
		if _, err = readPGStartup(secure); err != nil {
			return
		}
		_ = writePGAuth(secure, 3, nil)
		kind, payload, err := readPGMessage(secure)
		if err != nil || kind != 'p' {
			return
		}
		passwords <- strings.TrimSuffix(string(payload), "\x00")
		_ = writePGAuth(secure, 0, nil)
		_ = writePGParameter(secure, "server_version", "16.3")
		_ = writePGMessage(secure, 'K', []byte{9, 9, 9, 9, 9, 9, 9, 9})
		_ = writePGMessage(secure, 'Z', []byte{'I'})
		kind, payload, err = readPGMessage(secure)
		if err != nil || kind != 'Q' {
			return
		}
		queries <- strings.TrimSuffix(string(payload), "\x00")
		_ = writePGMessage(secure, 'C', []byte("SELECT 1\x00"))
		_ = writePGMessage(secure, 'Z', []byte{'I'})
		time.Sleep(50 * time.Millisecond)
	}()
	return listener, passwords, queries
}

// runPostgresClient drives a session through the adapter and returns the
// ParameterStatus values and BackendKeyData the client was shown.
func runPostgresClient(t *testing.T, address string, roots *x509.CertPool, user, password, database, query string) (map[string]string, []byte) {
	return runPostgresClientWithServerName(t, address, "127.0.0.1", roots, user, password, database, query)
}

func runPostgresClientWithServerName(t *testing.T, address, serverName string, roots *x509.CertPool, user, password, database, query string) (map[string]string, []byte) {
	t.Helper()
	statuses := map[string]string{}
	var backendKey []byte
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ssl := make([]byte, 8)
	binary.BigEndian.PutUint32(ssl, 8)
	binary.BigEndian.PutUint32(ssl[4:], 80877103)
	_, _ = connection.Write(ssl)
	response := make([]byte, 1)
	_, _ = io.ReadFull(connection, response)
	if response[0] != 'S' {
		t.Fatal("PG TLS rejected")
	}
	secure := tls.Client(connection, &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12})
	if err = secure.Handshake(); err != nil {
		t.Fatal(err)
	}
	_, _ = secure.Write(pgStartupPacket(user, database, nil))
	for {
		kind, payload, err := readPGMessage(secure)
		if err != nil {
			t.Fatal(err)
		}
		if kind == 'R' && binary.BigEndian.Uint32(payload) == 3 {
			_ = writePGMessage(secure, 'p', []byte(password+"\x00"))
		}
		if kind == 'S' {
			if parts := bytesSplitNUL(payload); len(parts) >= 2 {
				statuses[parts[0]] = parts[1]
			}
		}
		if kind == 'K' {
			backendKey = append([]byte(nil), payload...)
		}
		if kind == 'E' {
			t.Fatalf("PG auth error: %q", payload)
		}
		if kind == 'Z' {
			break
		}
	}
	_ = writePGMessage(secure, 'Q', []byte(query+"\x00"))
	for {
		kind, payload, err := readPGMessage(secure)
		if err != nil {
			t.Fatal(err)
		}
		if kind == 'E' {
			t.Fatalf("PG query error: %q", payload)
		}
		if kind == 'Z' {
			break
		}
	}
	return statuses, backendKey
}
