package aiproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

func TestRemoteProxyTLSBootstrapAndPostgres(t *testing.T) {
	const (
		advertisedHost = "remote.phase.test"
		capability     = "remote-session-capability"
		pgUser         = "remote_db_user"
		pgPassword     = "remote-live-db-password"
		pgDecoy        = "remote-decoy-db-password"
	)
	outerCertPath, outerKeyPath, outerRoots := writeRemoteTLSIdentity(t, advertisedHost)
	proxyCA, proxyCAPEM, _, err := phaseproxy.GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AppendCertsFromPEM(proxyCAPEM)
	upstreamLeaf, err := proxyCA.CertificateForHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pgListener, pgPasswordSeen, pgQuerySeen := startFakePostgres(t, upstreamLeaf)
	defer pgListener.Close()
	var unboundRequests atomic.Int32
	unboundUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		unboundRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer unboundUpstream.Close()
	_, unboundPort, _ := net.SplitHostPort(unboundUpstream.Listener.Addr().String())
	publicUnboundURL := "http://" + net.JoinHostPort("public-unbound.example", unboundPort)
	rebindingURL := "http://" + net.JoinHostPort("rebind-unbound.example", unboundPort)
	_, pgPortRaw, _ := net.SplitHostPort(pgListener.Addr().String())

	var unsafeDiscover atomic.Bool
	var refreshResponse atomic.Value
	var approvalOrigin string
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/config/"):
			payload, _ := refreshResponse.Load().([]byte)
			if len(payload) == 0 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write(payload)
		case strings.HasSuffix(r.URL.Path, "/context/"):
			if r.Header.Get(agentapi.SessionCredentialHeader) != capability {
				t.Errorf("context #1=%q", r.Header.Get(agentapi.SessionCredentialHeader))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": 1, "sessionUid": "remote-session", "markdown": "remote-safe context"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/requests/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "remote-request", "status": "pending", "kind": "credential_update",
				"connectionId": "pg", "credentialId": "pg-cred", "credentialProvider": "postgres", "credentialName": "Test postgres credential", "grantId": "grant-pg",
				"approvalUrl": approvalOrigin + "/phase/agents/requests?request=remote-request",
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/requests/remote-request/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "remote-request", "status": "approved", "kind": "credential_update",
				"connectionId": "pg", "credentialId": "pg-cred", "credentialProvider": "postgres", "credentialName": "Test postgres credential", "grantId": "grant-pg",
			})
		case strings.HasSuffix(r.URL.Path, "/discover/"):
			if r.Header.Get(agentapi.SessionCredentialHeader) != capability {
				t.Errorf("discover #1=%q", r.Header.Get(agentapi.SessionCredentialHeader))
			}
			pgEnvironment := map[string]string{"PGUSER": pgUser}
			if unsafeDiscover.Load() {
				pgEnvironment["UNSAFE_LIVE_PASSWORD"] = pgPassword
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 1, "sessionUid": "remote-session", "configGeneration": 1,
				"configEnv": map[string]string{},
				"connections": []any{
					map[string]any{"grantId": "grant-pg", "connectionId": "pg", "credentialId": "pg-cred", "credentialProvider": "postgres", "credentialName": "Test postgres credential", "credentialRevision": "credential-v1", "serviceType": "postgres", "protocol": "postgres", "hosts": []any{map[string]any{"match": "exact", "value": "127.0.0.1", "port": mustPort(t, pgPortRaw)}}, "injection": map[string]any{"action": "pg_handshake", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}}}, "identifiers": map[string]string{"username": pgUser}, "decoyMaterial": map[string]string{"password": pgDecoy}, "configEnv": map[string]string{}, "agentEnv": pgEnvironment, "environmentBindings": []any{map[string]any{"name": "PGUSER", "action": "set", "source": "identifier", "sourceField": "username", "sensitive": false, "systemManaged": true}}},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/events/"):
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"schemaVersion":1,"accepted":1,"duplicates":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer console.Close()
	approvalOrigin = console.URL
	client, err := agentapi.NewClient(console.URL, remoteAgentToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	sessionPayload := map[string]any{
		"schemaVersion": 1, "sessionUid": "remote-session", "sessionCredential": capability,
		"expiresAt": time.Now().Add(time.Hour).UTC(), "maxExpiresAt": time.Now().Add(2 * time.Hour).UTC(),
		"configGeneration": 1, "configEnv": map[string]string{},
		"connections": []any{
			map[string]any{
				"grantId": "grant-pg", "connectionId": "pg", "credentialId": "pg-cred", "credentialProvider": "postgres", "credentialName": "Test postgres credential", "credentialRevision": "credential-v1", "serviceType": "postgres", "protocol": "postgres",
				"hosts":       []any{map[string]any{"match": "exact", "value": "127.0.0.1", "port": mustPort(t, pgPortRaw)}},
				"injection":   map[string]any{"action": "pg_handshake", "valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"username": "username", "password": "password"}}},
				"identifiers": map[string]string{"username": pgUser}, "decoyMaterial": map[string]string{"password": pgDecoy},
				"configEnv": map[string]string{}, "agentEnv": map[string]string{"PGUSER": pgUser},
				"environmentBindings": []any{map[string]any{"name": "PGUSER", "action": "set", "source": "identifier", "sourceField": "username", "sensitive": false, "systemManaged": true}},
				"secretMaterial":      map[string]string{"username": pgUser, "password": pgPassword},
			},
		},
	}
	session := decodeTestSession(t, sessionPayload)
	delete(sessionPayload, "sessionCredential")
	sessionPayload["configGeneration"] = 2
	encodedRefresh, _ := json.Marshal(sessionPayload)
	refreshResponse.Store(encodedRefresh)
	caDirectory := t.TempDir()
	caPath := filepath.Join(caDirectory, "ca.pem")
	bundlePath := filepath.Join(caDirectory, "ca-bundle.pem")
	if err := os.WriteFile(caPath, proxyCAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, proxyCAPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	engine := New()
	engine.Remote = true
	listenAddresses := unusedTestListenAddresses(t, "0.0.0.0", "0.0.0.0")
	engine.ListenAddress = listenAddresses[0]
	engine.AdvertiseHost = advertisedHost
	engine.TLSCertificatePath = outerCertPath
	engine.TLSPrivateKeyPath = outerKeyPath
	engine.PostgresListenAddress = listenAddresses[1]
	engine.RemoteRootCAs = outerRoots
	engine.BootstrapSkills = []BootstrapSkill{{Path: ".claude/skills/phase-cli/SKILL.md", Content: "# phase-cli relay test skill"}}
	engine.RemoteResolver = staticIPResolver{
		"public-unbound.example": {{IP: net.ParseIP("93.184.216.34")}},
		"rebind-unbound.example": {{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("127.0.0.1")}},
	}
	engine.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, splitErr := net.SplitHostPort(address)
		if splitErr == nil && host == "93.184.216.34" && port == unboundPort {
			address = unboundUpstream.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	engine.UpstreamTLSConfig = &tls.Config{RootCAs: upstreamRoots, MinVersion: tls.VersionTLS12}
	engine.RefreshInterval = time.Hour
	engine.EventFlushInterval = 10 * time.Millisecond
	engine.EventSpoolDirectory = t.TempDir()
	engine.Stdout = io.Discard
	started := make(chan Endpoints, 1)
	engine.OnStarted = func(endpoints Endpoints) { started <- endpoints }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- engine.Serve(ctx, &airuntime.ProxySession{Config: session, Client: client, CA: proxyCA, CAPaths: phaseproxy.CAPaths{Certificate: caPath, Bundle: bundlePath}})
	}()
	var endpoints Endpoints
	select {
	case endpoints = <-started:
	case err := <-done:
		t.Fatalf("remote engine stopped before start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("remote engine did not start")
	}
	if !endpoints.Remote || !strings.HasPrefix(endpoints.ProxyURL.Reveal(), "https://") {
		t.Fatalf("remote endpoints=%+v", endpoints)
	}
	parsedProxyURL, _ := url.Parse(endpoints.ProxyURL.Reveal())
	runtimeCapability, _ := parsedProxyURL.User.Password()
	if runtimeCapability == "" || runtimeCapability == capability {
		t.Fatal("remote proxy did not use a distinct process-local capability")
	}
	for _, address := range []string{endpoints.ProxyAddress, endpoints.PostgresAddress} {
		host, _, err := net.SplitHostPort(address)
		if err != nil || host != advertisedHost {
			t.Fatalf("advertised address=%q", address)
		}
	}
	bootstrapClient := remoteProxyHTTPClient(t, endpoints.ProxyURL.Reveal(), outerRoots)
	request, _ := http.NewRequest(http.MethodGet, ManifestURL, nil)
	response, err := bootstrapClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPayload, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap status=%d body=%s", response.StatusCode, bootstrapPayload)
	}
	for _, forbidden := range []string{capability, pgPassword, "secretMaterial", "sessionCredential"} {
		if strings.Contains(string(bootstrapPayload), forbidden) {
			t.Fatalf("bootstrap leaked %q: %s", forbidden, bootstrapPayload)
		}
	}
	var bootstrap remoteapi.ManifestResponse
	if err := json.Unmarshal(bootstrapPayload, &bootstrap); err != nil {
		t.Fatal(err)
	}
	if bootstrap.SessionUID != "remote-session" || bootstrap.CACertificatePEM == "" || bootstrap.Postgres == nil {
		t.Fatalf("bootstrap=%+v", bootstrap)
	}
	for _, connection := range bootstrap.Discover.Connections {
		if connection.AgentEnv["PGPASSWORD"] != "" {
			t.Fatalf("bootstrap retained #1-bearing Agent env: %+v", connection.AgentEnv)
		}
	}
	// The sandbox bootstrap is served only through the relay and repeats only
	// what the client already holds: its own proxy credential and the decoys.
	bootstrapScript, err := bootstrapClient.Get(phaseproxy.ControlURL + "/v1/bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	scriptPayload, _ := io.ReadAll(bootstrapScript.Body)
	bootstrapScript.Body.Close()
	if bootstrapScript.StatusCode != http.StatusOK || !strings.HasPrefix(bootstrapScript.Header.Get("Content-Type"), "text/x-shellscript") {
		t.Fatalf("bootstrap script status=%d type=%q body=%s", bootstrapScript.StatusCode, bootstrapScript.Header.Get("Content-Type"), scriptPayload)
	}
	for _, required := range []string{
		"export HTTPS_PROXY='" + endpoints.ProxyURL.Reveal() + "'", "export PGPASSWORD='" + pgDecoy + "'", "export PGHOST='" + advertisedHost + "'",
		"export PGPORT='" + strings.TrimPrefix(endpoints.PostgresAddress, advertisedHost+":") + "'", strings.TrimSpace(string(proxyCAPEM)),
		"# phase-cli relay test skill", `export PHASE_AI_CA_BUNDLE="$HOME/.phase/ai/ca-bundle.pem"`,
	} {
		if !strings.Contains(string(scriptPayload), required) {
			t.Fatalf("bootstrap script missing %q:\n%s", required, scriptPayload)
		}
	}
	for _, forbidden := range []string{capability, pgPassword, caPath, bundlePath} {
		if strings.Contains(string(scriptPayload), forbidden) {
			t.Fatalf("bootstrap script leaked %q:\n%s", forbidden, scriptPayload)
		}
	}
	unsafeDiscover.Store(true)
	response, err = bootstrapClient.Get(ManifestURL)
	if err != nil {
		t.Fatal(err)
	}
	unsafePayload, _ := io.ReadAll(response.Body)
	response.Body.Close()
	unsafeDiscover.Store(false)
	if response.StatusCode != http.StatusBadGateway || strings.Contains(string(unsafePayload), pgPassword) {
		t.Fatalf("unsafe discover response status=%d body=%s", response.StatusCode, unsafePayload)
	}

	wrongProxy, _ := url.Parse(endpoints.ProxyURL.Reveal())
	wrongProxy.User = url.UserPassword("phase", "wrong-capability")
	response, err = remoteProxyHTTPClient(t, wrongProxy.String(), outerRoots).Get(ManifestURL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("wrong #1 bootstrap status=%d", response.StatusCode)
	}
	privateUnbound, err := bootstrapClient.Get(unboundUpstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	privateUnbound.Body.Close()
	if privateUnbound.StatusCode != http.StatusForbidden || unboundRequests.Load() != 0 {
		t.Fatalf("private unbound status=%d requests=%d", privateUnbound.StatusCode, unboundRequests.Load())
	}
	authenticatedUnbound, err := bootstrapClient.Get(publicUnboundURL)
	if err != nil {
		t.Fatal(err)
	}
	authenticatedUnbound.Body.Close()
	if authenticatedUnbound.StatusCode != http.StatusNoContent || unboundRequests.Load() != 1 {
		t.Fatalf("public unbound status=%d requests=%d", authenticatedUnbound.StatusCode, unboundRequests.Load())
	}
	rebindingUnbound, err := bootstrapClient.Get(rebindingURL)
	if err != nil {
		t.Fatal(err)
	}
	rebindingUnbound.Body.Close()
	if rebindingUnbound.StatusCode != http.StatusForbidden || unboundRequests.Load() != 1 {
		t.Fatalf("rebinding unbound status=%d requests=%d", rebindingUnbound.StatusCode, unboundRequests.Load())
	}
	unauthenticatedProxy, _ := url.Parse(endpoints.ProxyURL.Reveal())
	unauthenticatedProxy.User = nil
	unauthenticatedUnbound, err := remoteProxyHTTPClient(t, unauthenticatedProxy.String(), outerRoots).Get(publicUnboundURL)
	if err != nil {
		t.Fatal(err)
	}
	unauthenticatedUnbound.Body.Close()
	if unauthenticatedUnbound.StatusCode != http.StatusProxyAuthRequired || unboundRequests.Load() != 1 {
		t.Fatalf("unauthenticated unbound status=%d requests=%d", unauthenticatedUnbound.StatusCode, unboundRequests.Load())
	}
	_, proxyPort, _ := net.SplitHostPort(endpoints.ProxyAddress)
	outerConnection, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", proxyPort), &tls.Config{
		RootCAs: outerRoots, ServerName: advertisedHost, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(outerConnection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", strings.TrimPrefix(unboundUpstream.URL, "http://"), strings.TrimPrefix(unboundUpstream.URL, "http://"))
	connectResponse, err := http.ReadResponse(bufio.NewReader(outerConnection), &http.Request{Method: http.MethodConnect})
	_ = outerConnection.Close()
	if err != nil {
		t.Fatal(err)
	}
	connectResponse.Body.Close()
	if connectResponse.StatusCode != http.StatusProxyAuthRequired || unboundRequests.Load() != 1 {
		t.Fatalf("unauthenticated CONNECT status=%d requests=%d", connectResponse.StatusCode, unboundRequests.Load())
	}
	outerConnection, err = tls.Dial("tcp", net.JoinHostPort("127.0.0.1", proxyPort), &tls.Config{
		RootCAs: outerRoots, ServerName: advertisedHost, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	privateAuthority := strings.TrimPrefix(unboundUpstream.URL, "http://")
	proxyAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("phase:"+runtimeCapability))
	_, _ = fmt.Fprintf(outerConnection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", privateAuthority, privateAuthority, proxyAuthorization)
	connectResponse, err = http.ReadResponse(bufio.NewReader(outerConnection), &http.Request{Method: http.MethodConnect})
	_ = outerConnection.Close()
	if err != nil {
		t.Fatal(err)
	}
	connectResponse.Body.Close()
	if connectResponse.StatusCode != http.StatusForbidden || unboundRequests.Load() != 1 {
		t.Fatalf("authenticated private CONNECT status=%d requests=%d", connectResponse.StatusCode, unboundRequests.Load())
	}

	remoteControl := remoteProxyHTTPClient(t, endpoints.ProxyURL.Reveal(), outerRoots)
	var contextResponse agentapi.ContextResponse
	remoteControlJSON(t, remoteControl, http.MethodGet, "/v1/context", nil, &contextResponse)
	if contextResponse.Markdown != "remote-safe context" {
		t.Fatalf("remote context=%+v", contextResponse)
	}
	var requestResponse agentapi.RequestResponse
	remoteControlJSON(t, remoteControl, http.MethodPost, "/v1/requests", agentapi.CreateRequestRequest{
		Kind: "credential_update", ConnectionID: "pg", CredentialID: "pg-cred",
		CredentialProvider: "postgres", CredentialName: "Test postgres credential", Markdown: "update remote database credential",
	}, &requestResponse)
	if requestResponse.ID != "remote-request" || requestResponse.Status != "pending" {
		t.Fatalf("remote request=%+v", requestResponse)
	}
	remoteControlJSON(t, remoteControl, http.MethodGet, "/v1/requests/"+requestResponse.ID, nil, &requestResponse)
	if requestResponse.Status != "approved" {
		t.Fatalf("remote request poll=%+v", requestResponse)
	}
	var refreshResult agentapi.RefreshResponse
	remoteControlJSON(t, remoteControl, http.MethodPost, "/v1/refresh", nil, &refreshResult)
	if !refreshResult.Refreshed || refreshResult.ConfigGeneration != 2 {
		t.Fatalf("remote refresh=%+v", refreshResult)
	}

	pgDialAddress := advertisedToLoopback(t, endpoints.PostgresAddress)
	assertPostgresRejectsWrongRemoteHostname(t, pgDialAddress, outerRoots)
	runPostgresClientWithServerName(t, pgDialAddress, advertisedHost, outerRoots, pgUser, pgDecoy, "appdb", "SELECT * FROM reports")
	select {
	case value := <-pgPasswordSeen:
		if value != pgPassword {
			t.Fatalf("PG password=%q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("PG upstream auth not observed")
	}
	select {
	case value := <-pgQuerySeen:
		if value != "SELECT * FROM reports" {
			t.Fatalf("PG query=%q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("PG query not observed")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRemoteReadyRejectsUnsafeTLSAndBindConfiguration(t *testing.T) {
	certPath, keyPath, roots := writeRemoteTLSIdentity(t, "remote.phase.test")
	valid := *New()
	valid.Remote = true
	valid.ListenAddress = "0.0.0.0:8443"
	valid.AdvertiseHost = "remote.phase.test"
	valid.TLSCertificatePath = certPath
	valid.TLSPrivateKeyPath = keyPath
	valid.RemoteRootCAs = roots
	if err := valid.Ready(); err != nil {
		t.Fatalf("valid remote config: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Engine)
	}{
		{"loopback bind", func(engine *Engine) { engine.ListenAddress = "127.0.0.1:8443" }},
		{"IP advertisement", func(engine *Engine) { engine.AdvertiseHost = "192.0.2.1" }},
		{"missing cert", func(engine *Engine) { engine.TLSCertificatePath = "" }},
		{"missing key", func(engine *Engine) { engine.TLSPrivateKeyPath = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := candidate.Ready(); err == nil {
				t.Fatal("unsafe remote configuration was accepted")
			}
		})
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := valid.Ready(); err == nil {
			t.Fatal("world-readable TLS key was accepted")
		}
		if err := os.Chmod(keyPath, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	userClient, err := agentapi.NewClient("https://console.phase.dev", durableTestToken(), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := valid.Serve(context.Background(), emptyProxySession(t, userClient, "user-sponsored-capability")); err == nil || !strings.Contains(err.Error(), "Agent-token") {
		t.Fatalf("remote proxy accepted non-Agent authentication: %v", err)
	}
}

func writeRemoteTLSIdentity(t *testing.T, host string) (string, string, *x509.CertPool) {
	t.Helper()
	now := time.Now().UTC()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Remote Test Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	directory := t.TempDir()
	certPath := filepath.Join(directory, "outer-chain.pem")
	keyPath := filepath.Join(directory, "outer-key.pem")
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	if err := os.WriteFile(certPath, chain, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return certPath, keyPath, roots
}

func remoteAgentToken() string {
	return "pss_agent:v1:" + strings.Repeat("a", 64)
}

func remoteProxyHTTPClient(t *testing.T, rawProxyURL string, roots *x509.CertPool) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(rawProxyURL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(proxyURL.Host)
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func advertisedToLoopback(t *testing.T, address string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort("127.0.0.1", port)
}

func assertPostgresRejectsWrongRemoteHostname(t *testing.T, address string, roots *x509.CertPool) {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ssl := make([]byte, 8)
	binary.BigEndian.PutUint32(ssl, 8)
	binary.BigEndian.PutUint32(ssl[4:], 80877103)
	_, _ = connection.Write(ssl)
	var response [1]byte
	_, _ = io.ReadFull(connection, response[:])
	secure := tls.Client(connection, &tls.Config{RootCAs: roots, ServerName: "wrong.phase.test", MinVersion: tls.VersionTLS12})
	if err := secure.Handshake(); err == nil {
		t.Fatal("PostgreSQL adapter accepted the wrong TLS hostname")
	}
}

// remoteControlJSON calls a phase.invalid control route through the
// authenticated remote proxy and decodes a successful JSON response.
func remoteControlJSON(t *testing.T, client *http.Client, method, path string, body any, out any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, phaseproxy.ControlURL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		t.Fatalf("%s %s status=%d body=%s", method, path, response.StatusCode, payload)
	}
	if out != nil {
		if err := json.Unmarshal(payload, out); err != nil {
			t.Fatal(err)
		}
	}
}
