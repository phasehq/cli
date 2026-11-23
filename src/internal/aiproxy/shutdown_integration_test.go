package aiproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// A request read off a decrypted CONNECT tunnel has no deadline of its own.
// When the engine stops while such a request still waits on its upstream, the
// tunnel must be cancelled with the engine instead of holding shutdown until
// the upstream answers.
func TestShutdownCancelsStalledTunneledUpstreamRequests(t *testing.T) {
	const (
		sessionCredential = "psx_sess_test_capability_0123456789"
		decoyToken        = "ghp_phx_decoy_01234567890123456789012345678901"
		liveToken         = "ghp_live_proxy_only_012345678901234567890123"
	)
	arrived := make(chan struct{}, 1)
	release := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-release
	}))
	defer func() {
		close(release)
		upstream.Close()
	}()
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHost, upstreamPort, _ := net.SplitHostPort(upstreamURL.Host)
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"schemaVersion":1,"accepted":1,"duplicates":0}`))
	}))
	defer console.Close()
	client, err := agentapi.NewClient(console.URL, durableTestToken(), console.Client())
	if err != nil {
		t.Fatal(err)
	}
	session := decodeTestSession(t, map[string]any{
		"schemaVersion": 1, "sessionUid": "session-123", "sessionCredential": sessionCredential,
		"expiresAt":        time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		"maxExpiresAt":     time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339Nano),
		"configGeneration": 1, "configEnv": map[string]string{},
		"connections": []any{map[string]any{
			"grantId": "grant-github", "connectionId": "connection-github", "credentialId": "credential-github",
			"serviceType": "github", "protocol": "http",
			"hosts":       []any{map[string]any{"match": "exact", "value": upstreamHost, "port": mustPort(t, upstreamPort)}},
			"injection":   map[string]any{"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}", "valueFrom": map[string]any{"source": "credential", "field": "access_token"}},
			"identifiers": map[string]string{}, "decoyMaterial": map[string]string{"access_token": decoyToken},
			"configEnv": map[string]string{}, "agentEnv": map[string]string{}, "environmentBindings": []any{},
			"secretMaterial": map[string]string{"access_token": liveToken},
		}},
	})
	ca, certPEM, _, err := phaseproxy.GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificatePath, bundlePath := filepath.Join(directory, "ca.pem"), filepath.Join(directory, "bundle.pem")
	if err := os.WriteFile(certificatePath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	proxySession := &airuntime.ProxySession{Config: session, Client: client, CA: ca, CAPaths: phaseproxy.CAPaths{Certificate: certificatePath, Bundle: bundlePath}}
	engine := New()
	engine.ListenAddress = unusedTestListenAddresses(t, "127.0.0.1")[0]
	engine.RefreshInterval = time.Hour
	engine.EventFlushInterval = 20 * time.Millisecond
	engine.EventSpoolDirectory = t.TempDir()
	engine.Transport = upstream.Client().Transport
	started := make(chan Endpoints, 1)
	engine.OnStarted = func(endpoints Endpoints) { started <- endpoints }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- engine.Serve(ctx, proxySession) }()
	endpoints := <-started

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	proxyURL, _ := url.Parse(endpoints.ProxyURL.Reveal())
	httpClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/stall", nil)
		req.Header.Set("Authorization", "Bearer "+decoyToken)
		if response, err := httpClient.Do(req); err == nil {
			response.Body.Close()
		}
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream never received the tunneled request")
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v after cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return while a tunneled upstream request was stalled")
	}
	select {
	case <-clientDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the tunneled client was not released")
	}
}
