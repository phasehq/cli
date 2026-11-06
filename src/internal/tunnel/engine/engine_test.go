package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/tunnel"
	"github.com/phasehq/cli/internal/tunnel/control"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

const (
	apiHost = "api.example.test"
	decoy   = "ghp_phase_decoy_0123456789abcdef"
	live    = "ghp_live_0123456789abcdef0123"
)

// fakeRuntime hands the engine a session directly, as Console would.
type fakeRuntime struct {
	session *agentapi.OpenSessionResponse
	client  *agentapi.Client
	ca      *phaseproxy.CA
	paths   phaseproxy.CAPaths
}

func (r fakeRuntime) ServeManaged(ctx context.Context, engine airuntime.Engine) error {
	copy := *r.session
	return engine.Serve(ctx, &airuntime.ProxySession{Config: &copy, Client: r.client, CA: r.ca, CAPaths: r.paths})
}

func testSession(t *testing.T) *agentapi.OpenSessionResponse {
	t.Helper()
	authorization := map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"}
	value := map[string]any{
		"schemaVersion": 1, "sessionUid": "test-session", "sessionCredential": "psx_sess_test_0123456789",
		"expiresAt": time.Now().Add(12 * time.Hour).UTC(), "maxExpiresAt": time.Now().Add(24 * time.Hour).UTC(),
		"configGeneration": 1, "configEnv": map[string]string{},
		"connections": []any{map[string]any{
			"grantId": "grant-api", "connectionId": "api", "connectionName": "Test API", "credentialId": "api-cred",
			"credentialProvider": "github", "credentialName": "Test API", "credentialRevision": "v1",
			"serviceType": "github", "protocol": "http", "authorization": authorization,
			"hosts":       []any{map[string]any{"match": "exact", "value": apiHost, "port": 443}},
			"injection":   map[string]any{"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}", "valueFrom": map[string]any{"source": "credential", "field": "access_token"}},
			"identifiers": map[string]string{}, "decoyMaterial": map[string]string{"access_token": decoy},
			"configEnv": map[string]string{}, "agentEnv": map[string]string{"GITHUB_TOKEN": decoy},
			"environmentBindings": []any{map[string]any{"name": "GITHUB_TOKEN", "action": "set", "source": "decoy", "sourceField": "access_token", "sensitive": true, "systemManaged": true}},
			"secretMaterial":      map[string]string{"access_token": live},
		}},
	}
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var session agentapi.OpenSessionResponse
	if err := json.Unmarshal(payload, &session); err != nil {
		t.Fatal(err)
	}
	return &session
}

// provider answers with what it received, compared to the known values.
func startProvider(t *testing.T, ca *phaseproxy.CA) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return ca.CertificateForHost(apiHost) },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw := map[string]string{"Bearer " + live: "live", "Bearer " + decoy: "decoy", "": "none"}[r.Header.Get("Authorization")]
		if saw == "" {
			saw = "other"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"saw": saw})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

func startConsole(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/events/") {
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"schemaVersion":1,"accepted":0,"duplicates":0}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{}`)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return "http://" + listener.Addr().String()
}

func startEcho(t *testing.T) (tcpAddr, udpAddr string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packet.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := packet.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = packet.WriteTo(buf[:n], from)
		}
	}()
	return listener.Addr().String(), packet.LocalAddr().String()
}

func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).Port
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// fakeHelper accepts one attach with peerPublic, then reads until the engine leaves.
func fakeHelper(t *testing.T, path, peerPublic string) (attached chan control.Attach, updates chan []string) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	attached, updates = make(chan control.Attach, 4), make(chan []string, 16)
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				conn := control.Wrap(raw)
				var request control.Request
				if err := conn.Receive(&request, 5*time.Second); err != nil || request.Op != control.OpAttach {
					return
				}
				attached <- *request.Attach
				_ = conn.Send(control.Reply{PeerPublicKey: peerPublic})
				for {
					var next control.Request
					if err := conn.Receive(&next, 10*time.Second); err != nil {
						return
					}
					if next.Op == control.OpUpdate {
						updates <- next.Domains
					}
				}
			}()
		}
	}()
	return attached, updates
}

func TestEngineEndToEnd(t *testing.T) {
	proxyCA, proxyCert, _, err := phaseproxy.GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	providerCA, providerCert, _, err := phaseproxy.GenerateCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificatePath, bundlePath := filepath.Join(directory, "ca.pem"), filepath.Join(directory, "bundle.pem")
	if err := os.WriteFile(certificatePath, proxyCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, proxyCert, 0o600); err != nil {
		t.Fatal(err)
	}
	provider := startProvider(t, providerCA)
	echoTCP, echoUDP := startEcho(t)
	client, err := agentapi.NewClient(startConsole(t), "pss_user:v1:"+strings.Repeat("a", 64)+":"+strings.Repeat("b", 64)+":"+strings.Repeat("c", 64)+":"+strings.Repeat("d", 64), &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	socketDirectory, err := os.MkdirTemp("", "pe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDirectory) })
	peerPrivate, peerPublic, err := tunnel.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	attached, updates := fakeHelper(t, filepath.Join(socketDirectory, "s"), peerPublic)

	// Real-looking addresses that the stand-ins answer for. A program reaching them
	// directly, with its own DNS, is what the TLS-name check is for.
	const realAPI, realEchoTCP, realEchoUDP, realClosed = "192.0.2.10:443", "192.0.2.11:7000", "192.0.2.11:7001", "192.0.2.12:9"
	upstream := &tunnel.Upstream{Servers: []string{"127.0.0.1"}, Override: map[string]string{
		apiHost + ":443": provider, realAPI: provider, realEchoTCP: echoTCP, realEchoUDP: echoUDP,
		realClosed: fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp")),
	}}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(providerCert)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			Runtime:    fakeRuntime{session: testSession(t), client: client, ca: proxyCA, paths: phaseproxy.CAPaths{Certificate: certificatePath, Bundle: bundlePath}},
			SocketPath: filepath.Join(socketDirectory, "s"), StateDirectory: directory,
			ProxyAddress:    fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp")),
			PostgresAddress: fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp")),
			WireGuardPort:   freePort(t, "udp"), Upstream: upstream, UpstreamRootCAs: roots, Logf: t.Logf,
		})
	}()
	var attach control.Attach
	select {
	case attach = <-attached:
	case err := <-done:
		t.Fatalf("the engine stopped: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("the engine never attached to the helper")
	}
	if !contains(attach.Domains, apiHost) || !contains(attach.Domains, tunnel.ControlHost) {
		t.Fatalf("the engine sent the wrong names: %v", attach.Domains)
	}
	if strings.Join(attach.Routes, ",") != strings.Join(tunnel.FullRoutes, ",") {
		t.Fatalf("routes: %v", attach.Routes)
	}
	select {
	case <-updates:
	default:
	}

	// The helper's side: a WireGuard peer with its own user-space network stack, so a
	// "program" here goes through exactly what a real one would after the routes.
	tunDevice, program, err := netstack.CreateNetTUN([]netip.Addr{tunnel.LocalAddress}, []netip.Addr{tunnel.DNSAddress}, tunnel.MTU)
	if err != nil {
		t.Fatal(err)
	}
	peer := device.NewDevice(tunDevice, &tunnel.LoopbackBind{}, device.NewLogger(device.LogLevelError, "peer: "))
	t.Cleanup(peer.Close)
	if err := peer.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=5\n",
		peerPrivate, attach.EnginePublicKey, attach.EnginePort)); err != nil {
		t.Fatal(err)
	}
	if err := peer.Up(); err != nil {
		t.Fatal(err)
	}

	t.Run("the probe answers", func(t *testing.T) {
		conn, err := program.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", tunnel.ProbeAddress, tunnel.ProbePort))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reply, _ := bufio.NewReader(conn).ReadString('\n')
		if reply != tunnel.ProbeReply {
			t.Fatalf("probe reply %q", reply)
		}
	})

	t.Run("a Connection host resolves into the tunnel", func(t *testing.T) {
		addresses, err := program.LookupContextHost(ctx, apiHost)
		if err != nil || len(addresses) == 0 || !tunnel.TunnelPrefix.Contains(netip.MustParseAddr(addresses[0])) {
			t.Fatalf("%v, %v", addresses, err)
		}
	})

	proxyRoots := x509.NewCertPool()
	proxyRoots.AppendCertsFromPEM(proxyCert)
	httpClient := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: program.DialContext, TLSClientConfig: &tls.Config{RootCAs: proxyRoots}, DisableKeepAlives: true,
	}}
	saw := func(t *testing.T, client *http.Client, url, token string) string {
		t.Helper()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var parsed struct {
			Saw string `json:"saw"`
		}
		_ = json.NewDecoder(response.Body).Decode(&parsed)
		return parsed.Saw
	}

	t.Run("the decoy is swapped for the live token", func(t *testing.T) {
		if got := saw(t, httpClient, "https://"+apiHost+"/whoami", decoy); got != "live" {
			t.Fatalf("the provider saw %q", got)
		}
	})

	t.Run("a wrong token gets no live credential", func(t *testing.T) {
		if got := saw(t, httpClient, "https://"+apiHost+"/whoami", "not-the-decoy"); got == "live" {
			t.Fatal("a wrong token reached the provider as the live token")
		}
	})

	t.Run("a program with its own DNS still gets the swap", func(t *testing.T) {
		direct := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return program.DialContext(ctx, network, realAPI)
			},
			TLSClientConfig: &tls.Config{RootCAs: proxyRoots, ServerName: apiHost}, DisableKeepAlives: true,
		}}
		if got := saw(t, direct, "https://"+apiHost+"/whoami", decoy); got != "live" {
			t.Fatalf("the provider saw %q", got)
		}
	})

	t.Run("other TCP passes through", func(t *testing.T) {
		conn, err := program.DialContext(ctx, "tcp", realEchoTCP)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(conn, "hello\n")
		reply, _ := bufio.NewReader(conn).ReadString('\n')
		if reply != "hello\n" {
			t.Fatalf("echo %q", reply)
		}
	})

	t.Run("a closed port is refused rather than hanging", func(t *testing.T) {
		start := time.Now()
		_, err := program.DialContext(ctx, "tcp", realClosed)
		if err == nil {
			t.Fatal("connected to nothing")
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("took %s", elapsed)
		}
	})

	t.Run("UDP passes through", func(t *testing.T) {
		conn, err := program.DialContext(ctx, "udp", realEchoUDP)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte("datagram"))
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != "datagram" {
			t.Fatalf("%q, %v", buf[:n], err)
		}
	})

	t.Run("the control API works with no proxy settings", func(t *testing.T) {
		plain := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DialContext: program.DialContext, DisableKeepAlives: true}}
		response, err := plain.Get("http://" + tunnel.ControlHost + "/v1/status")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"api"`) {
			t.Fatalf("%d: %.200s", response.StatusCode, body)
		}
	})

	t.Run("status holds no credential", func(t *testing.T) {
		time.Sleep(1200 * time.Millisecond)
		content, err := os.ReadFile(StatusPath(directory))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content), live) || strings.Contains(string(content), decoy) {
			t.Fatal("the status file holds a credential")
		}
		var status Status
		if err := json.Unmarshal(content, &status); err != nil || !status.Ready || !status.HelperLinked || status.Counts["proxy"] == 0 {
			t.Fatalf("status: %+v, %v", status, err)
		}
	})
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
