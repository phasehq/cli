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
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/tunnel"
	"github.com/phasehq/cli/internal/tunnel/control"
	"github.com/phasehq/cli/internal/tunnel/owner"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

const (
	apiHost = "api.example.test"
	decoy   = "ghp_phase_decoy_0123456789abcdef"
	live    = "ghp_live_0123456789abcdef0123"
	// modelHost stands in for a tool's model host. It is no Connection's host.
	modelHost = "model.example.test"
	// addedHost belongs to a Connection that a session gains while it runs.
	addedHost = "added.example.test"
	liveAdded = "sk-live-added-0123456789abcdefgh"
)

// Real-looking addresses that the stand-ins answer for. A program reaching them
// directly, with its own DNS, is what the TLS-name check is for.
const (
	realAPI     = "192.0.2.10:443"
	realEchoTCP = "192.0.2.11:7000"
	realEchoUDP = "192.0.2.11:7001"
	realClosed  = "192.0.2.12:9"
	realModel   = "192.0.2.20:443"
)

var (
	claudeCode = owner.Process{PID: 4001, Executable: "/Users/someone/.local/share/claude/versions/2.1.316", Args: []string{"claude"}}
	browser    = owner.Process{PID: 4002, Executable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
)

// fakeReader reads modelHost for Claude Code only, as the proxy's own table would.
type fakeReader struct {
	mu    sync.Mutex
	notes []string
}

func (r *fakeReader) ReadsHost(host string) bool        { return host == modelHost }
func (r *fakeReader) ShouldRead(tool, host string) bool { return tool == "claude" && host == modelHost }
func (r *fakeReader) ToolHosts() map[string][]string {
	return map[string][]string{"claude": {modelHost}}
}
func (r *fakeReader) NoteFlow(connectFrom, tool string) (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if address, err := netip.ParseAddrPort(connectFrom); err != nil || !address.Addr().IsLoopback() {
		tool = "from " + connectFrom
	}
	r.notes = append(r.notes, tool)
	return func() {}, nil
}

// noted returns the tools noted so far, and forgets them.
func (r *fakeReader) noted() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	notes := r.notes
	r.notes = nil
	return notes
}

// fakeOwners says which program opened the next flow. The test's programs live in a
// network stack of their own, so there's no real socket to find.
type fakeOwners struct {
	mu      sync.Mutex
	process owner.Process
	err     error
}

func (o *fakeOwners) next(process owner.Process, err error) {
	o.mu.Lock()
	o.process, o.err = process, err
	o.mu.Unlock()
}

func (o *fakeOwners) find(context.Context, int, netip.AddrPort) (owner.Process, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.process, o.err
}

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
	return sessionFrom(t, testSessionPayload())
}

// sessionFrom is a session as the engine gets it from Console.
func sessionFrom(t *testing.T, config map[string]any) *agentapi.OpenSessionResponse {
	t.Helper()
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var session agentapi.OpenSessionResponse
	if err := json.Unmarshal(payload, &session); err != nil {
		t.Fatal(err)
	}
	return &session
}

// testSessionPayload is a session as Console sends it, with one packaged Connection.
func testSessionPayload() map[string]any {
	authorization := map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"}
	return map[string]any{
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
}

// addedConnectionPayload is a custom Connection that puts nothing in a program's
// environment: its credential is only ever attached. A session can gain one while it
// runs.
func addedConnectionPayload() map[string]any {
	return map[string]any{
		"grantId": "grant-added", "connectionId": "added", "connectionName": "Added API",
		"credentialId": "added", "credentialName": "Added API", "credentialProvider": "http",
		"credentialRevision": "1", "materialGeneration": "1.1", "serviceType": "http", "protocol": "http",
		"hosts":            []any{map[string]any{"match": "exact", "value": addedHost, "port": 443}},
		"connectionConfig": map[string]any{"specVersion": 1, "preset": "bearer"},
		"configEnv":        map[string]string{},
		"injections": []any{map[string]any{
			"action": "set_header", "name": "Authorization", "valueFormat": "Bearer {value}",
			"valueFrom": map[string]any{"source": "credential", "field": "token"}, "whenAbsent": "attach",
		}},
		"identifiers": map[string]string{}, "decoyMaterial": map[string]string{"token": "sk-phx-decoy-added-0123456789abcdef"},
		"agentEnv": map[string]string{}, "environmentBindings": []any{},
		"secretMaterial": map[string]string{"token": liveAdded},
		"authorization":  map[string]any{"version": 1, "mode": "connection", "accessMode": "allow", "state": "allowed"},
	}
}

// provider answers with what it received, compared to the known values.
func startProvider(t *testing.T, ca *phaseproxy.CA) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" {
				return ca.CertificateForHost(hello.ServerName)
			}
			return ca.CertificateForHost(apiHost)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw := map[string]string{"Bearer " + live: "live", "Bearer " + liveAdded: "live-added", "Bearer " + decoy: "decoy", "": "none"}[r.Header.Get("Authorization")]
		if saw == "" {
			saw = "other"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"saw": saw})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

// startLabelled answers for modelHost with a label, so a test can tell by which way a
// flow reached it.
func startLabelled(t *testing.T, ca *phaseproxy.CA, label string) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return ca.CertificateForHost(modelHost) },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"reached": label})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

func startConsole(t *testing.T) string {
	t.Helper()
	return startConsoleWith(t, unchangedSession())
}

// unchangedSession is what Console answers a refresh with while nothing has changed:
// the session as it was opened. The proxy asks every few seconds, and stops serving a
// session it can't refresh.
func unchangedSession() *atomic.Pointer[map[string]any] {
	return unchanged(testSessionPayload())
}

// unchanged is unchangedSession for a session of the test's own.
func unchanged(config map[string]any) *atomic.Pointer[map[string]any] {
	delete(config, "sessionCredential")
	refreshed := &atomic.Pointer[map[string]any]{}
	refreshed.Store(&config)
	return refreshed
}

// startConsoleWith is a Console that answers a session's refresh with refreshed.
func startConsoleWith(t *testing.T, refreshed *atomic.Pointer[map[string]any]) string {
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
		if config := refreshed.Load(); config != nil && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/config/") {
			_ = json.NewEncoder(w).Encode(*config)
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

// running is an engine with a stand-in helper, and a program's view of the network
// behind the tunnel.
type running struct {
	ctx       context.Context
	directory string
	attach    control.Attach
	program   *netstack.Net
	// proxyCert is what programs trust for a Connection's host. providerRoots are
	// what they'd trust anyway: an unread flow shows the provider's own certificate.
	proxyCert     []byte
	providerRoots *x509.CertPool
	// reader is the stand-in reader. It's nil when the test set a reader of its own.
	reader *fakeReader
	owners *fakeOwners
	// refreshed is what Console answers a refresh with, and updates are the names the
	// helper is sent after it attached.
	refreshed *atomic.Pointer[map[string]any]
	updates   chan []string
	// stop ends the engine and waits for it to have gone. The test's end does it too.
	stop func()
}

// startEngine runs the engine as phase up does, capturing routes, or everything when
// there are none. A stand-in reads modelHost for Claude Code.
func startEngine(t *testing.T, routes []string) *running {
	t.Helper()
	return startEngineWith(t, engineSetup{routes: routes})
}

// engineSetup is what a test changes about the engine it starts.
type engineSetup struct {
	routes []string
	// reader replaces the stand-in reader, and noReader leaves the engine without one.
	reader   func(*aiproxy.Engine) tunnel.Reader
	noReader bool
	// session is the session Console opens, and answers every refresh with.
	session func() map[string]any
	// standIns answers for more addresses, each with the stand-in that takes it. The
	// certificate authority is the providers' own.
	standIns func(t *testing.T, providers *phaseproxy.CA) map[string]string
	// sealed refuses every address that has no stand-in, for a test that uses the
	// names of real hosts.
	sealed bool
}

func startEngineWith(t *testing.T, setup engineSetup) *running {
	t.Helper()
	routes := setup.routes
	if setup.session == nil {
		setup.session = testSessionPayload
	}
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
	refreshed := unchanged(setup.session())
	client, err := agentapi.NewClient(startConsoleWith(t, refreshed), "pss_user:v1:"+strings.Repeat("a", 64)+":"+strings.Repeat("b", 64)+":"+strings.Repeat("c", 64)+":"+strings.Repeat("d", 64), &http.Client{Timeout: 10 * time.Second})
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

	// The model host answers differently by its address and by its name: an unread
	// flow goes to the address the program dialled, and the proxy reaches it by name.
	upstream := &tunnel.Upstream{Servers: []string{"127.0.0.1"}, OnlyOverrides: setup.sealed, Override: map[string]string{
		apiHost + ":443": provider, addedHost + ":443": provider, realAPI: provider, realEchoTCP: echoTCP, realEchoUDP: echoUDP,
		realClosed: fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp")),
		realModel:  startLabelled(t, providerCA, "by address"), modelHost + ":443": startLabelled(t, providerCA, "by name"),
	}}
	if setup.standIns != nil {
		for address, standIn := range setup.standIns(t, providerCA) {
			upstream.Override[address] = standIn
		}
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(providerCert)
	reader, owners := &fakeReader{}, &fakeOwners{process: browser}
	readWith := func(*aiproxy.Engine) tunnel.Reader { return reader }
	if setup.reader != nil || setup.noReader {
		reader, readWith = nil, setup.reader
	}
	session := sessionFrom(t, setup.session())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	// The engine has let go of its state directory before the test takes it away.
	stopped := make(chan struct{})
	stop := func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(30 * time.Second):
			t.Error("the engine didn't stop")
		}
	}
	t.Cleanup(stop)
	go func() {
		defer close(stopped)
		done <- Run(ctx, Config{
			Runtime:    fakeRuntime{session: session, client: client, ca: proxyCA, paths: phaseproxy.CAPaths{Certificate: certificatePath, Bundle: bundlePath}},
			SocketPath: filepath.Join(socketDirectory, "s"), StateDirectory: directory,
			ProxyAddress:    fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp")),
			PostgresAddress: fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp")),
			WireGuardPort:   freePort(t, "udp"), Upstream: upstream, UpstreamRootCAs: roots, Logf: t.Logf,
			Routes: routes, Reader: readWith, Owner: owners.find,
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
	return &running{
		ctx: ctx, directory: directory, attach: attach, program: program,
		proxyCert: proxyCert, providerRoots: roots, reader: reader, owners: owners,
		refreshed: refreshed, updates: updates, stop: stop,
	}
}

// reachModel asks the model host a question as a program would, and says by which
// way the answer came. address, when set, is where the program connects, as one with
// its own DNS would; otherwise it asks the system resolver.
func (e *running) reachModel(t *testing.T, address string) string {
	t.Helper()
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if address != "" {
				target = address
			}
			return e.program.DialContext(ctx, network, target)
		},
		TLSClientConfig: &tls.Config{RootCAs: e.providerRoots}, DisableKeepAlives: true,
	}}
	response, err := client.Get("https://" + modelHost + "/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var parsed struct {
		Reached string `json:"reached"`
	}
	_ = json.NewDecoder(response.Body).Decode(&parsed)
	return parsed.Reached
}

// status waits for the engine to write a status that satisfies ready.
func (e *running) status(t *testing.T, ready func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, err := ReadStatus(e.directory)
		if err == nil && ready(status) {
			return status
		}
		if time.Now().After(deadline) {
			t.Fatalf("status never got there: %+v, %v", status, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestEngineEndToEnd(t *testing.T) {
	e := startEngine(t, nil)
	ctx, program, directory, proxyCert := e.ctx, e.program, e.directory, e.proxyCert
	if !reflect.DeepEqual(e.attach.Routes, tunnel.FullRoutes) {
		t.Fatalf("routes: %v", e.attach.Routes)
	}
	// With everything captured, a model host is caught by its TLS hello, and needs no
	// DNS entry.
	if contains(e.attach.Domains, modelHost) {
		t.Fatalf("a model host was captured by name: %v", e.attach.Domains)
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

	// Every flow handed to the proxy so far was a Connection's, and the proxy was told
	// of each that it isn't to be read.
	t.Run("the proxy is told of every flow it is handed", func(t *testing.T) {
		noted := e.reader.noted()
		if len(noted) < 3 || strings.Join(noted, "") != "" {
			t.Fatalf("the proxy was told %q", noted)
		}
	})

	// The same model host, at the same address, opened by three different programs.
	t.Run("a tool's model traffic goes to the proxy", func(t *testing.T) {
		e.owners.next(claudeCode, nil)
		if got := e.reachModel(t, realModel); got != "by name" {
			t.Fatalf("the model host was reached %q", got)
		}
		if noted := e.reader.noted(); !reflect.DeepEqual(noted, []string{"claude"}) {
			t.Fatalf("the proxy was told %q", noted)
		}
	})

	t.Run("another program's traffic to the same host is left unread", func(t *testing.T) {
		e.owners.next(browser, nil)
		if got := e.reachModel(t, realModel); got != "by address" {
			t.Fatalf("the model host was reached %q", got)
		}
		if noted := e.reader.noted(); len(noted) != 0 {
			t.Fatalf("the proxy was told %q about a flow it never got", noted)
		}
	})

	t.Run("a program that can't be found is left unread", func(t *testing.T) {
		e.owners.next(claudeCode, owner.ErrNotFound)
		if got := e.reachModel(t, realModel); got != "by address" {
			t.Fatalf("the model host was reached %q", got)
		}
		if noted := e.reader.noted(); len(noted) != 0 {
			t.Fatalf("the proxy was told %q about a flow it never got", noted)
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

	t.Run("status says what is read, and counts what was", func(t *testing.T) {
		status := e.status(t, func(status Status) bool { return status.Counts["owner_lookup_failed"] == 1 })
		if status.Counts["read"] != 1 || status.Counts["unread_not_tool"] != 1 {
			t.Fatalf("counts: %v", status.Counts)
		}
		if !reflect.DeepEqual(status.ReadTools, map[string][]string{"claude": {modelHost}}) {
			t.Fatalf("read for: %v", status.ReadTools)
		}
		if len(status.Routes) != 0 {
			t.Fatalf("routes: %v", status.Routes)
		}
		// Who opened what stays out of it: no program's name or path, and no host
		// beyond the table of what is read.
		content, err := os.ReadFile(StatusPath(directory))
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{"Chrome", "versions", "/Users/", "/Applications/", realModel, "192.0.2."} {
			if strings.Contains(string(content), private) {
				t.Fatalf("the status file holds %q", private)
			}
		}
	})
}

// With less than everything routed in, a model host only reaches the tunnel if its
// name resolves into it, as a Connection host's does.
func TestEngineCapturesModelHostsByNameWhenItCapturesLess(t *testing.T) {
	routes := []string{"192.0.2.0/24"}
	e := startEngine(t, routes)
	if !reflect.DeepEqual(e.attach.Routes, routes) {
		t.Fatalf("the helper was asked for %v", e.attach.Routes)
	}
	if !contains(e.attach.Domains, modelHost) {
		t.Fatalf("the model host isn't among the names sent to the helper: %v", e.attach.Domains)
	}

	t.Run("the model host resolves into the tunnel", func(t *testing.T) {
		addresses, err := e.program.LookupContextHost(e.ctx, modelHost)
		if err != nil || len(addresses) == 0 || !tunnel.TunnelPrefix.Contains(netip.MustParseAddr(addresses[0])) {
			t.Fatalf("%v, %v", addresses, err)
		}
	})

	t.Run("a tool's model traffic goes to the proxy", func(t *testing.T) {
		e.owners.next(claudeCode, nil)
		if got := e.reachModel(t, ""); got != "by name" {
			t.Fatalf("the model host was reached %q", got)
		}
		if noted := e.reader.noted(); !reflect.DeepEqual(noted, []string{"claude"}) {
			t.Fatalf("the proxy was told %q", noted)
		}
	})

	t.Run("another program's traffic still gets there, unread", func(t *testing.T) {
		e.owners.next(browser, nil)
		if got := e.reachModel(t, ""); got != "by name" {
			t.Fatalf("the model host was reached %q", got)
		}
		if noted := e.reader.noted(); len(noted) != 0 {
			t.Fatalf("the proxy was told %q about a flow it never got", noted)
		}
	})

	t.Run("status says which routes are captured", func(t *testing.T) {
		status := e.status(t, func(status Status) bool { return status.Counts["unread_not_tool"] == 1 })
		if !reflect.DeepEqual(status.Routes, routes) || status.Counts["read"] != 1 || !contains(status.Domains, modelHost) {
			t.Fatalf("status: %+v", status)
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

// A Connection approved while phase up runs is served by the session it joins, with
// no new one. The tunnel has to learn its host then, or its traffic would pass unread
// until the session was next reopened.
func TestAConnectionAddedWhileTheEngineRunsIsCaptured(t *testing.T) {
	e := startEngine(t, nil)
	if contains(e.attach.Domains, addedHost) {
		t.Fatalf("the host was captured before its Connection existed: %v", e.attach.Domains)
	}
	proxyRoots := x509.NewCertPool()
	proxyRoots.AppendCertsFromPEM(e.proxyCert)
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: e.program.DialContext, TLSClientConfig: &tls.Config{RootCAs: proxyRoots}, DisableKeepAlives: true,
	}}

	// Console now lists the new Connection, and the proxy is told to look.
	config := testSessionPayload()
	delete(config, "sessionCredential")
	config["configGeneration"] = 2
	config["connections"] = append(config["connections"].([]any), addedConnectionPayload())
	e.refreshed.Store(&config)
	response, err := client.Post("http://"+tunnel.ControlHost+"/v1/refresh", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"refreshed":true`) {
		t.Fatalf("refresh: %d %.300s", response.StatusCode, body)
	}

	// The helper may first be sent the names the session started with again.
	for sent, deadline := false, time.After(10*time.Second); !sent; {
		select {
		case domains := <-e.updates:
			sent = contains(domains, addedHost)
			if !contains(domains, apiHost) {
				t.Fatalf("the helper was sent %v", domains)
			}
		case <-deadline:
			t.Fatal("the helper was never sent the new Connection's host")
		}
	}
	addresses, err := e.program.LookupContextHost(e.ctx, addedHost)
	if err != nil || len(addresses) == 0 || !tunnel.TunnelPrefix.Contains(netip.MustParseAddr(addresses[0])) {
		t.Fatalf("the new host resolves to %v, %v", addresses, err)
	}
	for name, dial := range map[string]func(context.Context, string, string) (net.Conn, error){
		"by its name": e.program.DialContext,
		"by an address, as a program with its own DNS would": func(ctx context.Context, network, _ string) (net.Conn, error) {
			return e.program.DialContext(ctx, network, realAPI)
		},
	} {
		client.Transport.(*http.Transport).DialContext = dial
		response, err := client.Get("https://" + addedHost + "/whoami")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var parsed struct {
			Saw string `json:"saw"`
		}
		_ = json.NewDecoder(response.Body).Decode(&parsed)
		response.Body.Close()
		if parsed.Saw != "live-added" {
			t.Fatalf("%s: the provider saw %q", name, parsed.Saw)
		}
	}
	status := e.status(t, func(status Status) bool { return contains(status.Connections, "Added API") })
	if !contains(status.Domains, addedHost) || !contains(status.Connections, "Test API") || status.LastError != "" {
		t.Fatalf("status: %+v", status)
	}
	if content, _ := os.ReadFile(StatusPath(e.directory)); strings.Contains(string(content), liveAdded) {
		t.Fatal("the status file holds a credential")
	}
}
