package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/internal/tunnel"
	"github.com/phasehq/cli/internal/tunnel/owner"
	"github.com/phasehq/cli/pkg/censor"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// The proxy's own table of model hosts is used here, so these are real names. They
// only ever name a stand-in on this machine: the engine these tests start refuses
// every address that has none.
const (
	// claudeHost is on Claude Code's list, and not on Codex's.
	claudeHost = "api.anthropic.com"
	claudePath = "/v1/messages"
	// codexHost is on Codex's list, and not on Claude Code's. In these tests it is a
	// Connection's host as well.
	codexHost = "api.openai.com"
	codexPath = "/v1/responses"

	realClaudeHost = "192.0.2.30:443"
	realCodexHost  = "192.0.2.31:443"

	// handedOut is a secret value Phase handed out, and registered with the proxy.
	handedOut = "Vq8Lm2Zr6Tx4Nb9Wc1Ke7Hy3Pd5Sg0Uf"
	liveModel = "sk-live-model-0123456789abcdefgh"
)

var (
	codexCLI = owner.Process{PID: 4003, Executable: "/opt/homebrew/bin/codex", Args: []string{"codex"}}
	// ownHello is what a program in these tests offers in its TLS hello, and nothing
	// else does. A provider that was offered it completed the handshake the program
	// itself began.
	ownHello = []string{"phase-up-test", "http/1.1"}
)

// modelArrival is one request as a stand-in provider got it.
type modelArrival struct {
	// way is how the flow reached the provider: at the address the program dialled,
	// or by the name the proxy asked for.
	way  string
	host string
	// offered are the protocols in the hello of the connection it came on.
	offered       []string
	authorization string
	body          []byte
}

// modelProvider stands in for the model providers.
type modelProvider struct {
	mu       sync.Mutex
	hellos   map[string][]string
	arrivals []modelArrival
}

func (p *modelProvider) listen(t *testing.T, ca *phaseproxy.CA, way string) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.hellos == nil {
				p.hellos = map[string][]string{}
			}
			p.hellos[hello.Conn.RemoteAddr().String()] = append([]string(nil), hello.SupportedProtos...)
			return nil, nil
		},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return ca.CertificateForHost(hello.ServerName)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.arrivals = append(p.arrivals, modelArrival{
			way: way, host: r.Host, offered: p.hellos[r.RemoteAddr],
			authorization: r.Header.Get("Authorization"), body: body,
		})
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"message","content":[]}`)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

// next returns the one request that arrived since the last call.
func (p *modelProvider) next(t *testing.T) modelArrival {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.arrivals) != 1 {
		t.Fatalf("%d requests reached the provider, and one was sent", len(p.arrivals))
	}
	arrival := p.arrivals[0]
	p.arrivals = nil
	return arrival
}

// modelConnectionPayload is a Connection whose host is a model host as well. Its
// credential is attached to a request that carries none.
func modelConnectionPayload() map[string]any {
	connection := addedConnectionPayload()
	connection["grantId"], connection["connectionId"], connection["connectionName"] = "grant-model", "model", "Model API"
	connection["credentialId"], connection["credentialName"] = "model", "Model API"
	connection["hosts"] = []any{map[string]any{"match": "exact", "value": codexHost, "port": 443}}
	connection["decoyMaterial"] = map[string]string{"token": "sk-phx-decoy-model-0123456789abcdef"}
	connection["secretMaterial"] = map[string]string{"token": liveModel}
	return connection
}

// startLeakEngine runs the engine with the proxy's own say on model traffic, as phase
// up does, and stand-ins for the model providers.
func startLeakEngine(t *testing.T, routes []string) (*running, *modelProvider) {
	t.Helper()
	// Whatever the machine's own setting is, the proxy in these tests replaces.
	t.Setenv(aiproxy.LeakProtectionEnvironmentKey, "censor")
	provider := &modelProvider{}
	e := startEngineWith(t, engineSetup{
		routes: routes, reader: ProxyReader, sealed: true,
		session: func() map[string]any {
			config := testSessionPayload()
			config["connections"] = append(config["connections"].([]any), modelConnectionPayload())
			return config
		},
		standIns: func(t *testing.T, providers *phaseproxy.CA) map[string]string {
			byAddress, byName := provider.listen(t, providers, "by address"), provider.listen(t, providers, "by name")
			return map[string]string{
				realClaudeHost: byAddress, realCodexHost: byAddress,
				claudeHost + ":443": byName, codexHost + ":443": byName,
			}
		},
	})
	return e, provider
}

// registerHandedOut registers a value with the proxy's leak protection as a program
// behind the tunnel can: through the control API, with keyed hashes only.
func (e *running) registerHandedOut(t *testing.T, id, value string) {
	t.Helper()
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DialContext: e.program.DialContext, DisableKeepAlives: true}}
	response, err := client.Get(phaseproxy.ControlURL + "/v1/inventory/key")
	if err != nil {
		t.Fatal(err)
	}
	var answer remoteapi.InventoryKeyResponse
	err = json.NewDecoder(response.Body).Decode(&answer)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("the proxy's key: %d, %v", response.StatusCode, err)
	}
	raw, err := base64.StdEncoding.DecodeString(answer.Key)
	if err != nil {
		t.Fatal(err)
	}
	key, err := censor.KeyFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := censor.IndexValue(key, "secret", id, value)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := entries.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(remoteapi.InventoryRequest{
		SchemaVersion: agentapi.SchemaVersion, Entries: []json.RawMessage{encoded}, IDKinds: []string{remoteapi.InventoryIDPhase},
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err = client.Post(phaseproxy.ControlURL+"/v1/inventory", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var registered remoteapi.InventoryResponse
	err = json.NewDecoder(response.Body).Decode(&registered)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || registered.Added != 1 {
		t.Fatalf("registering the value: %d, %+v, %v", response.StatusCode, registered, err)
	}
}

// modelRequest is what a program sends its model: something a tool read, with a
// secret value in it.
func modelRequest(host string) []byte {
	if host == codexHost {
		return []byte(`{"model":"gpt-test","input":[{"role":"user","content":"the key is ` + handedOut + `"}]}`)
	}
	return []byte(`{"model":"claude-test","max_tokens":64,"messages":[{"role":"user","content":"the key is ` + handedOut + `"}]}`)
}

// ask sends one model request to host as a program would, with a TLS hello of its
// own, and trusting only roots: the proxy's certificate authority for a flow that is
// to be read, or the providers' for one that isn't. address, when set, is where the
// program connects, as one with its own DNS does.
func (e *running) ask(t *testing.T, address, host, path string, roots *x509.CertPool) error {
	t.Helper()
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if address != "" {
				target = address
			}
			return e.program.DialContext(ctx, network, target)
		},
		TLSClientConfig: &tls.Config{RootCAs: roots, NextProtos: ownHello}, DisableKeepAlives: true,
	}}
	response, err := client.Post("https://"+host+path, "application/json", bytes.NewReader(modelRequest(host)))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", response.StatusCode)
	}
	return nil
}

// wasRead checks that the proxy took the flow: it answered with Phase's certificate,
// opened a connection of its own to the provider, and sent the request on with the
// secret value replaced.
func wasRead(t *testing.T, arrival modelArrival, host string) {
	t.Helper()
	if arrival.way != "by name" || arrival.host != host {
		t.Fatalf("the request reached the provider %s, for %q", arrival.way, arrival.host)
	}
	if reflect.DeepEqual(arrival.offered, ownHello) {
		t.Fatal("the provider was sent the program's own hello, so the proxy wasn't in between")
	}
	if bytes.Contains(arrival.body, []byte(handedOut)) || !bytes.Contains(arrival.body, []byte("ph:secret:deploy-key")) {
		t.Fatalf("the secret value wasn't replaced: %s", arrival.body)
	}
}

// wasUntouched checks that the flow went on as the program sent it: the provider
// completed the handshake the program began, and got the body byte for byte.
func wasUntouched(t *testing.T, arrival modelArrival, host, way string) {
	t.Helper()
	if arrival.way != way || arrival.host != host {
		t.Fatalf("the request reached the provider %s, for %q", arrival.way, arrival.host)
	}
	if !reflect.DeepEqual(arrival.offered, ownHello) {
		t.Fatalf("the provider's handshake wasn't the program's own: it was offered %q", arrival.offered)
	}
	if !bytes.Equal(arrival.body, modelRequest(host)) {
		t.Fatalf("the body was changed on the way: %s", arrival.body)
	}
}

// The whole of it, with the real proxy deciding: a tool's own model traffic is read
// and a secret value in it replaced, and every other program's traffic to the same
// host goes on with its own TLS and its body as it was.
func TestModelTrafficIsReadForItsOwnToolOnly(t *testing.T) {
	e, provider := startLeakEngine(t, nil)
	proxyRoots := x509.NewCertPool()
	proxyRoots.AppendCertsFromPEM(e.proxyCert)
	// The value is registered as a secrets command registers one with only phase up
	// running: with the proxy the engine's state names.
	e.registerAsACommandDoes(t, "deploy-key", handedOut)

	t.Run("Claude Code's flow to its own model host is read", func(t *testing.T) {
		e.owners.next(claudeCode, nil)
		if err := e.ask(t, realClaudeHost, claudeHost, claudePath, proxyRoots); err != nil {
			t.Fatalf("the proxy didn't answer for the host: %v", err)
		}
		wasRead(t, provider.next(t), claudeHost)
	})

	t.Run("the same flow from a program that is no tool is untouched", func(t *testing.T) {
		e.owners.next(browser, nil)
		if err := e.ask(t, realClaudeHost, claudeHost, claudePath, e.providerRoots); err != nil {
			t.Fatalf("the provider's own certificate didn't arrive: %v", err)
		}
		wasUntouched(t, provider.next(t), claudeHost, "by address")
	})

	t.Run("the same flow from a program nobody could find is untouched", func(t *testing.T) {
		e.owners.next(claudeCode, owner.ErrNotFound)
		if err := e.ask(t, realClaudeHost, claudeHost, claudePath, e.providerRoots); err != nil {
			t.Fatalf("the provider's own certificate didn't arrive: %v", err)
		}
		wasUntouched(t, provider.next(t), claudeHost, "by address")
	})

	t.Run("Codex's flow to Claude's host is untouched", func(t *testing.T) {
		e.owners.next(codexCLI, nil)
		if err := e.ask(t, realClaudeHost, claudeHost, claudePath, e.providerRoots); err != nil {
			t.Fatalf("the provider's own certificate didn't arrive: %v", err)
		}
		wasUntouched(t, provider.next(t), claudeHost, "by address")
	})

	// A Connection's host goes to the proxy for its credential whoever opened the
	// flow. When it is a model host too, it is still read for its own tool only: the
	// proxy is told which flow is whose, and never reads one as it would for a
	// program that was given the proxy through its environment.
	t.Run("a Connection's model host gets its credential, and is unread for another program", func(t *testing.T) {
		e.owners.next(browser, nil)
		if err := e.ask(t, realCodexHost, codexHost, codexPath, proxyRoots); err != nil {
			t.Fatalf("the proxy didn't answer for the Connection's host: %v", err)
		}
		arrival := provider.next(t)
		if arrival.way != "by name" || arrival.authorization != "Bearer "+liveModel {
			t.Fatalf("the Connection's credential wasn't attached: reached %s", arrival.way)
		}
		if !bytes.Equal(arrival.body, modelRequest(codexHost)) {
			t.Fatalf("another program's body was read at a Connection's host: %s", arrival.body)
		}
	})

	t.Run("a Connection's model host is read for its own tool", func(t *testing.T) {
		e.owners.next(codexCLI, nil)
		if err := e.ask(t, realCodexHost, codexHost, codexPath, proxyRoots); err != nil {
			t.Fatalf("the proxy didn't answer for the Connection's host: %v", err)
		}
		arrival := provider.next(t)
		if arrival.authorization != "Bearer "+liveModel {
			t.Fatal("the Connection's credential wasn't attached")
		}
		wasRead(t, arrival, codexHost)
	})

	t.Run("status counts each", func(t *testing.T) {
		status := e.status(t, func(status Status) bool { return status.Counts["read"] == 2 && status.Counts["unread_not_tool"] == 3 })
		for route, want := range map[string]int{
			"read": 2, "unread_not_tool": 3, "owner_lookup_failed": 1, "proxy_by_tls_name": 2,
			"unread_no_proxy": 0, "unread_not_noted": 0, "proxy_not_noted": 0,
		} {
			if status.Counts[route] != want {
				t.Errorf("%s: %d, want %d (%v)", route, status.Counts[route], want, status.Counts)
			}
		}
		// The three flows that weren't read went on by the address the program dialled.
		if status.Counts["tcp"] != 3 {
			t.Errorf("%d flows passed through unread: %v", status.Counts["tcp"], status.Counts)
		}
		// What is read is the proxy's own table, for the tools the tunnel can recognise.
		if !contains(status.ReadTools["claude"], claudeHost) || contains(status.ReadTools["codex"], claudeHost) || !contains(status.ReadTools["codex"], codexHost) {
			t.Errorf("read for: %v", status.ReadTools)
		}
		// A domain the proxy reads with every name under it is listed as both.
		if !contains(status.ReadTools["cursor"], "cursor.sh") || !contains(status.ReadTools["cursor"], "*.cursor.sh") {
			t.Errorf("Cursor's domain isn't listed with the names under it: %v", status.ReadTools)
		}
		// With everything captured, a model host is caught by its TLS hello.
		if contains(status.Domains, claudeHost) {
			t.Errorf("a model host was captured by name: %v", status.Domains)
		}
		content, err := os.ReadFile(StatusPath(e.directory))
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{handedOut, liveModel, "Chrome", "/opt/homebrew", "192.0.2."} {
			if strings.Contains(string(content), private) {
				t.Errorf("the status file holds %q", private)
			}
		}
	})
}

// With less than everything routed in, the proxy's model hosts are captured by name,
// and the same rule holds for a flow that comes in that way.
func TestModelHostsCapturedByNameAreReadForTheirOwnToolOnly(t *testing.T) {
	routes := []string{"192.0.2.0/24"}
	e, provider := startLeakEngine(t, routes)
	for _, host := range []string{claudeHost, codexHost, "chatgpt.com"} {
		if !contains(e.attach.Domains, host) {
			t.Fatalf("%s isn't among the names sent to the helper: %v", host, e.attach.Domains)
		}
	}
	if addresses, err := e.program.LookupContextHost(e.ctx, claudeHost); err != nil || len(addresses) == 0 || !tunnel.TunnelPrefix.Contains(netip.MustParseAddr(addresses[0])) {
		t.Fatalf("%s resolves to %v, %v", claudeHost, addresses, err)
	}
	proxyRoots := x509.NewCertPool()
	proxyRoots.AppendCertsFromPEM(e.proxyCert)
	e.registerHandedOut(t, "deploy-key", handedOut)

	e.owners.next(claudeCode, nil)
	if err := e.ask(t, "", claudeHost, claudePath, proxyRoots); err != nil {
		t.Fatalf("the proxy didn't answer for the host: %v", err)
	}
	wasRead(t, provider.next(t), claudeHost)

	e.owners.next(browser, nil)
	if err := e.ask(t, "", claudeHost, claudePath, e.providerRoots); err != nil {
		t.Fatalf("the provider's own certificate didn't arrive: %v", err)
	}
	wasUntouched(t, provider.next(t), claudeHost, "by name")

	status := e.status(t, func(status Status) bool { return status.Counts["unread_not_tool"] == 1 })
	if status.Counts["read"] != 1 || !reflect.DeepEqual(status.Routes, routes) {
		t.Fatalf("status: %+v", status)
	}
}

// Without a reader the tunnel reads nothing, and the proxy is still told that each
// flow it is handed is the tunnel's. A Connection's host that is a model host as well
// gets its credential, and nobody's body is read: not even its own tool's, which the
// proxy would read for a program that was given the proxy through its environment.
func TestWithoutAReaderTheProxyReadsNothingBehindTheTunnel(t *testing.T) {
	t.Setenv(aiproxy.LeakProtectionEnvironmentKey, "censor")
	provider := &modelProvider{}
	e := startEngineWith(t, engineSetup{
		sealed: true, noReader: true,
		session: func() map[string]any {
			config := testSessionPayload()
			config["connections"] = append(config["connections"].([]any), modelConnectionPayload())
			return config
		},
		standIns: func(t *testing.T, providers *phaseproxy.CA) map[string]string {
			return map[string]string{realCodexHost: provider.listen(t, providers, "by address"), codexHost + ":443": provider.listen(t, providers, "by name")}
		},
	})
	proxyRoots := x509.NewCertPool()
	proxyRoots.AppendCertsFromPEM(e.proxyCert)
	e.registerHandedOut(t, "deploy-key", handedOut)
	e.owners.next(codexCLI, nil)
	if err := e.ask(t, realCodexHost, codexHost, codexPath, proxyRoots); err != nil {
		t.Fatalf("the proxy didn't answer for the Connection's host: %v", err)
	}
	arrival := provider.next(t)
	if arrival.authorization != "Bearer "+liveModel {
		t.Fatal("the Connection's credential wasn't attached")
	}
	if !bytes.Equal(arrival.body, modelRequest(codexHost)) {
		t.Fatalf("the body was read with no reader set: %s", arrival.body)
	}
	status := e.status(t, func(status Status) bool { return status.Counts["proxy_by_tls_name"] == 1 })
	if len(status.ReadTools) != 0 || status.Counts["read"] != 0 {
		t.Fatalf("status: %+v", status)
	}
}
