// Package engine is the unprivileged half of `phase up`: the credential proxy, the
// user-space network stack in front of it, and the link to the privileged helper.
package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/aiproxy"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/tunnel"
	"github.com/phasehq/cli/internal/tunnel/control"
)

// The engine's loopback ports. They differ from `phase ai run`'s, so both can run.
const (
	DefaultProxyAddress    = "127.0.0.1:9553"
	DefaultPostgresAddress = "127.0.0.1:9554"
	DefaultWireGuardPort   = 9555
)

// ErrNoKeystore stops the engine when the certificate authority's key can only be
// kept in memory. Programs behind the tunnel trust the certificate authority through
// the system trust store, and one that is new in every process is never in it, so
// every Connection host would fail. The engine stops instead, and the helper steps
// aside. The process keeps an in-memory certificate authority once it has made one,
// so trying again in the same process would change nothing.
var ErrNoKeystore = errors.New("the certificate authority's key can't be kept in a system keystore, so programs couldn't trust it; phase up has stopped")

// Runtime opens backend sessions. airuntime.Runtime is one.
type Runtime interface {
	ServeManaged(context.Context, airuntime.Engine) error
}

// Config configures the engine.
type Config struct {
	Runtime         Runtime
	SocketPath      string
	StateDirectory  string
	ProxyAddress    string
	PostgresAddress string
	WireGuardPort   int
	Logf            func(format string, args ...any)
	// Upstream and UpstreamRootCAs replace how the proxy reaches providers. Tests use
	// them to reach stand-ins.
	Upstream        *tunnel.Upstream
	UpstreamRootCAs *x509.CertPool

	// Routes replace the routes that capture everything, for a run that captures
	// less. Model hosts are then captured by name too, as Connection hosts are, or
	// they would never reach the tunnel.
	Routes []string
	// Reader gives the tunnel the proxy's say on model traffic: which hosts are read,
	// and for which tool. ProxyReader is the proxy's own. Without one, no model host
	// is read, and the proxy is still told that every flow the tunnel hands it is the
	// tunnel's, from no known tool.
	Reader func(*aiproxy.Engine) tunnel.Reader
	// Owner finds the program that opened a flow. Tests replace it.
	Owner tunnel.OwnerFunc
}

// Status is what `phase status` shows about the engine. It holds no credential.
type Status struct {
	PID          int            `json:"pid"`
	Started      time.Time      `json:"started"`
	Ready        bool           `json:"ready"`
	Interface    string         `json:"interface,omitempty"`
	Connections  []string       `json:"connections,omitempty"`
	Domains      []string       `json:"domains,omitempty"`
	Counts       map[string]int `json:"counts,omitempty"`
	TCPBytes     int64          `json:"tcpBytes"`
	UDPBytes     int64          `json:"udpBytes"`
	LastError    string         `json:"lastError,omitempty"`
	HelperLinked bool           `json:"helperLinked"`

	// Routes are what is captured in place of everything, when less was asked for.
	Routes []string `json:"routes,omitempty"`
	// ReadTools are the tools whose model traffic is read, each with its model hosts.
	// It's the proxy's own table, and says nothing about what any program did. What
	// programs did is in Counts, as numbers only: a flow to a model host is counted
	// as "read" for the host's own tool, "unread_not_tool" for any other program,
	// "owner_lookup_failed" when the program couldn't be found in time,
	// "unread_no_proxy" when the proxy couldn't take it, and "unread_not_noted" when
	// the proxy couldn't be told whose it was. All but the first leave the flow
	// unread. "proxy_not_noted" is a Connection's flow that went to the proxy for its
	// credential without that word, and was read for nobody.
	ReadTools map[string][]string `json:"readTools,omitempty"`
}

// StatusPath is where a running engine writes its status.
func StatusPath(directory string) string { return filepath.Join(directory, "engine.json") }

// ReadStatus reads a running engine's status.
func ReadStatus(directory string) (Status, error) {
	var status Status
	content, err := os.ReadFile(StatusPath(directory))
	if err != nil {
		return status, err
	}
	return status, json.Unmarshal(content, &status)
}

type engine struct {
	cfg     Config
	router  *tunnel.Router
	link    *helperLink
	started time.Time

	mu          sync.Mutex
	ready       bool
	connections []string
	domains     []string
	lastError   string
}

// Run serves until ctx ends.
func Run(ctx context.Context, cfg Config) error {
	if cfg.ProxyAddress == "" {
		cfg.ProxyAddress = DefaultProxyAddress
	}
	if cfg.PostgresAddress == "" {
		cfg.PostgresAddress = DefaultPostgresAddress
	}
	if cfg.WireGuardPort == 0 {
		cfg.WireGuardPort = DefaultWireGuardPort
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(cfg.StateDirectory, 0o700); err != nil {
		return err
	}
	// An engine that was killed leaves its proxy's state behind. It names no proxy
	// of this engine's.
	_ = os.Remove(ProxyStatePath(cfg.StateDirectory))
	// Before anything dials out: once everything is captured, a socket that isn't
	// pinned to the real interface would come straight back into the tunnel.
	tunnel.Physical.Refresh()
	go tunnel.Physical.Watch(ctx)

	upstream := cfg.Upstream
	if upstream == nil {
		upstream = tunnel.NewUpstream()
	}
	router := tunnel.NewRouter(upstream, cfg.Logf)
	if cfg.Owner != nil {
		router.FindOwnersWith(cfg.Owner, 0)
	}
	proxy := aiproxy.New()
	routes := cfg.Routes
	if len(routes) == 0 {
		routes = tunnel.FullRoutes
	}
	// The router always has someone to tell the proxy whose flow a CONNECT carries.
	// The proxy takes a CONNECT it was told nothing about for a program that was
	// given the proxy through its environment, and reads any model host for it.
	reader := tunnel.Reader(proxyReader{proxy: proxy})
	if cfg.Reader != nil {
		reader = cfg.Reader(proxy)
	}
	// With everything captured, a model host is caught by the name in its TLS hello.
	// With less, it only reaches the tunnel if it's captured by name.
	router.Read(reader, len(cfg.Routes) > 0)
	stack, err := tunnel.NewStack(tunnel.Hooks{
		Prepare: router.Prepare, TCP: router.HandleTCP, UDP: router.HandleUDP,
		DNSAddr: tunnel.DNSAddress, DNS: router.AnswerDNS, Echo: router.Echo,
	}, tunnel.MTU)
	if err != nil {
		return err
	}
	defer stack.Close()
	device, err := tunnel.StartEngineDevice(stack, cfg.WireGuardPort)
	if err != nil {
		return fmt.Errorf("listen for the helper on 127.0.0.1:%d: %w", cfg.WireGuardPort, err)
	}
	defer device.Close()

	e := &engine{cfg: cfg, router: router, started: time.Now()}
	e.link = &helperLink{path: cfg.SocketPath, device: device, port: cfg.WireGuardPort, routes: routes, logf: cfg.Logf, ready: make(chan struct{})}
	go e.link.run(ctx)
	// The status file is gone, and nothing more is written to the state directory,
	// by the time Run returns, however it ends.
	statusContext, stopStatus := context.WithCancel(ctx)
	statusStopped := make(chan struct{})
	go func() {
		defer close(statusStopped)
		e.writeStatus(statusContext)
	}()
	defer func() {
		stopStatus()
		<-statusStopped
	}()

	proxy.ListenAddress = cfg.ProxyAddress
	proxy.PostgresListenAddress = cfg.PostgresAddress
	transport := upstream.Transport()
	if cfg.UpstreamRootCAs != nil {
		transport.TLSClientConfig.RootCAs = cfg.UpstreamRootCAs
		proxy.UpstreamTLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.UpstreamRootCAs}
	}
	proxy.Transport = transport
	proxy.DialContext = upstream.DialContext
	proxy.EventSpoolDirectory = filepath.Join(cfg.StateDirectory, "events")
	proxy.Stdout, proxy.Stderr = io.Discard, io.Discard
	return e.serve(ctx, &sessionEngine{inner: proxy, engine: e})
}

// serve keeps a backend session open, replacing it whenever it expires or changes,
// and retrying with a growing wait when it can't be opened.
func (e *engine) serve(ctx context.Context, session *sessionEngine) error {
	attempt := 0
	for ctx.Err() == nil {
		err := e.cfg.Runtime.ServeManaged(ctx, session)
		if ctx.Err() != nil {
			return nil
		}
		switch {
		case errors.Is(err, airuntime.ErrSessionReprovisionRequired), errors.Is(err, airuntime.ErrSessionExpired):
			e.cfg.Logf("the session changed; opening a new one")
			attempt = 0
			continue
		case errors.Is(err, airuntime.ErrAuthenticationRequired), errors.Is(err, ErrNoKeystore):
			e.setError(err)
			return err
		case err == nil:
			attempt = 0
			continue
		}
		e.setError(err)
		delay := min(time.Second<<attempt, 30*time.Second)
		attempt++
		e.cfg.Logf("couldn't open a session: %v; retrying in %s", err, delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
	return nil
}

func (e *engine) setError(err error) {
	e.mu.Lock()
	e.lastError = err.Error()
	e.mu.Unlock()
}

// sessionEngine is the proxy, with the tunnel told about each session's Connections.
type sessionEngine struct {
	inner  *aiproxy.Engine
	engine *engine
}

func (s *sessionEngine) Ready() error                               { return s.inner.Ready() }
func (s *sessionEngine) Capabilities() airuntime.EngineCapabilities { return s.inner.Capabilities() }
func (s *sessionEngine) Run(context.Context, *airuntime.ProxySession, []string) error {
	return errors.New("phase up doesn't run commands")
}

func (s *sessionEngine) Serve(ctx context.Context, session *airuntime.ProxySession) error {
	if session.CAPaths.MemoryOnly {
		return ErrNoKeystore
	}
	rules := tunnel.RulesFromConnections(session.Config.Connections)
	names := connectionNames(session.Config.Connections)
	s.inner.OnStarted = func(endpoints aiproxy.Endpoints) {
		if err := s.engine.router.Update(endpoints.ProxyURL.Reveal(), endpoints.PostgresAddress, rules); err != nil {
			s.engine.setError(err)
			return
		}
		// From here a command on this machine can register a secret value it hands
		// out with the proxy's leak protection. Without the state the tunnel works
		// as before, and such a value isn't known to the proxy.
		if err := s.engine.publishProxy(endpoints.ProxyURL.Reveal()); err != nil {
			s.engine.cfg.Logf("couldn't write the proxy's state, so secret values handed out on this machine aren't registered with leak protection: %v", err)
		}
		s.engine.serving(names)
	}
	s.inner.OnConnectionsChanged = s.connectionsChanged
	// The state goes when the proxy stops serving this session, however that ends.
	defer s.engine.withdrawProxy()
	return s.inner.Serve(ctx, session)
}

// connectionsChanged follows a session whose Connections changed while it ran: a
// Connection added, given other hosts, or removed. Without it the tunnel would keep
// the hosts the session started with, and a new Connection's traffic would pass
// unread until the session was next reopened.
func (s *sessionEngine) connectionsChanged(connections []aiproxy.ConnectionHosts) {
	var rules []tunnel.Rule
	names := make([]string, 0, len(connections))
	for _, connection := range connections {
		for _, host := range connection.Hosts {
			rules = append(rules, tunnel.Rule{ConnectionID: connection.ConnectionID, Protocol: connection.Protocol, Host: host})
		}
		name := connection.Name
		if name == "" {
			name = connection.ConnectionID
		}
		names = append(names, name)
	}
	sort.Strings(names)
	s.engine.router.SetRules(rules)
	s.engine.serving(names)
}

// serving records which Connections the tunnel now serves, and sends the names to
// capture for them to the helper.
func (e *engine) serving(connections []string) {
	domains := e.router.CapturedDomains()
	e.mu.Lock()
	e.ready, e.connections, e.domains, e.lastError = true, connections, domains, ""
	e.mu.Unlock()
	e.link.setDomains(domains)
}

func connectionNames(connections []agentapi.Connection) []string {
	names := make([]string, 0, len(connections))
	for _, connection := range connections {
		name := connection.ConnectionName
		if name == "" {
			name = connection.ConnectionID
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (e *engine) writeStatus(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	path := StatusPath(e.cfg.StateDirectory)
	defer os.Remove(path)
	for {
		e.mu.Lock()
		name, _, _ := tunnel.Physical.Current()
		status := Status{
			PID: os.Getpid(), Started: e.started, Ready: e.ready, Interface: name,
			Connections: e.connections, Domains: e.domains, Counts: e.router.Counts(),
			Routes: e.cfg.Routes, ReadTools: e.router.ReadTools(),
			TCPBytes:  e.router.Traffic.TCPUp.Load() + e.router.Traffic.TCPDown.Load(),
			UDPBytes:  e.router.Traffic.UDPUp.Load() + e.router.Traffic.UDPDown.Load(),
			LastError: e.lastError, HelperLinked: e.link.linked(),
		}
		e.mu.Unlock()
		if content, err := json.Marshal(status); err == nil {
			temporary := path + ".tmp"
			if os.WriteFile(temporary, content, 0o600) == nil {
				_ = os.Rename(temporary, path)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// helperLink attaches to the helper once the first session is ready, and stays
// attached. Its open connection is how the helper knows the engine is alive.
type helperLink struct {
	path   string
	device *tunnel.EngineDevice
	port   int
	// routes are what the helper is asked to send into the tunnel.
	routes []string
	logf   func(string, ...any)

	mu        sync.Mutex
	domains   []string
	ready     chan struct{}
	readyOnce sync.Once
	changed   chan struct{}
	attached  bool
}

func (l *helperLink) setDomains(domains []string) {
	l.mu.Lock()
	l.domains = append([]string(nil), domains...)
	if l.changed == nil {
		l.changed = make(chan struct{}, 1)
	}
	changed := l.changed
	l.mu.Unlock()
	select {
	case changed <- struct{}{}:
	default:
	}
	l.readyOnce.Do(func() { close(l.ready) })
}

func (l *helperLink) linked() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.attached
}

func (l *helperLink) run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-l.ready:
	}
	for ctx.Err() == nil {
		if err := l.attach(ctx); err != nil && ctx.Err() == nil {
			l.logf("helper: %v", err)
		}
		l.mu.Lock()
		l.attached = false
		l.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (l *helperLink) attach(ctx context.Context) error {
	conn, err := control.Dial(l.path)
	if err != nil {
		return err
	}
	defer conn.Close()
	l.mu.Lock()
	domains := append([]string(nil), l.domains...)
	changed := l.changed
	l.mu.Unlock()
	reply, err := conn.Call(control.Request{Op: control.OpAttach, Attach: &control.Attach{
		EnginePublicKey: l.device.PublicKey, EnginePort: l.port, Domains: domains, Routes: l.routes,
	}}, 15*time.Second)
	if err != nil {
		return err
	}
	if err := l.device.SetPeer(reply.PeerPublicKey); err != nil {
		return err
	}
	l.mu.Lock()
	l.attached = true
	l.mu.Unlock()
	l.logf("attached to the helper")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
			l.mu.Lock()
			domains := append([]string(nil), l.domains...)
			l.mu.Unlock()
			if err := conn.Send(control.Request{Op: control.OpUpdate, Domains: domains}); err != nil {
				return err
			}
		case <-ticker.C:
			if err := conn.Send(control.Request{Op: control.OpPing}); err != nil {
				return err
			}
		}
	}
}
