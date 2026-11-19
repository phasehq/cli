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
	// Before anything dials out: once everything is captured, a socket that isn't
	// pinned to the real interface would come straight back into the tunnel.
	tunnel.Physical.Refresh()
	go tunnel.Physical.Watch(ctx)

	upstream := cfg.Upstream
	if upstream == nil {
		upstream = tunnel.NewUpstream()
	}
	router := tunnel.NewRouter(upstream, cfg.Logf)
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
	e.link = &helperLink{path: cfg.SocketPath, device: device, port: cfg.WireGuardPort, logf: cfg.Logf, ready: make(chan struct{})}
	go e.link.run(ctx)
	go e.writeStatus(ctx)

	proxy := aiproxy.New()
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
		domains := tunnel.Domains(rules)
		s.engine.mu.Lock()
		s.engine.ready, s.engine.connections, s.engine.domains, s.engine.lastError = true, names, domains, ""
		s.engine.mu.Unlock()
		s.engine.link.setDomains(domains)
	}
	return s.inner.Serve(ctx, session)
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
		EnginePublicKey: l.device.PublicKey, EnginePort: l.port, Domains: domains, Routes: tunnel.FullRoutes,
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
