package aiproxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

const (
	DefaultProxyListenAddress    = "127.0.0.1:9543"
	DefaultPostgresListenAddress = "127.0.0.1:9544"
)

type Endpoints struct {
	ProxyAddress       string
	ProxyURL           agentapi.SensitiveString
	PostgresAddress    string
	ProcessEnvironment phaseproxy.ProcessEnvironmentPlan
	// Connections is a printable summary of the session's Connections. It
	// carries no decoy, credential, host, or proxy material.
	Connections []EndpointConnection
}

type EndpointConnection struct {
	ConnectionID string `json:"connectionId"`
	Name         string `json:"name,omitempty"`
	ServiceType  string `json:"serviceType"`
	Protocol     string `json:"protocol"`
}

type Engine struct {
	ListenAddress         string
	Lockdown              bool
	ConnectionID          string
	RefreshInterval       time.Duration
	EventFlushInterval    time.Duration
	EventSpoolDirectory   string
	EventSpoolMaxBytes    int64
	PostgresListenAddress string
	Transport             http.RoundTripper
	DialContext           func(context.Context, string, string) (net.Conn, error)
	Stdout                io.Writer
	Stderr                io.Writer
	OnStarted             func(Endpoints)
	UpstreamTLSConfig     *tls.Config

	runtime *engineRuntime
}

type engineRuntime struct {
	mu         sync.Mutex
	capability agentapi.SensitiveString
	decoys     *decoyHistory
	// leak is the process's leak protection inventory. It outlives a recycled
	// backend session and goes with the process.
	leak *leakGuard
	// flows holds what capture layers said about connections that have not
	// sent their CONNECT yet. It goes with the process as well, so a note
	// left while a session is recycled is still found.
	flows *flowNotes
}

// drainingHandler prevents a new HTTP request from entering the old backend
// session while the engine is shutting down. Waiting for the tracked handlers
// is required before a successor OpenSession mutates the shared Agent client.
type drainingHandler struct {
	handler http.Handler
	// refused is told of each request turned away here, which the handler
	// never sees.
	refused func(*http.Request)
	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup
}

// draining wraps the proxy for one engine run. A CONNECT turned away while
// the run ends uses its flow note up like any other CONNECT.
func (p *httpProxy) draining() *drainingHandler {
	return &drainingHandler{handler: p, refused: p.dropFlow}
}

func (h *drainingHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	h.mu.Lock()
	if h.closing {
		h.mu.Unlock()
		if h.refused != nil {
			h.refused(request)
		}
		http.Error(writer, "Phase AI session is refreshing", http.StatusServiceUnavailable)
		return
	}
	h.wg.Add(1)
	h.mu.Unlock()
	defer h.wg.Done()
	h.handler.ServeHTTP(writer, request)
}

func (h *drainingHandler) closeAndWait() {
	h.mu.Lock()
	h.closing = true
	h.mu.Unlock()
	h.wg.Wait()
}

var engineRuntimeInitMu sync.Mutex

func New() *Engine {
	return &Engine{
		ListenAddress: DefaultProxyListenAddress,
		Stdout:        os.Stdout, Stderr: os.Stderr, runtime: &engineRuntime{decoys: newDecoyHistory()},
	}
}

// decoyHistory returns the process-wide credential-generation memory. It is
// created lazily so a zero Engine behaves like New().
func (e *Engine) decoyHistory() *decoyHistory {
	engineRuntimeInitMu.Lock()
	defer engineRuntimeInitMu.Unlock()
	if e.runtime == nil {
		e.runtime = &engineRuntime{}
	}
	if e.runtime.decoys == nil {
		e.runtime.decoys = newDecoyHistory()
	}
	return e.runtime.decoys
}

func (e *Engine) Ready() error {
	if e.PostgresListenAddress != "" {
		if err := validateExplicitListenPort(e.PostgresListenAddress, "local PostgreSQL proxy listener"); err != nil {
			return err
		}
		host, _, err := net.SplitHostPort(e.PostgresListenAddress)
		if err != nil || !phaseproxy.IsLoopbackHost(host) {
			return errors.New("local PostgreSQL proxy listener must bind to loopback")
		}
	}
	proxyAddress := defaultAddress(e.ListenAddress)
	if err := validateExplicitListenPort(proxyAddress, "local Phase AI proxy listener"); err != nil {
		return err
	}
	proxyHost, _, err := net.SplitHostPort(proxyAddress)
	if err != nil || !phaseproxy.IsLoopbackHost(proxyHost) {
		return errors.New("local Phase AI proxy listener must bind to loopback")
	}
	return nil
}

func validateExplicitListenPort(address, label string) error {
	_, rawPort, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return fmt.Errorf("%s address is invalid", label)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s must use an explicit port from 1 through 65535; port 0/random allocation is not supported", label)
	}
	return nil
}

// leakGuard returns the process-wide leak protection, made on first use with
// the mode in the process's environment, the inventory the store holds and
// the login of the first session, which is the process's for its life.
func (e *Engine) leakGuard(store *phaseproxy.InventoryStore, login string) (*leakGuard, error) {
	engineRuntimeInitMu.Lock()
	defer engineRuntimeInitMu.Unlock()
	if e.runtime == nil {
		e.runtime = &engineRuntime{}
	}
	if e.runtime.leak == nil {
		guard, err := newStoredLeakGuard(os.Getenv(LeakProtectionEnvironmentKey), store, login)
		if err != nil {
			return nil, fmt.Errorf("start leak protection: %w", err)
		}
		e.runtime.leak = guard
	}
	return e.runtime.leak, nil
}

func (e *Engine) processRuntimeCapability(backend agentapi.SensitiveString) (agentapi.SensitiveString, error) {
	engineRuntimeInitMu.Lock()
	if e.runtime == nil {
		e.runtime = &engineRuntime{}
	}
	runtime := e.runtime
	engineRuntimeInitMu.Unlock()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.capability.Reveal() != "" {
		if runtime.capability.Reveal() == backend.Reveal() {
			return "", errors.New("backend session credential collides with the stable Phase AI runtime capability")
		}
		return runtime.capability, nil
	}
	for attempts := 0; attempts < 2; attempts++ {
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			return "", fmt.Errorf("generate Phase AI runtime capability: %w", err)
		}
		candidate := "phase_runtime_" + base64.RawURLEncoding.EncodeToString(random)
		if candidate != backend.Reveal() {
			runtime.capability = agentapi.SensitiveString(candidate)
			return runtime.capability, nil
		}
	}
	return "", errors.New("could not generate a distinct Phase AI runtime capability")
}

func (e *Engine) Capabilities() airuntime.EngineCapabilities {
	return airuntime.EngineCapabilities{
		Protocols: []string{"http", "postgres"},
		InjectionActions: []string{
			"set_header", "replace_header", "remove_header", "set_param", "set_path", "replace_path_regex", "aws_sigv4", "pg_handshake", "basic_auth",
		},
		// sealed_material is what this engine can do with the right login; the
		// runtime advertises it only when the client holds an Agent token.
		Features: []string{agentapi.FeatureInjectionList, agentapi.FeatureWhenAbsent, agentapi.FeatureSealedMaterial, agentapi.FeatureAccessPolicy, agentapi.FeatureProviderRules},
	}
}

func (e *Engine) Serve(ctx context.Context, session *airuntime.ProxySession) error {
	return e.execute(ctx, session, nil)
}

func (e *Engine) Run(ctx context.Context, session *airuntime.ProxySession, command []string) error {
	if len(command) == 0 {
		return errors.New("a child command is required")
	}
	return e.execute(ctx, session, command)
}

func (e *Engine) execute(parent context.Context, session *airuntime.ProxySession, command []string) error {
	if err := e.Ready(); err != nil {
		return err
	}
	if session == nil || session.Config == nil {
		return errors.New("Agent proxy session is incomplete")
	}
	runtimeCapability, err := e.processRuntimeCapability(session.Config.SessionCredential)
	if err != nil {
		return err
	}
	state, err := newRuntimeStateWithCapability(session, runtimeCapability)
	if err != nil {
		return err
	}
	defer state.destroy()
	// One Engine may serve several backend sessions in a row (the hook daemon
	// recycles sessions in place). Remember this session's
	// Agent-visible material so clients provisioned by an earlier session keep
	// working after a recycle.
	state.decoys = e.decoyHistory()
	state.decoys.remember(session.Config.Connections)

	proxyListener, err := net.Listen("tcp", defaultAddress(e.ListenAddress))
	if err != nil {
		return fmt.Errorf("listen for Phase AI HTTP proxy: %w", err)
	}
	defer proxyListener.Close()
	if !listenerIsLoopback(proxyListener) {
		return errors.New("Phase AI proxy listener resolved on an unsafe interface")
	}

	transport := e.Transport
	if transport == nil {
		transport = defaultUpstreamTransport()
	}
	dial := e.DialContext
	if dial == nil {
		dial = defaultUpstreamDialer().DialContext
	}
	ctx, cancel := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	leak, err := e.leakGuard(session.Inventory, session.Principal)
	if err != nil {
		return err
	}
	events, err := newEventBuffer(state, e.EventFlushInterval, e.EventSpoolDirectory, e.EventSpoolMaxBytes)
	if err != nil {
		return err
	}
	events.leak = leak
	defer events.Stop()
	adapters, err := e.startProtocolAdapters(ctx, state, events, session.CA, dial)
	if err != nil {
		return err
	}
	defer adapters.Close()

	credential := runtimeCapability.Reveal()
	proxyAddress := proxyListener.Addr().String()
	proxyEndpoint, err := endpointForListener(proxyListener, false, "")
	if err != nil {
		return err
	}
	proxyURL := (&url.URL{Scheme: "http", User: url.UserPassword("phase", credential), Host: proxyAddress}).String()
	baseEnvironment := os.Environ()
	scopedTrustKeys := make([]string, 0)
	for _, connection := range session.Config.Connections {
		scopedTrustKeys = append(scopedTrustKeys, phaseproxy.ScopedTrustEnvironmentKeys(connection.PrimaryInjectionAction())...)
	}
	preparedCABundle, prepareErr := phaseproxy.PrepareStableProcessCABundle(session.CAPaths.Bundle, baseEnvironment, scopedTrustKeys)
	if prepareErr != nil {
		return prepareErr
	}
	if !preparedCABundle.Complete {
		writer := e.Stderr
		if writer == nil {
			writer = os.Stderr
		}
		trustHint := "System-store clients require the Phase CA trusted by `phase ai enable --trust-ca`"
		if session.CAPaths.MemoryOnly {
			trustHint = "System-store clients cannot trust the Phase CA because its key is kept in memory only"
		}
		_, _ = fmt.Fprintln(writer, "Phase AI could not build a complete replacement CA bundle. "+trustHint+"; clients that require SSL_CERT_FILE must inherit a complete public/enterprise CA bundle.")
	}
	session.CAPaths.Bundle = preparedCABundle.BundlePath
	session.CAPaths.BundleComplete = preparedCABundle.Complete
	// A model host named in an inherited NO_PROXY would never reach the
	// proxy, and nothing sent to it would be read.
	session.ReadHosts = leak.readHostNames()
	processEnvironment, environmentErr := session.CompileProcessEnvironment(proxyURL, baseEnvironment, adapters.environment)
	if environmentErr != nil {
		return environmentErr
	}
	providerEnvironment, providerEnvironmentErr := session.ProviderProcessEnvironment()
	if providerEnvironmentErr != nil {
		return providerEnvironmentErr
	}
	endpoints := Endpoints{
		ProxyAddress: proxyAddress, ProxyURL: agentapi.SensitiveString(proxyURL),
		PostgresAddress:    adapters.postgresAddress,
		ProcessEnvironment: processEnvironment,
	}
	for _, connection := range session.Config.Connections {
		endpoints.Connections = append(endpoints.Connections, EndpointConnection{
			ConnectionID: connection.ConnectionID, Name: connection.ConnectionName,
			ServiceType: connection.ServiceType, Protocol: connection.Protocol,
		})
	}
	manifest := &manifestHandler{
		state: state, ca: session.CA, proxy: proxyEndpoint,
		postgres: adapters.postgresEndpoint, events: events,
		processEnvironment: processEnvironment, providerEnvironment: providerEnvironment,
	}
	environments := &connectionEnvironmentCompiler{session: session, proxyURL: proxyURL, base: baseEnvironment, adapters: adapters.environment}
	state.setEnvironmentCheck(environments.holdsFor(processEnvironment, e.ConnectionID))
	if e.ConnectionID != "" {
		selected, err := environments.compile(state, e.ConnectionID)
		if err != nil {
			return err
		}
		processEnvironment = selected.ProcessEnvironment
		endpoints.ProcessEnvironment = processEnvironment
		manifest.processEnvironment = processEnvironment
	}
	// A proxy started for one harness names its clients' flows as that tool's
	// wherever the tool's own list reads the host. Every host a list reads is
	// read either way, and in the same way. A label that names no listed tool
	// leaves the tool unknown.
	tool := leak.hosts.toolFor(session.HarnessLabel)
	control := &controlHandler{state: state, environments: environments, leak: leak}
	httpHandler := &httpProxy{
		state: state, ca: session.CA, transport: transport,
		dial: dial, lockdown: e.Lockdown, events: events, manifest: manifest, control: control, lifecycle: ctx,
		leak: leak, tool: tool, flows: e.flowNotes(),
	}
	trackedHandler := httpHandler.draining()
	proxyServer := &http.Server{
		Handler: trackedHandler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		serveHTTP(proxyServer, proxyListener, state)
	}()
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		e.monitor(ctx, state)
	}()
	if e.OnStarted != nil {
		e.OnStarted(endpoints)
	}

	var runErr error
	if command == nil {
		select {
		case <-ctx.Done():
			runErr = ctx.Err()
		case runErr = <-state.fatal:
		}
	} else {
		environment, envErr := phaseproxy.ApplyProcessEnvironment(baseEnvironment, processEnvironment)
		if envErr != nil {
			return envErr
		}
		child := exec.CommandContext(ctx, command[0], command[1:]...)
		child.Env = environment
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, e.Stdout, e.Stderr
		if child.Stdout == nil {
			child.Stdout = os.Stdout
		}
		if child.Stderr == nil {
			child.Stderr = os.Stderr
		}
		if err := child.Start(); err != nil {
			return fmt.Errorf("start proxy-managed child: %w", err)
		}
		childDone := make(chan error, 1)
		go func() { childDone <- child.Wait() }()
		select {
		case runErr = <-childDone:
		case runErr = <-state.fatal:
			cancel()
			<-childDone
		case <-ctx.Done():
			runErr = ctx.Err()
			<-childDone
		}
	}

	cancel()
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := proxyServer.Shutdown(shutdownContext); err != nil {
		_ = proxyServer.Close()
	}
	httpHandler.CloseHijacked()
	trackedHandler.closeAndWait()
	adapters.Close()
	<-serverDone
	<-monitorDone
	if err := events.Stop(); err != nil {
		// The flush failure is reported, but a session lifecycle error stays
		// visible so callers still recognise it and recycle the session.
		if errors.Is(runErr, airuntime.ErrSessionExpired) || errors.Is(runErr, airuntime.ErrSessionReprovisionRequired) {
			return errors.Join(runErr, err)
		}
		return err
	}
	if errors.Is(runErr, context.Canceled) {
		return nil
	}
	return runErr
}

// defaultUpstreamTransport is what sends the proxy's requests when the engine
// is given no transport: Go's default, without the environment's proxy.
func defaultUpstreamTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return transport
}

// defaultUpstreamDialer opens the proxy's tunnels when the engine is given no
// dialer.
func defaultUpstreamDialer() *net.Dialer {
	return &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
}

func endpointForListener(listener net.Listener, tlsEnabled bool, serverName string) (remoteapi.Endpoint, error) {
	host, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return remoteapi.Endpoint{}, err
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return remoteapi.Endpoint{}, err
	}
	return remoteapi.Endpoint{Host: host, Port: port, TLS: tlsEnabled, TLSServerName: serverName}, nil
}

func serveHTTP(server *http.Server, listener net.Listener, state *runtimeState) {
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
		state.fail(errors.New("Phase AI listener stopped unexpectedly"))
	}
}

func defaultAddress(value string) string {
	if value == "" {
		return DefaultProxyListenAddress
	}
	return value
}

func listenerIsLoopback(listener net.Listener) bool {
	address, ok := listener.Addr().(*net.TCPAddr)
	return ok && address.IP.IsLoopback()
}
