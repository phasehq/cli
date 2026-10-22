package aiproxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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
	ManifestURL        string
	Remote             bool
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
	Remote                bool
	AdvertiseHost         string
	TLSCertificatePath    string
	TLSPrivateKeyPath     string
	PostgresListenAddress string
	RemoteRootCAs         *x509.CertPool
	RemoteResolver        IPResolver
	Transport             http.RoundTripper
	DialContext           func(context.Context, string, string) (net.Conn, error)
	Stdout                io.Writer
	Stderr                io.Writer
	OnStarted             func(Endpoints)
	UpstreamTLSConfig     *tls.Config
	// BootstrapSkills are installed by the remote bootstrap snippet served at
	// GET http://phase.invalid/v1/bootstrap (remote mode only).
	BootstrapSkills []BootstrapSkill

	runtime *engineRuntime
}

type engineRuntime struct {
	mu         sync.Mutex
	capability agentapi.SensitiveString
	decoys     *decoyHistory
}

// BootstrapSkill is an Agent skill file the relay bootstrap installs into a
// sandbox, with Path relative to the sandbox user's home directory.
type BootstrapSkill struct {
	Path    string
	Content string
}

// drainingHandler prevents a new HTTP request from entering the old backend
// session while the engine is shutting down. Waiting for the tracked handlers
// is required before a successor OpenSession mutates the shared Agent client.
type drainingHandler struct {
	handler http.Handler
	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup
}

func (h *drainingHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	h.mu.Lock()
	if h.closing {
		h.mu.Unlock()
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
	if e.Remote {
		_, err := e.validateRemoteConfiguration()
		return err
	}
	if _, err := e.validateRemoteConfiguration(); err != nil {
		return err
	}
	proxyAddress := defaultAddress(e.ListenAddress)
	if err := validateExplicitListenPort(proxyAddress, "local Phase AI proxy listener"); err != nil {
		return err
	}
	proxyHost, _, err := net.SplitHostPort(proxyAddress)
	if err != nil || !isLoopbackHost(proxyHost) {
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
			"set_header", "replace_header", "remove_header", "set_param", "set_path", "replace_path_regex", "aws_sigv4", "pg_handshake",
		},
	}
}

func (e *Engine) RequiresAgentToken() bool { return e.Remote }

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
	remoteIdentity, err := e.validateRemoteConfiguration()
	if err != nil {
		return err
	}
	if e.Remote {
		if command != nil {
			return errors.New("remote Phase AI mode runs only under phase relay start, without a child command")
		}
		if session == nil || session.Client == nil || session.Client.TokenType() != agentapi.TokenAgent {
			return errors.New("remote Phase AI mode requires Agent-token login")
		}
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
	// and the relay recycle sessions in place). Remember this session's
	// Agent-visible material so clients provisioned by an earlier session keep
	// working after a recycle.
	state.decoys = e.decoyHistory()
	state.decoys.remember(session.Config.Connections)

	rawProxyListener, err := net.Listen("tcp", defaultAddress(e.ListenAddress))
	if err != nil {
		return fmt.Errorf("listen for Phase AI HTTP proxy: %w", err)
	}
	var proxyListener net.Listener = rawProxyListener
	if e.Remote {
		proxyListener = tls.NewListener(rawProxyListener, &tls.Config{
			Certificates: []tls.Certificate{*remoteIdentity.certificate}, MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		})
	}
	defer proxyListener.Close()
	if (e.Remote && !listenerIsNonLoopback(proxyListener)) || (!e.Remote && !listenerIsLoopback(proxyListener)) {
		return errors.New("Phase AI proxy listener resolved on an unsafe interface")
	}

	transport := e.Transport
	if transport == nil {
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.Proxy = nil
		base.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		transport = base
	}
	dial := e.DialContext
	if dial == nil {
		dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
		dial = dialer.DialContext
	}
	unboundTransport := transport
	unboundDial := dial
	if e.Remote {
		base, ok := transport.(*http.Transport)
		if !ok {
			return errors.New("remote Phase AI proxy requires a controllable HTTP transport")
		}
		guard := newRemoteEgressGuard(e.RemoteResolver)
		guardedDial := guard.guardedDial(dial)
		guardedTransport := guardedRemoteHTTPTransport(base, guardedDial)
		unboundTransport = guardedTransport
		unboundDial = guardedDial
	}
	ctx, cancel := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	events, err := newEventBuffer(state, e.EventFlushInterval, e.EventSpoolDirectory, e.EventSpoolMaxBytes)
	if err != nil {
		return err
	}
	defer events.Stop()
	adapters, err := e.startProtocolAdapters(ctx, state, events, session.CA, dial, remoteIdentity)
	if err != nil {
		return err
	}
	defer adapters.Close()

	credential := runtimeCapability.Reveal()
	proxyScheme := "http"
	proxyAddress := proxyListener.Addr().String()
	proxyEndpoint, err := endpointForListener(proxyListener, false, "")
	if err != nil {
		return err
	}
	if e.Remote {
		proxyScheme = "https"
		proxyEndpoint, err = advertisedEndpoint(remoteIdentity.host, proxyListener)
		if err != nil {
			return err
		}
		proxyAddress = net.JoinHostPort(proxyEndpoint.Host, fmt.Sprintf("%d", proxyEndpoint.Port))
	}
	proxyURL := (&url.URL{Scheme: proxyScheme, User: url.UserPassword("phase", credential), Host: proxyAddress}).String()
	baseEnvironment := os.Environ()
	credentialFamilies := make([]string, 0)
	for _, connection := range session.Config.Connections {
		credentialFamilies = append(credentialFamilies, phaseproxy.CredentialFamiliesForConnection(connection.ServiceType, connection.Injection.Action)...)
	}
	preparedCABundle, prepareErr := phaseproxy.PrepareStableProcessCABundle(session.CAPaths.Bundle, baseEnvironment, credentialFamilies)
	if prepareErr != nil {
		return prepareErr
	}
	if !preparedCABundle.Complete {
		writer := e.Stderr
		if writer == nil {
			writer = os.Stderr
		}
		_, _ = fmt.Fprintln(writer, "Phase AI could not build a complete replacement CA bundle. System-store clients require the Phase CA trusted by `phase ai enable --trust-ca`; clients that require SSL_CERT_FILE must inherit a complete public/enterprise CA bundle.")
	}
	session.CAPaths.Bundle = preparedCABundle.BundlePath
	session.CAPaths.BundleComplete = preparedCABundle.Complete
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
		PostgresAddress: adapters.postgresAddress,
		ManifestURL:     ManifestURL, Remote: e.Remote, ProcessEnvironment: processEnvironment,
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
	if e.ConnectionID != "" {
		selected, err := environments.compile(state, e.ConnectionID)
		if err != nil {
			return err
		}
		processEnvironment = selected.ProcessEnvironment
		endpoints.ProcessEnvironment = processEnvironment
		manifest.processEnvironment = processEnvironment
	}
	control := &controlHandler{state: state, environments: environments}
	if e.Remote {
		control.relayBootstrap = &bootstrapMaterial{
			proxyURL: proxyURL, caPEM: session.CA.CertificatePEM(), caPaths: session.CAPaths,
			plan: processEnvironment, skills: e.BootstrapSkills, connections: endpoints.Connections,
		}
	}
	httpHandler := &httpProxy{
		state: state, ca: session.CA, transport: transport, unboundTransport: unboundTransport,
		dial: dial, unboundDial: unboundDial, lockdown: e.Lockdown,
		remote: e.Remote, events: events, manifest: manifest, control: control, lifecycle: ctx,
	}
	trackedHandler := &drainingHandler{handler: httpHandler}
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

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func listenerIsLoopback(listener net.Listener) bool {
	address, ok := listener.Addr().(*net.TCPAddr)
	return ok && address.IP.IsLoopback()
}
