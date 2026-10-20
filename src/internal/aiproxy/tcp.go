package aiproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
)

type protocolAdapters struct {
	state  *runtimeState
	events *eventBuffer
	ca     interface {
		CertificateForHost(string) (*tls.Certificate, error)
	}
	tlsConfig         *tls.Config
	dial              func(context.Context, string, string) (net.Conn, error)
	serverCertificate *tls.Certificate

	mu               sync.Mutex
	listeners        []net.Listener
	connections      map[net.Conn]struct{}
	closed           bool
	wg               sync.WaitGroup
	environment      map[string]string
	postgresAddress  string
	postgresEndpoint *remoteapi.Endpoint
}

func (e *Engine) startProtocolAdapters(ctx context.Context, state *runtimeState, events *eventBuffer, ca interface {
	CertificateForHost(string) (*tls.Certificate, error)
}, dial func(context.Context, string, string) (net.Conn, error), remoteIdentity *remoteTLSIdentity) (*protocolAdapters, error) {
	adapters := &protocolAdapters{state: state, events: events, ca: ca, tlsConfig: e.UpstreamTLSConfig, dial: dial, connections: make(map[net.Conn]struct{}), environment: make(map[string]string)}
	if remoteIdentity != nil {
		adapters.serverCertificate = remoteIdentity.certificate
	}
	postgres := state.protocolBindings("postgres")
	if len(postgres) > 0 {
		for _, binding := range postgres {
			if _, _, err := exactUpstream(binding.connection, 5432); err != nil {
				return nil, err
			}
		}
		listenAddress := e.PostgresListenAddress
		if listenAddress == "" {
			listenAddress = DefaultPostgresListenAddress
		}
		if e.Remote {
			if e.PostgresListenAddress == "" {
				return nil, errors.New("remote PostgreSQL binding requires a PostgreSQL listen address")
			}
			listenAddress = e.PostgresListenAddress
		}
		listener, err := net.Listen("tcp", listenAddress)
		if err != nil {
			return nil, err
		}
		if e.Remote && !listenerIsNonLoopback(listener) {
			_ = listener.Close()
			return nil, errors.New("remote PostgreSQL listener resolved on loopback")
		}
		adapters.listeners = append(adapters.listeners, listener)
		adapterHost := "127.0.0.1"
		localEndpoint, endpointErr := endpointForListener(listener, true, adapterHost)
		if endpointErr != nil {
			adapters.Close()
			return nil, endpointErr
		}
		adapters.postgresEndpoint = &localEndpoint
		if e.Remote {
			endpoint, endpointErr := advertisedEndpoint(remoteIdentity.host, listener)
			if endpointErr != nil {
				adapters.Close()
				return nil, endpointErr
			}
			adapters.postgresEndpoint = &endpoint
			adapters.postgresAddress = net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
			adapterHost = endpoint.Host
		} else {
			adapters.postgresAddress = listener.Addr().String()
		}
		_, port, _ := net.SplitHostPort(listener.Addr().String())
		adapters.environment["PGHOST"] = adapterHost
		adapters.environment["PGPORT"] = port
		if len(postgres) == 1 {
			adapters.environment["PGPASSWORD"] = postgres[0].connection.DecoyMaterial["password"]
		}
		adapters.environment["PGSSLMODE"] = "verify-full"
		adapters.wg.Add(1)
		grantID := ""
		if len(postgres) == 1 {
			grantID = postgres[0].connection.GrantID
		}
		go adapters.acceptPostgres(ctx, listener, grantID)
	}
	return adapters, nil
}

func exactUpstream(connection agentapi.Connection, defaultPort int) (string, int, error) {
	if len(connection.Hosts) != 1 || connection.Hosts[0].Match != "exact" || connection.Hosts[0].Path != "" {
		return "", 0, fmt.Errorf("%s binding requires one exact upstream host", connection.Protocol)
	}
	rule := connection.Hosts[0]
	port := rule.Port
	if port == 0 {
		port = defaultPort
	}
	return strings.ToLower(rule.Value), port, nil
}

func (a *protocolAdapters) track(connection net.Conn, add bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if add {
		if a.closed {
			return false
		}
		a.connections[connection] = struct{}{}
	} else {
		delete(a.connections, connection)
	}
	return true
}

func (a *protocolAdapters) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		a.wg.Wait()
		return
	}
	a.closed = true
	for _, listener := range a.listeners {
		_ = listener.Close()
	}
	for connection := range a.connections {
		_ = connection.Close()
	}
	a.mu.Unlock()
	a.wg.Wait()
}

func (a *protocolAdapters) acceptPostgres(ctx context.Context, listener net.Listener, grantID string) {
	defer a.wg.Done()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		if !a.track(connection, true) {
			_ = connection.Close()
			return
		}
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			defer a.track(connection, false)
			defer connection.Close()
			a.handlePostgres(ctx, connection, grantID)
		}()
	}
}

type protocolRoute struct {
	protocol string
	host     string
	port     int
}

func routeForBinding(binding *binding, protocol string, defaultPort int) (protocolRoute, error) {
	if binding == nil || binding.connection.Protocol != protocol {
		return protocolRoute{}, errors.New("Agent protocol binding is unavailable")
	}
	host, port, err := exactUpstream(binding.connection, defaultPort)
	if err != nil {
		return protocolRoute{}, err
	}
	return protocolRoute{protocol: protocol, host: host, port: port}, nil
}

// watchProtocolRoute closes an idle connection as soon as the session becomes
// unavailable, its grant is removed/rebound, or its credential expires.
func (a *protocolAdapters) watchProtocolRoute(ctx context.Context, connection net.Conn, grantID string, expected protocolRoute, defaultPort int, stop <-chan struct{}) {
	for {
		changed := a.state.changeSignal()
		snapshot, err := a.state.protocolBinding(grantID, expected.protocol)
		var expiryTimer *time.Timer
		var expiry <-chan time.Time
		if err == nil {
			if !snapshot.binding.authorizationDecision(time.Now()).allowed {
				err = errors.New("Agent connection authorization is unavailable")
			} else {
				expiresAt := time.Time{}
				if credentialExpiry := snapshot.binding.connection.CredentialExpiresAt; credentialExpiry != nil {
					expiresAt = *credentialExpiry
				}
				if !expiresAt.IsZero() {
					delay := time.Until(expiresAt)
					if delay <= 0 {
						err = errors.New("Agent connection or source expired")
					} else {
						expiryTimer = time.NewTimer(delay)
						expiry = expiryTimer.C
					}
				}
			}
		}
		if err == nil {
			var current protocolRoute
			current, err = routeForBinding(snapshot.binding, expected.protocol, defaultPort)
			if err == nil && current != expected {
				err = errors.New("Agent protocol route changed")
			}
		}
		snapshot.release()
		if err != nil {
			if expiryTimer != nil {
				expiryTimer.Stop()
			}
			_ = connection.Close()
			return
		}
		select {
		case <-ctx.Done():
			if expiryTimer != nil {
				expiryTimer.Stop()
			}
			_ = connection.Close()
			return
		case <-stop:
			if expiryTimer != nil {
				expiryTimer.Stop()
			}
			return
		case <-expiry:
			_ = connection.Close()
			return
		case <-changed:
			if expiryTimer != nil {
				expiryTimer.Stop()
			}
		}
	}
}

func upstreamAddress(connection agentapi.Connection, defaultPort int) (string, string, error) {
	host, port, err := exactUpstream(connection, defaultPort)
	if err != nil {
		return "", "", err
	}
	return host, net.JoinHostPort(host, strconv.Itoa(port)), nil
}
