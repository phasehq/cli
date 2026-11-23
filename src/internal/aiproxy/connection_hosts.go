package aiproxy

import (
	"context"
	"reflect"

	"github.com/phasehq/cli/internal/agentapi"
)

// ConnectionHosts is where one Connection's traffic goes. It carries no credential.
type ConnectionHosts struct {
	ConnectionID string
	Name         string
	Protocol     string
	Hosts        []agentapi.HostRule
}

// connectionHosts lists the hosts of every Connection the session serves now.
func (s *runtimeState) connectionHosts() []ConnectionHosts {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hosts := make([]ConnectionHosts, 0, len(s.bindings))
	for _, candidate := range s.bindings {
		connection := candidate.connection
		hosts = append(hosts, ConnectionHosts{
			ConnectionID: connection.ConnectionID, Name: connection.ConnectionName, Protocol: connection.Protocol,
			Hosts: append([]agentapi.HostRule(nil), connection.Hosts...),
		})
	}
	return hosts
}

// watchConnections tells OnConnectionsChanged when a refresh changes, in place, where
// the session's Connections go: a custom Connection added, given other hosts, or
// removed. known is what the session started with. A change that needs a new session
// ends this one instead, and the next begins with OnStarted.
func (e *Engine) watchConnections(ctx context.Context, state *runtimeState, known []ConnectionHosts) {
	for {
		changed := state.changeSignal()
		if current := state.connectionHosts(); !reflect.DeepEqual(current, known) {
			known = current
			e.OnConnectionsChanged(current)
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		}
	}
}
