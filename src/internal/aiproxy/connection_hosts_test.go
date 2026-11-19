package aiproxy

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
)

// A front end that routes by host has to hear when a running session's Connections
// change where they go. A custom Connection can be added, moved or removed without a
// new session, so OnStarted alone would leave it with the hosts the session began
// with.
func TestConnectionsThatChangeWhileASessionRunsAreReported(t *testing.T) {
	const auditLive = "sk-live-audit-0123456789abcdefgh"
	existing := func() map[string]any { return customConnectionPayload(customDecoyToken, customLiveToken) }
	audit := func(host string) map[string]any { return exportlessConnectionPayload("audit", host, auditLive) }
	console := newRequestConsole(t)
	state, _ := console.state(t, "runtime-hosts")
	state.decoys = newDecoyHistory()

	reported := make(chan []ConnectionHosts, 4)
	engine := &Engine{OnConnectionsChanged: func(hosts []ConnectionHosts) { reported <- hosts }}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		engine.watchConnections(ctx, state, state.connectionHosts())
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})

	generation := 1
	refresh := func(connections ...map[string]any) {
		t.Helper()
		generation++
		console.config = func() map[string]any { return customSessionPayload("", generation, connections...) }
		if _, err := state.refreshConfig(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	expect := func(what string, want ...ConnectionHosts) {
		t.Helper()
		select {
		case got := <-reported:
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s: reported %+v, want %+v", what, got, want)
			}
			described, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{auditLive, customLiveToken, customDecoyToken} {
				if strings.Contains(string(described), secret) {
					t.Fatalf("%s: the report carries a credential", what)
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: nothing was reported", what)
		}
	}
	quiet := func(what string) {
		t.Helper()
		select {
		case got := <-reported:
			t.Fatalf("%s: reported %+v", what, got)
		case <-time.After(150 * time.Millisecond):
		}
	}
	example := ConnectionHosts{ConnectionID: "connection-example", Name: "Example API", Protocol: "http",
		Hosts: []agentapi.HostRule{{Match: "exact", Value: "api.example.test", Port: 443, Path: "/v1/*"}}}
	auditAt := func(host string) ConnectionHosts {
		return ConnectionHosts{ConnectionID: "connection-audit", Name: "audit", Protocol: "http",
			Hosts: []agentapi.HostRule{{Match: "exact", Value: host, Port: 443}}}
	}

	quiet("before anything changed")
	refresh(existing(), audit("audit.example.test"))
	expect("a Connection was added", example, auditAt("audit.example.test"))
	refresh(existing(), audit("audit.example.test"))
	quiet("a refresh that moved nothing")
	refresh(existing(), audit("audit.internal.example.test"))
	expect("a Connection moved to another host", example, auditAt("audit.internal.example.test"))
	refresh(existing())
	expect("a Connection was removed", example)
}
