package aiproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// Hints are the proxy's memory of recent dead ends and what to ask for to get
// past each one. Some refusals reach the Agent without a readable body: a
// refused CONNECT, an AWS-shaped error an SDK reduces to a code, or an
// upstream's own 401 that the proxy passes on untouched. GET /v1/hints lists
// the same ready-to-send requests those answers carried or could not carry.
// Hints live in memory for the session only and hold no secret.

const (
	maxHints = 20

	hintAccessPolicyAsk  = "access_policy_ask"
	hintAccessExpired    = "access_expired"
	hintConnectionNeeded = "connection_needed"

	// Reasons a Connection is needed for a host no Connection covers.
	hintReasonLockdown         = "lockdown_unbound_host"
	hintReasonUpstreamRejected = "upstream_rejected_unbound_host"
	hintReasonPresetHost       = "unbound_preset_host"
)

type proxyHint struct {
	kind, reason      string
	host              string
	port              int
	statusCode        int
	method, path      string
	class             string
	connectionID      string
	connectionName    string
	request           json.RawMessage
	firstAt, latestAt time.Time
	count             int
}

type hintLog struct {
	mu    sync.Mutex
	hints []proxyHint
	// unbound are hosts recently tunnelled untouched. They become hints only
	// for a host that belongs to a preset, decided when the hints are read.
	unbound []unboundHost
}

type unboundHost struct {
	host string
	port int
	at   time.Time
}

const maxUnboundHosts = 64

// noteUnboundHost remembers a host the proxy tunnelled without a Connection.
func (l *hintLog) noteUnboundHost(host string, port int) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for index, existing := range l.unbound {
		if existing.host == host && existing.port == port {
			l.unbound = append(l.unbound[:index], l.unbound[index+1:]...)
			break
		}
	}
	l.unbound = append(l.unbound, unboundHost{host: host, port: port, at: time.Now()})
	if len(l.unbound) > maxUnboundHosts {
		l.unbound = append(l.unbound[:0], l.unbound[len(l.unbound)-maxUnboundHosts:]...)
	}
}

func (l *hintLog) unboundHosts() []unboundHost {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]unboundHost(nil), l.unbound...)
}

// record keeps one entry per distinct dead end and moves a repeated one to
// the end, so the list reads oldest to newest.
func (l *hintLog) record(hint proxyHint, now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	hint.firstAt, hint.latestAt, hint.count = now, now, 1
	for index, existing := range l.hints {
		if existing.kind == hint.kind && existing.host == hint.host && existing.port == hint.port &&
			existing.connectionID == hint.connectionID && existing.method == hint.method && existing.path == hint.path {
			hint.firstAt, hint.count = existing.firstAt, existing.count+1
			l.hints = append(l.hints[:index], l.hints[index+1:]...)
			break
		}
	}
	l.hints = append(l.hints, hint)
	if len(l.hints) > maxHints {
		l.hints = append(l.hints[:0], l.hints[len(l.hints)-maxHints:]...)
	}
}

func (l *hintLog) snapshot() []proxyHint {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]proxyHint(nil), l.hints...)
}

// noteConnectionNeeded records that a host no Connection covers stopped the
// Agent. Only the host is kept: an unbound request's path is none of the
// proxy's business.
func (s *runtimeState) noteConnectionNeeded(reason, host string, port, statusCode int) {
	s.hints.record(proxyHint{kind: hintConnectionNeeded, reason: reason, host: host, port: port, statusCode: statusCode}, time.Now())
}

// hints serves GET /v1/hints. A hint about a host is completed here, where
// waiting for the preset list is acceptable, with a request the Agent can
// send as it is. Hosts a Connection covers by now are left out.
func (h *controlHandler) hints(w http.ResponseWriter, req *http.Request) {
	presetContext, cancel := context.WithTimeout(req.Context(), presetFetchTimeout)
	presets, services, _ := h.state.presets.registry(presetContext)
	cancel()
	response := remoteapi.HintsResponse{SchemaVersion: agentapi.SchemaVersion, Kind: "phase.ai.hints", Hints: []remoteapi.Hint{}}
	for _, hint := range h.state.hints.snapshot() {
		entry := remoteapi.Hint{
			Kind: hint.kind, Reason: hint.reason, Host: hint.host, StatusCode: hint.statusCode,
			Method: hint.method, Path: hint.path, Class: hint.class,
			ConnectionID: hint.connectionID, ConnectionName: hint.connectionName,
			Request: hint.request, Count: hint.count, FirstAt: hint.firstAt.UTC(), LatestAt: hint.latestAt.UTC(),
		}
		if hint.kind == hintConnectionNeeded {
			if bound, err := h.state.hasBoundHost(hint.host, hint.port); err != nil || bound {
				continue
			}
			match := matchRegistry(presets, services, hint.host, hint.port)
			entry.Preset, entry.Service = match.names()
			entry.Request = match.request(hint.host, hint.port)
		}
		response.Hints = append(response.Hints, entry)
	}
	for _, unbound := range h.state.hints.unboundHosts() {
		match := matchRegistry(presets, services, unbound.host, unbound.port)
		if (match.preset == nil && match.service == nil) || hintsName(response.Hints, unbound.host) {
			continue
		}
		if bound, err := h.state.hasBoundHost(unbound.host, unbound.port); err != nil || bound {
			continue
		}
		presetID, serviceType := match.names()
		response.Hints = append(response.Hints, remoteapi.Hint{
			Kind: hintConnectionNeeded, Reason: hintReasonPresetHost, Host: unbound.host, Preset: presetID, Service: serviceType,
			Request: match.request(unbound.host, unbound.port), Count: 1,
			FirstAt: unbound.at.UTC(), LatestAt: unbound.at.UTC(),
		})
	}
	payload, err := json.Marshal(response)
	if err != nil || manifestPayloadContains(payload, h.state.eventSecrets()) {
		writeControlError(w, http.StatusBadGateway, "unsafe_hints_response", "The hints contained proxy-only material.", false)
		return
	}
	h.writeRelay(w, response, nil)
}

func hintsName(hints []remoteapi.Hint, host string) bool {
	for _, hint := range hints {
		if hint.Kind == hintConnectionNeeded && hint.Host == host {
			return true
		}
	}
	return false
}

// names returns the preset ID or the service type the host matched.
func (m hostMatch) names() (presetID, serviceType string) {
	switch {
	case m.service != nil:
		return "", m.service.ServiceType
	case m.preset != nil:
		return m.preset.ID, ""
	}
	return "", ""
}

// request is the ready-to-send body for the match: the ordinary packaged
// setup request for a service, otherwise the preset or custom request.
func (m hostMatch) request(host string, port int) json.RawMessage {
	if m.service != nil {
		return serviceSetupRequest(*m.service, host)
	}
	return connectionRequest(host, port, m.preset)
}

// serviceSetupRequest asks for a packaged service by its type; the member
// picks or adds the integration credential in the Console.
func serviceSetupRequest(service agentapi.RegistryService, host string) json.RawMessage {
	name := plainTitleText(service.DisplayName)
	credentialName := name + " for this Workflow"
	if runes := []rune(credentialName); len(runes) > 64 {
		credentialName = strings.TrimSpace(string(runes[:64]))
	}
	return mustRequestBody(map[string]any{
		"kind": "setup", "title": requestTitle("Connect " + name),
		"serviceType": service.ServiceType, "credentialProvider": service.CredentialProviders[0],
		"credentialName": credentialName,
		"markdown":       "Calls to " + plainTitleText(host) + " need a " + name + " Connection.",
	})
}

// connectionRequest is a complete body for POST /v1/requests that asks for a
// Connection to host. With a preset it names the preset and the Console fills
// in the definition. Without one it carries the most common definition, a
// bearer token in the Authorization header attached when the request has
// none, which exports nothing and so is served by the running session once
// approved; a member or the Agent adjusts it when the service authenticates
// differently.
func connectionRequest(host string, port int, preset *agentapi.Preset) json.RawMessage {
	if preset != nil {
		name := plainTitleText(preset.Name)
		if name == "" {
			name = preset.ID
		}
		return mustRequestBody(map[string]any{
			"kind": "setup", "title": requestTitle("Connect " + name),
			"action": map[string]any{
				"type": "agent_connection.create", "version": 1, "serviceType": agentapi.CustomHTTPServiceType,
				"name": name, "preset": preset.ID,
			},
		})
	}
	// The credential travels only over HTTPS, so a plain-HTTP port is not
	// carried into the definition.
	if port == 0 || port == 80 {
		port = 443
	}
	return mustRequestBody(map[string]any{
		"kind": "setup", "title": requestTitle("Connect " + host),
		"action": map[string]any{
			"type": "agent_connection.create", "version": 1, "serviceType": agentapi.CustomHTTPServiceType, "name": host,
			"definition": map[string]any{
				"specVersion": 1,
				"hosts":       []any{map[string]any{"match": "exact", "value": host, "port": port}},
				"fields":      []any{map[string]any{"name": "token", "kind": "secret", "source": map[string]any{"type": "sealed"}}},
				"injections": []any{map[string]any{
					"type": "header", "name": "Authorization", "prefix": "Bearer ", "field": "token", "whenAbsent": "attach",
				}},
			},
		},
	})
}

// connectionNeededDetails is what a refusal for an unbound host carries: how
// to ask for a Connection. It never waits for the Console. The request is
// built from the presets already held, and is left out until a copy is held
// at all, because a guessed definition for a host that has a preset would
// mislead; GET /v1/hints always has it.
func (s *runtimeState) connectionNeededDetails(host string, port int) map[string]any {
	details := map[string]any{"host": host, "hints": phaseproxy.ControlURL + "/v1/hints"}
	match, held := s.presets.lookup(host, port)
	if !held {
		return details
	}
	if presetID, serviceType := match.names(); presetID != "" {
		details["preset"] = presetID
	} else if serviceType != "" {
		details["service"] = serviceType
	}
	details["request"] = match.request(host, port)
	return details
}

const connectionNeededGuidance = " To ask a member for a Connection to it, GET " + phaseproxy.ControlURL +
	"/v1/hints and send the request listed for this host unchanged to POST " + phaseproxy.ControlURL +
	"/v1/requests; when this answer carries details.request, that is the same request."
