package aiproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

const (
	ManifestHost = phaseproxy.ManifestHost
	ManifestPath = phaseproxy.ManifestPath
	ManifestURL  = phaseproxy.ManifestURL

	// ManifestRefreshRequiredCode is returned only when the authenticated
	// manifest detects that its process-visible environment has changed. Hook
	// wrappers may retry this one response after the managed daemon has opened
	// a successor backend session.
	ManifestRefreshRequiredCode = "agent_manifest_refresh_required"
)

type manifestHandler struct {
	state               *runtimeState
	ca                  *phaseproxy.CA
	proxy               remoteapi.Endpoint
	postgres            *remoteapi.Endpoint
	events              *eventBuffer
	processEnvironment  phaseproxy.ProcessEnvironmentPlan
	providerEnvironment phaseproxy.ProcessEnvironmentPlan
}

func (h *manifestHandler) matchesManifest(req *http.Request) bool {
	return req != nil && req.URL != nil && req.URL.IsAbs() && req.URL.Scheme == "http" &&
		strings.EqualFold(req.URL.Host, ManifestHost) && req.URL.EscapedPath() == ManifestPath
}

func (h *manifestHandler) ServeManifestHTTP(w http.ResponseWriter, req *http.Request) {
	if !h.matchesManifest(req) || req.Method != http.MethodGet || req.URL.RawQuery != "" ||
		req.URL.Fragment != "" || req.URL.User != nil {
		h.writeManifestFailure(w, req, http.StatusBadRequest, "invalid_agent_manifest_request", "unclassifiable_request")
		return
	}
	h.serveManifest(w, req, ManifestHost, ManifestPath)
}

func (h *manifestHandler) serveManifest(w http.ResponseWriter, req *http.Request, eventHost, eventPath string) {
	discover, err := h.state.client.Discover(req.Context(), h.state.sessionUID, h.state.currentBackendCredential())
	if err != nil {
		h.writeManifestFailure(w, req, http.StatusBadGateway, "agent_manifest_discover_failed", "backend_discover_failed")
		return
	}
	if discover.SchemaVersion != agentapi.SchemaVersion || discover.SessionUID != h.state.sessionUID {
		h.writeManifestFailure(w, req, http.StatusBadGateway, "invalid_agent_manifest_discover", "backend_discover_invalid")
		return
	}
	forbidden := h.state.manifestForbiddenSecrets()
	backendCredential := h.state.currentBackendCredential().Reveal()
	// Redact and reject proxy-only material before classifying a process-visible
	// mismatch as retryable. A malformed backend response must never be able to
	// turn secret leakage into an apparently routine lifecycle refresh.
	if err := sanitizeManifestDiscover(discover, backendCredential, forbidden); err != nil {
		h.writeManifestFailure(w, req, http.StatusBadGateway, "unsafe_agent_manifest_response", "manifest_redaction_failed")
		return
	}
	if err := h.state.applyTrustedDiscoverAuthorization(discover); errors.Is(err, errDiscoverProcessEnvironmentMismatch) {
		h.writeManifestRefreshRequired(w, req)
		return
	} else if err != nil {
		h.writeManifestFailure(w, req, http.StatusBadGateway, "invalid_agent_manifest_discover", "backend_discover_invalid")
		return
	}
	providerEnvironment, err := manifestProcessEnvironment(discover)
	if err != nil {
		h.writeManifestFailure(w, req, http.StatusBadGateway, "invalid_agent_manifest_environment", "manifest_environment_invalid")
		return
	}
	if !reflect.DeepEqual(providerEnvironment, h.providerEnvironment) {
		h.writeManifestRefreshRequired(w, req)
		return
	}
	caPEM := h.ca.CertificatePEM()
	if len(caPEM) == 0 {
		h.writeManifestFailure(w, req, http.StatusBadGateway, "agent_manifest_ca_unavailable", "manifest_ca_unavailable")
		return
	}
	response := remoteapi.ManifestResponse{
		SchemaVersion: agentapi.SchemaVersion, SessionUID: h.state.sessionUID,
		ConfigGeneration: discover.ConfigGeneration, Proxy: h.proxy, Postgres: h.postgres,
		CACertificatePEM:   string(caPEM),
		Links:              publicControlLinks(),
		ProcessEnvironment: cloneProcessEnvironmentPlan(h.processEnvironment),
		Discover:           *discover,
	}
	payload, err := json.Marshal(response)
	if err != nil || manifestPayloadContains(payload, append(h.state.manifestPayloadForbiddenSecrets(), backendCredential)) {
		h.writeManifestFailure(w, req, http.StatusBadGateway, "unsafe_agent_manifest_response", "manifest_redaction_failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_, _ = w.Write(payload)
	if h.events != nil {
		h.events.Emit(newRequestEvent(nil, req.Method, eventHost, 80, eventPath, "allow", "ok", "agent_manifest", http.StatusOK, 0, "none"))
	}
}

func cloneProcessEnvironmentPlan(plan phaseproxy.ProcessEnvironmentPlan) phaseproxy.ProcessEnvironmentPlan {
	set := make(map[string]string, len(plan.Set))
	for key, value := range plan.Set {
		set[key] = value
	}
	return phaseproxy.ProcessEnvironmentPlan{Set: set, Unset: append([]string(nil), plan.Unset...)}
}

func manifestProcessEnvironment(discover *agentapi.DiscoverResponse) (phaseproxy.ProcessEnvironmentPlan, error) {
	config := &agentapi.OpenSessionResponse{SessionConfig: agentapi.SessionConfig{ConfigEnv: discover.ConfigEnv}}
	for _, c := range discover.Connections {
		encoded, err := json.Marshal(c.AgentEnv)
		if err != nil {
			return phaseproxy.ProcessEnvironmentPlan{}, err
		}
		var env agentapi.AgentEnvironment
		if err := json.Unmarshal(encoded, &env); err != nil {
			return phaseproxy.ProcessEnvironmentPlan{}, err
		}
		config.Connections = append(config.Connections, agentapi.Connection{ConnectionID: c.ConnectionID, ServiceType: c.ServiceType, Hosts: c.Hosts, Injection: c.Injection, Identifiers: c.Identifiers, DecoyMaterial: c.DecoyMaterial, ConnectionConfig: c.ConnectionConfig, ConfigEnv: c.ConfigEnv, AgentEnv: env, EnvironmentBindings: c.EnvironmentBindings})
	}
	return (&airuntime.ProxySession{Config: config}).ProviderProcessEnvironment()
}

func (h *manifestHandler) writeManifestFailure(w http.ResponseWriter, req *http.Request, status int, code, reason string) {
	writeProxyError(w, &requestFailure{status: status, code: code, message: "The Phase Agent manifest request was rejected."})
	if h.events != nil {
		decision, outcome := "block", "denied"
		if status >= 500 {
			decision, outcome = "error", "error"
		}
		h.events.Emit(newRequestEvent(nil, req.Method, ManifestHost, 80, ManifestPath, decision, outcome, reason, status, 0, "none"))
	}
}

// writeManifestRefreshRequired deliberately writes the complete retryable
// response before signaling the engine supervisor. The draining handler keeps
// this request alive while the old engine shuts down, so callers can classify
// the response and wait for the successor session instead of seeing a generic
// authentication failure.
func (h *manifestHandler) writeManifestRefreshRequired(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Retry-After", "1")
	w.Header().Set("X-Phase-Error-Code", ManifestRefreshRequiredCode)
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"code": ManifestRefreshRequiredCode, "message": "The Phase AI session is refreshing.",
		"retryable": true, "details": map[string]any{},
	}})
	if h.events != nil {
		h.events.Emit(newRequestEvent(nil, req.Method, ManifestHost, 80, ManifestPath, "error", "error", "manifest_environment_reprovision_required", http.StatusServiceUnavailable, 0, "none"))
	}
	h.state.fail(fmt.Errorf("%w: the Agent manifest detected a changed process environment", airuntime.ErrSessionReprovisionRequired))
}

func sanitizeManifestDiscover(discover *agentapi.DiscoverResponse, backendCredential string, forbidden []string) error {
	if discover == nil {
		return errors.New("missing discover response")
	}
	for connectionIndex := range discover.Connections {
		environment := discover.Connections[connectionIndex].AgentEnv
		for key, value := range environment {
			upper := strings.ToUpper(key)
			if containsAny(value, forbidden) {
				return errors.New("discover response contains proxy-only material")
			}
			if upper == "PHASE_AI_SESSION_CREDENTIAL" || upper == "PHASE_AGENT_SESSION_CREDENTIAL" || (backendCredential != "" && strings.Contains(value, backendCredential)) {
				delete(environment, key)
			}
		}
	}
	payload, err := json.Marshal(discover)
	if err != nil || manifestPayloadContains(payload, append(forbidden, backendCredential)) {
		return errors.New("discover response contains proxy-only material")
	}
	return nil
}

func manifestPayloadContains(payload []byte, forbidden []string) bool {
	if bytes.Contains(bytes.ToLower(payload), []byte("secretmaterial")) || bytes.Contains(bytes.ToLower(payload), []byte("sessioncredential")) {
		return true
	}
	for _, value := range forbidden {
		if value == "" {
			continue
		}
		if bytes.Contains(payload, []byte(value)) {
			return true
		}
		encoded, err := json.Marshal(value)
		if err == nil && len(encoded) >= 2 && bytes.Contains(payload, encoded[1:len(encoded)-1]) {
			return true
		}
	}
	return false
}

func containsAny(value string, forbidden []string) bool {
	for _, candidate := range forbidden {
		if candidate != "" && strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}
