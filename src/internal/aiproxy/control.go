package aiproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/airuntime"
	"github.com/phasehq/cli/internal/remoteapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

const (
	maxControlBodyBytes        = 64 << 10
	maxControlWaitSeconds      = 300
	defaultControlPollInterval = 3 * time.Second
)

var controlIdentifier = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
var controlServiceType = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var controlPollInterval = defaultControlPollInterval
var errApprovedRequestRefreshFailed = errors.New("approved Agent request refresh failed")

type controlHandler struct {
	state        *runtimeState
	environments *connectionEnvironmentCompiler
	// relayBootstrap is present in remote (relay) mode only.
	relayBootstrap *bootstrapMaterial
}

// ServeProxyHTTP serves control routes at the reserved phase.invalid origin.
// The proxy boundary has already authenticated the process-local capability,
// and this origin is intercepted before any resolver or upstream transport.
func (h *controlHandler) ServeProxyHTTP(w http.ResponseWriter, req *http.Request, remote bool) {
	if req == nil || req.URL == nil || !req.URL.IsAbs() || req.URL.Scheme != "http" ||
		!strings.EqualFold(req.URL.Host, ManifestHost) || req.URL.User != nil ||
		req.URL.Fragment != "" || (remote && req.TLS == nil) {
		writeControlError(w, http.StatusBadRequest, "invalid_proxy_control_request", "The Phase AI control request is invalid.", false)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if req.Method == http.MethodPost && browserMutation(req) {
		writeControlError(w, http.StatusForbidden, "browser_control_mutation_rejected", "Browser-originated Phase AI control mutations are not accepted.", false)
		return
	}
	h.serveRoutes(w, req, remote)
}

func (h *controlHandler) serveRoutes(w http.ResponseWriter, req *http.Request, remote bool) {
	path := req.URL.EscapedPath()
	waitRoute := (req.Method == http.MethodPost && path == "/v1/requests") ||
		(req.Method == http.MethodGet && strings.HasPrefix(path, "/v1/requests/"))
	contextRoute := req.Method == http.MethodGet && path == "/v1/context"
	if req.URL.RawQuery != "" && !waitRoute && !contextRoute {
		writeControlError(w, http.StatusBadRequest, "invalid_control_query", "The Phase AI control query is invalid.", false)
		return
	}
	switch {
	case req.Method == http.MethodGet && strings.HasPrefix(path, "/v1/connections/"):
		id, ok := exactControlID(path, "/v1/connections/", "/environment")
		if !ok {
			writeControlError(w, http.StatusBadRequest, "invalid_connection_id", "The Connection ID is invalid.", false)
			return
		}
		h.connectionEnvironment(w, req, id)
	case req.Method == http.MethodGet && path == "/v1/status":
		h.status(w)
	case remote && req.Method == http.MethodGet && path == "/v1/bootstrap":
		h.serveBootstrap(w, req)
	case req.Method == http.MethodGet && path == "/v1/capabilities":
		h.capabilities(w, req)
	case req.Method == http.MethodGet && path == "/v1/context":
		h.context(w, req)
	case !remote && req.Method == http.MethodGet && path == "/v1/discover":
		h.discover(w, req)
	case req.Method == http.MethodGet && path == "/v1/requests":
		h.listRequests(w, req)
	case req.Method == http.MethodPost && strings.HasPrefix(path, "/v1/requests/") && strings.HasSuffix(path, "/cancel"):
		id, ok := exactControlID(path, "/v1/requests/", "/cancel")
		if !ok {
			writeControlError(w, http.StatusBadRequest, "invalid_request_id", "The request ID is invalid.", false)
			return
		}
		h.cancelRequest(w, req, id)
	case req.Method == http.MethodPost && path == "/v1/requests":
		h.createRequest(w, req)
	case req.Method == http.MethodGet && strings.HasPrefix(path, "/v1/requests/"):
		requestID, ok := exactControlID(path, "/v1/requests/", "")
		if !ok {
			writeControlError(w, http.StatusBadRequest, "invalid_request_id", "The request ID is invalid.", false)
			return
		}
		h.pollRequest(w, req, requestID)
	case !remote && req.Method == http.MethodPost && path == "/v1/revoke":
		h.revoke(w, req)
	case !remote && req.Method == http.MethodPost && path == "/v1/rotate":
		h.rotate(w, req)
	case req.Method == http.MethodPost && path == "/v1/refresh":
		h.refresh(w, req)
	default:
		message := "The local control route was not found."
		if remote {
			message = "The remote control route was not found."
		}
		writeControlError(w, http.StatusNotFound, "control_route_not_found", message, false)
	}
}

func publicControlLinks() remoteapi.ControlLinks {
	return remoteapi.ControlLinks{
		ListRequests:          phaseproxy.ControlURL + "/v1/requests",
		CancelRequest:         phaseproxy.ControlURL + "/v1/requests/{requestId}/cancel",
		ConnectionEnvironment: phaseproxy.ControlURL + "/v1/connections/{connectionId}/environment",
		Capabilities:          phaseproxy.ControlURL + "/v1/capabilities",
		Status:                phaseproxy.ControlURL + "/v1/status",
		Context:               phaseproxy.ControlURL + "/v1/context",
		CreateRequest:         phaseproxy.ControlURL + "/v1/requests",
		PollRequest:           phaseproxy.ControlURL + "/v1/requests/{requestId}",
	}
}

func (h *controlHandler) capabilities(w http.ResponseWriter, req *http.Request) {
	credential := h.state.currentBackendCredential()
	response, err := h.state.client.Capabilities(req.Context(), h.state.sessionUID, credential)
	if err != nil {
		h.writeRelay(w, nil, err)
		return
	}
	if response == nil || response.SessionUID != h.state.sessionUID || response.Validate() != nil {
		writeControlError(w, http.StatusBadGateway, "unsafe_agent_capabilities_response", "The Phase control plane returned invalid Agent capabilities.", false)
		return
	}
	payload, err := json.Marshal(response)
	if err != nil || manifestPayloadContains(payload, append(h.state.manifestForbiddenSecrets(), credential.Reveal())) {
		writeControlError(w, http.StatusBadGateway, "unsafe_agent_capabilities_response", "The Phase control plane returned unsafe Agent capabilities.", false)
		return
	}
	h.writeRelay(w, response, nil)
}

func (h *controlHandler) status(w http.ResponseWriter) {
	h.writeRelay(w, remoteapi.StatusResponse{
		SchemaVersion: agentapi.SchemaVersion,
		Kind:          "phase.ai.status",
		SafeToPrint:   true,
		Connections:   h.state.statusConnections(time.Now()),
		Links:         publicControlLinks(),
	}, nil)
}

func (h *controlHandler) context(w http.ResponseWriter, req *http.Request) {
	serviceType, err := controlContextServiceType(req)
	if err != nil {
		writeControlError(w, http.StatusBadRequest, "invalid_context_query", "Context accepts at most one valid serviceType query parameter.", false)
		return
	}
	response, err := h.state.client.ContextForService(req.Context(), h.state.sessionUID, h.state.currentBackendCredential(), serviceType)
	if err != nil {
		h.writeRelay(w, nil, err)
		return
	}
	if response == nil || response.SchemaVersion != agentapi.SchemaVersion || response.SessionUID != h.state.sessionUID ||
		(serviceType != "" && response.ServiceType != strings.ToLower(serviceType)) ||
		(serviceType == "" && response.ServiceType != "") ||
		containsAny(response.Markdown, append(h.state.manifestForbiddenSecrets(), h.state.currentBackendCredential().Reveal())) {
		writeControlError(w, http.StatusBadGateway, "unsafe_agent_context_response", "The Phase control plane returned unsafe Agent context.", false)
		return
	}
	h.writeRelay(w, response, nil)
}

func controlContextServiceType(req *http.Request) (string, error) {
	if req == nil || req.URL == nil || req.URL.RawQuery == "" {
		return "", nil
	}
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["serviceType"]) != 1 {
		return "", errors.New("invalid context query")
	}
	serviceType := strings.TrimSpace(query.Get("serviceType"))
	if !controlServiceType.MatchString(serviceType) {
		return "", errors.New("invalid context service type")
	}
	return serviceType, nil
}

func (h *controlHandler) discover(w http.ResponseWriter, req *http.Request) {
	credential := h.state.currentBackendCredential()
	response, err := h.state.client.Discover(req.Context(), h.state.sessionUID, credential)
	if err != nil {
		h.writeRelay(w, nil, err)
		return
	}
	if response == nil || response.SchemaVersion != agentapi.SchemaVersion || response.SessionUID != h.state.sessionUID ||
		sanitizeManifestDiscover(response, credential.Reveal(), h.state.manifestForbiddenSecrets()) != nil ||
		h.state.applyTrustedDiscoverAuthorization(response) != nil {
		writeControlError(w, http.StatusBadGateway, "unsafe_agent_discover_response", "The Phase control plane returned unsafe Agent discovery data.", false)
		return
	}
	h.writeRelay(w, response, nil)
}

func (h *controlHandler) refresh(w http.ResponseWriter, req *http.Request) {
	if err := decodeOptionalEmptyJSONObject(req.Body); err != nil {
		writeControlError(w, http.StatusBadRequest, "unexpected_request_body", "Refresh accepts only an empty body or an empty JSON object.", false)
		return
	}
	config, err := h.state.refreshConfig(req.Context())
	if err != nil {
		h.handleConfigRefreshFailure(err)
		h.writeRelay(w, nil, err)
		return
	}
	h.writeRelay(w, agentapi.RefreshResponse{
		SchemaVersion: agentapi.SchemaVersion, SessionUID: h.state.sessionUID,
		ConfigGeneration: config.ConfigGeneration, Refreshed: true,
	}, nil)
}

func (h *controlHandler) createRequest(w http.ResponseWriter, req *http.Request) {
	wait, err := controlWait(req)
	if err != nil {
		writeControlError(w, http.StatusBadRequest, "invalid_control_wait", "wait must be one whole number of seconds from 0 through 300.", false)
		return
	}
	if !controlJSONContentType(req) {
		writeControlError(w, http.StatusUnsupportedMediaType, "invalid_control_content_type", "The request Content-Type must be application/json.", false)
		return
	}
	var request agentapi.CreateRequestRequest
	if err := decodeControlJSON(req.Body, &request); err != nil {
		writeControlError(w, http.StatusBadRequest, "invalid_control_request", "The request body is invalid.", false)
		return
	}
	request.ConnectionID = strings.TrimSpace(request.ConnectionID)
	request.CredentialID = strings.TrimSpace(request.CredentialID)
	request.Markdown = strings.TrimSpace(request.Markdown)
	if (request.SchemaVersion != 0 && request.SchemaVersion != agentapi.SchemaVersion) ||
		request.Markdown == "" || len(request.Markdown) > 16<<10 ||
		(request.DedupKey != "" && !controlIdentifier.MatchString(request.DedupKey)) ||
		!validCreateRequest(request) {
		writeControlError(w, http.StatusBadRequest, "invalid_control_request", "Use setup with serviceType or credential_update with connectionId and credentialId. credentialProvider, credentialName, markdown, and an optional dedupKey are required.", false)
		return
	}
	response, statusCode, err := h.state.client.CreateRequestWithStatus(req.Context(), request, h.state.currentBackendCredential())
	if err == nil {
		response, err = h.finishRequest(req, response, wait)
	}
	if errors.Is(err, errApprovedRequestRefreshFailed) {
		writeControlError(w, http.StatusBadGateway, "approved_request_refresh_failed", "The request was approved, but the Phase proxy could not safely apply the updated Connection configuration or credential. Do not retry the connection until Phase status reports it as ready.", true)
		return
	}
	h.writeRelayStatus(w, response, statusCode, err)
	h.applyRequestRuntimeAction(response, err)
}

func validCreateRequest(request agentapi.CreateRequestRequest) bool {
	if request.RelatedRequestID != "" && !controlIdentifier.MatchString(request.RelatedRequestID) {
		return false
	}
	if request.SchemaVersion != 0 && request.SchemaVersion != agentapi.SchemaVersion {
		return false
	}
	if len(request.CredentialProvider) > 64 || !controlIdentifier.MatchString(request.CredentialProvider) ||
		request.CredentialName == "" || request.CredentialName != strings.TrimSpace(request.CredentialName) ||
		len(request.CredentialName) > 64 || strings.IndexFunc(request.CredentialName, unicode.IsControl) >= 0 {
		return false
	}
	switch request.Kind {
	case "setup":
		return request.ConnectionID == "" && request.CredentialID == "" &&
			len(request.ServiceType) <= 64 && controlIdentifier.MatchString(request.ServiceType)
	case "credential_update":
		return controlIdentifier.MatchString(request.ConnectionID) &&
			controlIdentifier.MatchString(request.CredentialID) && request.ServiceType == ""
	default:
		return false
	}
}

func (h *controlHandler) pollRequest(w http.ResponseWriter, req *http.Request, requestID string) {
	wait, err := controlWait(req)
	if err != nil {
		writeControlError(w, http.StatusBadRequest, "invalid_control_wait", "wait must be one whole number of seconds from 0 through 300.", false)
		return
	}
	if !controlIdentifier.MatchString(requestID) {
		writeControlError(w, http.StatusBadRequest, "invalid_request_id", "The request ID is invalid.", false)
		return
	}
	var response *agentapi.RequestResponse
	if wait > 0 {
		waitContext, cancelWait := context.WithTimeout(req.Context(), wait)
		response, err = h.state.client.PollRequest(waitContext, requestID, h.state.currentBackendCredential())
		if err != nil && req.Context().Err() == nil && errors.Is(waitContext.Err(), context.DeadlineExceeded) {
			response = &agentapi.RequestResponse{ID: requestID, Status: "pending"}
			err = nil
		} else if err == nil && req.Context().Err() == nil && errors.Is(waitContext.Err(), context.DeadlineExceeded) {
			response = &agentapi.RequestResponse{ID: requestID, Status: "pending"}
		} else if req.Context().Err() != nil {
			err = req.Context().Err()
		}
		if err == nil && response.ID != requestID {
			err = errors.New("Phase returned the wrong Agent request")
		}
		if err == nil {
			response, err = h.finishRequestWithin(req, response, waitContext, false)
		}
		cancelWait()
	} else {
		response, err = h.state.client.PollRequest(req.Context(), requestID, h.state.currentBackendCredential())
		if err == nil && response.ID != requestID {
			err = errors.New("Phase returned the wrong Agent request")
		}
		if err == nil {
			response, err = h.finishRequestWithin(req, response, nil, false)
		}
	}
	if errors.Is(err, errApprovedRequestRefreshFailed) {
		writeControlError(w, http.StatusBadGateway, "approved_request_refresh_failed", "The request was approved, but the Phase proxy could not safely apply the updated Connection configuration or credential. Do not retry the connection until Phase status reports it as ready.", true)
		return
	}
	h.writeRelay(w, response, err)
	h.applyRequestRuntimeAction(response, err)
}

func (h *controlHandler) finishRequest(req *http.Request, response *agentapi.RequestResponse, wait time.Duration) (*agentapi.RequestResponse, error) {
	if wait <= 0 {
		return h.finishRequestWithin(req, response, nil, true)
	}
	waitContext, cancelWait := context.WithTimeout(req.Context(), wait)
	defer cancelWait()
	return h.finishRequestWithin(req, response, waitContext, true)
}

func (h *controlHandler) finishRequestWithin(req *http.Request, response *agentapi.RequestResponse, waitContext context.Context, requirePendingApprovalURL bool) (*agentapi.RequestResponse, error) {
	if response == nil || !controlIdentifier.MatchString(response.ID) {
		return nil, errors.New("Phase returned an invalid Agent request")
	}
	requestID := response.ID
	if err := validateRequestApprovalURL(response, requestID, requirePendingApprovalURL); err != nil {
		return nil, errors.New("Phase returned an invalid Agent approval URL")
	}
	if strings.EqualFold(response.Status, "pending") && waitContext != nil {
		for strings.EqualFold(response.Status, "pending") {
			delay := controlPollInterval
			if delay <= 0 {
				delay = defaultControlPollInterval
			}
			timer := time.NewTimer(delay)
			select {
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			case <-waitContext.Done():
				timer.Stop()
				if req.Context().Err() != nil {
					return nil, req.Context().Err()
				}
				break
			case <-timer.C:
			}
			if waitContext.Err() != nil {
				break
			}
			polled, err := h.state.client.PollRequest(waitContext, requestID, h.state.currentBackendCredential())
			if err != nil {
				if req.Context().Err() != nil {
					return nil, req.Context().Err()
				}
				if errors.Is(waitContext.Err(), context.DeadlineExceeded) {
					break
				}
				return nil, err
			}
			if req.Context().Err() != nil {
				return nil, req.Context().Err()
			}
			if errors.Is(waitContext.Err(), context.DeadlineExceeded) {
				break
			}
			if polled == nil || polled.ID != requestID {
				return nil, errors.New("Phase returned the wrong Agent request")
			}
			if err := validateRequestApprovalURL(polled, requestID, false); err != nil {
				return nil, err
			}
			response = polled
		}
	}
	if strings.EqualFold(response.Status, "pending") {
		if response.RuntimeAction != "" {
			return nil, errors.New("Phase returned a runtime action for a pending Agent request")
		}
		response.PollURL = phaseproxy.ControlURL + "/v1/requests/" + response.ID
		return response, nil
	}
	response.PollURL = ""
	if response.Kind == "credential_update" && strings.EqualFold(response.Status, "approved") {
		if !controlIdentifier.MatchString(response.CredentialID) ||
			!controlIdentifier.MatchString(response.ConnectionID) || !controlIdentifier.MatchString(response.GrantID) {
			err := errors.New("approved credential update response omitted its target mapping")
			h.state.setUnhealthy()
			return nil, errors.Join(errApprovedRequestRefreshFailed, err)
		}
		config, err := h.state.refreshConfig(req.Context())
		if err != nil {
			if errors.Is(err, airuntime.ErrSessionReprovisionRequired) {
				if !sessionConfigHasTarget(config, response.GrantID, response.ConnectionID, response.CredentialID) {
					h.state.setUnhealthy()
					return nil, errors.Join(errApprovedRequestRefreshFailed, errors.New("refreshed config substituted the updated credential target"))
				}
				response.RuntimeAction = agentapi.RequestRuntimeActionRestartRequired
				return response, nil
			}
			h.handleConfigRefreshFailure(err)
			return nil, errors.Join(errApprovedRequestRefreshFailed, err)
		}
		if !h.state.hasBindingTarget(response.GrantID, response.ConnectionID, response.CredentialID) {
			err := errors.New("refreshed config did not activate the updated credential target")
			h.state.setUnhealthy()
			return nil, errors.Join(errApprovedRequestRefreshFailed, err)
		}
		if response.RuntimeAction != "" && response.RuntimeAction != agentapi.RequestRuntimeActionRetry {
			return nil, errors.New("Phase returned an invalid runtime action for an approved credential update request")
		}
		response.RuntimeAction = agentapi.RequestRuntimeActionRetry
	}
	if isSetupRequest(response.Kind) && strings.EqualFold(response.Status, "approved") {
		if !controlIdentifier.MatchString(response.CredentialID) ||
			!controlIdentifier.MatchString(response.ConnectionID) ||
			!controlIdentifier.MatchString(response.GrantID) {
			return nil, errors.New("approved setup request omitted its fulfilled target mapping")
		}
		if response.RuntimeAction != "" && response.RuntimeAction != agentapi.RequestRuntimeActionRestartRequired &&
			response.RuntimeAction != agentapi.RequestRuntimeActionRetry {
			return nil, errors.New("Phase returned an invalid runtime action for an approved setup request")
		}
		if h.state.hasBindingTarget(response.GrantID, response.ConnectionID, response.CredentialID) {
			response.RuntimeAction = agentapi.RequestRuntimeActionRetry
		} else {
			response.RuntimeAction = agentapi.RequestRuntimeActionRestartRequired
		}
	}
	if !strings.EqualFold(response.Status, "approved") && response.RuntimeAction != "" {
		return nil, errors.New("Phase returned a runtime action for an unresolved Agent request")
	}
	return response, nil
}

func sessionConfigHasTarget(config *agentapi.SessionConfig, grantID, connectionID, credentialID string) bool {
	if config == nil {
		return false
	}
	for _, connection := range config.Connections {
		if connection.GrantID == grantID && connection.ConnectionID == connectionID && connection.CredentialID == credentialID {
			return true
		}
	}
	return false
}

// applyRequestRuntimeAction runs only after the approved response has been
// encoded. A newly fulfilled credential changes Agent-visible decoys and
// provider environment, so the current engine cannot be mutated safely. A
// hook-owned supervisor drains that engine and opens a fresh backend session
// in the same daemon; foreground run/serve retain their restart-required error.
func (h *controlHandler) applyRequestRuntimeAction(response *agentapi.RequestResponse, relayErr error) {
	if relayErr != nil || response == nil ||
		response.RuntimeAction != agentapi.RequestRuntimeActionRestartRequired {
		return
	}
	h.state.fail(fmt.Errorf("%w: credential fulfillment changed the Agent process environment", airuntime.ErrSessionReprovisionRequired))
}

func validateRequestApprovalURL(response *agentapi.RequestResponse, requestID string, requirePending bool) error {
	if response == nil {
		return errors.New("Phase returned an invalid Agent approval URL")
	}
	if response.ApprovalURL == "" {
		if requirePending && strings.EqualFold(response.Status, "pending") {
			return errors.New("Phase returned a pending Agent request without an approval URL")
		}
		return nil
	}
	if !validApprovalURL(response.ApprovalURL, requestID, response.Kind) {
		return errors.New("Phase returned an invalid Agent approval URL")
	}
	return nil
}

func validApprovalURL(rawURL, requestID, requestKind string) bool {
	if rawURL == "" || rawURL != strings.TrimSpace(rawURL) || !controlIdentifier.MatchString(requestID) {
		return false
	}
	if !isSetupRequest(requestKind) && requestKind != "credential_update" {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed == nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if !parsed.IsAbs() || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" ||
		parsed.Fragment != "" || parsed.ForceQuery || (scheme != "https" && scheme != "http") {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	// The authenticated backend constructs this from its canonical
	// ALLOWED_ORIGINS entry. That UI origin may intentionally differ from the
	// Agent API origin in split deployments, so enforce HTTPS rather than
	// incorrectly pinning the two origins together. Plain HTTP is dev-only.
	if strings.ContainsAny(host, "\\/%\r\n\t ") || (scheme == "http" && !explicitLoopbackHost(host)) {
		return false
	}
	segments := strings.Split(strings.TrimPrefix(parsed.EscapedPath(), "/"), "/")
	if len(segments) != 3 || segments[0] == "" || segments[1] != "agents" || segments[2] != "requests" {
		return false
	}
	organisation, err := url.PathUnescape(segments[0])
	if err != nil || strings.TrimSpace(organisation) == "" || strings.ContainsAny(organisation, "\r\n") {
		return false
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query) < 1 || len(query) > 2 {
		return false
	}
	values, ok := query["request"]
	if !ok || len(values) != 1 || values[0] != requestID {
		return false
	}
	actions, hasAction := query["action"]
	if !hasAction {
		return len(query) == 1
	}
	return len(actions) == 1 && actions[0] == "setup"
}

func explicitLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.Unmap().IsLoopback()
}

func (h *controlHandler) handleConfigRefreshFailure(err error) {
	if errors.Is(err, errRefreshedConfigRejected) {
		h.state.fail(err)
		return
	}
	h.state.setUnhealthy()
}

func controlWait(req *http.Request) (time.Duration, error) {
	values, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return 0, err
	}
	if len(values) == 0 {
		return 0, nil
	}
	waits, ok := values["wait"]
	if len(values) != 1 || !ok || len(waits) != 1 || waits[0] == "" {
		return 0, errors.New("invalid wait query")
	}
	seconds, err := strconv.Atoi(waits[0])
	if err != nil || seconds < 0 || seconds > maxControlWaitSeconds {
		return 0, errors.New("invalid wait seconds")
	}
	return time.Duration(seconds) * time.Second, nil
}

func (h *controlHandler) revoke(w http.ResponseWriter, req *http.Request) {
	if req.ContentLength > 0 {
		writeControlError(w, http.StatusBadRequest, "unexpected_request_body", "Revoke does not accept a request body.", false)
		return
	}
	response, err := h.state.client.RevokeSession(req.Context(), h.state.sessionUID, h.state.currentBackendCredential())
	if err != nil {
		h.writeRelay(w, nil, err)
		return
	}
	h.writeRelay(w, response, nil)
	h.state.markRevoked()
	go func() {
		time.Sleep(10 * time.Millisecond)
		h.state.fail(errors.New("Agent session revoked through local control API"))
	}()
}

func (h *controlHandler) rotate(w http.ResponseWriter, req *http.Request) {
	if req.ContentLength > 0 {
		writeControlError(w, http.StatusBadRequest, "unexpected_request_body", "Rotate does not accept a request body.", false)
		return
	}
	response, err := h.state.client.RotateSessionCredential(req.Context(), h.state.sessionUID, h.state.currentBackendCredential())
	if err != nil {
		h.writeRelay(w, nil, err)
		return
	}
	// Backend session credential #1 is proxy-only. Rotation updates the relay's
	// credential without changing or revealing the process-local capability.
	h.state.setBackendCredential(response.SessionCredential)
	h.writeRelay(w, map[string]any{
		"schemaVersion":    response.SchemaVersion,
		"sessionUid":       response.SessionUID,
		"expiresAt":        response.ExpiresAt,
		"configGeneration": response.ConfigGeneration,
		"rotated":          true,
	}, nil)
}

func controlJSONContentType(req *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func browserMutation(req *http.Request) bool {
	if strings.TrimSpace(req.Header.Get("Origin")) != "" || strings.TrimSpace(req.Header.Get("Referer")) != "" {
		return true
	}
	site := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Site")))
	return site != "" && site != "none"
}

func exactControlID(path, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	identifier := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	return identifier, controlIdentifier.MatchString(identifier)
}

func decodeControlJSON(reader io.Reader, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, maxControlBodyBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}

func decodeOptionalEmptyJSONObject(reader io.Reader) error {
	if reader == nil {
		return nil
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maxControlBodyBytes+1))
	if err != nil || len(payload) > maxControlBodyBytes {
		return errors.New("invalid request body")
	}
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 {
		return nil
	}
	var object map[string]json.RawMessage
	if err := decodeControlJSON(bytes.NewReader(payload), &object); err != nil || object == nil || len(object) != 0 {
		return errors.New("request body is not an empty JSON object")
	}
	return nil
}

func (h *controlHandler) writeRelay(w http.ResponseWriter, response any, err error) {
	h.writeRelayStatus(w, response, http.StatusOK, err)
}

func (h *controlHandler) writeRelayStatus(w http.ResponseWriter, response any, statusCode int, err error) {
	if err != nil {
		var apiErr *agentapi.Error
		if errors.As(err, &apiErr) {
			writeControlError(w, apiErr.StatusCode, apiErr.Code, apiErr.Message, apiErr.Retryable)
			return
		}
		writeControlError(w, http.StatusBadGateway, "agent_control_relay_failed", "The Phase control plane could not complete the request.", true)
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		statusCode = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(response)
}

func writeControlError(w http.ResponseWriter, status int, code, message string, retryable bool) {
	if status < 400 || status > 599 {
		status = http.StatusBadGateway
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"code": code, "message": message, "retryable": retryable, "details": map[string]any{},
	}})
}

func isSetupRequest(kind string) bool { return kind == "setup" }

func (h *controlHandler) listRequests(w http.ResponseWriter, req *http.Request) {
	response, err := h.state.client.ListPendingRequests(req.Context(), h.state.currentBackendCredential())
	if err == nil {
		if response == nil || response.SchemaVersion != agentapi.SchemaVersion {
			writeControlError(w, http.StatusBadGateway, "invalid_request_list", "The request list is invalid.", false)
			return
		}
		for i := range response.Requests {
			item := &response.Requests[i]
			if !controlIdentifier.MatchString(item.ID) || item.Status != "pending" || validateRequestApprovalURL(item, item.ID, true) != nil {
				writeControlError(w, http.StatusBadGateway, "invalid_request_list", "The request list is invalid.", false)
				return
			}
			item.PollURL = phaseproxy.ControlURL + "/v1/requests/" + item.ID
		}
	}
	h.writeRelay(w, response, err)
}

func (h *controlHandler) cancelRequest(w http.ResponseWriter, req *http.Request, id string) {
	if !controlIdentifier.MatchString(id) || decodeOptionalEmptyJSONObject(req.Body) != nil {
		writeControlError(w, http.StatusBadRequest, "invalid_control_request", "Cancellation accepts an empty object and a request ID.", false)
		return
	}
	response, err := h.state.client.CancelRequest(req.Context(), id, h.state.currentBackendCredential())
	if err == nil {
		if response == nil || response.ID != id {
			writeControlError(w, http.StatusBadGateway, "invalid_control_response", "The cancellation result is invalid.", false)
			return
		}
		response, err = h.finishRequestWithin(req, response, nil, false)
	}
	h.writeRelay(w, response, err)
	h.applyRequestRuntimeAction(response, err)
}
