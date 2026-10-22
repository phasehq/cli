package agentsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/phasehq/golang-sdk/v2/phase/network"
)

const (
	apiPathPrefix                 = "/v1/agents"
	SessionCredentialHeader       = "X-Phase-Session-Credential"
	camelCaseHeader               = "X-Use-Camel-Case"
	maxResponseBytes        int64 = 8 << 20
)

type ClientConfig struct {
	// BaseURL is the Phase API origin, optionally with a deployment base path.
	// The client appends /v1/agents/... to it.
	BaseURL        string
	HTTPClient     *http.Client
	Authentication Authentication
	// UserAgent overrides the SDK-wide user agent. When empty, the client uses
	// network.GetUserAgent so callers share the same SDK or CLI identity.
	UserAgent string
}

// Client is a context-aware Agent runtime API client. It never follows HTTP
// redirects, preventing the durable Authorization header or #1 credential from
// being forwarded to another URL.
type Client struct {
	baseURL        string
	httpClient     *http.Client
	authentication Authentication
	userAgent      string
}

func NewClient(config ClientConfig) (*Client, error) {
	baseURL, err := normalizeBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	if err := validateAuthentication(config.Authentication); err != nil {
		return nil, err
	}

	provided := config.HTTPClient
	if provided == nil {
		provided = &http.Client{Timeout: 30 * time.Second}
	}
	client := *provided
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = network.GetUserAgent()
	}

	return &Client{
		baseURL:        baseURL,
		httpClient:     &client,
		authentication: config.Authentication,
		userAgent:      userAgent,
	}, nil
}

func (c *Client) String() string {
	if c == nil {
		return "Client<nil>"
	}
	return fmt.Sprintf("Client{BaseURL:%q Authentication:%s}", c.baseURL, c.authentication.String())
}
func (c *Client) GoString() string { return c.String() }
func (c *Client) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, c.String())
}

func normalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("agents: base URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("agents: invalid base URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("agents: base URL scheme must be http or https")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("agents: base URL host is required")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("agents: base URL must not contain user info")
	}
	if parsed.Scheme == "http" && !isLoopbackHostname(parsed.Hostname()) {
		return "", fmt.Errorf("agents: HTTP base URLs are allowed only on loopback")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("agents: base URL must not contain a query or fragment")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func isLoopbackHostname(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

func validateAuthentication(authentication Authentication) error {
	switch authentication.Type {
	case AuthenticationAgent, AuthenticationUser, AuthenticationServiceAccount:
	default:
		return fmt.Errorf("agents: unsupported authentication type %q", authentication.Type)
	}
	return validateCredential("durable Phase token", authentication.Token)
}

func validateCredential(name string, credential SensitiveString) error {
	value := credential.Reveal()
	if value == "" {
		return fmt.Errorf("agents: %s is required", name)
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return fmt.Errorf("agents: %s contains whitespace or control characters", name)
	}
	return nil
}

func validateSession(session SessionAuth) error {
	if session.SessionUID == "" {
		return fmt.Errorf("agents: session UID is required")
	}
	return validateCredential("session credential", session.Credential)
}

func (c *Client) OpenSession(ctx context.Context, input OpenSessionRequest) (*OpenSessionResponse, error) {
	if input.SchemaVersion == 0 {
		input.SchemaVersion = CurrentSchemaVersion
	}
	var output OpenSessionResponse
	if err := c.doJSON(ctx, http.MethodPost, "/sessions/", nil, input, &output, http.StatusOK, http.StatusCreated); err != nil {
		return nil, err
	}
	return &output, nil
}

func (c *Client) RefreshConfig(ctx context.Context, session SessionAuth) (*RefreshConfigResponse, error) {
	if err := validateSession(session); err != nil {
		return nil, err
	}
	var output RefreshConfigResponse
	path := sessionPath(session.SessionUID, "/config/")
	if err := c.doJSON(ctx, http.MethodGet, path, &session.Credential, nil, &output, http.StatusOK); err != nil {
		return nil, err
	}
	return &output, nil
}

// Context fetches the advisory, non-authoritative context for a session.
func (c *Client) Context(ctx context.Context, session SessionAuth) (*ContextResponse, error) {
	if err := validateSession(session); err != nil {
		return nil, err
	}
	var output ContextResponse
	path := sessionPath(session.SessionUID, "/context/")
	if err := c.doJSON(ctx, http.MethodGet, path, &session.Credential, nil, &output, http.StatusOK); err != nil {
		return nil, err
	}
	return &output, nil
}

// GetContext is an explicit-name alias for Context.
func (c *Client) GetContext(ctx context.Context, session SessionAuth) (*ContextResponse, error) {
	return c.Context(ctx, session)
}

// ContextForService fetches advisory context scoped to one dynamically
// discovered service. An empty service type is rejected; use Context for the
// unscoped response.
func (c *Client) ContextForService(ctx context.Context, session SessionAuth, serviceType string) (*ContextResponse, error) {
	if err := validateSession(session); err != nil {
		return nil, err
	}
	serviceType = strings.TrimSpace(serviceType)
	if !validRequestServiceType(serviceType) {
		return nil, fmt.Errorf("agents: service type must contain 1-64 letters, digits, dots, underscores, or hyphens")
	}
	serviceType = strings.ToLower(serviceType)
	var output ContextResponse
	path := sessionPath(session.SessionUID, "/context/") + "?" + url.Values{"serviceType": {serviceType}}.Encode()
	if err := c.doJSON(ctx, http.MethodGet, path, &session.Credential, nil, &output, http.StatusOK); err != nil {
		return nil, err
	}
	if output.ServiceType != serviceType {
		return nil, fmt.Errorf("agents: context response service type does not match the request")
	}
	return &output, nil
}

// Capabilities returns credential-free, registry-derived hints describing the
// services Phase can manage. Selecting managed execution remains explicit.
func (c *Client) Capabilities(ctx context.Context, session SessionAuth) (*CapabilitiesResponse, error) {
	if err := validateSession(session); err != nil {
		return nil, err
	}
	var output CapabilitiesResponse
	path := sessionPath(session.SessionUID, "/capabilities/")
	if err := c.doJSON(ctx, http.MethodGet, path, &session.Credential, nil, &output, http.StatusOK); err != nil {
		return nil, err
	}
	return &output, nil
}

func (c *Client) Discover(ctx context.Context, session SessionAuth) (*DiscoverResponse, error) {
	if err := validateSession(session); err != nil {
		return nil, err
	}
	var output DiscoverResponse
	path := sessionPath(session.SessionUID, "/discover/")
	if err := c.doJSON(ctx, http.MethodGet, path, &session.Credential, nil, &output, http.StatusOK); err != nil {
		return nil, err
	}
	return &output, nil
}

func (c *Client) RotateSession(ctx context.Context, session SessionAuth) (*RotateSessionResponse, error) {
	if err := validateSession(session); err != nil {
		return nil, err
	}
	var output RotateSessionResponse
	path := sessionPath(session.SessionUID, "/rotate/")
	if err := c.doJSON(ctx, http.MethodPost, path, &session.Credential, struct{}{}, &output, http.StatusOK, http.StatusCreated); err != nil {
		return nil, err
	}
	return &output, nil
}

func (c *Client) RevokeSession(ctx context.Context, session SessionAuth) error {
	if err := validateSession(session); err != nil {
		return err
	}
	path := sessionPath(session.SessionUID, "/revoke/")
	return c.doJSON(ctx, http.MethodPost, path, &session.Credential, struct{}{}, nil, http.StatusOK, http.StatusAccepted, http.StatusNoContent)
}

func (c *Client) CreateRequest(ctx context.Context, session SessionAuth, input CreateRequestInput) (*AgentRequest, error) {
	response, _, err := c.CreateRequestWithStatus(ctx, session, input)
	return response, err
}

// CreateRequestWithStatus preserves the successful HTTP status so callers can
// distinguish a newly-created request (201) from a deduplicated or cooldown
// response (200) without duplicating the Agent API transport.
func (c *Client) CreateRequestWithStatus(ctx context.Context, session SessionAuth, input CreateRequestInput) (*AgentRequest, int, error) {
	if err := validateSession(session); err != nil {
		return nil, 0, err
	}
	if input.Kind != RequestSetup && input.Kind != RequestCredentialUpdate {
		return nil, 0, fmt.Errorf("agents: request kind must be setup or credential_update")
	}
	if strings.TrimSpace(input.Markdown) == "" {
		return nil, 0, fmt.Errorf("agents: request justification is required")
	}
	if !validRequestServiceType(input.CredentialProvider) {
		return nil, 0, fmt.Errorf("agents: credential provider must contain 1-64 letters, digits, dots, underscores, or hyphens")
	}
	if input.CredentialName == "" || input.CredentialName != strings.TrimSpace(input.CredentialName) || len(input.CredentialName) > 64 {
		return nil, 0, fmt.Errorf("agents: credential name must contain 1-64 non-padding characters")
	}
	switch input.Kind {
	case RequestSetup:
		if input.ConnectionID != "" || input.CredentialID != "" {
			return nil, 0, fmt.Errorf("agents: connection and credential IDs are not valid for a setup request")
		}
		if !validRequestServiceType(input.ServiceType) {
			return nil, 0, fmt.Errorf("agents: service type is required for a setup request")
		}
	case RequestCredentialUpdate:
		if strings.TrimSpace(input.ConnectionID) == "" || strings.TrimSpace(input.CredentialID) == "" {
			return nil, 0, fmt.Errorf("agents: connection and credential IDs are required for a credential update request")
		}
		if input.ServiceType != "" {
			return nil, 0, fmt.Errorf("agents: service type is valid only for a setup request")
		}
	}
	if input.SchemaVersion == 0 {
		input.SchemaVersion = CurrentSchemaVersion
	}
	var output AgentRequest
	path := "/requests/"
	statusCode, err := c.doJSONWithStatus(ctx, http.MethodPost, path, &session.Credential, input, &output, http.StatusOK, http.StatusCreated, http.StatusAccepted)
	if err != nil {
		return nil, statusCode, err
	}
	return &output, statusCode, nil
}

func validRequestServiceType(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'A' && character <= 'Z') ||
			(character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func (c *Client) PollRequest(ctx context.Context, session SessionAuth, requestID string) (*AgentRequest, error) {
	if err := validateSession(session); err != nil {
		return nil, err
	}
	if requestID == "" {
		return nil, fmt.Errorf("agents: request ID is required")
	}
	var output AgentRequest
	path := "/requests/" + url.PathEscape(requestID) + "/"
	if err := c.doJSON(ctx, http.MethodGet, path, &session.Credential, nil, &output, http.StatusOK); err != nil {
		return nil, err
	}
	return &output, nil
}

// ListPendingRequests returns resumable pending requests visible to the
// authenticated Workflow. An empty workflowID lets an Agent token select its
// own Workflow; User and Service Account callers supply the intended Workflow.
// It neither acquires source material nor changes any request's state.
func (c *Client) ListPendingRequests(ctx context.Context, session SessionAuth, workflowID string) (*ListRequestsResponse, error) {
	if err := validateSession(session); err != nil {
		return nil, err
	}
	path := "/requests/"
	if workflowID != "" {
		query := url.Values{"workflow_id": []string{workflowID}}
		path += "?" + query.Encode()
	}
	var output ListRequestsResponse
	if err := c.doJSON(ctx, http.MethodGet, path, &session.Credential, nil, &output, http.StatusOK); err != nil {
		return nil, err
	}
	return &output, nil
}

// CancelRequest explicitly cancels a pending request. Cancellation is
// idempotent at the server; cancellation racing fulfillment returns the
// server's single recorded outcome. Cancelling a poll alone never calls this.
func (c *Client) CancelRequest(ctx context.Context, session SessionAuth, requestID string) (*AgentRequest, error) {
	if err := validateSession(session); err != nil {
		return nil, err
	}
	if strings.TrimSpace(requestID) == "" {
		return nil, fmt.Errorf("agents: request ID is required")
	}
	var output AgentRequest
	path := "/requests/" + url.PathEscape(requestID) + "/cancel/"
	if err := c.doJSON(ctx, http.MethodPost, path, &session.Credential, struct{}{}, &output, http.StatusOK); err != nil {
		return nil, err
	}
	return &output, nil
}

func (c *Client) ShipEvents(ctx context.Context, session SessionAuth, batch EventBatch) (*ShipEventsResponse, error) {
	if err := validateSession(session); err != nil {
		return nil, err
	}
	if batch.SchemaVersion == 0 {
		batch.SchemaVersion = CurrentSchemaVersion
	}
	var output ShipEventsResponse
	path := sessionPath(session.SessionUID, "/events/")
	if err := c.doJSON(ctx, http.MethodPost, path, &session.Credential, batch, &output, http.StatusOK, http.StatusAccepted, http.StatusNoContent); err != nil {
		return nil, err
	}
	return &output, nil
}

func (c *Client) MintAgentToken(ctx context.Context, agentID string, input MintAgentTokenRequest) (*MintAgentTokenResponse, error) {
	if agentID == "" {
		return nil, fmt.Errorf("agents: agent ID is required")
	}
	if input.SchemaVersion == 0 {
		input.SchemaVersion = CurrentSchemaVersion
	}
	var output MintAgentTokenResponse
	path := "/" + url.PathEscape(agentID) + "/tokens/"
	if err := c.doJSON(ctx, http.MethodPost, path, nil, input, &output, http.StatusOK, http.StatusCreated); err != nil {
		return nil, err
	}
	return &output, nil
}

func sessionPath(sessionUID, suffix string) string {
	return "/sessions/" + url.PathEscape(sessionUID) + suffix
}

func (c *Client) doJSON(
	ctx context.Context,
	method string,
	path string,
	sessionCredential *SensitiveString,
	input interface{},
	output interface{},
	acceptedStatuses ...int,
) error {
	_, err := c.doJSONWithStatus(ctx, method, path, sessionCredential, input, output, acceptedStatuses...)
	return err
}

func (c *Client) doJSONWithStatus(
	ctx context.Context,
	method string,
	path string,
	sessionCredential *SensitiveString,
	input interface{},
	output interface{},
	acceptedStatuses ...int,
) (int, error) {
	if c == nil {
		return 0, fmt.Errorf("agents: nil client")
	}
	if ctx == nil {
		return 0, fmt.Errorf("agents: context is required")
	}

	var payload []byte
	var err error
	if input != nil {
		payload, err = json.Marshal(input)
		if err != nil {
			return 0, fmt.Errorf("agents: encode request: %w", err)
		}
		defer zeroBytes(payload)
	}

	requestURL := c.baseURL + apiPathPrefix + path
	req, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("agents: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(camelCaseHeader, "true")
	req.Header.Set("Authorization", "Bearer "+string(c.authentication.Type)+" "+c.authentication.Token.Reveal())
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if sessionCredential != nil {
		req.Header.Set(SessionCredentialHeader, sessionCredential.Reveal())
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("agents: perform request: %w", err)
	}
	defer resp.Body.Close()

	body, err := readResponseBody(resp.Body)
	if err != nil {
		return resp.StatusCode, err
	}
	defer zeroBytes(body)

	if !containsStatus(acceptedStatuses, resp.StatusCode) {
		return resp.StatusCode, decodeAPIError(resp, body)
	}
	if output == nil || len(bytes.TrimSpace(body)) == 0 {
		return resp.StatusCode, nil
	}
	if err := json.Unmarshal(body, output); err != nil {
		return resp.StatusCode, fmt.Errorf("agents: decode response: %w", err)
	}
	return resp.StatusCode, nil
}

func readResponseBody(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("agents: read response: %w", err)
	}
	if int64(len(body)) > maxResponseBytes {
		zeroBytes(body)
		return nil, &ResponseTooLargeError{Limit: maxResponseBytes}
	}
	return body, nil
}

func containsStatus(statuses []int, status int) bool {
	for _, accepted := range statuses {
		if status == accepted {
			return true
		}
	}
	return false
}

func decodeAPIError(response *http.Response, body []byte) error {
	payload := ErrorPayload{}
	var envelope ErrorResponse
	if len(body) > 0 && json.Unmarshal(body, &envelope) == nil {
		payload = envelope.Error
	}
	message := payload.Message
	if message == "" {
		message = http.StatusText(response.StatusCode)
	}
	return &APIError{
		StatusCode: response.StatusCode,
		Code:       payload.Code,
		Message:    message,
		Retryable:  payload.Retryable,
		Details:    payload.Details,
		RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
		RequestID:  response.Header.Get("X-Request-ID"),
	}
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return when.Sub(now)
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
