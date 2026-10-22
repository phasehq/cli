package agentapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	sdkagents "github.com/phasehq/cli/internal/agentsdk"
)

// Identity resolves non-secret display metadata for an Agent token without
// opening a session or provisioning any provider credentials.
func (c *Client) Identity(ctx context.Context) (*AgentIdentity, error) {
	if c.tokenType != TokenAgent {
		return nil, errors.New("token is not a Phase Agent token")
	}
	var response AgentIdentity
	if err := c.do(ctx, http.MethodGet, c.endpoint("identity"), nil, &response, ""); err != nil {
		return nil, err
	}
	if response.SchemaVersion != SchemaVersion || response.PrincipalType != "agent" ||
		response.Agent.ID == "" || response.Agent.Name == "" ||
		response.Workflow.ID == "" || response.Workflow.Name == "" ||
		response.Organization.ID == "" || response.Organization.Name == "" {
		return nil, errors.New("Agent identity response is incomplete")
	}
	return &response, nil
}

func (c *Client) OpenSession(ctx context.Context, request OpenSessionRequest) (*OpenSessionResponse, error) {
	if request.SchemaVersion == 0 {
		request.SchemaVersion = SchemaVersion
	}
	if c.tokenType != TokenAgent && request.WorkflowID == "" {
		return nil, errors.New("workflowId is required for User and Service Account authentication")
	}
	c.workflowID = request.WorkflowID
	var response OpenSessionResponse
	if err := c.do(ctx, http.MethodPost, c.endpoint("sessions"), request, &response, ""); err != nil {
		return nil, err
	}
	c.rememberSessionUID(response.SessionUID)
	return &response, nil
}

func (c *Client) RefreshSession(ctx context.Context, sessionUID string, credential SensitiveString) (*SessionConfig, error) {
	var response SessionConfig
	if err := c.do(ctx, http.MethodGet, c.endpoint("sessions", sessionUID, "config"), nil, &response, credential); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) Context(ctx context.Context, sessionUID string, credential SensitiveString) (*ContextResponse, error) {
	var response ContextResponse
	if err := c.do(ctx, http.MethodGet, c.endpoint("sessions", sessionUID, "context"), nil, &response, credential); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) ContextForService(ctx context.Context, sessionUID string, credential SensitiveString, serviceType string) (*ContextResponse, error) {
	serviceType = strings.TrimSpace(serviceType)
	if serviceType == "" {
		return c.Context(ctx, sessionUID, credential)
	}
	if session, ok := c.sdkRequestSession(credential); ok {
		response, err := c.requestClient.ContextForService(ctx, session, serviceType)
		if err != nil {
			return nil, mapSDKError(err)
		}
		return &ContextResponse{
			SchemaVersion: response.SchemaVersion,
			SessionUID:    response.SessionUID,
			ServiceType:   response.ServiceType,
			Markdown:      response.Markdown,
		}, nil
	}
	endpoint, err := url.Parse(c.endpoint("sessions", sessionUID, "context"))
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("serviceType", serviceType)
	endpoint.RawQuery = query.Encode()
	var response ContextResponse
	if err := c.do(ctx, http.MethodGet, endpoint.String(), nil, &response, credential); err != nil {
		return nil, err
	}
	if response.ServiceType != strings.ToLower(serviceType) {
		return nil, errors.New("Agent context response serviceType does not match the request")
	}
	return &response, nil
}

func (c *Client) Capabilities(ctx context.Context, sessionUID string, credential SensitiveString) (*CapabilitiesResponse, error) {
	if session, ok := c.sdkRequestSession(credential); ok {
		response, err := c.requestClient.Capabilities(ctx, session)
		if err != nil {
			return nil, mapSDKError(err)
		}
		return response, nil
	}
	var response CapabilitiesResponse
	if err := c.do(ctx, http.MethodGet, c.endpoint("sessions", sessionUID, "capabilities"), nil, &response, credential); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) Discover(ctx context.Context, sessionUID string, credential SensitiveString) (*DiscoverResponse, error) {
	var response DiscoverResponse
	if err := c.do(ctx, http.MethodGet, c.endpoint("sessions", sessionUID, "discover"), nil, &response, credential); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) RotateSessionCredential(ctx context.Context, sessionUID string, credential SensitiveString) (*RotateResponse, error) {
	var response RotateResponse
	if err := c.do(ctx, http.MethodPost, c.endpoint("sessions", sessionUID, "rotate"), struct{}{}, &response, credential); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) RevokeSession(ctx context.Context, sessionUID string, credential SensitiveString) (*RevokeResponse, error) {
	var response RevokeResponse
	if err := c.do(ctx, http.MethodPost, c.endpoint("sessions", sessionUID, "revoke"), struct{}{}, &response, credential); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) CreateRequest(ctx context.Context, request CreateRequestRequest, credential SensitiveString) (*RequestResponse, error) {
	response, _, err := c.CreateRequestWithStatus(ctx, request, credential)
	return response, err
}

// CreateRequestWithStatus preserves the Console's success status for the
// proxy control relay: 201 means a request was created, while 200 can mean a
// deduplicated request or denial cooldown response.
func (c *Client) CreateRequestWithStatus(ctx context.Context, request CreateRequestRequest, credential SensitiveString) (*RequestResponse, int, error) {
	if request.SchemaVersion == 0 {
		request.SchemaVersion = SchemaVersion
	}
	if session, ok := c.sdkRequestSession(credential); ok {
		response, statusCode, err := c.requestClient.CreateRequestWithStatus(ctx, session, sdkagents.CreateRequestInput{
			SchemaVersion:      request.SchemaVersion,
			Kind:               sdkagents.RequestKind(request.Kind),
			ConnectionID:       request.ConnectionID,
			CredentialID:       request.CredentialID,
			CredentialProvider: request.CredentialProvider,
			CredentialName:     request.CredentialName,
			ServiceType:        request.ServiceType,
			Markdown:           request.Markdown,
			DedupKey:           request.DedupKey,
			RelatedRequestID:   request.RelatedRequestID,
		})
		if err != nil {
			return nil, statusCode, mapSDKError(err)
		}
		return requestResponseFromSDK(response), statusCode, nil
	}
	// Legacy Service authentication and compatibility clients that have not
	// opened a session retain the hardened internal transport. Normal phase ai
	// runtimes bind their session during OpenSession and use the shared SDK.
	var response RequestResponse
	statusCode, err := c.doWithStatus(ctx, http.MethodPost, c.endpoint("requests"), request, &response, credential)
	if err != nil {
		return nil, statusCode, err
	}
	return &response, statusCode, nil
}

func (c *Client) PollRequest(ctx context.Context, requestID string, credential SensitiveString) (*RequestResponse, error) {
	if session, ok := c.sdkRequestSession(credential); ok {
		response, err := c.requestClient.PollRequest(ctx, session, requestID)
		if err != nil {
			return nil, mapSDKError(err)
		}
		return requestResponseFromSDK(response), nil
	}
	var response RequestResponse
	if err := c.do(ctx, http.MethodGet, c.endpoint("requests", requestID), nil, &response, credential); err != nil {
		return nil, err
	}
	return &response, nil
}

func requestResponseFromSDK(response *sdkagents.AgentRequest) *RequestResponse {
	if response == nil {
		return nil
	}
	converted := &RequestResponse{
		SchemaVersion: response.SchemaVersion,
		Revision:      response.Revision, WorkflowID: response.WorkflowID,
		Progress: response.Progress, Resolution: response.Resolution, RelatedRequestID: response.RelatedRequestID,
		ID:                 response.ID,
		ApprovalURL:        response.ApprovalURL,
		Status:             string(response.Status),
		Kind:               string(response.Kind),
		CredentialProvider: response.CredentialProvider,
		CredentialName:     response.CredentialName,
		ServiceType:        response.ServiceType,
		CredentialID:       response.CredentialID,
		ConnectionID:       response.ConnectionID,
		GrantID:            response.GrantID,
		RuntimeAction:      RequestRuntimeAction(response.RuntimeAction),
		Markdown:           response.Markdown,
		Cooldown:           response.Cooldown,
		ResolutionNote:     response.ResolutionNote,
		ResolvedAt:         response.ResolvedAt,
		RequestExpiresAt:   response.RequestExpiresAt,
	}
	return converted
}

func mapSDKError(err error) error {
	if err == nil {
		return nil
	}
	var apiErr *sdkagents.APIError
	if errors.As(err, &apiErr) {
		return &Error{
			Code:       safeErrorText(apiErr.Code, 128),
			Message:    safeErrorText(apiErr.Message, 512),
			StatusCode: apiErr.StatusCode,
			Retryable:  apiErr.Retryable,
			RetryAfter: apiErr.RetryAfter,
			RequestID:  safeErrorText(apiErr.RequestID, 256),
		}
	}
	var tooLarge *sdkagents.ResponseTooLargeError
	if errors.As(err, &tooLarge) {
		return errors.New("Agent response exceeds the allowed limit")
	}
	// SDK construction/validation/transport errors never include response
	// bodies. Still redact credential-shaped strings before they cross the
	// proxy relay error boundary.
	return errors.New(safeErrorText(strings.TrimSpace(err.Error()), 512))
}

func (c *Client) ShipEvents(ctx context.Context, sessionUID string, request EventBatchRequest, credential SensitiveString) (*EventBatchResponse, error) {
	if request.SchemaVersion == 0 {
		request.SchemaVersion = SchemaVersion
	}
	var response EventBatchResponse
	if err := c.do(ctx, http.MethodPost, c.endpoint("sessions", sessionUID, "events"), request, &response, credential); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) ListPendingRequests(ctx context.Context, credential SensitiveString) (*ListRequestsResponse, error) {
	if session, ok := c.sdkRequestSession(credential); ok {
		response, err := c.requestClient.ListPendingRequests(ctx, session, c.workflowID)
		if err != nil {
			return nil, mapSDKError(err)
		}
		result := &ListRequestsResponse{SchemaVersion: response.SchemaVersion, Requests: make([]RequestResponse, 0, len(response.Requests))}
		for i := range response.Requests {
			result.Requests = append(result.Requests, *requestResponseFromSDK(&response.Requests[i]))
		}
		return result, nil
	}
	endpoint := c.endpoint("requests")
	if c.workflowID != "" {
		endpoint += "?workflow_id=" + url.QueryEscape(c.workflowID)
	}
	var response ListRequestsResponse
	if err := c.do(ctx, http.MethodGet, endpoint, nil, &response, credential); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) CancelRequest(ctx context.Context, id string, credential SensitiveString) (*RequestResponse, error) {
	if session, ok := c.sdkRequestSession(credential); ok {
		response, err := c.requestClient.CancelRequest(ctx, session, id)
		if err != nil {
			return nil, mapSDKError(err)
		}
		return requestResponseFromSDK(response), nil
	}
	var response RequestResponse
	if err := c.do(ctx, http.MethodPost, c.endpoint("requests", id, "cancel"), struct{}{}, &response, credential); err != nil {
		return nil, err
	}
	return &response, nil
}
