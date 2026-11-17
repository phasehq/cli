package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	sdkagents "github.com/phasehq/cli/internal/agentsdk"
)

// App secrets are read and written through the Console's plaintext secrets
// API for server-side encrypted apps, with the Agent token alone: no session
// is needed and no environment key ever reaches this process. The Console
// checks the Workflow's app Connections on every call, so expiry and
// revocation take effect on the next one.

// maxRefusalRequestBytes bounds the ready-to-send request a refusal may carry.
const maxRefusalRequestBytes = 16 << 10

// AppSecret is one secret as the secrets API returns it.
type AppSecret struct {
	ID        string   `json:"id"`
	Key       string   `json:"key"`
	Value     string   `json:"value"`
	Comment   string   `json:"comment"`
	Path      string   `json:"path"`
	Tags      []string `json:"tags"`
	Type      string   `json:"type"`
	Lifecycle string   `json:"lifecycle"`
}

func (s AppSecret) String() string   { return "AppSecret{key:" + s.Key + " value:[REDACTED]}" }
func (s AppSecret) GoString() string { return s.String() }

// AppSecretsQuery selects the environment by app ID and environment name, as
// the public API does. An empty Path means every path; Key narrows to one key;
// Raw returns values without resolving references.
type AppSecretsQuery struct {
	AppID string
	Env   string
	Path  string
	Key   string
	Raw   bool
}

// AppSecretWrite is one entry of a create or update. Update names the secret
// by ID and leaves out what it keeps.
type AppSecretWrite struct {
	ID    string  `json:"id,omitempty"`
	Key   string  `json:"key,omitempty"`
	Value *string `json:"value,omitempty"`
	Path  string  `json:"path,omitempty"`
	Type  string  `json:"type,omitempty"`
}

// AppSecretsError is a refusal from the secrets API or app access listing.
// Message is the Console's sentence for a person; Request, when present, is a
// complete body for POST /v1/requests that asks a member for what the call
// needed. Neither ever carries a secret value: the body is not kept.
type AppSecretsError struct {
	StatusCode     int
	Code           string
	Message        string
	Request        json.RawMessage
	ConnectionName string
	Class          string
	RetryAfter     time.Duration
}

func (e *AppSecretsError) Error() string { return e.Message }

// AppAccess lists the app Connections this token's Workflow can use now.
func (c *Client) AppAccess(ctx context.Context) (*AppAccessResponse, error) {
	if c.tokenType != TokenAgent {
		return nil, errors.New("token is not a Phase Agent token")
	}
	var response AppAccessResponse
	if _, err := c.doRequest(ctx, http.MethodGet, c.endpoint("app-access"), nil, &response, "", decodeAppSecretsError); err != nil {
		return nil, err
	}
	if response.SchemaVersion != SchemaVersion {
		return nil, errors.New("Agent app access response has an unsupported schema version")
	}
	return &response, nil
}

// ListAppSecrets reads secrets of one environment.
func (c *Client) ListAppSecrets(ctx context.Context, query AppSecretsQuery) ([]AppSecret, error) {
	values := c.environmentQuery(query.AppID, query.Env)
	if query.Path != "" {
		values.Set("path", query.Path)
	}
	if query.Key != "" {
		values.Set("key", query.Key)
	}
	if query.Raw {
		values.Set("raw", "true")
	}
	var secrets []AppSecret
	if _, err := c.doRequest(ctx, http.MethodGet, c.secretsEndpoint(values), nil, &secrets, "", decodeAppSecretsError); err != nil {
		return nil, err
	}
	return secrets, nil
}

// CreateAppSecrets creates secrets in one environment.
func (c *Client) CreateAppSecrets(ctx context.Context, appID, env string, secrets []AppSecretWrite) error {
	return c.writeAppSecrets(ctx, http.MethodPost, appID, env, map[string]any{"secrets": secrets})
}

// UpdateAppSecrets updates secrets, each named by ID, in one environment.
func (c *Client) UpdateAppSecrets(ctx context.Context, appID, env string, secrets []AppSecretWrite) error {
	return c.writeAppSecrets(ctx, http.MethodPut, appID, env, map[string]any{"secrets": secrets})
}

// DeleteAppSecrets deletes secrets by ID from one environment.
func (c *Client) DeleteAppSecrets(ctx context.Context, appID, env string, ids []string) error {
	return c.writeAppSecrets(ctx, http.MethodDelete, appID, env, map[string]any{"secrets": ids})
}

func (c *Client) writeAppSecrets(ctx context.Context, method, appID, env string, body any) error {
	// The response echoes the written secrets with their values; nothing
	// reads it, so it is not decoded.
	_, err := c.doRequest(ctx, method, c.secretsEndpoint(c.environmentQuery(appID, env)), body, nil, "", decodeAppSecretsError)
	return err
}

func (c *Client) environmentQuery(appID, env string) url.Values {
	values := url.Values{}
	values.Set("app_id", appID)
	values.Set("env", env)
	return values
}

// secretsEndpoint is the public secrets API, a sibling of the Agent API.
func (c *Client) secretsEndpoint(query url.Values) string {
	u := *c.baseURL
	u.Path = path.Join(strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/agents"), "secrets") + "/"
	u.RawQuery = query.Encode()
	u.Fragment = ""
	return u.String()
}

// decodeAppSecretsError reads the secrets API's error body, a flat
// {"error": "<sentence>", "code": ...} with the members of the contract, and
// also the Agent API envelope and DRF's {"detail": ...}, which the same routes
// return for authentication and throttling.
func decodeAppSecretsError(statusCode int, payload []byte, headers http.Header) error {
	refusal := &AppSecretsError{
		StatusCode: statusCode,
		RetryAfter: parseRetryAfter(headers.Get("Retry-After"), time.Now()),
	}
	var body struct {
		Error          json.RawMessage `json:"error"`
		Detail         string          `json:"detail"`
		Code           string          `json:"code"`
		Request        json.RawMessage `json:"request"`
		ConnectionName string          `json:"connectionName"`
		Class          string          `json:"class"`
	}
	if json.Unmarshal(payload, &body) == nil {
		var sentence string
		var envelope struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		switch {
		case json.Unmarshal(body.Error, &sentence) == nil:
			refusal.Message = sentence
		case json.Unmarshal(body.Error, &envelope) == nil:
			refusal.Message = envelope.Message
			if body.Code == "" {
				body.Code = envelope.Code
			}
		}
		if strings.TrimSpace(refusal.Message) == "" {
			refusal.Message = body.Detail
		}
		refusal.Code = safeErrorText(body.Code, 128)
		refusal.ConnectionName = safeErrorText(body.ConnectionName, 256)
		refusal.Class = safeErrorText(body.Class, 64)
		refusal.Request = refusalRequest(body.Request)
	}
	refusal.Message = strings.TrimSpace(safeErrorText(refusal.Message, 512))
	if refusal.Message == "" {
		refusal.Message = http.StatusText(statusCode)
		if refusal.Message == "" {
			refusal.Message = "The Phase Console refused the request"
		}
	}
	return refusal
}

// refusalRequest keeps a ready-to-send request only when it is a bounded JSON
// object with nothing credential-shaped in it, and one the local control API
// would forward: a known action under its kind that carries no secret value.
func refusalRequest(raw json.RawMessage) json.RawMessage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > maxRefusalRequestBytes || raw[0] != '{' ||
		credentialShapedText.Match(raw) {
		return nil
	}
	var request struct {
		Kind   sdkagents.RequestKind `json:"kind"`
		Title  string                `json:"title"`
		Action json.RawMessage       `json:"action"`
	}
	if json.Unmarshal(raw, &request) != nil || !sdkagents.ValidRequestTitle(request.Title) ||
		sdkagents.ValidateRequestAction(request.Kind, request.Action) != nil {
		return nil
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil
	}
	return json.RawMessage(compact.Bytes())
}
