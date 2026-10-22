// Package agentapi contains the CLI's narrow v1 Agent runtime facade. Shared
// token parsing and Agent request calls live in the Go SDK; proxy, CA, decoy,
// and runtime lifecycle behavior remains CLI-owned.
package agentapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	sdkagents "github.com/phasehq/cli/internal/agentsdk"
	"github.com/phasehq/golang-sdk/v2/phase/misc"
	"github.com/phasehq/golang-sdk/v2/phase/network"
)

var credentialShapedText = regexp.MustCompile(`(?i)(?:pss_(?:user|service|agent):v\d+:[^\s"']+|psx_sess_[A-Za-z0-9_-]+|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-(?:proj-|admin-)?[A-Za-z0-9_-]{16,})`)

const (
	SchemaVersion           = 1
	SessionCredentialHeader = "X-Phase-Session-Credential"
	maxResponseBytes        = 4 << 20
)

type TokenType string

const (
	TokenUser           TokenType = "User"
	TokenService        TokenType = "Service"
	TokenServiceAccount TokenType = "ServiceAccount"
	TokenAgent          TokenType = "Agent"
)

// Error is a typed and deliberately bounded Agent API error. Raw response
// bodies and server detail maps are never retained because they may contain
// credential-shaped material on a misconfigured server.
type Error struct {
	Code       string
	Message    string
	StatusCode int
	Retryable  bool
	RetryAfter time.Duration
	RequestID  string
}

func (e *Error) Error() string {
	message := strings.TrimSpace(e.Message)
	if message == "" {
		message = "Agent runtime request failed"
	}
	if e.Code == "" {
		return fmt.Sprintf("%s (HTTP %d)", message, e.StatusCode)
	}
	return fmt.Sprintf("%s: %s (HTTP %d)", e.Code, message, e.StatusCode)
}

type Client struct {
	baseURL       *url.URL
	authorization string
	tokenType     TokenType
	httpClient    *http.Client
	userAgent     string
	requestClient *sdkagents.Client
	sessionMu     sync.RWMutex
	sessionUID    string
	workflowID    string
}

func (c *Client) String() string   { return "agentapi.Client{credentials:[REDACTED]}" }
func (c *Client) GoString() string { return c.String() }

func NewClient(host, durableToken string, httpClient *http.Client) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimSpace(host))
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("invalid Phase host URL")
	}
	if baseURL.Scheme != "https" && baseURL.Scheme != "http" {
		return nil, fmt.Errorf("Phase host must use http or https")
	}
	if baseURL.Scheme == "http" && !agentAPILoopbackHost(baseURL.Hostname()) {
		return nil, fmt.Errorf("Phase host must use https unless it is an explicit loopback address")
	}
	if baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("Phase host must not contain user information, a query, or a fragment")
	}
	basePath := strings.TrimSuffix(baseURL.Path, "/")
	sdkBasePath := basePath
	switch {
	case strings.HasSuffix(basePath, "/service/public/v1/agents"):
		sdkBasePath = strings.TrimSuffix(basePath, "/v1/agents")
	case strings.HasSuffix(basePath, "/service/public"):
		sdkBasePath = basePath
		basePath = path.Join(basePath, "v1", "agents")
	default:
		sdkBasePath = path.Join(basePath, "service", "public")
		basePath = path.Join(sdkBasePath, "v1", "agents")
	}
	baseURL.Path = basePath
	authentication, tokenType, lookup, err := parseAuthentication(durableToken)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		// A phase ai command invoked inside a proxy-managed child must reach the
		// control plane directly. Sending its durable Authorization header back
		// through the data-plane proxy would violate the credential boundary and
		// can recurse into itself.
		if os.Getenv("PHASE_AI_ENABLED") == "1" {
			transport.Proxy = nil
		}
		if !misc.VerifySSL {
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{}
			} else {
				transport.TLSClientConfig = transport.TLSClientConfig.Clone()
			}
			transport.TLSClientConfig.InsecureSkipVerify = true // user-requested PHASE_VERIFY_SSL=False
		}
		httpClient = &http.Client{Timeout: 30 * time.Second, Transport: transport}
	}
	// Never allow net/http to replay the durable Authorization header or the
	// per-session #1 to a redirect target. Clone the caller's client so this
	// hardening does not mutate shared process state.
	clonedHTTPClient := *httpClient
	clonedHTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	userAgent := network.GetUserAgent()
	var requestClient *sdkagents.Client
	if tokenType != TokenService {
		sdkBaseURL := *baseURL
		sdkBaseURL.Path = sdkBasePath
		// Preserve the CLI's explicit loopback spelling compatibility. The SDK
		// validates localhost itself, but URL.Hostname retains a legal trailing
		// DNS dot that its stricter validator does not currently normalize.
		if hostname := sdkBaseURL.Hostname(); strings.HasSuffix(hostname, ".") && agentAPILoopbackHost(hostname) {
			sdkBaseURL.Host = strings.Replace(sdkBaseURL.Host, hostname, strings.TrimSuffix(hostname, "."), 1)
		}
		requestClient, err = sdkagents.NewClient(sdkagents.ClientConfig{
			BaseURL:        sdkBaseURL.String(),
			HTTPClient:     &clonedHTTPClient,
			Authentication: authentication,
			UserAgent:      userAgent,
		})
		if err != nil {
			return nil, fmt.Errorf("initialize shared Agent client: %w", err)
		}
	}
	return &Client{
		baseURL:       baseURL,
		authorization: fmt.Sprintf("Bearer %s %s", tokenType, lookup),
		tokenType:     tokenType,
		httpClient:    &clonedHTTPClient,
		userAgent:     userAgent,
		requestClient: requestClient,
	}, nil
}

func agentAPILoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.Unmap().IsLoopback()
}

func (c *Client) TokenType() TokenType { return c.tokenType }

func (c *Client) rememberSessionUID(sessionUID string) {
	if strings.TrimSpace(sessionUID) == "" {
		return
	}
	c.sessionMu.Lock()
	c.sessionUID = sessionUID
	c.sessionMu.Unlock()
}

func (c *Client) sdkRequestSession(credential SensitiveString) (sdkagents.SessionAuth, bool) {
	if c.requestClient == nil {
		return sdkagents.SessionAuth{}, false
	}
	c.sessionMu.RLock()
	sessionUID := c.sessionUID
	c.sessionMu.RUnlock()
	if sessionUID == "" {
		return sdkagents.SessionAuth{}, false
	}
	return sdkagents.SessionAuth{
		SessionUID: sessionUID,
		Credential: sdkagents.SensitiveString(credential.Reveal()),
	}, true
}

// ParseDurableToken uses the shared SDK parser for current Agent, Personal
// Access, and Service Account tokens. The small compatibility branch retains
// legacy token classification so phase ai can reject it with a useful error;
// legacy Service credentials are never passed to the Agent request SDK.
func ParseDurableToken(token string) (TokenType, string, error) {
	_, tokenType, lookup, err := parseAuthentication(token)
	return tokenType, lookup, err
}

func parseAuthentication(token string) (sdkagents.Authentication, TokenType, string, error) {
	token = strings.TrimSpace(token)
	authentication, err := sdkagents.AuthenticationFromPhaseToken(token)
	if err == nil {
		switch authentication.Type {
		case sdkagents.AuthenticationAgent:
			return authentication, TokenAgent, authentication.Token.Reveal(), nil
		case sdkagents.AuthenticationUser:
			return authentication, TokenUser, authentication.Token.Reveal(), nil
		case sdkagents.AuthenticationServiceAccount:
			return authentication, TokenServiceAccount, authentication.Token.Reveal(), nil
		default:
			return sdkagents.Authentication{}, "", "", errors.New("invalid Phase token")
		}
	}

	// The core SDK still accepts newer User token versions and v1 Service
	// tokens. Keep that compatibility at the CLI boundary while the Agent SDK
	// deliberately rejects legacy Service authentication.
	if matches := misc.PssUserPattern.FindStringSubmatch(token); len(matches) == 6 {
		version, versionErr := strconv.Atoi(matches[1])
		if versionErr == nil && version >= 1 {
			authentication = sdkagents.UserAuthentication(matches[2])
			return authentication, TokenUser, matches[2], nil
		}
	}
	if matches := misc.PssServicePattern.FindStringSubmatch(token); len(matches) == 6 {
		version, versionErr := strconv.Atoi(matches[1])
		if versionErr == nil && version >= 1 {
			if version == 2 {
				authentication = sdkagents.ServiceAccountAuthentication(matches[2])
				return authentication, TokenServiceAccount, matches[2], nil
			}
			return sdkagents.Authentication{}, TokenService, matches[2], nil
		}
	}
	return sdkagents.Authentication{}, "", "", errors.New("invalid Phase token")
}

func (c *Client) endpoint(segments ...string) string {
	u := *c.baseURL
	joined := strings.TrimSuffix(u.Path, "/")
	for _, segment := range segments {
		joined = path.Join(joined, url.PathEscape(segment))
	}
	u.Path = joined + "/"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func (c *Client) do(ctx context.Context, method, endpoint string, requestBody, responseBody any, sessionCredential SensitiveString) error {
	_, err := c.doWithStatus(ctx, method, endpoint, requestBody, responseBody, sessionCredential)
	return err
}

// doWithStatus is used only by relay routes whose successful HTTP status is
// part of the Console contract (for example, request creation distinguishes a
// newly created 201 response from a deduplicated/cooldown 200 response).
func (c *Client) doWithStatus(ctx context.Context, method, endpoint string, requestBody, responseBody any, sessionCredential SensitiveString) (int, error) {
	var body io.Reader
	var requestPayload []byte
	if requestBody != nil {
		payload, err := json.Marshal(requestBody)
		if err != nil {
			return 0, fmt.Errorf("encode Agent request: %w", err)
		}
		requestPayload = payload
		defer zeroBytes(requestPayload)
		body = bytes.NewReader(requestPayload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, fmt.Errorf("create Agent request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.authorization)
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if credential := sessionCredential.Reveal(); credential != "" {
		req.Header.Set(SessionCredentialHeader, credential)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Agent runtime request failed: %w", err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	responsePayload, err := io.ReadAll(limited)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("read Agent response: %w", err)
	}
	defer zeroBytes(responsePayload)
	if len(responsePayload) > maxResponseBytes {
		return resp.StatusCode, errors.New("Agent response exceeds the 4 MiB limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, decodeAPIError(resp.StatusCode, responsePayload, resp.Header)
	}
	if responseBody == nil || len(bytes.TrimSpace(responsePayload)) == 0 {
		return resp.StatusCode, nil
	}
	if err := json.Unmarshal(responsePayload, responseBody); err != nil {
		return resp.StatusCode, fmt.Errorf("decode Agent response: %w", err)
	}
	return resp.StatusCode, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func decodeAPIError(statusCode int, payload []byte, headers http.Header) error {
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			Retryable bool   `json:"retryable"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return &Error{
			Message: http.StatusText(statusCode), StatusCode: statusCode,
			RetryAfter: parseRetryAfter(headers.Get("Retry-After"), time.Now()),
			RequestID:  headers.Get("X-Request-ID"),
		}
	}
	return &Error{
		Code:       safeErrorText(envelope.Error.Code, 128),
		Message:    safeErrorText(envelope.Error.Message, 512),
		StatusCode: statusCode,
		Retryable:  envelope.Error.Retryable,
		RetryAfter: parseRetryAfter(headers.Get("Retry-After"), time.Now()),
		RequestID:  headers.Get("X-Request-ID"),
	}
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	retryAt, err := http.ParseTime(value)
	if err != nil || !retryAt.After(now) {
		return 0
	}
	return retryAt.Sub(now)
}

func safeErrorText(value string, limit int) string {
	value = credentialShapedText.ReplaceAllString(value, "[REDACTED]")
	value = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, value)
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}
