package agentsdk

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// ErrorResponse is the canonical error envelope returned by the Agent API.
type ErrorResponse struct {
	Error ErrorPayload `json:"error"`
}

type ErrorPayload struct {
	Code      string          `json:"code"`
	Message   string          `json:"message"`
	Retryable bool            `json:"retryable"`
	Details   json.RawMessage `json:"details"`
}

// APIError is returned for every non-2xx response. Raw response bodies are not
// retained. Details is structured canonical JSON and is excluded from fmt
// output to avoid accidental disclosure by logging an error value.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	Retryable  bool
	Details    json.RawMessage
	RetryAfter time.Duration
	RequestID  string
}

func (e *APIError) Error() string {
	if e.Code != "" && e.Message != "" {
		return fmt.Sprintf("agents: request failed (HTTP %d, %s): %s", e.StatusCode, e.Code, e.Message)
	}
	if e.Message != "" {
		return fmt.Sprintf("agents: request failed (HTTP %d): %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("agents: request failed with HTTP %d", e.StatusCode)
}

func (e *APIError) String() string   { return e.Error() }
func (e *APIError) GoString() string { return e.Error() }
func (e *APIError) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.Error())
}

type ResponseTooLargeError struct {
	Limit int64
}

func (e *ResponseTooLargeError) Error() string {
	return fmt.Sprintf("agents: response exceeds %d-byte limit", e.Limit)
}
