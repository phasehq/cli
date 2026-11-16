// Package remoteapi defines public endpoint and authenticated manifest wire
// types shared by local-loopback and remote-TLS Phase AI proxy modes.
package remoteapi

import (
	"encoding/json"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

type Endpoint struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	TLS           bool   `json:"tls"`
	TLSServerName string `json:"tlsServerName"`
}

type ControlLinks struct {
	ListRequests          string `json:"listRequests"`
	CancelRequest         string `json:"cancelRequest"`
	ConnectionEnvironment string `json:"connectionEnvironment"`
	Connections           string `json:"connections"`
	Connection            string `json:"connection"`
	Capabilities          string `json:"capabilities"`
	Status                string `json:"status"`
	Context               string `json:"context"`
	CreateRequest         string `json:"createRequest"`
	PollRequest           string `json:"pollRequest"`
	Presets               string `json:"presets"`
	Hints                 string `json:"hints"`
}

type StatusConnection struct {
	ConnectionID       string `json:"connectionId"`
	Name               string `json:"name,omitempty"`
	CredentialID       string `json:"credentialId"`
	CredentialName     string `json:"credentialName,omitempty"`
	CredentialProvider string `json:"credentialProvider"`
	CredentialRevision string `json:"credentialRevision,omitempty"`
	ServiceType        string `json:"serviceType"`
	Protocol           string `json:"protocol"`
	State              string `json:"state"`
	// StateReason says why a Connection is not ready, for example
	// access_expired.
	StateReason string     `json:"stateReason,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	// GrantExpiresAt is when time-limited access to the Connection ends.
	GrantExpiresAt *time.Time `json:"grantExpiresAt,omitempty"`
}

type StatusResponse struct {
	SchemaVersion int                `json:"schemaVersion"`
	Kind          string             `json:"kind"`
	SafeToPrint   bool               `json:"safeToPrint"`
	Connections   []StatusConnection `json:"connections"`
	Links         ControlLinks       `json:"links"`
}

// ConnectionDetail is what an Agent may read about one of its Connections. It
// never carries a secret, a decoy, or a host the definition does not name.
type ConnectionDetail struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	ServiceType string `json:"serviceType"`
	// State is ready, expired or unavailable; StateReason says why a sealed
	// value could not be opened.
	State       string `json:"state"`
	StateReason string `json:"stateReason,omitempty"`
	// Definition, ValueRevision and KeyVersion describe a custom HTTP
	// Connection and are absent for packaged services.
	Definition    map[string]any `json:"definition,omitempty"`
	ValueRevision *int           `json:"valueRevision,omitempty"`
	KeyVersion    *int           `json:"keyVersion,omitempty"`
	// Policy is the access policy on this Workflow's grant, as the Console
	// sent it: rules, temporary allows and the managed secret guard.
	Policy *agentapi.AccessPolicy `json:"policy,omitempty"`
	// GrantExpiresAt is when time-limited access ends; ExpiredAt is when it
	// ended. Request is a complete body for POST /v1/requests that asks to
	// renew expired access.
	GrantExpiresAt *time.Time      `json:"grantExpiresAt,omitempty"`
	ExpiredAt      *time.Time      `json:"expiredAt,omitempty"`
	Request        json.RawMessage `json:"request,omitempty"`
}

// PresetsResponse lists the provider presets a Connection can be asked for by
// ID.
type PresetsResponse struct {
	SchemaVersion int               `json:"schemaVersion"`
	Kind          string            `json:"kind"`
	Presets       []agentapi.Preset `json:"presets"`
}

// Hint is one recent dead end and, where there is one, the request that asks
// a member to open it.
type Hint struct {
	Kind           string          `json:"kind"`
	Reason         string          `json:"reason"`
	Host           string          `json:"host,omitempty"`
	StatusCode     int             `json:"statusCode,omitempty"`
	Method         string          `json:"method,omitempty"`
	Path           string          `json:"path,omitempty"`
	Class          string          `json:"class,omitempty"`
	ConnectionID   string          `json:"connectionId,omitempty"`
	ConnectionName string          `json:"connectionName,omitempty"`
	Preset         string          `json:"preset,omitempty"`
	Service        string          `json:"service,omitempty"`
	Request        json.RawMessage `json:"request,omitempty"`
	Count          int             `json:"count"`
	FirstAt        time.Time       `json:"firstAt"`
	LatestAt       time.Time       `json:"latestAt"`
}

type HintsResponse struct {
	SchemaVersion int    `json:"schemaVersion"`
	Kind          string `json:"kind"`
	Hints         []Hint `json:"hints"`
}

type ConnectionsResponse struct {
	SchemaVersion int                `json:"schemaVersion"`
	Kind          string             `json:"kind"`
	Connections   []ConnectionDetail `json:"connections"`
}

type ConnectionResponse struct {
	SchemaVersion int    `json:"schemaVersion"`
	Kind          string `json:"kind"`
	ConnectionDetail
}

type ManifestResponse struct {
	SchemaVersion      int                               `json:"schemaVersion"`
	SessionUID         string                            `json:"sessionUid"`
	ConfigGeneration   int                               `json:"configGeneration"`
	Proxy              Endpoint                          `json:"proxy"`
	Postgres           *Endpoint                         `json:"postgres,omitempty"`
	CACertificatePEM   string                            `json:"caCertificatePem"`
	Links              ControlLinks                      `json:"links"`
	ProcessEnvironment phaseproxy.ProcessEnvironmentPlan `json:"processEnvironment"`
	Discover           agentapi.DiscoverResponse         `json:"discover"`
}
