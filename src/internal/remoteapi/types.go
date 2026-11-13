// Package remoteapi defines public endpoint and authenticated manifest wire
// types shared by local-loopback and remote-TLS Phase AI proxy modes.
package remoteapi

import (
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
}

type StatusConnection struct {
	ConnectionID       string     `json:"connectionId"`
	Name               string     `json:"name,omitempty"`
	CredentialID       string     `json:"credentialId"`
	CredentialName     string     `json:"credentialName,omitempty"`
	CredentialProvider string     `json:"credentialProvider"`
	CredentialRevision string     `json:"credentialRevision,omitempty"`
	ServiceType        string     `json:"serviceType"`
	Protocol           string     `json:"protocol"`
	State              string     `json:"state"`
	ExpiresAt          *time.Time `json:"expiresAt,omitempty"`
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
