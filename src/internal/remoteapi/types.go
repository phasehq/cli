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
