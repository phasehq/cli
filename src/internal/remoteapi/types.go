// Package remoteapi defines public endpoint and authenticated manifest wire
// types served by the local Phase AI proxy.
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
	AppScope
}

// AppScope describes an app Connection (serviceType phase_app): the app, the
// environments it covers and what this Workflow may do in them now. Secrets
// calls go to the Console with the Agent token, never through the proxy.
type AppScope struct {
	App          *agentapi.AppRef          `json:"app,omitempty"`
	Environments []agentapi.AppEnvironment `json:"environments,omitempty"`
	Access       agentapi.AppAccess        `json:"access,omitempty"`
}

type StatusResponse struct {
	SchemaVersion int                `json:"schemaVersion"`
	Kind          string             `json:"kind"`
	SafeToPrint   bool               `json:"safeToPrint"`
	Connections   []StatusConnection `json:"connections"`
	Links         ControlLinks       `json:"links"`
	// LeakProtection is what the proxy does with model traffic: counts and
	// host names only.
	LeakProtection *LeakProtectionStatus `json:"leakProtection,omitempty"`
}

// InventoryKeyRequest is POST /v1/inventory/key: who the registering command
// is, as phaseproxy.NewInventoryIdentity writes it. Empty, it is nobody's.
type InventoryKeyRequest struct {
	SchemaVersion int    `json:"schemaVersion"`
	Tenant        string `json:"tenant,omitempty"`
	Login         string `json:"login,omitempty"`
}

// InventoryKeyResponse answers /v1/inventory/key: what a command indexes
// values with. Format is the version of the entries the proxy reads.
type InventoryKeyResponse struct {
	SchemaVersion int `json:"schemaVersion"`
	// Key is the lookup key: the proxy's tenant's for a command that states
	// the proxy's own login, and one of this proxy process alone for any other.
	Key string `json:"key"`
	// ConfirmKey is the proxy's own login's confirming key for such a command,
	// and a guest's of this process for any other. Scheme 1 alone sends none.
	ConfirmKey string `json:"confirmKey,omitempty"`
	Format     int    `json:"format"`
	// KeyID names the two keys without giving either: a registration sends
	// it back.
	KeyID string `json:"keyId,omitempty"`
}

// InventoryRequest is POST /v1/inventory: entries built by censor.IndexValue
// with the key the proxy handed the command. Keyed hashes, never a value.
type InventoryRequest struct {
	SchemaVersion int               `json:"schemaVersion"`
	Entries       []json.RawMessage `json:"entries"`
	// Tenant and Login say who the registering command is, as in
	// InventoryKeyRequest, and KeyID which keys its entries were made under.
	Tenant string `json:"tenant,omitempty"`
	Login  string `json:"login,omitempty"`
	KeyID  string `json:"keyId,omitempty"`
	// IDKinds says, entry by entry, what each entry's id is: InventoryIDPhase
	// or InventoryIDKeyName. The client knows which it sent; the proxy never
	// guesses from the id's shape. Absent, every id is taken for a key name.
	IDKinds []string `json:"idKinds,omitempty"`
}

const (
	// InventoryIDPhase is an id the Console issued, such as a secret's id or
	// a lease's id.
	InventoryIDPhase = "phase_id"
	// InventoryIDKeyName is a secret's key name. The Console does not know
	// the key names of an end-to-end encrypted app, so the proxy keeps such
	// an id out of the events it sends.
	InventoryIDKeyName = "key_name"
)

// InventoryResponse counts the values a registration protected and those it
// could not.
type InventoryResponse struct {
	SchemaVersion int `json:"schemaVersion"`
	Added         int `json:"added"`
	Unprotected   int `json:"unprotected"`
}

// LeakProtectionStatus describes the proxy's leak protection. It never names a
// value, a secret's id or anything derived from a value.
type LeakProtectionStatus struct {
	Mode           string   `json:"mode"`
	SecretsKnown   int      `json:"secretsKnown"`
	Unprotected    int      `json:"unprotected"`
	InspectedHosts []string `json:"inspectedHosts"`
	UnreadHosts    []string `json:"unreadHosts"`
	// UnreadReasons says why a host the proxy's table reads is listed under
	// UnreadHosts at this moment: tls_refused while its client's pass-through
	// window is open or a connection opened in one still is, and the reason a
	// connection to it was handed to the service unread, while that
	// connection is open and for a minute after it was opened. It is absent
	// when every such host is being read.
	UnreadReasons map[string][]string `json:"unreadReasons,omitempty"`
	// MirroredHosts counts how the connections went to each host that is sent
	// a copy of its client's TLS hello.
	MirroredHosts []MirroredHostStatus `json:"mirroredHosts,omitempty"`
	// RulesSkipped counts the pattern rules the proxy is not applying: rules
	// of its rule file that this version cannot apply, and rules it depends
	// on that the file does not hold. SkippedRules names them by rule id.
	// Both are absent when every rule applies, as with the shipped file.
	RulesSkipped int      `json:"rulesSkipped,omitempty"`
	SkippedRules []string `json:"skippedRules,omitempty"`
	// Inventory says whether the values the proxy knows outlive it.
	Inventory *LeakInventoryStatus `json:"inventory,omitempty"`
}

// Where the leak protection inventory is kept.
const (
	// LeakInventoryStored: the key is in the system keystore and the entries
	// in a file, so a proxy that starts again knows the same values.
	LeakInventoryStored = "stored"
	// LeakInventoryMemory: the inventory goes with the proxy process.
	LeakInventoryMemory = "memory"
)

// LeakInventoryStatus describes how the leak protection inventory is kept:
// counts and a reason, never an entry, a hash or an id.
type LeakInventoryStatus struct {
	// Storage is LeakInventoryStored or LeakInventoryMemory.
	Storage string `json:"storage"`
	// Reason says why the inventory is in memory only: no_keystore,
	// key_unreadable, key_replaced, newer_store_format, store_unreadable,
	// store_busy, store_unusable, no_tenant or not_configured.
	Reason string `json:"reason,omitempty"`
	// Loaded counts the values the proxy knew from the store when it started.
	Loaded int `json:"loaded"`
	// NotLoaded counts stored entries left out at start to leave the index
	// room: each login's registered longest ago. They stay in the store.
	NotLoaded int `json:"notLoaded"`
	// UnmatchedScheme counts stored entries this version cannot match,
	// because they were made by a version that matches differently. They are
	// kept, and matched again once a command reads their value.
	UnmatchedScheme int `json:"unmatchedScheme"`
	// UnmatchedKey counts stored entries made under a key that has since been
	// replaced. They are never matched and have been dropped.
	UnmatchedKey int `json:"unmatchedKey"`
	// OtherTenants counts stored records of other hosts or organisations.
	// They are never opened or matched: this is all a session learns of them.
	OtherTenants int `json:"otherTenants,omitempty"`
	// Unstored counts registrations from commands that are not of the proxy's
	// own login: kept until the proxy exits, counted whatever they held.
	Unstored int `json:"unstored,omitempty"`
	// Dropped counts records of the proxy's own login that a bound of the
	// store dropped when this proxy wrote: they are not stored.
	Dropped int `json:"dropped,omitempty"`
	// Damaged counts stored entries that could not be read.
	Damaged int `json:"damaged,omitempty"`
}

// MirroredHostStatus counts, since the proxy process started, the client
// connections to one host that answers only its own client's TLS.
type MirroredHostStatus struct {
	Host string `json:"host"`
	// Copied is how many were opened with a copy of the client's hello and
	// read.
	Copied int `json:"copied"`
	// Rebuilt is how many times the hello sent was rebuilt from one that
	// offered a session, because that client had not been seen without one.
	// Such a hello can differ from the client's own in its padding. It is
	// counted whether or not the service took it.
	Rebuilt int `json:"rebuilt"`
	// PassedThrough is how many were handed to the service unread, by reason.
	PassedThrough map[string]int `json:"passedThrough,omitempty"`
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
	AppScope
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
