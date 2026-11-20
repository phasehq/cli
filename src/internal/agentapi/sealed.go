package agentapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/phasehq/golang-sdk/v2/phase/crypto"
)

const sealedMaterialVersion = 1

// Reasons a sealed Connection value could not be opened. They name the failed
// step only and are safe to print.
const (
	SealedFailureAgentKey      = "sealed_material_agent_key_unavailable"
	SealedFailureLanes         = "sealed_material_conflicting_lanes"
	SealedFailureVersion       = "sealed_material_unsupported_version"
	SealedFailureConnectionKey = "sealed_material_key_unreadable"
	SealedFailureValue         = "sealed_material_value_unreadable"
	SealedFailureHostMismatch  = "sealed_material_host_mismatch"
	SealedFailureFieldMissing  = "sealed_material_field_missing"
	SealedFailureUnopened      = "sealed_material_unopened"
	// MaterialFailureMissing: the payload carried the value on neither lane.
	MaterialFailureMissing = "material_missing"
	// MaterialFailureExposed: the value also appears inside something the
	// Agent can see, so the client withheld it.
	MaterialFailureExposed = "material_exposed"
)

// SealedMaterial is a Connection's value encrypted to that Connection's own
// keypair, with the Agent's copy of the Connection private key. The client
// opens it in memory; see Client.openSealedMaterial.
type SealedMaterial struct {
	Version    int             `json:"version"`
	KeyVersion int             `json:"keyVersion"`
	PublicKey  string          `json:"publicKey"`
	Ciphertext SensitiveString `json:"ciphertext"`
	WrappedKey SensitiveString `json:"wrappedKey"`

	opened  bool
	failure string
}

func (s SealedMaterial) String() string   { return "[REDACTED]" }
func (s SealedMaterial) GoString() string { return "[REDACTED]" }

// MaterialUnavailable reports whether the Connection's value arrived sealed
// and was not opened, or, for a custom HTTP Connection, did not arrive on
// either lane. Its secret material is then incomplete, so the proxy blocks
// requests to it as credential material unavailable; nothing else about the
// session is affected.
func (c Connection) MaterialUnavailable() bool {
	return c.MaterialFailure() != ""
}

// MaterialFailure names why the Connection's value is unavailable, or is
// empty when it is usable.
func (c Connection) MaterialFailure() string {
	if c.materialFailure != "" {
		return c.materialFailure
	}
	if c.SealedMaterial != nil {
		switch {
		case c.SealedMaterial.opened:
			return ""
		case c.SealedMaterial.failure == "":
			return SealedFailureUnopened
		}
		return c.SealedMaterial.failure
	}
	if c.ServiceType != CustomHTTPServiceType {
		return ""
	}
	for _, field := range sealedFieldNames(c) {
		if live, status := c.SecretMaterial.Resolve(field); status != MaterialFound || live == "" {
			return MaterialFailureMissing
		}
	}
	return ""
}

// agentKeyShares is what a key-bearing Agent token contributes to rebuilding
// the Agent's key exchange private key. The other share comes from the
// server, wrapped with wrapKey, so neither side can rebuild the key alone.
type agentKeyShares struct {
	kxPublicKey string
	shareA      string
	wrapKey     string
}

func (agentKeyShares) String() string   { return "[REDACTED]" }
func (agentKeyShares) GoString() string { return "[REDACTED]" }

func agentKeySharesFromToken(tokenType TokenType, token string) *agentKeyShares {
	if tokenType != TokenAgent {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(token), ":")
	if len(parts) != 6 || parts[0] != "pss_agent" || parts[1] != "v1" {
		return nil
	}
	return &agentKeyShares{kxPublicKey: parts[3], shareA: parts[4], wrapKey: parts[5]}
}

func (s *agentKeyShares) privateKey(wrappedKeyShare string) (string, error) {
	wrapped, err := hex.DecodeString(wrappedKeyShare)
	if err != nil {
		return "", errors.New("the Agent key share is invalid")
	}
	wrapKeyBytes, err := hex.DecodeString(s.wrapKey)
	if err != nil || len(wrapKeyBytes) != 32 {
		return "", errors.New("the Agent token's wrap key is invalid")
	}
	var wrapKey [32]byte
	copy(wrapKey[:], wrapKeyBytes)
	crypto.ZeroBytes(wrapKeyBytes)
	defer crypto.ZeroBytes(wrapKey[:])
	shareB, err := crypto.DecryptRaw(wrapped, wrapKey)
	if err != nil {
		return "", errors.New("the Agent key share could not be opened with this token")
	}
	defer crypto.ZeroBytes(shareB)
	return crypto.ReconstructSecret(s.shareA, string(shareB))
}

// CanOpenSealedMaterial reports whether this client was built from an Agent
// token, the only credential the Agent key can be rebuilt from. It decides
// whether the sealed_material feature is advertised.
func (c *Client) CanOpenSealedMaterial() bool {
	return c != nil && c.agentKey != nil
}

// prepareMaterial runs on every session payload, at open and on each refresh,
// before anything else reads it: sealed values are opened, then any custom
// Connection value that would leak into the Agent's view is withheld.
func (c *Client) prepareMaterial(config *SessionConfig) {
	if config == nil {
		return
	}
	c.openSealedMaterial(config)
	withholdExposedCustomMaterial(config)
}

// openSealedMaterial opens every sealed Connection value in a session payload
// and puts the result where the resolved lane puts it, so the rest of the
// runtime treats both lanes alike. Keys and plaintext stay in memory. A value
// that cannot be opened leaves only that Connection without material.
func (c *Client) openSealedMaterial(config *SessionConfig) {
	if config.AgentKey != nil {
		if share := config.AgentKey.WrappedKeyShare; share.Reveal() != "" {
			c.sessionMu.Lock()
			c.wrappedKeyShare = share
			c.sessionMu.Unlock()
		}
		config.AgentKey = nil
	}
	agentPrivateKey, keyFailure, rebuilt := "", "", false
	for index := range config.Connections {
		connection := &config.Connections[index]
		if connection.SealedMaterial == nil {
			continue
		}
		if !rebuilt {
			agentPrivateKey, keyFailure = c.rebuildAgentKey()
			rebuilt = true
		}
		failure := keyFailure
		if failure == "" {
			failure = openSealedConnection(connection, agentPrivateKey, c.agentKey.kxPublicKey)
		}
		sealed := connection.SealedMaterial
		sealed.Ciphertext, sealed.WrappedKey = "", ""
		sealed.opened, sealed.failure = failure == "", failure
		if failure != "" {
			connection.SecretMaterial.Destroy()
			connection.SecretMaterial = SecretMaterial{}
		}
	}
}

func (c *Client) rebuildAgentKey() (string, string) {
	if c.agentKey == nil {
		return "", SealedFailureAgentKey
	}
	c.sessionMu.RLock()
	wrapped := c.wrappedKeyShare.Reveal()
	c.sessionMu.RUnlock()
	if wrapped == "" {
		return "", SealedFailureAgentKey
	}
	privateKey, err := c.agentKey.privateKey(wrapped)
	if err != nil {
		return "", SealedFailureAgentKey
	}
	return privateKey, ""
}

// sealedValue is the plaintext a member's browser sealed to the Connection
// key. The hosts are bound inside it so a value entered for one set of hosts
// cannot be routed to another.
type sealedValue struct {
	Version int               `json:"v"`
	Hosts   []sealedHost      `json:"hosts"`
	Fields  map[string]string `json:"fields"`
}

type sealedHost struct {
	Match string `json:"match"`
	Value string `json:"value"`
	Port  int    `json:"port"`
}

// openSealedConnection returns an empty string on success, otherwise the
// reason the value was refused.
func openSealedConnection(connection *Connection, agentPrivateKey, agentPublicKey string) string {
	sealed := connection.SealedMaterial
	// A payload carries exactly one lane.
	if len(connection.SecretMaterial.values) != 0 {
		return SealedFailureLanes
	}
	if sealed.Version != sealedMaterialVersion {
		return SealedFailureVersion
	}
	connectionPrivateKey, err := crypto.DecryptAsymmetric(sealed.WrappedKey.Reveal(), agentPrivateKey, agentPublicKey)
	if err != nil {
		return SealedFailureConnectionKey
	}
	plaintext, err := crypto.DecryptAsymmetric(sealed.Ciphertext.Reveal(), connectionPrivateKey, sealed.PublicKey)
	if err != nil {
		return SealedFailureValue
	}
	var value sealedValue
	decoder := json.NewDecoder(strings.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return SealedFailureValue
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return SealedFailureValue
	}
	if value.Version != sealedMaterialVersion {
		return SealedFailureVersion
	}
	if !sameBoundHosts(connection.Hosts, value.Hosts) {
		return SealedFailureHostMismatch
	}
	for _, field := range sealedFieldNames(*connection) {
		if live, status := ResolveMaterial(value.Fields, field); status != MaterialFound || live == "" {
			return SealedFailureFieldMissing
		}
	}
	connection.SecretMaterial = SecretMaterial{values: value.Fields}
	return ""
}

type boundHost struct {
	match string
	value string
	port  int
}

func reduceBoundHost(match, value string, port int) boundHost {
	return boundHost{match: match, value: strings.TrimRight(strings.ToLower(strings.TrimSpace(value)), "."), port: port}
}

// sameBoundHosts compares the routed hosts with the hosts the value was sealed
// for, as sets of match, host and port. Paths are deliberately not bound.
func sameBoundHosts(routed []HostRule, sealed []sealedHost) bool {
	routedSet := make(map[boundHost]struct{}, len(routed))
	for _, rule := range routed {
		routedSet[reduceBoundHost(rule.Match, rule.Value, rule.Port)] = struct{}{}
	}
	sealedSet := make(map[boundHost]struct{}, len(sealed))
	for _, host := range sealed {
		sealedSet[reduceBoundHost(host.Match, host.Value, host.Port)] = struct{}{}
	}
	if len(routedSet) == 0 || len(routedSet) != len(sealedSet) {
		return false
	}
	for host := range routedSet {
		if _, bound := sealedSet[host]; !bound {
			return false
		}
	}
	return true
}

// sealedFieldNames lists the secret fields the Connection's injections read,
// which is what either lane has to supply.
func sealedFieldNames(connection Connection) []string {
	names := make([]string, 0)
	for _, injection := range connection.EffectiveInjections() {
		if injection.ValueFrom.Source != "credential" {
			continue
		}
		if injection.ValueFrom.Field != "" {
			names = append(names, injection.ValueFrom.Field)
		}
		if password, status := ResolveMaterial(injection.ValueFrom.Fields, "password"); status == MaterialFound && password != "" {
			names = append(names, password)
		}
	}
	return names
}
