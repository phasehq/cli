package aiproxy

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
)

// connectionDetails projects the session's Connections for an Agent to read.
// It is served from the configuration the proxy already holds, so it costs no
// Console call. An empty id returns every Connection. A Connection whose
// time-limited access has ended is listed as expired with the request that
// asks to renew it: one still in the configuration because no refresh has
// removed it yet, and those the Console lists as recently expired.
func (s *runtimeState) connectionDetails(now time.Time, id string) []remoteapi.ConnectionDetail {
	s.mu.RLock()
	defer s.mu.RUnlock()

	details := make([]remoteapi.ConnectionDetail, 0, len(s.bindings))
	for _, candidate := range s.bindings {
		connection := candidate.connection
		if id != "" && connection.ConnectionID != id {
			continue
		}
		detail := remoteapi.ConnectionDetail{
			ID:             connection.ConnectionID,
			Name:           connection.ConnectionName,
			ServiceType:    connection.ServiceType,
			State:          candidate.printableState(now),
			StateReason:    candidate.stateReason(now),
			Policy:         connection.Policy,
			GrantExpiresAt: connection.GrantExpiresAt,
		}
		if connection.ServiceType == agentapi.CustomHTTPServiceType {
			detail.Definition = connection.ConnectionConfig
			detail.KeyVersion, detail.ValueRevision = customConnectionVersions(connection)
		}
		if connection.GrantExpired(now) {
			detail.ExpiredAt = connection.GrantExpiresAt
			detail.Request = renewRequest(connection.ConnectionID, connection.ConnectionName)
		}
		details = append(details, detail)
	}
	for _, expired := range s.expired {
		if (id != "" && expired.ConnectionID != id) || !controlIdentifier.MatchString(expired.ConnectionID) {
			continue
		}
		// Access that was renewed since is live again and listed above.
		renewed := false
		for _, candidate := range s.bindings {
			renewed = renewed || candidate.connection.ConnectionID == expired.ConnectionID
		}
		if renewed {
			continue
		}
		expiredAt := expired.ExpiredAt
		details = append(details, remoteapi.ConnectionDetail{
			ID: expired.ConnectionID, Name: expired.ConnectionName, ServiceType: expired.ServiceType,
			State: "expired", StateReason: agentapi.AccessExpired, ExpiredAt: &expiredAt,
			Request: renewRequest(expired.ConnectionID, expired.ConnectionName),
		})
	}
	return details
}

// customConnectionVersions reads a custom Connection's counters from the
// session payload: credentialRevision is the value revision and
// materialGeneration is "<keyVersion>.<valueRevision>".
func customConnectionVersions(connection agentapi.Connection) (keyVersion, valueRevision *int) {
	positive := func(raw string) *int {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			return nil
		}
		return &value
	}
	rawKeyVersion, rawValueRevision, _ := strings.Cut(connection.MaterialGeneration, ".")
	keyVersion = positive(rawKeyVersion)
	if keyVersion == nil && connection.SealedMaterial != nil && connection.SealedMaterial.KeyVersion > 0 {
		version := connection.SealedMaterial.KeyVersion
		keyVersion = &version
	}
	if valueRevision = positive(connection.CredentialRevision); valueRevision == nil {
		valueRevision = positive(rawValueRevision)
	}
	return keyVersion, valueRevision
}

func (h *controlHandler) connections(w http.ResponseWriter) {
	details := h.state.connectionDetails(time.Now(), "")
	h.writeConnectionRead(w, remoteapi.ConnectionsResponse{
		SchemaVersion: agentapi.SchemaVersion,
		Kind:          "phase.ai.connections",
		Connections:   details,
	}, details)
}

func (h *controlHandler) connection(w http.ResponseWriter, id string) {
	details := h.state.connectionDetails(time.Now(), id)
	if len(details) != 1 {
		writeControlError(w, http.StatusNotFound, "connection_unavailable", "The Connection is not part of this Workflow session.", false)
		return
	}
	h.writeConnectionRead(w, remoteapi.ConnectionResponse{
		SchemaVersion: agentapi.SchemaVersion, Kind: "phase.ai.connection", ConnectionDetail: details[0],
	}, details)
}

// writeConnectionRead refuses to serve a projection that contains a decoy, a
// session credential or a packaged Connection's live value anywhere, or a
// custom Connection's live value in what the Console said about that
// Connection. A definition holds none of them, so a hit means the payload is
// not what the contract says it is. A custom value is a member's choice and is
// compared only with its own Connection's description: one that reads like an
// ordinary word must not cost every other Connection its read.
func (h *controlHandler) writeConnectionRead(w http.ResponseWriter, response any, details []remoteapi.ConnectionDetail) {
	payload, err := json.Marshal(response)
	if err != nil || manifestPayloadContains(payload, h.state.readTripwireSecrets()) ||
		detailsCarryOwnValue(details, h.state.customLiveValues()) {
		writeControlError(w, http.StatusBadGateway, "unsafe_connection_response", "The Connection data contained proxy-only material.", false)
		return
	}
	h.writeRelay(w, response, nil)
}

// detailsCarryOwnValue reports whether a custom Connection's name, definition
// or policy, as it would be served, contains that Connection's own live value.
func detailsCarryOwnValue(details []remoteapi.ConnectionDetail, custom map[string][]string) bool {
	for _, detail := range details {
		own := custom[detail.ID]
		if len(own) == 0 {
			continue
		}
		described, err := json.Marshal([]any{detail.Name, detail.Definition, detail.Policy})
		if err != nil || manifestPayloadContains(described, own) {
			return true
		}
	}
	return false
}
