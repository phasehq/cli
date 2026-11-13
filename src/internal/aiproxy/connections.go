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
// Console call. An empty id returns every Connection.
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
			ID:          connection.ConnectionID,
			Name:        connection.ConnectionName,
			ServiceType: connection.ServiceType,
			State:       candidate.printableState(now),
			StateReason: connection.MaterialFailure(),
		}
		if connection.ServiceType == agentapi.CustomHTTPServiceType {
			detail.Definition = connection.ConnectionConfig
			detail.KeyVersion, detail.ValueRevision = customConnectionVersions(connection)
		}
		details = append(details, detail)
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
	h.writeConnectionRead(w, remoteapi.ConnectionsResponse{
		SchemaVersion: agentapi.SchemaVersion,
		Kind:          "phase.ai.connections",
		Connections:   h.state.connectionDetails(time.Now(), ""),
	})
}

func (h *controlHandler) connection(w http.ResponseWriter, id string) {
	details := h.state.connectionDetails(time.Now(), id)
	if len(details) != 1 {
		writeControlError(w, http.StatusNotFound, "connection_unavailable", "The Connection is not part of this Workflow session.", false)
		return
	}
	h.writeConnectionRead(w, remoteapi.ConnectionResponse{
		SchemaVersion: agentapi.SchemaVersion, Kind: "phase.ai.connection", ConnectionDetail: details[0],
	})
}

// writeConnectionRead refuses to serve a projection that contains any live
// value, decoy or session credential. A definition holds none of them, so a
// hit means the payload is not what the contract says it is.
func (h *controlHandler) writeConnectionRead(w http.ResponseWriter, response any) {
	payload, err := json.Marshal(response)
	if err != nil || manifestPayloadContains(payload, h.state.eventSecrets()) {
		writeControlError(w, http.StatusBadGateway, "unsafe_connection_response", "The Connection data contained proxy-only material.", false)
		return
	}
	h.writeRelay(w, response, nil)
}
