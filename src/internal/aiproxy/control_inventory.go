package aiproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
)

const (
	// maxInventoryBodyBytes bounds one registration. The CLI splits a larger
	// set of values over several.
	maxInventoryBodyBytes = 4 << 20
	// maxInventoryEntries bounds the values in one registration.
	maxInventoryEntries = 4096
)

func (h *controlHandler) leakStatus() *remoteapi.LeakProtectionStatus {
	if h.leak == nil {
		return nil
	}
	return h.leak.status()
}

// inventoryKey hands the key to a process of this session that is about to
// index values it decrypted. That process already holds the plaintext.
func (h *controlHandler) inventoryKey(w http.ResponseWriter) {
	if h.leak == nil {
		writeControlError(w, http.StatusServiceUnavailable, "leak_protection_unavailable", "Leak protection is not running in this proxy.", false)
		return
	}
	h.writeForward(w, remoteapi.InventoryKeyResponse{
		SchemaVersion: agentapi.SchemaVersion, Key: base64.StdEncoding.EncodeToString(h.leak.key.Bytes()), Format: censor.EntriesVersion,
	}, nil)
}

// addInventory takes entries from any process that holds the proxy
// capability, the Agent's included, so everything in them is checked as
// untrusted input. Nothing about the entries is logged or echoed back.
func (h *controlHandler) addInventory(w http.ResponseWriter, req *http.Request) {
	if h.leak == nil {
		writeControlError(w, http.StatusServiceUnavailable, "leak_protection_unavailable", "Leak protection is not running in this proxy.", false)
		return
	}
	if !controlJSONContentType(req) {
		writeControlError(w, http.StatusUnsupportedMediaType, "invalid_control_content_type", "The request Content-Type must be application/json.", false)
		return
	}
	payload, err := io.ReadAll(io.LimitReader(req.Body, maxInventoryBodyBytes+1))
	if err != nil {
		writeControlError(w, http.StatusBadRequest, "invalid_inventory", "The inventory body could not be read.", false)
		return
	}
	if len(payload) > maxInventoryBodyBytes {
		writeControlError(w, http.StatusRequestEntityTooLarge, "inventory_too_large", "An inventory registration must not exceed 4 MiB; send the entries in several.", false)
		return
	}
	var request remoteapi.InventoryRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		request.SchemaVersion != agentapi.SchemaVersion || len(request.Entries) > maxInventoryEntries {
		writeControlError(w, http.StatusBadRequest, "invalid_inventory", "The inventory must be {\"schemaVersion\":1,\"entries\":[...]} with at most 4096 entries.", false)
		return
	}
	entries := make([]*censor.Entries, 0, len(request.Entries))
	for _, raw := range request.Entries {
		entry, err := censor.ParseEntries(raw)
		if err != nil {
			writeControlError(w, http.StatusBadRequest, "invalid_inventory", "An inventory entry is not valid.", false)
			return
		}
		entries = append(entries, entry)
	}
	added, unprotected, err := h.leak.add(entries)
	switch {
	case errors.Is(err, errLeakInventoryFull):
		writeControlError(w, http.StatusInsufficientStorage, "leak_inventory_full", "The leak protection inventory is full: this proxy cannot protect more values. Restart the Phase AI session to start a new inventory.", false)
		return
	case err != nil:
		writeControlError(w, http.StatusBadRequest, "invalid_inventory", "An inventory entry is not valid.", false)
		return
	}
	h.writeForward(w, remoteapi.InventoryResponse{SchemaVersion: agentapi.SchemaVersion, Added: added, Unprotected: unprotected}, nil)
}
