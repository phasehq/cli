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
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
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

// maxInventoryKeyBody bounds a key request: two short strings.
const maxInventoryKeyBody = 4096

const invalidInventoryKeyMessage = "The key request must be {\"schemaVersion\":1} with, when the command knows them, its tenant and login."

// inventoryKey hands a command the keys it indexes with, by who it says it
// is (leakGuard.place): never the master, never a stored tenant's to another's.
func (h *controlHandler) inventoryKey(w http.ResponseWriter, req *http.Request) {
	if h.leak == nil {
		writeControlError(w, http.StatusServiceUnavailable, "leak_protection_unavailable", "Leak protection is not running in this proxy.", false)
		return
	}
	// A GET states nothing: the command is nobody's.
	var stated phaseproxy.InventoryIdentity
	if req.Method == http.MethodPost {
		if !controlJSONContentType(req) {
			writeControlError(w, http.StatusUnsupportedMediaType, "invalid_control_content_type", "The request Content-Type must be application/json.", false)
			return
		}
		var request remoteapi.InventoryKeyRequest
		decoder := json.NewDecoder(io.LimitReader(req.Body, maxInventoryKeyBody))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.SchemaVersion != agentapi.SchemaVersion {
			writeControlError(w, http.StatusBadRequest, "invalid_inventory", invalidInventoryKeyMessage, false)
			return
		}
		stated = phaseproxy.InventoryIdentity{Tenant: request.Tenant, Login: request.Login}
	}
	place, err := h.leak.place(stated)
	if err != nil {
		writeControlError(w, http.StatusServiceUnavailable, "leak_protection_unavailable", "Leak protection could not make a key.", false)
		return
	}
	h.writeForward(w, remoteapi.InventoryKeyResponse{
		SchemaVersion: agentapi.SchemaVersion, Format: censor.EntriesVersion,
		Key:        base64.StdEncoding.EncodeToString(place.key.LookupBytes()),
		ConfirmKey: base64.StdEncoding.EncodeToString(place.key.ConfirmBytes()),
		KeyID:      place.keyID(),
	}, nil)
}

const invalidInventoryMessage = "The inventory must be {\"schemaVersion\":1,\"entries\":[...]} with at most 4096 entries; idKinds, when sent, says phase_id or key_name for each entry; tenant, login and keyId are as the key route took and gave them."

// inventoryKeyNamed reads what a registration says of its ids: for each
// entry, whether the id is a secret's key name. The client says so; nothing
// is guessed from an id's shape. A registration that does not say is taken to
// hold key names throughout, so an id it sent never reaches an event.
func inventoryKeyNamed(kinds []string, entries int) ([]bool, bool) {
	keyNamed := make([]bool, entries)
	if len(kinds) == 0 {
		for i := range keyNamed {
			keyNamed[i] = true
		}
		return keyNamed, true
	}
	if len(kinds) != entries {
		return nil, false
	}
	for i, kind := range kinds {
		switch kind {
		case remoteapi.InventoryIDPhase:
		case remoteapi.InventoryIDKeyName:
			keyNamed[i] = true
		default:
			return nil, false
		}
	}
	return keyNamed, true
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
		writeControlError(w, http.StatusBadRequest, "invalid_inventory", invalidInventoryMessage, false)
		return
	}
	keyNamed, ok := inventoryKeyNamed(request.IDKinds, len(request.Entries))
	if !ok {
		writeControlError(w, http.StatusBadRequest, "invalid_inventory", invalidInventoryMessage, false)
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
	// Where the entries go is decided here, from what this request states,
	// and never from what an earlier one did.
	place, err := h.leak.place(phaseproxy.InventoryIdentity{Tenant: request.Tenant, Login: request.Login})
	if err != nil {
		writeControlError(w, http.StatusServiceUnavailable, "leak_protection_unavailable", "Leak protection could not make a key.", false)
		return
	}
	// Entries made under other keys than this place's would be held and
	// never matched: the command fetches the key again.
	if request.KeyID != "" && request.KeyID != place.keyID() {
		writeControlError(w, http.StatusConflict, "inventory_key_changed", "The entries were made under a key this proxy does not use for this command. Fetch the key again and register again.", true)
		return
	}
	added, unprotected, err := h.leak.addAt(place, entries, keyNamed)
	switch {
	case errors.Is(err, errLeakInventoryFull):
		writeControlError(w, http.StatusInsufficientStorage, "leak_inventory_full", "The leak protection inventory has no room for more values from this login. A proxy that starts again has room: it starts with the values registered most recently.", false)
		return
	case err != nil:
		writeControlError(w, http.StatusBadRequest, "invalid_inventory", "An inventory entry is not valid.", false)
		return
	}
	h.writeForward(w, remoteapi.InventoryResponse{SchemaVersion: agentapi.SchemaVersion, Added: added, Unprotected: unprotected}, nil)
}
