package agentsdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// RequestActionType names the change a request proposes. A member reviews and
// applies it in the Console; an Agent never changes anything directly.
type RequestActionType string

const (
	RequestActionVersion = 1

	ActionConnectionCreate       RequestActionType = "agent_connection.create"
	ActionConnectionUpdate       RequestActionType = "agent_connection.update"
	ActionConnectionSecretUpdate RequestActionType = "agent_connection.secret_update"
	ActionConnectionRemove       RequestActionType = "agent_connection.remove"

	// CustomHTTPServiceType is the service type of a member-defined HTTP
	// Connection.
	CustomHTTPServiceType = "http"

	maxRequestTitleLength = 120
)

// requestActionKinds is the action registry: every action type this client
// forwards and the request kind it travels under. An action is otherwise
// opaque, so a member the Console adds later is forwarded without a release.
var requestActionKinds = map[RequestActionType]RequestKind{
	ActionConnectionCreate:       RequestSetup,
	ActionConnectionUpdate:       RequestConnectionUpdate,
	ActionConnectionSecretUpdate: RequestCredentialUpdate,
	ActionConnectionRemove:       RequestConnectionRemoval,
}

// NormalizeRequestAction maps an absent or JSON null action to nil so callers
// can treat both as a request without an action.
func NormalizeRequestAction(action json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(action)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	return action
}

// ValidateRequestAction checks the only things a client decides about an
// action: its type is known, its version is 1, it arrived under the request
// kind that type uses, and it carries no secret value. Every other member is
// the Console's to validate and is passed through unchanged.
func ValidateRequestAction(kind RequestKind, action json.RawMessage) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(action, &members); err != nil || members == nil {
		return fmt.Errorf("agents: the request action must be a JSON object")
	}
	var actionType string
	if err := json.Unmarshal(members["type"], &actionType); err != nil {
		return fmt.Errorf("agents: unsupported request action type")
	}
	wantKind, known := requestActionKinds[RequestActionType(actionType)]
	if !known {
		return fmt.Errorf("agents: unsupported request action type")
	}
	var version int
	if err := json.Unmarshal(members["version"], &version); err != nil || version != RequestActionVersion {
		return fmt.Errorf("agents: unsupported request action version")
	}
	if kind != wantKind {
		return fmt.Errorf("agents: action %s requires request kind %s", actionType, wantKind)
	}
	return validateActionCarriesNoSecret(members)
}

var errActionCarriesSecret = fmt.Errorf("agents: a request action must not carry a secret value; a member enters it in the Console")

// validateActionCarriesNoSecret refuses the places a secret value could be
// written into an action: a value member on the action itself, and a value on
// any definition field that is not an identifier. A definition it cannot
// inspect is refused, because nothing can then be said about it.
func validateActionCarriesNoSecret(members map[string]json.RawMessage) error {
	if _, present := members["value"]; present {
		return errActionCarriesSecret
	}
	rawDefinition, present := members["definition"]
	if !present {
		return nil
	}
	var definition map[string]json.RawMessage
	if err := json.Unmarshal(rawDefinition, &definition); err != nil || definition == nil {
		return fmt.Errorf("agents: the proposed definition must be a JSON object")
	}
	rawFields, present := definition["fields"]
	if !present {
		return nil
	}
	var fields []map[string]json.RawMessage
	if err := json.Unmarshal(rawFields, &fields); err != nil {
		return fmt.Errorf("agents: the proposed definition has invalid fields")
	}
	for _, field := range fields {
		if _, carriesValue := field["value"]; carriesValue {
			var kind string
			if err := json.Unmarshal(field["kind"], &kind); err != nil || kind != "identifier" {
				return errActionCarriesSecret
			}
		}
		for name, member := range field {
			if name != "value" && containsValueMember(member) {
				return errActionCarriesSecret
			}
		}
	}
	return nil
}

// containsValueMember reports whether any object nested in raw has a member
// named value, such as a value slipped into a secret field's source.
func containsValueMember(raw json.RawMessage) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err == nil && object != nil {
		if _, present := object["value"]; present {
			return true
		}
		for _, member := range object {
			if containsValueMember(member) {
				return true
			}
		}
		return false
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err == nil {
		for _, member := range list {
			if containsValueMember(member) {
				return true
			}
		}
	}
	return false
}

// ValidRequestTitle reports whether a title is absent or short plain text.
func ValidRequestTitle(title string) bool {
	return title == strings.TrimSpace(title) && utf8.RuneCountInString(title) <= maxRequestTitleLength &&
		strings.IndexFunc(title, unicode.IsControl) < 0
}
