package agentsdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// RequestActionType names the change a request asks for. A member reviews and
// applies it in the Console; an Agent never changes anything directly.
type RequestActionType string

const (
	RequestActionVersion = 1

	ActionConnectionCreate       RequestActionType = "agent_connection.create"
	ActionConnectionUpdate       RequestActionType = "agent_connection.update"
	ActionConnectionSecretUpdate RequestActionType = "agent_connection.secret_update"
	ActionConnectionRemove       RequestActionType = "agent_connection.remove"
	// ActionConnectionAppAccess asks for access to an app's secrets in some
	// of its environments, through an app Connection.
	ActionConnectionAppAccess RequestActionType = "agent_connection.app_access"
	// ActionGrantAllow asks to allow, for a limited time, a call the access
	// policy asks about. ActionGrantRenew asks to renew time-limited access.
	ActionGrantAllow RequestActionType = "agent_grant.allow"
	ActionGrantRenew RequestActionType = "agent_grant.renew"
	// ActionWorkflowContextUpdate asks to replace the Workflow's saved context.
	ActionWorkflowContextUpdate RequestActionType = "agent_workflow.context_update"

	// CustomHTTPServiceType is the service type of a member-defined HTTP
	// Connection.
	CustomHTTPServiceType = "http"

	maxRequestTitleLength = 120
	// MaxWorkflowContextLength is the most characters a Workflow's saved
	// context may hold.
	MaxWorkflowContextLength = 16384
	maxPresetIDLength        = 64
	// maxAppAccessEnvironments is the most environments one app access
	// request may name.
	maxAppAccessEnvironments = 20
)

// requestActionKinds is the action registry: every action type this client
// forwards and the request kind it travels under. An action is otherwise
// opaque, so a member the Console adds later is forwarded without a release.
var requestActionKinds = map[RequestActionType]RequestKind{
	ActionConnectionCreate:       RequestSetup,
	ActionConnectionUpdate:       RequestConnectionUpdate,
	ActionConnectionSecretUpdate: RequestCredentialUpdate,
	ActionConnectionRemove:       RequestConnectionRemoval,
	ActionConnectionAppAccess:    RequestSetup,
	ActionGrantAllow:             RequestAccessChange,
	ActionGrantRenew:             RequestAccessChange,
	ActionWorkflowContextUpdate:  RequestContextUpdate,
}

// RequestKindEndsInAccess reports whether an approved request of this kind
// grants access, which is what a requested duration limits.
func RequestKindEndsInAccess(kind RequestKind) bool {
	return kind == RequestSetup || kind == RequestAccessChange
}

// ValidRequestDuration reports whether a requested duration may accompany a
// request of this kind. The Console owns the bounds and states them when it
// refuses one; the client only refuses what can never be valid.
func ValidRequestDuration(kind RequestKind, durationSeconds *int) bool {
	return durationSeconds == nil || (*durationSeconds > 0 && RequestKindEndsInAccess(kind))
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
// kind that type uses, it carries no secret value, and the few members a type
// defines locally have the right shape (see validateActionMembers). Every
// other member is the Console's to validate and is passed through unchanged.
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
	if err := validateActionCarriesNoSecret(members); err != nil {
		return err
	}
	return validateActionMembers(RequestActionType(actionType), members)
}

// validateActionMembers holds the per-type checks: a preset stands in place
// of a definition, an app access request names one app, its environments and
// an access level, an allow names exactly one of a class, a list of classes, a
// match or an operation and never the secret guard's class, and a Workflow
// context is text within the size cap.
func validateActionMembers(actionType RequestActionType, members map[string]json.RawMessage) error {
	switch actionType {
	case ActionConnectionCreate:
		rawPreset, present := members["preset"]
		if !present {
			return nil
		}
		var preset string
		if err := json.Unmarshal(rawPreset, &preset); err != nil || !validPresetID(preset) {
			return fmt.Errorf("agents: preset must be the ID of a preset")
		}
		if _, both := members["definition"]; both {
			return fmt.Errorf("agents: send a preset or a definition, not both")
		}
	case ActionConnectionAppAccess:
		return validateAppAccessMembers(members)
	case ActionGrantAllow:
		var allow map[string]json.RawMessage
		if err := json.Unmarshal(members["allow"], &allow); err != nil || allow == nil {
			return fmt.Errorf("agents: allow must be an object with a class, classes, a match or an operation")
		}
		rawClass, hasClass := allow["class"]
		rawClasses, hasClasses := allow["classes"]
		_, hasMatch := allow["match"]
		rawOperation, hasOperation := allow["operation"]
		if countTrue(hasClass, hasClasses, hasMatch, hasOperation) != 1 {
			return fmt.Errorf("agents: allow must have exactly one of class, classes, match or operation")
		}
		if hasOperation {
			var operation string
			if err := json.Unmarshal(rawOperation, &operation); err != nil || !ValidAWSOperation(operation) {
				return fmt.Errorf("agents: allow.operation must be an AWS action such as ec2:TerminateInstances")
			}
		}
		var classes []string
		if hasClass {
			var class string
			if err := json.Unmarshal(rawClass, &class); err != nil || class == "" {
				return fmt.Errorf("agents: allow.class must name a class")
			}
			classes = []string{class}
		}
		if hasClasses {
			if err := json.Unmarshal(rawClasses, &classes); err != nil || len(classes) == 0 || !distinctNonEmpty(classes) {
				return fmt.Errorf("agents: allow.classes must name one or more different classes")
			}
		}
		for _, class := range classes {
			if OperationClass(class) == ClassCredentialMinting {
				return fmt.Errorf("agents: calls that mint credentials are always blocked and cannot be requested")
			}
		}
	case ActionWorkflowContextUpdate:
		var markdown string
		if err := json.Unmarshal(members["markdown"], &markdown); err != nil || members["markdown"] == nil ||
			bytes.Equal(bytes.TrimSpace(members["markdown"]), []byte("null")) {
			return fmt.Errorf("agents: markdown must be the complete new context text")
		}
		if utf8.RuneCountInString(markdown) > MaxWorkflowContextLength {
			return fmt.Errorf("agents: the Workflow context holds at most %d characters", MaxWorkflowContextLength)
		}
	}
	return nil
}

// validateAppAccessMembers checks the shape of an app access request: one
// app by ID or by name, the environments by name or ID, and the access level.
// Whether the app and environments exist is the Console's to say.
func validateAppAccessMembers(members map[string]json.RawMessage) error {
	var appID, appName string
	_, hasID := members["appId"]
	_, hasName := members["appName"]
	if hasID {
		if err := json.Unmarshal(members["appId"], &appID); err != nil || strings.TrimSpace(appID) == "" {
			return fmt.Errorf("agents: appId must be an app ID")
		}
	}
	if hasName {
		if err := json.Unmarshal(members["appName"], &appName); err != nil || strings.TrimSpace(appName) == "" {
			return fmt.Errorf("agents: appName must be an app name")
		}
	}
	if hasID == hasName {
		return fmt.Errorf("agents: name the app with exactly one of appId or appName")
	}
	var environments []string
	if err := json.Unmarshal(members["environments"], &environments); err != nil || len(environments) == 0 ||
		len(environments) > maxAppAccessEnvironments || !distinctNonEmpty(environments) {
		return fmt.Errorf("agents: environments must name 1 to %d different environments", maxAppAccessEnvironments)
	}
	var access string
	if err := json.Unmarshal(members["access"], &access); err != nil || (access != "read" && access != "read_write") {
		return fmt.Errorf("agents: access must be read or read_write")
	}
	return nil
}

// distinctNonEmpty reports whether every value is non-blank and none repeats,
// ignoring case.
func distinctNonEmpty(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" {
			return false
		}
		if _, repeated := seen[key]; repeated {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func countTrue(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

// ValidAWSOperation reports whether value is an AWS action in the form a
// policy rule or an allow may name: "<service>:<Action>", the service in
// lower case, no wildcards.
func ValidAWSOperation(value string) bool {
	service, action, found := strings.Cut(value, ":")
	if !found || len(service) < 1 || len(service) > 64 || len(action) < 1 || len(action) > 128 {
		return false
	}
	for _, character := range service {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
			return false
		}
	}
	for _, character := range action {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')) {
			return false
		}
	}
	return true
}

func validPresetID(value string) bool {
	if len(value) < 1 || len(value) > maxPresetIDLength {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
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
		return fmt.Errorf("agents: the requested definition must be a JSON object")
	}
	rawFields, present := definition["fields"]
	if !present {
		return nil
	}
	var fields []map[string]json.RawMessage
	if err := json.Unmarshal(rawFields, &fields); err != nil {
		return fmt.Errorf("agents: the requested definition has invalid fields")
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
