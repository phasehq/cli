package agentsdk

import (
	"encoding/json"
	"time"
)

// PhaseAppServiceType is the service type of an app Connection: access to an
// app's secrets through the Console's secrets API. The proxy has nothing to do
// with it, so an app Connection never appears in a session's connections; it
// arrives in appConnections instead.
const PhaseAppServiceType = "phase_app"

// AppRef names an app.
type AppRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AppEnvironment is one environment an app Connection covers.
type AppEnvironment struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	EnvType string `json:"envType"`
}

// AppClassAccess is the effect a class of secrets call has right now. Until is
// set when an allow comes from a temporary allow and says when it ends.
type AppClassAccess struct {
	Effect PolicyEffect `json:"effect"`
	Until  *time.Time   `json:"until,omitempty"`
}

// AppAccess holds the effect per class (read, create, update, delete).
type AppAccess map[OperationClass]AppClassAccess

// AppConnection is one app Connection the token's Workflow can use now.
type AppConnection struct {
	ConnectionID   string           `json:"connectionId"`
	ConnectionName string           `json:"connectionName"`
	GrantID        string           `json:"grantId"`
	App            AppRef           `json:"app"`
	Environments   []AppEnvironment `json:"environments"`
	Access         AppAccess        `json:"access"`
	GrantExpiresAt *time.Time       `json:"grantExpiresAt"`
}

// ExpiredAppConnection is a grant of an app Connection that ended recently.
type ExpiredAppConnection struct {
	ConnectionID   string    `json:"connectionId"`
	ConnectionName string    `json:"connectionName"`
	App            AppRef    `json:"app"`
	ExpiredAt      time.Time `json:"expiredAt"`
}

// AppAccessResponse is GET /service/public/v1/agents/app-access/.
type AppAccessResponse struct {
	SchemaVersion int                    `json:"schemaVersion"`
	Apps          []AppConnection        `json:"apps"`
	Expired       []ExpiredAppConnection `json:"expired"`
}

// AppSecretsError is the error body of the secrets API for an Agent caller.
// Request, when present, is a complete body for POST /v1/requests that asks a
// member for what the refused call needed.
type AppSecretsError struct {
	Error          string          `json:"error"`
	Code           string          `json:"code,omitempty"`
	Request        json.RawMessage `json:"request,omitempty"`
	ConnectionName string          `json:"connectionName,omitempty"`
	Class          string          `json:"class,omitempty"`
}
