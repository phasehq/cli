package agentsdk

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAppSecretsContractFixtures(t *testing.T) {
	t.Run("app access response", func(t *testing.T) {
		value := fixtureRoundTrip[AppAccessResponse](t, "app_access_response.json")
		if len(value.Apps) != 1 || len(value.Expired) != 1 {
			t.Fatalf("apps = %d, expired = %d", len(value.Apps), len(value.Expired))
		}
		app := value.Apps[0]
		if app.App.Name != "orders-service" || len(app.Environments) != 2 || app.Environments[1].EnvType != "staging" {
			t.Fatalf("app connection did not decode: %+v", app)
		}
		if app.Access[ClassCreate].Effect != PolicyAllow || app.Access[ClassCreate].Until == nil ||
			app.Access[ClassUpdate].Effect != PolicyAsk || app.Access[ClassDelete].Effect != PolicyBlock || app.GrantExpiresAt != nil {
			t.Fatalf("access did not decode: %+v", app.Access)
		}
	})
	t.Run("session config with app connections", func(t *testing.T) {
		value := fixtureRoundTrip[RefreshConfigResponse](t, "refresh_session_response_app_connections.json")
		if len(value.Connections) != 0 || len(value.AppConnections) != 1 || value.AppConnections[0].GrantExpiresAt == nil {
			t.Fatalf("app connections did not decode: %+v", value.AppConnections)
		}
	})
	t.Run("session config without app connections", func(t *testing.T) {
		value := fixtureRoundTrip[RefreshConfigResponse](t, "refresh_session_response.json")
		if value.AppConnections != nil {
			t.Fatalf("an old-style session grew app connections: %+v", value.AppConnections)
		}
	})
	t.Run("grant missing error", func(t *testing.T) {
		value := fixtureRoundTrip[AppSecretsError](t, "app_secrets_error_response.json")
		if value.Code != "agent_grant_missing" || len(value.Request) == 0 {
			t.Fatalf("error did not decode: %+v", value)
		}
		var request struct {
			Kind   RequestKind     `json:"kind"`
			Action json.RawMessage `json:"action"`
		}
		if err := json.Unmarshal(value.Request, &request); err != nil {
			t.Fatal(err)
		}
		if err := ValidateRequestAction(request.Kind, request.Action); err != nil {
			t.Fatalf("the ready-to-send request is not one this client forwards: %v", err)
		}
	})
	t.Run("blocked error", func(t *testing.T) {
		value := fixtureRoundTrip[AppSecretsError](t, "app_secrets_blocked_error_response.json")
		if value.Code != "agent_access_blocked" || value.Class != "delete" || value.ConnectionName == "" || value.Request != nil {
			t.Fatalf("blocked error did not decode: %+v", value)
		}
	})
	for _, name := range []string{"app_access_request.json", "grant_allow_classes_request.json"} {
		t.Run(name, func(t *testing.T) {
			var request struct {
				Kind            RequestKind     `json:"kind"`
				Title           string          `json:"title"`
				DurationSeconds *int            `json:"durationSeconds"`
				Action          json.RawMessage `json:"action"`
			}
			if err := json.Unmarshal(readFixture(t, name), &request); err != nil {
				t.Fatal(err)
			}
			if err := ValidateRequestAction(request.Kind, request.Action); err != nil {
				t.Fatalf("canonical request refused: %v", err)
			}
			if !ValidRequestTitle(request.Title) || !ValidRequestDuration(request.Kind, request.DurationSeconds) {
				t.Fatalf("canonical request title or duration refused: %+v", request)
			}
		})
	}
}

func TestAppAccessActionValidation(t *testing.T) {
	valid := []string{
		`{"type":"agent_connection.app_access","version":1,"appId":"app-1","environments":["development"],"access":"read"}`,
		`{"type":"agent_connection.app_access","version":1,"appName":"orders-service","environments":["dev","env-2"],"access":"read_write"}`,
	}
	for _, action := range valid {
		if err := ValidateRequestAction(RequestSetup, json.RawMessage(action)); err != nil {
			t.Fatalf("valid app access action refused: %s: %v", action, err)
		}
	}
	tooMany := make([]string, maxAppAccessEnvironments+1)
	for index := range tooMany {
		tooMany[index] = `"env-` + strings.Repeat("x", index+1) + `"`
	}
	invalid := map[string]string{
		"wrong kind":         `{"type":"agent_connection.app_access","version":1,"appId":"app-1","environments":["dev"],"access":"read"}`,
		"no app":             `{"type":"agent_connection.app_access","version":1,"environments":["dev"],"access":"read"}`,
		"both app selectors": `{"type":"agent_connection.app_access","version":1,"appId":"a","appName":"b","environments":["dev"],"access":"read"}`,
		"blank app id":       `{"type":"agent_connection.app_access","version":1,"appId":" ","environments":["dev"],"access":"read"}`,
		"no environments":    `{"type":"agent_connection.app_access","version":1,"appId":"a","environments":[],"access":"read"}`,
		"repeated env":       `{"type":"agent_connection.app_access","version":1,"appId":"a","environments":["dev","DEV"],"access":"read"}`,
		"too many envs":      `{"type":"agent_connection.app_access","version":1,"appId":"a","environments":[` + strings.Join(tooMany, ",") + `],"access":"read"}`,
		"unknown access":     `{"type":"agent_connection.app_access","version":1,"appId":"a","environments":["dev"],"access":"admin"}`,
		"carries a value":    `{"type":"agent_connection.app_access","version":1,"appId":"a","environments":["dev"],"access":"read","value":"x"}`,
	}
	for name, action := range invalid {
		kind := RequestSetup
		if name == "wrong kind" {
			kind = RequestAccessChange
		}
		if err := ValidateRequestAction(kind, json.RawMessage(action)); err == nil {
			t.Fatalf("%s: invalid app access action accepted", name)
		}
	}
}

func TestGrantAllowClassesValidation(t *testing.T) {
	valid := []string{
		`{"type":"agent_grant.allow","version":1,"connectionId":"c","allow":{"classes":["create","update","delete"]}}`,
		`{"type":"agent_grant.allow","version":1,"connectionId":"c","allow":{"classes":["read"]}}`,
		`{"type":"agent_grant.allow","version":1,"connectionId":"c","allow":{"class":"delete"}}`,
	}
	for _, action := range valid {
		if err := ValidateRequestAction(RequestAccessChange, json.RawMessage(action)); err != nil {
			t.Fatalf("valid allow refused: %s: %v", action, err)
		}
	}
	invalid := []string{
		`{"type":"agent_grant.allow","version":1,"connectionId":"c","allow":{"classes":[]}}`,
		`{"type":"agent_grant.allow","version":1,"connectionId":"c","allow":{"classes":"create"}}`,
		`{"type":"agent_grant.allow","version":1,"connectionId":"c","allow":{"classes":["create","create"]}}`,
		`{"type":"agent_grant.allow","version":1,"connectionId":"c","allow":{"classes":["create",""]}}`,
		`{"type":"agent_grant.allow","version":1,"connectionId":"c","allow":{"classes":["credential_minting"]}}`,
		`{"type":"agent_grant.allow","version":1,"connectionId":"c","allow":{"classes":["create"],"class":"update"}}`,
		`{"type":"agent_grant.allow","version":1,"connectionId":"c","allow":{"classes":["create"],"match":{"methods":["POST"]}}}`,
	}
	for _, action := range invalid {
		if err := ValidateRequestAction(RequestAccessChange, json.RawMessage(action)); err == nil {
			t.Fatalf("invalid allow accepted: %s", action)
		}
	}
	if err := ValidateRequestAction(RequestSetup, json.RawMessage(`{"type":"agent_connection.future","version":1}`)); err == nil {
		t.Fatal("an unknown action type was accepted")
	}
}
