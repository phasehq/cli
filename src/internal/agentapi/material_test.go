package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const exposedCustomValue = "member-entered-value-01"

func resolvedCustomConnection(id, live string) map[string]any {
	connection := customConnectionPayload(nil)
	connection["connectionId"], connection["grantId"], connection["credentialId"] = id, "grant-"+id, id
	connection["decoyMaterial"] = map[string]string{"token": "sk-decoy-" + id + "-0123456789abcdef"}
	connection["secretMaterial"] = map[string]string{"token": live}
	return connection
}

func packagedPostgresConnection() map[string]any {
	return map[string]any{
		"grantId": "grant-pg", "connectionId": "connection-pg", "credentialId": "credential-pg",
		"credentialName": "Postgres", "credentialProvider": "postgres", "serviceType": "postgres", "protocol": "postgres",
		"hosts":     []any{map[string]any{"match": "exact", "value": "db.example", "port": 5432}},
		"injection": map[string]any{"action": "pg_handshake"}, "identifiers": map[string]string{"username": "db-user"},
		"decoyMaterial": map[string]string{"password": "pg-decoy-0123456789"}, "agentEnv": map[string]string{},
		"configEnv": map[string]string{}, "secretMaterial": map[string]string{"username": "db-user", "password": "pg-live-0123456789"},
	}
}

// A value a member typed for a custom Connection may collide with something
// the Agent can see. That Connection loses its material; the session and every
// other Connection are untouched.
func TestExposedCustomValueWithholdsOnlyThatConnection(t *testing.T) {
	tests := map[string]func(payload map[string]any, exposed, sibling, packaged map[string]any){
		"inside its own decoy": func(_ map[string]any, exposed, _, _ map[string]any) {
			exposed["decoyMaterial"] = map[string]string{"token": "sk-" + exposedCustomValue + "-decoy"}
		},
		"inside its own identifier": func(_ map[string]any, exposed, _, _ map[string]any) {
			exposed["identifiers"] = map[string]string{"account": "acct-" + exposedCustomValue}
		},
		"equal to its own exported variable": func(_ map[string]any, exposed, _, _ map[string]any) {
			exposed["agentEnv"] = map[string]string{"EXAMPLE_ACCOUNT": exposedCustomValue}
		},
		"inside another custom Connection's decoy": func(_ map[string]any, _, sibling, _ map[string]any) {
			sibling["decoyMaterial"] = map[string]string{"token": "sk-" + exposedCustomValue + "-sibling"}
		},
		"inside a packaged Connection's identifier": func(_ map[string]any, _, _, packaged map[string]any) {
			packaged["identifiers"] = map[string]string{"username": "svc-" + exposedCustomValue}
			packaged["secretMaterial"] = map[string]string{"username": "svc-" + exposedCustomValue, "password": "pg-live-0123456789"}
		},
		"inside a packaged Connection's config variable": func(_ map[string]any, _, _, packaged map[string]any) {
			packaged["configEnv"] = map[string]string{"PGAPPNAME": "app-" + exposedCustomValue}
		},
		"inside the session's environment": func(payload map[string]any, _, _, _ map[string]any) {
			payload["configEnv"] = map[string]string{"DEPLOYMENT": "eu-" + exposedCustomValue}
		},
	}
	for name, expose := range tests {
		t.Run(name, func(t *testing.T) {
			exposed := resolvedCustomConnection("connection-exposed", exposedCustomValue)
			sibling := resolvedCustomConnection("connection-sibling", "sibling-live-value-0123456789")
			packaged := packagedPostgresConnection()
			payload := sessionPayload("", exposed, sibling, packaged)
			expose(payload, exposed, sibling, packaged)
			_, response := openThroughConsole(t, testToken("pss_user", 1, ""), payload)

			withheld := response.Connections[0]
			if !withheld.MaterialUnavailable() || withheld.MaterialFailure() != MaterialFailureExposed || len(withheld.SecretMaterial.Clone()) != 0 {
				t.Fatalf("exposed Connection: failure=%q material=%d", withheld.MaterialFailure(), len(withheld.SecretMaterial.Clone()))
			}
			if live, _ := response.Connections[1].SecretMaterial.Get("token"); live != "sibling-live-value-0123456789" || response.Connections[1].MaterialUnavailable() {
				t.Fatal("another custom Connection was affected")
			}
			if live, _ := response.Connections[2].SecretMaterial.Get("password"); live != "pg-live-0123456789" || response.Connections[2].MaterialUnavailable() {
				t.Fatal("a packaged Connection was affected")
			}
			if err := ValidateAgentVisibleEnvironment(response.ConfigEnv, response.Connections); err != nil {
				t.Fatalf("the session would still be refused: %v", err)
			}
			for _, value := range ProxyOnlyCredentialValues(response.Connections) {
				if value == exposedCustomValue {
					t.Fatal("the withheld value is still held")
				}
			}
		})
	}

	// Nothing overlaps: nothing is withheld.
	_, untouched := openThroughConsole(t, testToken("pss_user", 1, ""), sessionPayload("",
		resolvedCustomConnection("connection-exposed", exposedCustomValue), packagedPostgresConnection()))
	if untouched.Connections[0].MaterialUnavailable() {
		t.Fatalf("a safe value was withheld: %s", untouched.Connections[0].MaterialFailure())
	}
}

func TestExposedCustomValueIsWithheldOnBothLanesAndOnRefresh(t *testing.T) {
	agent := newAgentKeyFixture(t)
	sealedConnection := func(live string) map[string]any {
		connection := customConnectionPayload(sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": live})))
		connection["identifiers"] = map[string]string{"account": "acct-" + exposedCustomValue}
		return connection
	}
	var refreshed map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/config/") {
			_ = json.NewEncoder(w).Encode(refreshed)
			return
		}
		_ = json.NewEncoder(w).Encode(sessionPayload(agent.wrappedKeyShare, sealedConnection(exposedCustomValue), packagedPostgresConnection()))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, agent.token, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	opened, err := client.OpenSession(context.Background(), OpenSessionRequest{IdempotencyKey: "proxy-start-exposed"})
	if err != nil {
		t.Fatal(err)
	}
	if opened.Connections[0].MaterialFailure() != MaterialFailureExposed || len(opened.Connections[0].SecretMaterial.Clone()) != 0 ||
		ValidateAgentVisibleEnvironment(opened.ConfigEnv, opened.Connections) != nil {
		t.Fatalf("a sealed value that the Agent can see was kept: %q", opened.Connections[0].MaterialFailure())
	}

	// A member enters a value that does not collide, then one that does.
	refreshed = sessionPayload("", sealedConnection("a-value-nothing-else-contains-01"), packagedPostgresConnection())
	config, err := client.RefreshSession(context.Background(), "session-sealed", "backend-capability")
	if err != nil {
		t.Fatal(err)
	}
	if live, _ := config.Connections[0].SecretMaterial.Get("token"); live != "a-value-nothing-else-contains-01" || config.Connections[0].MaterialUnavailable() {
		t.Fatalf("a safe value was withheld on refresh: %q", config.Connections[0].MaterialFailure())
	}
	refreshed = sessionPayload("", sealedConnection(exposedCustomValue), packagedPostgresConnection())
	config, err = client.RefreshSession(context.Background(), "session-sealed", "backend-capability")
	if err != nil {
		t.Fatal(err)
	}
	if config.Connections[0].MaterialFailure() != MaterialFailureExposed || config.Connections[1].MaterialUnavailable() ||
		ValidateAgentVisibleEnvironment(config.ConfigEnv, config.Connections) != nil {
		t.Fatalf("an exposed value was kept on refresh: %q", config.Connections[0].MaterialFailure())
	}
}

// Packaged services keep the rule they always had: a live value inside an
// Agent-visible value refuses the whole session, at open and on refresh.
func TestPackagedValueInsideAgentVisibleValueStillRefusesTheSession(t *testing.T) {
	aws := func() map[string]any {
		return map[string]any{
			"grantId": "grant-aws", "connectionId": "connection-aws", "credentialId": "credential-aws",
			"credentialName": "AWS", "credentialProvider": "aws", "serviceType": "aws", "protocol": "http",
			"hosts": []any{map[string]any{"match": "suffix", "value": ".amazonaws.com", "port": 443}},
			"injection": map[string]any{"action": "aws_sigv4", "serviceFrom": "host", "regionFrom": "host",
				"valueFrom": map[string]any{"source": "credential", "fields": map[string]string{"accessKeyId": "access_key_id", "secretAccessKey": "secret_access_key"}}},
			"identifiers": map[string]string{"accessKeyId": "AKIAPHASEDECOY000000"}, "decoyMaterial": map[string]string{"secretAccessKey": "phase-decoy-secret-0123"},
			"agentEnv": map[string]string{}, "configEnv": map[string]string{},
			"secretMaterial": map[string]string{"accessKeyId": "AKIALIVEEXAMPLE00000", "secretAccessKey": "aws-live-secret-0123456789"},
		}
	}
	tests := map[string]func() []map[string]any{
		"Postgres password inside its own environment": func() []map[string]any {
			postgres := packagedPostgresConnection()
			postgres["agentEnv"] = map[string]string{"PGAPPNAME": "app-pg-live-0123456789"}
			return []map[string]any{resolvedCustomConnection("connection-custom", "custom-live-value-0123456789"), postgres}
		},
		"AWS secret inside a custom Connection's identifier": func() []map[string]any {
			custom := resolvedCustomConnection("connection-custom", "custom-live-value-0123456789")
			custom["identifiers"] = map[string]string{"account": "acct-aws-live-secret-0123456789"}
			return []map[string]any{custom, aws()}
		},
		"AWS secret inside the session's environment": func() []map[string]any {
			return []map[string]any{resolvedCustomConnection("connection-custom", "custom-live-value-0123456789"), aws()}
		},
	}
	for name, connections := range tests {
		t.Run(name, func(t *testing.T) {
			payload := sessionPayload("", connections()...)
			if strings.HasSuffix(name, "session's environment") {
				payload["configEnv"] = map[string]string{"NOTE": "aws-live-secret-0123456789"}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(payload)
			}))
			defer server.Close()
			client, err := NewClient(server.URL, testToken("pss_user", 1, ""), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			opened, err := client.OpenSession(context.Background(), OpenSessionRequest{WorkflowID: "workflow-1", IdempotencyKey: "proxy-start-packaged"})
			if err != nil {
				t.Fatal(err)
			}
			refreshed, err := client.RefreshSession(context.Background(), "session-sealed", "backend-capability")
			if err != nil {
				t.Fatal(err)
			}
			for stage, config := range map[string]*SessionConfig{"open": &opened.SessionConfig, "refresh": refreshed} {
				if err := ValidateAgentVisibleEnvironment(config.ConfigEnv, config.Connections); !errors.Is(err, ErrUnsafeAgentVisibleEnvironment) {
					t.Fatalf("%s: the session was not refused: %v", stage, err)
				}
				for _, connection := range config.Connections {
					if connection.MaterialUnavailable() || len(connection.SecretMaterial.Clone()) == 0 {
						t.Fatalf("%s: %s was withheld instead of refusing the session", stage, connection.ConnectionID)
					}
				}
			}
		})
	}
}
