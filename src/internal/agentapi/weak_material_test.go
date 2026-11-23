package agentapi

import (
	"testing"
)

// A custom Connection's value shorter than eight bytes is not kept: it could
// be found by trying, and it turns up by chance in whatever it is compared
// with. Only that Connection loses its material.
func TestShortCustomValueIsWithheld(t *testing.T) {
	for _, short := range []string{"1", "1234", "token", "secret", "1234567"} {
		weak := resolvedCustomConnection("connection-weak", short)
		sibling := resolvedCustomConnection("connection-sibling", "sibling-live-value-0123456789")
		_, response := openThroughConsole(t, testToken("pss_user", 1, ""), sessionPayload("", weak, sibling, packagedPostgresConnection()))

		withheld := response.Connections[0]
		if withheld.MaterialFailure() != MaterialFailureExposed || len(withheld.SecretMaterial.Clone()) != 0 {
			t.Fatalf("value of %d bytes: failure=%q material=%d", len(short), withheld.MaterialFailure(), len(withheld.SecretMaterial.Clone()))
		}
		if response.Connections[1].MaterialUnavailable() || response.Connections[2].MaterialUnavailable() {
			t.Fatalf("value of %d bytes cost another Connection its material", len(short))
		}
		for _, value := range ProxyOnlyCredentialValues(response.Connections) {
			if value == short {
				t.Fatal("the withheld value is still held")
			}
		}
	}

	// Eight bytes is the least a Connection may hold.
	_, kept := openThroughConsole(t, testToken("pss_user", 1, ""), sessionPayload("", resolvedCustomConnection("connection-weak", "k7Qm2ZpX")))
	if live, _ := kept.Connections[0].SecretMaterial.Get("token"); live != "k7Qm2ZpX" || kept.Connections[0].MaterialUnavailable() {
		t.Fatalf("a value of eight bytes was withheld: %q", kept.Connections[0].MaterialFailure())
	}

	// Any one value of the Connection that is too short withholds it whole.
	mixed := resolvedCustomConnection("connection-weak", "long-enough-value-0123456789")
	mixed["secretMaterial"] = map[string]string{"token": "long-enough-value-0123456789", "pin": "4821"}
	_, response := openThroughConsole(t, testToken("pss_user", 1, ""), sessionPayload("", mixed))
	if response.Connections[0].MaterialFailure() != MaterialFailureExposed || len(response.Connections[0].SecretMaterial.Clone()) != 0 {
		t.Fatalf("a Connection with one short value kept its material: %q", response.Connections[0].MaterialFailure())
	}

	// The rule is for values a member chose: a packaged service is not touched.
	packaged := packagedPostgresConnection()
	packaged["secretMaterial"] = map[string]string{"username": "db-user", "password": "pg-live"}
	_, response = openThroughConsole(t, testToken("pss_user", 1, ""), sessionPayload("", packaged))
	if response.Connections[0].MaterialUnavailable() {
		t.Fatalf("a packaged Connection was withheld: %q", response.Connections[0].MaterialFailure())
	}
}

// The same on the sealed lane, where the client is the first to see the value.
func TestShortSealedValueIsWithheld(t *testing.T) {
	agent := newAgentKeyFixture(t)
	connection := customConnectionPayload(sealValue(t, agent.publicKey, sealedPlaintext(map[string]string{"token": "4821"})))
	_, response := openThroughConsole(t, agent.token, sessionPayload(agent.wrappedKeyShare, connection))
	if response.Connections[0].MaterialFailure() != MaterialFailureExposed || len(response.Connections[0].SecretMaterial.Clone()) != 0 {
		t.Fatalf("a short sealed value was kept: %q", response.Connections[0].MaterialFailure())
	}
}

// A value that the Connection's own description already contains is something
// the Agent can read, so it is withheld like one found in the environment.
func TestCustomValueFoundInItsOwnDescriptionIsWithheld(t *testing.T) {
	tests := map[string]func(connection map[string]any){
		"its name": func(connection map[string]any) {
			connection["connectionName"] = "Billing (" + exposedCustomValue + ")"
		},
		"its credential name": func(connection map[string]any) {
			connection["credentialName"] = exposedCustomValue
		},
		"a host it routes": func(connection map[string]any) {
			connection["hosts"] = []any{map[string]any{"match": "exact", "value": exposedCustomValue + ".example.com", "port": 443}}
		},
		"a value in its definition": func(connection map[string]any) {
			connection["connectionConfig"] = map[string]any{"specVersion": 1, "fields": []any{map[string]any{"name": "token", "kind": "secret", "note": "it is " + exposedCustomValue}}}
		},
		"a member name in its definition": func(connection map[string]any) {
			connection["connectionConfig"] = map[string]any{"specVersion": 1, exposedCustomValue: true}
		},
		"a path in its policy": func(connection map[string]any) {
			connection["policy"] = map[string]any{"version": 1, "default": "allow", "rules": []any{
				map[string]any{"match": map[string]any{"path": "/v1/" + exposedCustomValue + "/*"}, "effect": "block"},
			}}
		},
	}
	for name, describe := range tests {
		t.Run(name, func(t *testing.T) {
			described := resolvedCustomConnection("connection-described", exposedCustomValue)
			describe(described)
			sibling := resolvedCustomConnection("connection-sibling", "sibling-live-value-0123456789")
			_, response := openThroughConsole(t, testToken("pss_user", 1, ""), sessionPayload("", described, sibling))
			if response.Connections[0].MaterialFailure() != MaterialFailureExposed || len(response.Connections[0].SecretMaterial.Clone()) != 0 {
				t.Fatalf("failure=%q material=%d", response.Connections[0].MaterialFailure(), len(response.Connections[0].SecretMaterial.Clone()))
			}
			if response.Connections[1].MaterialUnavailable() {
				t.Fatal("another custom Connection was affected")
			}
		})
	}

	// A value that JSON writes with an escape is found in a definition as well.
	quoted := `member "quoted" value`
	escaped := resolvedCustomConnection("connection-described", quoted)
	escaped["connectionConfig"] = map[string]any{"specVersion": 1, "note": "it is " + quoted}
	_, response := openThroughConsole(t, testToken("pss_user", 1, ""), sessionPayload("", escaped))
	if response.Connections[0].MaterialFailure() != MaterialFailureExposed {
		t.Fatalf("a value needing a JSON escape was kept: %q", response.Connections[0].MaterialFailure())
	}

	// Another Connection saying the same text does not withhold this one: a
	// value is compared with its own Connection's description.
	plain := resolvedCustomConnection("connection-described", exposedCustomValue)
	other := resolvedCustomConnection("connection-sibling", "sibling-live-value-0123456789")
	other["connectionName"] = "Sibling (" + exposedCustomValue + ")"
	_, response = openThroughConsole(t, testToken("pss_user", 1, ""), sessionPayload("", plain, other))
	if response.Connections[0].MaterialUnavailable() || response.Connections[1].MaterialUnavailable() {
		t.Fatalf("a value was withheld for what another Connection is called: %q", response.Connections[0].MaterialFailure())
	}
}
