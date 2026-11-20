package agentapi

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// testdata/console_sealed_fixture.json was produced by the Console's own
// primitives: an Agent token, that token's wrapped key share, and a value
// sealed to a Connection key whose private half is wrapped to the Agent. If
// this client cannot open it, the two sides disagree on the sealed lane.
func TestConsoleSealedFixtureOpensWithTheAgentToken(t *testing.T) {
	raw, err := os.ReadFile("testdata/console_sealed_fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		AgentToken      string            `json:"agentToken"`
		WrappedKeyShare string            `json:"wrappedKeyShare"`
		SealedMaterial  map[string]any    `json:"sealedMaterial"`
		Hosts           []map[string]any  `json:"hosts"`
		ExpectedFields  map[string]string `json:"expectedFields"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.AgentToken == "" || fixture.WrappedKeyShare == "" || len(fixture.SealedMaterial) == 0 ||
		len(fixture.Hosts) == 0 || len(fixture.ExpectedFields) == 0 {
		t.Fatal("the fixture is incomplete")
	}
	tokenType, _, err := ParseDurableToken(fixture.AgentToken)
	if err != nil || tokenType != TokenAgent {
		t.Fatalf("the fixture token is not an Agent token this client accepts: %v", err)
	}

	hosts := make([]any, 0, len(fixture.Hosts))
	for _, host := range fixture.Hosts {
		hosts = append(hosts, host)
	}
	injections := make([]any, 0, len(fixture.ExpectedFields))
	decoys := make(map[string]string, len(fixture.ExpectedFields))
	for field := range fixture.ExpectedFields {
		injections = append(injections, map[string]any{
			"action": "set_header", "name": "X-Fixture-" + field, "valueFormat": "{value}",
			"valueFrom": map[string]any{"source": "credential", "field": field}, "whenAbsent": "attach",
		})
		decoys[field] = "decoy-for-" + field + "-0123456789abcdef"
	}
	connection := customConnectionPayload(fixture.SealedMaterial)
	connection["hosts"], connection["injections"], connection["decoyMaterial"] = hosts, injections, decoys

	client, response := openThroughConsole(t, fixture.AgentToken, sessionPayload(fixture.WrappedKeyShare, connection))
	if !client.CanOpenSealedMaterial() {
		t.Fatal("the client did not keep the fixture token's key shares")
	}
	opened := response.Connections[0]
	if opened.MaterialUnavailable() {
		t.Fatalf("the Console's sealed value did not open; failed step: %s", opened.MaterialFailure())
	}
	if got := opened.SecretMaterial.Clone(); !reflect.DeepEqual(got, fixture.ExpectedFields) {
		t.Fatalf("opened fields differ from the fixture's: got %d fields, want %d", len(got), len(fixture.ExpectedFields))
	}
	if keyVersion, _ := fixture.SealedMaterial["keyVersion"].(float64); opened.SealedMaterial.KeyVersion != int(keyVersion) {
		t.Fatalf("key version = %d, want %v", opened.SealedMaterial.KeyVersion, keyVersion)
	}
}
