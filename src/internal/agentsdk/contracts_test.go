package agentsdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCanonicalFixturesRoundTrip(t *testing.T) {
	t.Run("open request", func(t *testing.T) {
		value := fixtureRoundTrip[OpenSessionRequest](t, "open_session_request.json")
		if value.Client.InjectionActions[len(value.Client.InjectionActions)-1] != InjectionPGHandshake {
			t.Fatalf("last injection action = %q, want %q", value.Client.InjectionActions[len(value.Client.InjectionActions)-1], InjectionPGHandshake)
		}
	})
	t.Run("open response", func(t *testing.T) {
		value := fixtureRoundTrip[OpenSessionResponse](t, "open_session_response.json")
		if got := value.SessionCredential.Reveal(); got != "psx_sess_REDACTED_REVEAL_ONCE" {
			t.Fatalf("session credential did not decode")
		}
		if len(value.Connections) != 1 || value.Connections[0].Injection.Action != InjectionAWSSigV4 {
			t.Fatalf("runtime connection did not decode: %+v", value.Connections)
		}
		if err := value.Connections[0].Injection.Validate(); err != nil {
			t.Fatalf("canonical action rejected: %v", err)
		}
		if err := value.Connections[0].ValidateEnvironmentBindings(); err != nil {
			t.Fatalf("canonical environment bindings rejected: %v", err)
		}
		if got := value.Connections[0].ConfigEnv["AWS_DEFAULT_REGION"]; got != "us-east-1" {
			t.Fatalf("connection config environment region = %q", got)
		}
		if got := value.Connections[0].Authorization.State; got != ConnectionAuthorizationAllowed {
			t.Fatalf("authorization state = %q, want %q", got, ConnectionAuthorizationAllowed)
		}
		if got := value.Connections[0].AgentEnv["AWS_SESSION_TOKEN"]; got != "phx_aws_session_REDACTED_DECOY" {
			t.Fatalf("AWS session-token environment decoy = %q", got)
		}
		if got := value.Connections[0].DecoyMaterial["sessionToken"]; got != "phx_aws_session_REDACTED_DECOY" {
			t.Fatalf("AWS session-token decoy material = %q", got)
		}
	})
	t.Run("refresh response", func(t *testing.T) {
		fixtureRoundTrip[RefreshConfigResponse](t, "refresh_session_response.json")
	})
	t.Run("discover response", func(t *testing.T) {
		value := fixtureRoundTrip[DiscoverResponse](t, "discover_response.json")
		if len(value.Connections) != 1 {
			t.Fatalf("discover connections = %d, want 1", len(value.Connections))
		}
		if err := value.Connections[0].ValidateEnvironmentBindings(); err != nil {
			t.Fatalf("canonical discover environment bindings rejected: %v", err)
		}
		if got := value.Connections[0].ConfigEnv["AWS_DEFAULT_REGION"]; got != "us-east-1" {
			t.Fatalf("discover connection config environment region = %q", got)
		}
		if got := value.Connections[0].AgentEnv["AWS_SESSION_TOKEN"]; got != "phx_aws_session_REDACTED_DECOY" {
			t.Fatalf("discover AWS session-token environment decoy = %q", got)
		}
	})
	t.Run("capabilities response", func(t *testing.T) {
		value := fixtureRoundTrip[CapabilitiesResponse](t, "capabilities_response.json")
		if err := value.Validate(); err != nil {
			t.Fatalf("canonical capabilities rejected: %v", err)
		}
		if len(value.Services) != 2 || value.Services[1].ClientMatchers[1].Kind != ClientMatcherURIScheme {
			t.Fatalf("capabilities response did not decode: %+v", value)
		}
	})
	t.Run("events request", func(t *testing.T) {
		value := fixtureRoundTrip[EventBatch](t, "events_request.json")
		if len(value.Events) != 1 || value.Events[0].Port == nil || *value.Events[0].Port != 443 {
			t.Fatalf("event destination port did not round-trip: %+v", value.Events)
		}
	})
	t.Run("error response", func(t *testing.T) {
		fixtureRoundTrip[ErrorResponse](t, "error_response.json")
	})
}

func TestCheckedInFixturesMatchConsoleCanonicalFixtures(t *testing.T) {
	consoleDir := filepath.Join("..", "..", "..", "console", "backend", "ee", "integrations", "agents", "contracts", "v1")
	if _, err := os.Stat(consoleDir); err != nil {
		t.Skip("Console canonical fixture repository is not available")
	}

	entries, err := os.ReadDir("testdata/contracts/v1")
	if err != nil {
		t.Fatalf("ReadDir testdata: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			local := readFixture(t, entry.Name())
			canonical, err := os.ReadFile(filepath.Join(consoleDir, entry.Name()))
			if err != nil {
				t.Fatalf("read Console fixture: %v", err)
			}
			assertJSONEqual(t, canonical, local)
		})
	}
}

func TestDiscoverTypesCannotContainRuntimeSecrets(t *testing.T) {
	responseType := reflect.TypeOf(DiscoverResponse{})
	if _, exists := responseType.FieldByName("SessionCredential"); exists {
		t.Fatal("DiscoverResponse must not have SessionCredential")
	}
	connectionType := reflect.TypeOf(DiscoverConnection{})
	if _, exists := connectionType.FieldByName("SecretMaterial"); exists {
		t.Fatal("DiscoverConnection must not have SecretMaterial")
	}

	discover := fixtureRoundTrip[DiscoverResponse](t, "discover_response.json")
	encoded, err := json.Marshal(discover)
	if err != nil {
		t.Fatalf("Marshal discover: %v", err)
	}
	if bytes.Contains(encoded, []byte("sessionCredential")) || bytes.Contains(encoded, []byte("secretMaterial")) {
		t.Fatalf("discover encoded forbidden fields: %s", encoded)
	}
}

func TestAgentRuntimeDoesNotOwnProducerLeaseManagement(t *testing.T) {
	if _, exists := reflect.TypeOf(RuntimeConnection{}).FieldByName("Lease"); exists {
		t.Fatal("RuntimeConnection must not expose an Agent-owned lease")
	}
	if _, exists := reflect.TypeOf((*Client)(nil)).MethodByName("RenewLease"); exists {
		t.Fatal("Client must not expose the removed Agent lease renewal endpoint")
	}

}

func TestSensitiveMaterialIsRedactedFromFmt(t *testing.T) {
	const sessionSecret = "session-secret-sentinel"
	const liveSecret = "live-secret-sentinel"
	const adapterDecoy = "postgres-decoy-sentinel"
	response := OpenSessionResponse{
		SessionUID:        "session-123",
		SessionCredential: SensitiveString(sessionSecret),
		Connections: []RuntimeConnection{{
			DecoyMaterial: DecoyMaterial{"password": adapterDecoy},
			AgentEnv:      AgentEnvironment{"PGPASSWORD": adapterDecoy},
			EnvironmentBindings: []EnvironmentBinding{{
				Name: "PGPASSWORD", Action: EnvironmentBindingSet, Source: EnvironmentSourceDecoy,
				SourceField: "password", Sensitive: true, SystemManaged: true,
			}},
			SecretMaterial: SecretMaterial{"password": liveSecret},
		}},
	}
	discover := DiscoverResponse{Connections: []DiscoverConnection{{
		DecoyMaterial: DecoyMaterial{"password": adapterDecoy},
		AgentEnv:      AgentEnvironment{"PGPASSWORD": adapterDecoy},
		EnvironmentBindings: []EnvironmentBinding{{
			Name: "PGPASSWORD", Action: EnvironmentBindingSet, Source: EnvironmentSourceDecoy,
			SourceField: "password", Sensitive: true, SystemManaged: true,
		}},
	}}}

	for _, formatted := range []string{
		fmt.Sprintf("%v", response),
		fmt.Sprintf("%+v", response),
		fmt.Sprintf("%#v", response),
		fmt.Sprintf("%+v", discover),
		fmt.Sprintf("%#v", discover),
		fmt.Sprintf("%+v", response.SessionAuth()),
	} {
		if strings.Contains(formatted, sessionSecret) || strings.Contains(formatted, adapterDecoy) ||
			strings.Contains(formatted, liveSecret) {
			t.Fatalf("fmt leaked sensitive material: %s", formatted)
		}
		if !strings.Contains(formatted, redactedValue) {
			t.Fatalf("fmt did not mark redaction: %s", formatted)
		}
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Marshal response: %v", err)
	}
	if !bytes.Contains(encoded, []byte(sessionSecret)) || !bytes.Contains(encoded, []byte(adapterDecoy)) ||
		!bytes.Contains(encoded, []byte(liveSecret)) {
		t.Fatal("wire JSON must retain material for the typed transport")
	}

	auth := AgentAuthentication("durable-token-sentinel")
	minted := MintAgentTokenResponse{
		FullToken:   "full-token-sentinel",
		BearerToken: "bearer-token-sentinel",
	}
	for _, formatted := range []string{fmt.Sprintf("%+v", auth), fmt.Sprintf("%+v", minted)} {
		if strings.Contains(formatted, "token-sentinel") {
			t.Fatalf("fmt leaked a token: %s", formatted)
		}
	}
}

func TestEnvironmentBindingWireContractAndValidation(t *testing.T) {
	raw := []byte(`{
		"name":"AWS_SECRET_ACCESS_KEY",
		"action":"set",
		"source":"decoy",
		"sourceField":"secret_access_key",
		"sensitive":true,
		"systemManaged":true
	}`)
	var binding EnvironmentBinding
	if err := json.Unmarshal(raw, &binding); err != nil {
		t.Fatalf("Unmarshal binding: %v", err)
	}
	if err := binding.Validate(); err != nil {
		t.Fatalf("canonical binding rejected: %v", err)
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		t.Fatalf("Marshal binding: %v", err)
	}
	assertJSONEqual(t, raw, encoded)

	validUnset := EnvironmentBinding{
		Name: "AWS_SESSION_TOKEN", Action: EnvironmentBindingUnset, Source: EnvironmentSourceRuntime,
		SourceField: "secret_access_key",
		Sensitive:   true, SystemManaged: true,
	}
	if err := validUnset.Validate(); err != nil {
		t.Fatalf("canonical unset binding rejected: %v", err)
	}

	tests := []EnvironmentBinding{
		{Name: "1INVALID", Action: EnvironmentBindingSet, Source: EnvironmentSourceDecoy, SourceField: "field"},
		{Name: "lowercase", Action: EnvironmentBindingSet, Source: EnvironmentSourceDecoy, SourceField: "field"},
		{Name: "VALID", Action: "future_action", Source: EnvironmentSourceRuntime},
		{Name: "VALID", Action: EnvironmentBindingSet, Source: "future_source"},
		{Name: "VALID", Action: EnvironmentBindingSet, Source: EnvironmentSourceIdentifier, SourceField: "Invalid"},
		{Name: "VALID", Action: EnvironmentBindingSet, Source: EnvironmentSourceIdentifier},
		{Name: "VALID", Action: EnvironmentBindingSet, Source: EnvironmentSourceDecoy},
		{Name: "VALID", Action: EnvironmentBindingSet, Source: EnvironmentSourceConnectionConfig},
		{Name: "VALID", Action: EnvironmentBindingSet, Source: EnvironmentSourceRuntime, SourceField: "field"},
		{Name: "VALID", Action: EnvironmentBindingUnset, Source: EnvironmentSourceDecoy, SourceField: "field"},
		{Name: "VALID", Action: EnvironmentBindingUnset, Source: EnvironmentSourceRuntime},
	}
	for index, candidate := range tests {
		err := candidate.Validate()
		if err == nil {
			t.Fatalf("invalid binding %d passed validation: %+v", index, candidate)
		}
	}

	for _, source := range []EnvironmentBindingSource{EnvironmentSourceProxy, EnvironmentSourceCA} {
		candidate := EnvironmentBinding{Name: "VALID", Action: EnvironmentBindingSet, Source: source}
		if err := candidate.Validate(); err != nil {
			t.Fatalf("local source %q rejected: %v", source, err)
		}
	}
	for _, source := range []EnvironmentBindingSource{
		EnvironmentSourceConnectionConfig,
		EnvironmentSourceIdentifier,
		EnvironmentSourceDecoy,
	} {
		candidate := EnvironmentBinding{Name: "VALID", Action: EnvironmentBindingSet, Source: source, SourceField: "field"}
		if err := candidate.Validate(); err != nil {
			t.Fatalf("provider source %q rejected: %v", source, err)
		}
	}

	if err := ValidateEnvironmentBindings([]EnvironmentBinding{binding, binding}); err == nil {
		t.Fatal("duplicate environment binding names passed validation")
	}
	if err := ValidateEnvironmentBindings([]EnvironmentBinding{binding}); err != nil {
		t.Fatalf("valid environment binding collection rejected: %v", err)
	}
}

func TestResolvedEnvironmentBindingProvenanceIsFailClosedAndValueFree(t *testing.T) {
	bindings := []EnvironmentBinding{
		{Name: "AWS_ACCESS_KEY_ID", Action: EnvironmentBindingSet, Source: EnvironmentSourceIdentifier, SourceField: "access_key_id", SystemManaged: true},
		{Name: "AWS_SECRET_ACCESS_KEY", Action: EnvironmentBindingSet, Source: EnvironmentSourceDecoy, SourceField: "secret_access_key", Sensitive: true, SystemManaged: true},
		{Name: "PGDATABASE", Action: EnvironmentBindingSet, Source: EnvironmentSourceConnectionConfig, SourceField: "database_name", SystemManaged: true},
		{Name: "AWS_PROFILE", Action: EnvironmentBindingUnset, Source: EnvironmentSourceRuntime, SourceField: "secret_access_key", SystemManaged: true},
	}
	identifiers := map[string]string{"accessKeyId": "identifier-sentinel"}
	decoys := map[string]string{"secretAccessKey": "decoy-sentinel"}
	connectionConfig := map[string]interface{}{"databaseName": "database-sentinel"}
	agentEnv := map[string]string{
		"AWS_ACCESS_KEY_ID":     "identifier-sentinel",
		"AWS_SECRET_ACCESS_KEY": "decoy-sentinel",
	}
	configEnv := map[string]string{"PGDATABASE": "database-sentinel"}

	if err := ValidateResolvedEnvironmentBindings(bindings, identifiers, decoys, connectionConfig, agentEnv, configEnv); err != nil {
		t.Fatalf("resolved environment provenance rejected: %v", err)
	}
	if err := ValidateResolvedEnvironmentBindings(
		nil,
		identifiers,
		decoys,
		connectionConfig,
		map[string]string{"LEGACY_UNDECLARED": "legacy-value"},
		configEnv,
	); err == nil {
		t.Fatal("v1 response without environmentBindings accepted")
	}

	assertRejectedWithoutValues := func(err error) {
		t.Helper()
		if err == nil {
			t.Fatal("invalid resolved environment provenance was accepted")
		}
		for _, value := range []string{"identifier-sentinel", "decoy-sentinel", "database-sentinel", "wrong-sentinel"} {
			if strings.Contains(err.Error(), value) {
				t.Fatalf("resolved provenance error leaked a value: %v", err)
			}
		}
	}

	wrongAgentEnv := map[string]string{
		"AWS_ACCESS_KEY_ID":     "wrong-sentinel",
		"AWS_SECRET_ACCESS_KEY": "decoy-sentinel",
	}
	assertRejectedWithoutValues(ValidateResolvedEnvironmentBindings(
		bindings, identifiers, decoys, connectionConfig, wrongAgentEnv, configEnv,
	))

	extraAgentEnv := map[string]string{
		"AWS_ACCESS_KEY_ID":     "identifier-sentinel",
		"AWS_SECRET_ACCESS_KEY": "decoy-sentinel",
		"UNDECLARED":            "extra-agent-env-value-sentinel",
	}
	extraErr := ValidateResolvedEnvironmentBindings(
		bindings, identifiers, decoys, connectionConfig, extraAgentEnv, configEnv,
	)
	if extraErr == nil {
		t.Fatal("undeclared AgentEnv entry was accepted with modern bindings")
	}
	if strings.Contains(extraErr.Error(), "extra-agent-env-value-sentinel") {
		t.Fatalf("AgentEnv coverage error leaked an undeclared value: %v", extraErr)
	}

	caseAliasedAgentEnv := map[string]string{
		"aws_access_key_id":     "identifier-sentinel",
		"AWS_SECRET_ACCESS_KEY": "decoy-sentinel",
	}
	assertRejectedWithoutValues(ValidateResolvedEnvironmentBindings(
		bindings, identifiers, decoys, connectionConfig, caseAliasedAgentEnv, configEnv,
	))

	ambiguousIdentifiers := map[string]string{
		"accessKeyId":   "identifier-sentinel",
		"access_key_id": "identifier-sentinel",
	}
	assertRejectedWithoutValues(ValidateResolvedEnvironmentBindings(
		bindings, ambiguousIdentifiers, decoys, connectionConfig, agentEnv, configEnv,
	))

	wrongConfigEnv := map[string]string{"PGDATABASE": "wrong-sentinel"}
	assertRejectedWithoutValues(ValidateResolvedEnvironmentBindings(
		bindings, identifiers, decoys, connectionConfig, agentEnv, wrongConfigEnv,
	))

	ambiguousConfig := map[string]interface{}{
		"databaseName":  "database-sentinel",
		"database_name": "database-sentinel",
	}
	assertRejectedWithoutValues(ValidateResolvedEnvironmentBindings(
		bindings, identifiers, decoys, ambiguousConfig, agentEnv, configEnv,
	))

	runtimeOnly := []EnvironmentBinding{{
		Name: "AWS_PROFILE", Action: EnvironmentBindingUnset, Source: EnvironmentSourceRuntime,
		SourceField: "secret_access_key", SystemManaged: true,
	}}
	assertRejectedWithoutValues(ValidateResolvedEnvironmentBindings(
		runtimeOnly, identifiers, map[string]string{}, connectionConfig, agentEnv, configEnv,
	))

	for _, source := range []EnvironmentBindingSource{EnvironmentSourceProxy, EnvironmentSourceCA} {
		localOnly := []EnvironmentBinding{{
			Name: "PHASE_LOCAL", Action: EnvironmentBindingSet, Source: source, SystemManaged: true,
		}}
		assertRejectedWithoutValues(ValidateResolvedEnvironmentBindings(
			localOnly, identifiers, decoys, connectionConfig, agentEnv, configEnv,
		))
	}
}

func TestProcessEnvironmentPlanContractValidationAndRedaction(t *testing.T) {
	const decoy = "process-environment-decoy"
	plan := ProcessEnvironmentPlan{
		Set: AgentEnvironment{
			"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE", "AWS_SECRET_ACCESS_KEY": decoy,
			"HTTP_PROXY": "http://phase:capability@127.0.0.1:9543", "http_proxy": "http://phase:capability@127.0.0.1:9543",
			"HTTPS_PROXY": "http://phase:capability@127.0.0.1:9543", "https_proxy": "http://phase:capability@127.0.0.1:9543",
			"NO_PROXY": "localhost", "no_proxy": "localhost",
		},
		Unset: []string{"AWS_PROFILE", "AWS_CONFIG_FILE"},
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("canonical process environment rejected: %v", err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("Marshal process environment: %v", err)
	}
	if !bytes.Contains(encoded, []byte(decoy)) {
		t.Fatalf("wire JSON dropped process environment value: %s", encoded)
	}
	for _, formatted := range []string{fmt.Sprintf("%v", plan), fmt.Sprintf("%+v", plan), fmt.Sprintf("%#v", plan)} {
		if strings.Contains(formatted, decoy) || !strings.Contains(formatted, redactedValue) {
			t.Fatalf("process environment formatting leaked set values: %s", formatted)
		}
	}

	invalid := []ProcessEnvironmentPlan{
		{Set: AgentEnvironment{"TOKEN": "one", "token": "two"}},
		{Set: AgentEnvironment{"TOKEN": "same", "token": "same"}},
		{Set: AgentEnvironment{"TOKEN": "one"}, Unset: []string{"token"}},
		{Unset: []string{"TOKEN", "token"}},
		{Set: AgentEnvironment{"NOT-AN-ENV": "one"}},
	}
	for index, candidate := range invalid {
		err := candidate.Validate()
		if err == nil {
			t.Fatalf("invalid process environment %d passed validation", index)
		}
		for _, value := range candidate.Set {
			if value != "" && strings.Contains(err.Error(), value) {
				t.Fatalf("validation error leaked set value: %v", err)
			}
		}
	}
}

func TestUnknownInjectionActionCanBeRepresentedAndRejected(t *testing.T) {
	var injection Injection
	if err := json.Unmarshal([]byte(`{"action":"future_protocol_action"}`), &injection); err != nil {
		t.Fatalf("Unmarshal unknown action: %v", err)
	}
	if injection.Action != "future_protocol_action" {
		t.Fatalf("action = %q", injection.Action)
	}
	if injection.Action.IsKnown() {
		t.Fatal("unknown action reported as known")
	}
	if err := injection.Validate(); err == nil {
		t.Fatal("unknown action must fail explicit validation")
	}
}

func TestConnectionAuthorizationRoundTrip(t *testing.T) {
	raw := []byte(`{
		"version":1,
		"mode":"connection",
		"accessMode":"allow",
		"state":"allowed"
	}`)
	var authorization ConnectionAuthorization
	if err := json.Unmarshal(raw, &authorization); err != nil {
		t.Fatalf("Unmarshal authorization: %v", err)
	}
	encoded, err := json.Marshal(authorization)
	if err != nil {
		t.Fatalf("Marshal authorization: %v", err)
	}
	assertJSONEqual(t, raw, encoded)
	if !authorization.AllowsUse() {
		t.Fatal("allow attestation was not accepted")
	}
	authorization.AccessMode = "future_mode"
	if authorization.AllowsUse() {
		t.Fatal("unknown access mode was accepted")
	}
}

func TestRuntimeOperationalFieldsDecode(t *testing.T) {
	raw := []byte(`{
		"grantId":"grant-postgres",
		"connectionId":"connection-postgres",
		"credentialId":"credential-postgres",
		"credentialName":"PostgreSQL production",
		"credentialProvider":"postgres",
		"credentialRevision":"credential-v1",
		"serviceType":"postgres",
		"protocol":"postgres",
		"hosts":[{"match":"exact","value":"db.internal.example","port":5432}],
		"connectionConfig":{"database":"app"},
		"injection":{"action":"pg_handshake","valueFrom":{"source":"credential","fields":{"username":"username","password":"password"}}},
		"onRefresh":"none",
		"identifiers":{},
		"decoyMaterial":{},
		"agentEnv":{},
		"secretMaterial":{},
		"authorization":{"version":1,"mode":"connection","accessMode":"allow","state":"allowed"}
	}`)
	var connection RuntimeConnection
	if err := json.Unmarshal(raw, &connection); err != nil {
		t.Fatalf("Unmarshal runtime connection: %v", err)
	}
	if connection.OnRefresh != RefreshNone {
		t.Fatalf("operational fields missing: %+v", connection)
	}
	if err := connection.Injection.Validate(); err != nil {
		t.Fatalf("PostgreSQL injection rejected: %v", err)
	}
	if connection.Authorization.State != ConnectionAuthorizationAllowed {
		t.Fatalf("authorization = %+v", connection.Authorization)
	}
	encoded, err := json.Marshal(connection)
	if err != nil {
		t.Fatalf("Marshal runtime connection: %v", err)
	}
	assertJSONEqual(t, raw, encoded)
}

func TestAgentRequestCooldownContractFixture(t *testing.T) {
	request := readContractFixture[AgentRequest](t, "agent_request.json")
	if !request.Cooldown || request.Kind != RequestCredentialUpdate || request.CredentialProvider != "aws" || request.Markdown != "Update AWS permissions" || request.Status != RequestPending {
		t.Fatalf("request contract fields = %+v", request)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}
	if !bytes.Contains(encoded, []byte(`"cooldown":true`)) {
		t.Fatalf("cooldown missing from request wire JSON: %s", encoded)
	}
}

func fixtureRoundTrip[T any](t *testing.T, name string) T {
	t.Helper()
	raw := readFixture(t, name)
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("Unmarshal %s: %v", name, err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal %s: %v", name, err)
	}
	assertJSONEqual(t, raw, encoded)
	return value
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "contracts", "v1", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func assertJSONEqual(t *testing.T, want, got []byte) {
	t.Helper()
	var wantValue interface{}
	var gotValue interface{}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("decode expected JSON: %v", err)
	}
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("decode actual JSON: %v", err)
	}
	if !reflect.DeepEqual(wantValue, gotValue) {
		t.Fatalf("JSON mismatch\nwant: %s\n got: %s", want, got)
	}
}

func readContractFixture[T any](t *testing.T, name string) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(readFixture(t, name), &value); err != nil {
		t.Fatalf("unmarshal contract fixture %s: %v", name, err)
	}
	return value
}
