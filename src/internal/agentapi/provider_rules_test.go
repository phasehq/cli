package agentapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// decodeProviderRules decodes the rules the service's manifest sends into the
// Connection, as a session payload carries them. (providerrulestest imports
// this package, so its files are read directly here.)
func decodeProviderRules(t *testing.T, connection *Connection) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("providerrulestest", connection.ServiceType+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, connection); err != nil {
		t.Fatal(err)
	}
}

func TestProviderRulesDecodeFromTheSessionPayload(t *testing.T) {
	aws := Connection{ServiceType: "aws"}
	decodeProviderRules(t, &aws)
	if aws.SecretGuard.Unsupported() || len(aws.SecretGuard.Operations["sts"]) == 0 ||
		len(aws.SecretGuard.Paths) == 0 || len(aws.CredentialEnvironment) == 0 {
		t.Fatalf("aws rules = %+v %v", aws.SecretGuard, aws.CredentialEnvironment)
	}
	if err := ValidateCredentialEnvironment(aws.CredentialEnvironment); err != nil {
		t.Fatal(err)
	}
	// What the Agent may be shown is the rules as the Console sent them.
	encoded, err := json.Marshal(aws.SecretGuard)
	if err != nil || !strings.Contains(string(encoded), `"operations"`) {
		t.Fatalf("encoded = %s err=%v", encoded, err)
	}
}

func TestCredentialEnvironmentNamesAreBounded(t *testing.T) {
	for _, names := range [][]string{
		{"lower_case"}, {"WITH,COMMA"}, {"1LEADING_DIGIT"}, {""}, {"A-B"}, {strings.Repeat("A", 129)},
		make([]string, 65),
	} {
		if err := ValidateCredentialEnvironment(names); err == nil {
			t.Errorf("%q was accepted", names)
		}
	}
	if err := ValidateCredentialEnvironment([]string{"GITHUB_TOKEN", "_X1", strings.Repeat("A", 128)}); err != nil {
		t.Fatal(err)
	}
}

// The canonical session fixture carries the AWS rules the manifest sends, and
// its AWS Connection is usable.
func TestCanonicalSessionFixtureCarriesTheAWSProviderRules(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "open_session_response.json"))
	if err != nil {
		t.Fatal(err)
	}
	var response OpenSessionResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	fixture := response.Connections[0]
	want := Connection{ServiceType: "aws"}
	decodeProviderRules(t, &want)
	if fixture.AccessPolicyFailure() != "" {
		t.Fatalf("the fixture's AWS Connection is unavailable: %s", fixture.AccessPolicyFailure())
	}
	for name, pair := range map[string][2]any{
		"credentialEnvironment": {fixture.CredentialEnvironment, want.CredentialEnvironment},
		"secretGuard":           {fixture.SecretGuard, want.SecretGuard},
	} {
		left, _ := json.Marshal(pair[0])
		right, _ := json.Marshal(pair[1])
		var leftValue, rightValue any
		_ = json.Unmarshal(left, &leftValue)
		_ = json.Unmarshal(right, &rightValue)
		if !reflect.DeepEqual(leftValue, rightValue) {
			t.Errorf("fixture %s differs from providerrulestest/aws.json", name)
		}
	}
}
