package agentapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A value pasted into the Connection's own name is withheld like any value
// the Agent can read, and the name with it: status, events and every list of
// Connections print the name. A Connection withheld for another reason, and
// one that is not withheld, keep theirs.
func TestANameThatHoldsTheWithheldValueIsWithheldToo(t *testing.T) {
	const token = "tok_ABCDEFGHIJKLMNOPQRSTUV123456"
	named := resolvedCustomConnection("connection-named", token)
	named["connectionName"], named["credentialName"] = "Billing "+token, "Billing key "+token
	elsewhere := resolvedCustomConnection("connection-elsewhere", exposedCustomValue)
	elsewhere["connectionName"], elsewhere["credentialName"] = "Ledger", "Ledger key"
	elsewhere["identifiers"] = map[string]string{"account": "acct-" + exposedCustomValue}
	safe := resolvedCustomConnection("connection-safe", "safe-live-value-0123456789")
	safe["connectionName"], safe["credentialName"] = "Search", "Search key"
	_, response := openThroughConsole(t, testToken("pss_user", 1, ""), sessionPayload("", named, elsewhere, safe))

	withheld := response.Connections[0]
	if withheld.MaterialFailure() != MaterialFailureExposed || withheld.ConnectionName != WithheldConnectionName || withheld.CredentialName != WithheldConnectionName {
		t.Fatalf("a name that holds the value: failure=%q name=%q credential=%q", withheld.MaterialFailure(), withheld.ConnectionName, withheld.CredentialName)
	}
	printed, err := json.Marshal(withheld)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(printed), token) || strings.Contains(fmt.Sprintf("%+v", withheld), token) {
		t.Fatal("the Connection still holds the value somewhere it is printed from")
	}
	if other := response.Connections[1]; other.MaterialFailure() != MaterialFailureExposed || other.ConnectionName != "Ledger" || other.CredentialName != "Ledger key" {
		t.Fatalf("a Connection withheld for its identifier lost its name: %q %q %q", other.MaterialFailure(), other.ConnectionName, other.CredentialName)
	}
	if kept := response.Connections[2]; kept.MaterialUnavailable() || kept.ConnectionName != "Search" || kept.CredentialName != "Search key" {
		t.Fatalf("a Connection nothing is wrong with was changed: %q %q", kept.ConnectionName, kept.CredentialName)
	}
}
