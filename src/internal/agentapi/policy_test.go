package agentapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

const policyPayload = `{"version":1,"default":"allow","rules":[` +
	`{"class":"delete","effect":"block"},{"class":"create","effect":"ask"},` +
	`{"match":{"methods":["POST"],"path":"/v1/charges/*"},"effect":"block"}],` +
	`"temporaryAllows":[{"id":"allow-1","class":"delete","expiresAt":"2026-11-15T10:00:00Z"},` +
	`{"id":"allow-2","match":{"methods":["DELETE"],"path":"/repos/acme/x"},"expiresAt":"2026-11-15T11:00:00Z"}],` +
	`"managed":[{"id":"secret_guard","locked":true,"rules":[{"class":"credential_minting","effect":"block"}]}]}`

func TestConnectionDecodesPolicyAndGrantExpiry(t *testing.T) {
	payload := `{"grantId":"grant-1","connectionId":"connection-1","serviceType":"http","protocol":"http",` +
		`"policy":` + policyPayload + `,` +
		`"grantExpiresAt":"2026-11-15T10:00:00Z"}`
	var connection Connection
	if err := json.Unmarshal([]byte(payload), &connection); err != nil {
		t.Fatal(err)
	}
	policy := connection.Policy
	if policy == nil || policy.Unsupported() || !policy.Restricts() || policy.Default != PolicyAllow || len(policy.Rules) != 3 ||
		policy.Rules[0] != (PolicyRule{Class: ClassDelete, Effect: PolicyBlock}) || policy.Rules[1].Effect != PolicyAsk ||
		policy.Rules[2].Match == nil || !reflect.DeepEqual(policy.Rules[2].Match.Methods, []string{"POST"}) || policy.Rules[2].Match.Path != "/v1/charges/*" {
		t.Fatalf("policy = %+v", policy)
	}
	if len(policy.TemporaryAllows) != 2 || policy.TemporaryAllows[0].ID != "allow-1" || policy.TemporaryAllows[0].Class != ClassDelete ||
		!policy.TemporaryAllows[0].ExpiresAt.Equal(time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)) ||
		policy.TemporaryAllows[1].Match == nil || policy.TemporaryAllows[1].Match.Path != "/repos/acme/x" {
		t.Fatalf("temporary allows = %+v", policy.TemporaryAllows)
	}
	if connection.GrantExpiresAt == nil || connection.AccessPolicyFailure() != "" ||
		connection.GrantExpired(time.Date(2026, 11, 15, 9, 59, 59, 0, time.UTC)) ||
		!connection.GrantExpired(time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("grant expiry = %v", connection.GrantExpiresAt)
	}
	// The policy is shown to the Agent as the Console sent it, managed entry
	// and all.
	relayed, err := json.Marshal(connection.Policy)
	if err != nil || string(relayed) != policyPayload {
		t.Fatalf("relayed policy = %s err=%v", relayed, err)
	}

	var plain Connection
	if err := json.Unmarshal([]byte(`{"grantId":"grant-1","connectionId":"connection-1","serviceType":"http","protocol":"http"}`), &plain); err != nil {
		t.Fatal(err)
	}
	if plain.Policy != nil || plain.Policy.Restricts() || plain.Policy.Unsupported() ||
		plain.GrantExpiresAt != nil || plain.GrantExpired(time.Now()) || plain.AccessPolicyFailure() != "" {
		t.Fatalf("a Connection without the new members = %+v", plain)
	}
	encoded, err := json.Marshal(plain)
	if err != nil || strings.Contains(string(encoded), "policy") || strings.Contains(string(encoded), "grantExpiresAt") {
		t.Fatalf("absent members were encoded: %s", encoded)
	}
}

func TestPolicyThatOnlyAllowsDoesNotRestrict(t *testing.T) {
	for name, document := range map[string]string{
		"empty object":               `{}`,
		"default allow, no rules":    `{"version":1,"default":"allow","rules":[]}`,
		"only allow rules":           `{"version":1,"default":"allow","rules":[{"class":"read","effect":"allow"}]}`,
		"only the managed guard":     `{"version":1,"default":"allow","rules":[],"temporaryAllows":[],"managed":[{"id":"secret_guard","locked":true,"rules":[{"class":"credential_minting","effect":"block"}]}]}`,
		"a managed entry from later": `{"version":1,"default":"allow","rules":[],"managed":[{"id":"block_deletes","locked":true,"note":{"nested":true}}]}`,
	} {
		var policy AccessPolicy
		if err := json.Unmarshal([]byte(document), &policy); err != nil || policy.Unsupported() || policy.Restricts() || policy.Default != PolicyAllow {
			t.Errorf("%s: policy = %+v err=%v", name, policy, err)
		}
	}
	for name, document := range map[string]string{
		"default ask":   `{"version":1,"default":"ask","rules":[]}`,
		"default block": `{"version":1,"default":"block","rules":[]}`,
		"an ask rule":   `{"version":1,"rules":[{"class":"create","effect":"ask"}]}`,
		"a block rule":  `{"version":1,"default":"allow","rules":[{"match":{"methods":["DELETE"]},"effect":"block"}]}`,
	} {
		var policy AccessPolicy
		if err := json.Unmarshal([]byte(document), &policy); err != nil || policy.Unsupported() || !policy.Restricts() {
			t.Errorf("%s: policy = %+v err=%v", name, policy, err)
		}
	}
}

// A policy this client cannot read in full is never enforced in part: the
// whole Connection is unavailable instead. That covers a higher version, and a
// class, effect or rule kind this client does not know.
func TestUnreadablePolicyMakesTheConnectionUnavailable(t *testing.T) {
	for name, document := range map[string]string{
		"version 2":                       `{"version":2,"default":"allow","rules":[]}`,
		"a higher version, known content": `{"version":2,"default":"allow","rules":[{"class":"delete","effect":"block"}]}`,
		"version 0":                       `{"version":0,"default":"allow","rules":[]}`,
		"rules without a version":         `{"rules":[{"class":"delete","effect":"block"}]}`,
		"default without a version":       `{"default":"block"}`,
		"unknown default":                 `{"version":1,"default":"deny","rules":[]}`,
		"unknown effect":                  `{"version":1,"rules":[{"class":"delete","effect":"audit"}]}`,
		"unknown class":                   `{"version":1,"rules":[{"class":"billing","effect":"block"}]}`,
		"the admin class":                 `{"version":1,"rules":[{"class":"admin","effect":"block"}]}`,
		"the guard's class in a rule":     `{"version":1,"rules":[{"class":"credential_minting","effect":"allow"}]}`,
		"class and match":                 `{"version":1,"rules":[{"class":"delete","match":{"methods":["DELETE"]},"effect":"block"}]}`,
		"neither class nor match":         `{"version":1,"rules":[{"effect":"block"}]}`,
		"empty match":                     `{"version":1,"rules":[{"match":{},"effect":"block"}]}`,
		"a rule by AWS action":            `{"version":1,"rules":[{"operation":"ec2:TerminateInstances","effect":"block"}]}`,
		"a rule kind from later":          `{"version":1,"rules":[{"header":{"name":"X-Debug"},"effect":"block"}]}`,
		"a condition from later":          `{"version":1,"rules":[{"class":"delete","effect":"allow","when":{"hosts":["a.example"]}}]}`,
		"a match member from later":       `{"version":1,"rules":[{"match":{"methods":["GET"],"query":"x=*"},"effect":"allow"}]}`,
		"lower-case method":               `{"version":1,"rules":[{"match":{"methods":["delete"]},"effect":"block"}]}`,
		"too many methods":                `{"version":1,"rules":[{"match":{"methods":["A","B","C","D","E","F","G","H","I","J"]},"effect":"block"}]}`,
		"relative path":                   `{"version":1,"rules":[{"match":{"path":"v1/*"},"effect":"block"}]}`,
		"path too long":                   `{"version":1,"rules":[{"match":{"path":"/` + strings.Repeat("a", 1024) + `"},"effect":"block"}]}`,
		"rules is not a list":             `{"version":1,"rules":{"class":"delete"}}`,
		"not an object":                   `["allow"]`,
	} {
		var connection Connection
		payload := `{"connectionId":"connection-1","serviceType":"http","protocol":"http","policy":` + document + `}`
		if err := json.Unmarshal([]byte(payload), &connection); err != nil {
			t.Errorf("%s: the session payload was refused outright: %v", name, err)
			continue
		}
		if !connection.Policy.Unsupported() || connection.AccessPolicyFailure() != AccessPolicyUnsupported ||
			connection.Policy.Restricts() || len(connection.Policy.Rules) != 0 {
			t.Errorf("%s: policy = %+v failure=%q", name, connection.Policy, connection.AccessPolicyFailure())
		}
	}
}

// Keys this client does not know are ignored everywhere but inside a policy's
// rules: beside the policy's own members, on a Connection, in the payload.
func TestUnknownKeysOutsideThePolicyRulesAreIgnored(t *testing.T) {
	payload := `{"schemaVersion":1,"sessionUid":"session-1","configGeneration":2,"configEnv":{},"auditTrail":{"since":"2026-11-01"},"connections":[` +
		`{"connectionId":"connection-1","serviceType":"http","protocol":"http",` +
		`"operationClasses":[{"match":{"methods":["POST"]},"class":"read"}],"actionClasses":{"scheme":"aws_actions","version":7},"riskScore":3,` +
		`"policy":{"version":1,"default":"ask","rules":[{"class":"delete","effect":"block"}],"note":"set by ops","reviewAt":"2027-01-01T00:00:00Z"}}]}`
	var config SessionConfig
	if err := json.Unmarshal([]byte(payload), &config); err != nil {
		t.Fatal(err)
	}
	connection := config.Connections[0]
	if connection.AccessPolicyFailure() != "" || connection.Policy.Unsupported() || connection.Policy.Default != PolicyAsk ||
		len(connection.Policy.Rules) != 1 || connection.Policy.Rules[0] != (PolicyRule{Class: ClassDelete, Effect: PolicyBlock}) {
		t.Fatalf("connection = %+v failure=%q", connection.Policy, connection.AccessPolicyFailure())
	}
}

// A temporary allow can only turn an ask into an allow, so one that cannot be
// read is dropped and the rest of the policy stands.
func TestUnreadableTemporaryAllowIsDroppedNotFatal(t *testing.T) {
	document := `{"version":1,"rules":[{"class":"delete","effect":"ask"}],"temporaryAllows":[` +
		`{"id":"good","class":"delete","expiresAt":"2026-11-15T10:00:00Z"},` +
		`{"id":"no-expiry","class":"delete"},` +
		`{"id":"bad-expiry","class":"delete","expiresAt":"tomorrow"},` +
		`{"id":"guard","class":"credential_minting","expiresAt":"2026-11-15T10:00:00Z"},` +
		`{"id":"both","class":"delete","match":{"methods":["DELETE"]},"expiresAt":"2026-11-15T10:00:00Z"},` +
		`{"id":"later","class":"delete","expiresAt":"2026-11-15T10:00:00Z","uses":1},` +
		`{"id":"action","operation":"ec2:TerminateInstances","expiresAt":"2026-11-15T10:00:00Z"},` +
		`{"id":"admin","class":"admin","expiresAt":"2026-11-15T10:00:00Z"},` +
		`"not an object"]}`
	var policy AccessPolicy
	if err := json.Unmarshal([]byte(document), &policy); err != nil || policy.Unsupported() || !policy.Restricts() {
		t.Fatalf("policy = %+v err=%v", policy, err)
	}
	if len(policy.TemporaryAllows) != 1 || policy.TemporaryAllows[0].ID != "good" {
		t.Fatalf("temporary allows = %+v", policy.TemporaryAllows)
	}
}

func TestSessionConfigCarriesExpiredConnections(t *testing.T) {
	payload := `{"schemaVersion":1,"sessionUid":"session-1","configGeneration":2,"configEnv":{},"connections":[],` +
		`"expiredConnections":[{"connectionId":"connection-old","connectionName":"Staging AWS","serviceType":"aws","expiredAt":"2026-11-13T10:00:00Z"}]}`
	var config SessionConfig
	if err := json.Unmarshal([]byte(payload), &config); err != nil {
		t.Fatal(err)
	}
	want := ExpiredConnection{ConnectionID: "connection-old", ConnectionName: "Staging AWS", ServiceType: "aws", ExpiredAt: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)}
	if len(config.ExpiredConnections) != 1 || config.ExpiredConnections[0] != want {
		t.Fatalf("expired connections = %+v", config.ExpiredConnections)
	}
	var discover DiscoverResponse
	if err := json.Unmarshal([]byte(`{"schemaVersion":1,"sessionUid":"session-1","configGeneration":2,"configEnv":{},"connections":[{"connectionId":"c","policy":`+policyPayload+`,"grantExpiresAt":"2026-11-15T10:00:00Z"}],`+
		`"expiredConnections":[{"connectionId":"connection-old","serviceType":"aws","expiredAt":"2026-11-13T10:00:00Z"}]}`), &discover); err != nil {
		t.Fatal(err)
	}
	relayed, err := json.Marshal(discover)
	if err != nil || !strings.Contains(string(relayed), `"policy":`+policyPayload) || !strings.Contains(string(relayed), `"grantExpiresAt":"2026-11-15T10:00:00Z"`) ||
		!strings.Contains(string(relayed), `"expiredConnections":[{"connectionId":"connection-old","serviceType":"aws","expiredAt":"2026-11-13T10:00:00Z"}]`) {
		t.Fatalf("relayed discover = %s err=%v", relayed, err)
	}
}

func TestPresetHostsAreReadAsRulesOrNames(t *testing.T) {
	var registry RegistryResponse
	if err := json.Unmarshal([]byte(`{"schemaVersion":1,"capabilities":{},"services":{},"presets":[`+
		`{"id":"github","name":"GitHub","description":"GitHub REST and GraphQL","category":"developer","hosts":[{"match":"exact","value":"api.github.com","port":443}]},`+
		`{"id":"gitlab","name":"GitLab","category":"developer","hostsEditable":true,"hosts":["gitlab.com",{"match":"suffix","value":".gitlab.example"},{"value":"registry.gitlab.com"},7,""]},`+
		`{"id":"mcp","name":"MCP server","hostsEditable":true,"hosts":[]}]}`), &registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.Presets) != 3 || registry.Presets[0].ID != "github" || registry.Presets[1].HostsEditable != true {
		t.Fatalf("presets = %+v", registry.Presets)
	}
	if got := registry.Presets[0].HostRules(); !reflect.DeepEqual(got, []HostRule{{Match: "exact", Value: "api.github.com", Port: 443}}) {
		t.Fatalf("github hosts = %+v", got)
	}
	if got := registry.Presets[1].HostRules(); !reflect.DeepEqual(got, []HostRule{
		{Match: "exact", Value: "gitlab.com"}, {Match: "suffix", Value: ".gitlab.example"}, {Match: "exact", Value: "registry.gitlab.com"},
	}) {
		t.Fatalf("gitlab hosts = %+v", got)
	}
	if got := registry.Presets[2].HostRules(); len(got) != 0 {
		t.Fatalf("mcp hosts = %+v", got)
	}
}

func TestRegistryIsReadWithTheDurableTokenAndNoSessionCredential(t *testing.T) {
	var path, authorization, sessionCredential string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, authorization, sessionCredential = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get(SessionCredentialHeader)
		_, _ = w.Write([]byte(`{"schemaVersion":1,"presets":[{"id":"stripe","name":"Stripe","hosts":["api.stripe.com"]}]}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, testToken("pss_agent", 1, ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := client.Registry(context.Background())
	if err != nil || len(registry.Presets) != 1 || registry.Presets[0].ID != "stripe" {
		t.Fatalf("registry = %+v err=%v", registry, err)
	}
	if path != "/service/public/v1/agents/registry/" || !strings.HasPrefix(authorization, "Bearer Agent ") || sessionCredential != "" {
		t.Fatalf("registry request: path=%q authorization set=%t session credential=%q", path, authorization != "", sessionCredential)
	}
}

func TestCreateRequestCarriesDurationOnlyWhenSet(t *testing.T) {
	duration := 7200
	with, err := json.Marshal(CreateRequestRequest{Kind: "access_change", DurationSeconds: &duration, Action: json.RawMessage(`{"type":"agent_grant.renew","version":1,"connectionId":"c"}`)})
	if err != nil || !strings.Contains(string(with), `"durationSeconds":7200`) {
		t.Fatalf("with duration = %s err=%v", with, err)
	}
	without, err := json.Marshal(CreateRequestRequest{Kind: "access_change", Action: json.RawMessage(`{"type":"agent_grant.renew","version":1,"connectionId":"c"}`)})
	if err != nil || strings.Contains(string(without), "durationSeconds") {
		t.Fatalf("without duration = %s err=%v", without, err)
	}
}

func TestInjectionValueFormatsAreForwardedAndCompared(t *testing.T) {
	document := `{"injection":{"action":"set_header","name":"Authorization","valueFormat":"Bearer {value}","valueFormats":["token {value}"],"valueFrom":{"source":"credential","field":"token"}}}`
	var discover DiscoverConnection
	if err := json.Unmarshal([]byte(document), &discover); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(discover)
	if err != nil || !strings.Contains(string(encoded), `"valueFormats":["token {value}"]`) {
		t.Fatalf("discover = %s err=%v", encoded, err)
	}
	var connection Connection
	if err := json.Unmarshal([]byte(document), &connection); err != nil || len(connection.Injection.ValueFormats) != 1 {
		t.Fatalf("connection = %+v err=%v", connection.Injection, err)
	}
}
