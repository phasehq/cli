package aiproxy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/agentapi/providerrulestest"
)

// withProviderRules adds to a Connection payload the provider rules its
// service's manifest sends (credentialEnvironment, secretGuard,
// actionClasses), keeping any the test set itself.
func withProviderRules(connection map[string]any) map[string]any {
	service, _ := connection["serviceType"].(string)
	raw := providerrulestest.Raw(service)
	if raw == nil {
		return connection
	}
	var rules map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rules); err != nil {
		panic(err)
	}
	for name, value := range rules {
		if _, present := connection[name]; !present {
			connection[name] = value
		}
	}
	return connection
}

// withConnectionRules is withProviderRules for a Connection built in Go.
func withConnectionRules(connection agentapi.Connection) agentapi.Connection {
	return providerrulestest.Apply(connection)
}

// The provider's guard and call classes apply in place on refresh, like the
// policy. Its credential environment names reach the Agent's processes, so a
// change to them recycles the session like any other environment change.
func TestProviderRulesOnRefresh(t *testing.T) {
	aws := func(mutate func(map[string]any)) []*binding {
		payload := awsPolicyConnection(nil)
		if mutate != nil {
			mutate(payload)
		}
		return []*binding{bindingFor(t, payload)}
	}
	before := aws(nil)
	if change := classifyConfigChange(before, aws(nil), nil, nil); change.reprovision || change.reshaped {
		t.Fatalf("unchanged: %+v", change)
	}
	inPlace := map[string]func(map[string]any){
		"secret guard": func(c map[string]any) {
			c["secretGuard"] = map[string]any{"operations": map[string]any{"sts": []string{"AssumeRole"}}}
		},
		"call classes": func(c map[string]any) {
			var classes map[string]any
			_ = json.Unmarshal(c["actionClasses"].(json.RawMessage), &classes)
			classes["exact"] = map[string]string{"s3:DeleteObject": "admin"}
			c["actionClasses"] = classes
		},
		"credential environment order": func(c map[string]any) {
			names := append([]string(nil), providerrulestest.CredentialEnvironment("aws")...)
			names[0], names[1] = names[1], names[0]
			c["credentialEnvironment"] = names
		},
	}
	for name, mutate := range inPlace {
		after := aws(mutate)
		if change := classifyConfigChange(before, after, nil, nil); change.reprovision {
			t.Errorf("%s: a change the proxy alone applies recycled the session", name)
		}
	}
	guarded := aws(inPlace["secret guard"])[0].connection
	if len(guarded.SecretGuard.Operations) != 1 || len(guarded.SecretGuard.Paths) != 0 {
		t.Fatalf("refreshed guard = %+v", guarded.SecretGuard)
	}
	changed := aws(func(c map[string]any) { c["credentialEnvironment"] = []string{"AWS_ACCESS_KEY_ID"} })
	if change := classifyConfigChange(before, changed, nil, nil); !change.reprovision {
		t.Error("a credential environment change did not recycle the session")
	}

	invalid := awsPolicyConnection(nil)
	invalid["credentialEnvironment"] = []string{"AWS_ACCESS_KEY_ID,AWS_PROFILE"}
	session := decodeTestSession(t, customSessionPayload("backend", 1, invalid))
	if _, err := parseBindings(session.Connections); err == nil || !strings.Contains(err.Error(), "credentialEnvironment") {
		t.Fatalf("an invalid credential environment was accepted: %v", err)
	}
	missing := awsPolicyConnection(nil)
	missing["secretGuard"] = nil // sent as null, so the test helpers do not fill it in
	b := bindingFor(t, missing)
	if decision := b.authorizationDecision(time.Now()); decision.allowed || decision.code != codeProviderRulesMissing ||
		b.printableState(time.Now()) != "unavailable" || b.stateReason(time.Now()) != agentapi.ProviderRulesMissing {
		t.Fatalf("an AWS Connection without its guard: %+v", decision)
	}
}
