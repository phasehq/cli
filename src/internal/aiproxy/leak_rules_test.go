package aiproxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/remoteapi"
	"github.com/phasehq/cli/pkg/censor"
)

// A rule file that is not the binary's own: one Phase token rule is there,
// one is there and cannot be applied, one is missing, and two other rules
// are from a later version. The one that cannot be applied names its
// validators under a key this version does not know. A rule with a key like
// that is left out, because the key may be a constraint; one whose validator
// alone is unknown is applied without it, and so would not do here.
const laterRuleFile = `
scoring:
  keywords: [token]
rules:
  - id: phase-service-token
    regex: '\bpss_service:v\d+:[0-9a-f]{64}(?::[0-9a-f]{64}){0,3}'
    hints: ['pss_service:']
    label: phase_service_token
  - id: phase-agent-token
    regex: '\bpss_agent:v\d+:[0-9a-f]{64}(?::[0-9a-f]{64}){0,3}'
    validators: [phase-token-2031]
    label: phase_agent_token
  - id: later-format
    regex: '\blater_[a-z0-9]{20}\b'
    action: quarantine
  - id: Odd Rule
    regex: '\bodd_[a-z0-9]{20}\b'
  - id: acme-token
    regex: '\bacme_[a-z0-9]{24}\b'
    label: acme_token
`

func phaseAgentToken() string {
	return "pss_agent:v1:" + strings.Repeat("0f1e2d3c", 8) + ":" + strings.Repeat("4b5a6978", 8)
}

// Rules the proxy cannot apply, and Phase token rules its file does not
// hold, are counted and named in status. They never stop the proxy: what
// does apply still protects.
func TestSkippedRulesAreReportedAndNeverStopTheProxy(t *testing.T) {
	rules, err := censor.ParseRules([]byte(laterRuleFile))
	if err != nil {
		t.Fatal(err)
	}
	guard, err := newLeakGuardWithRules(leakModeCensor, rules)
	if err != nil {
		t.Fatalf("the guard did not start with a rule file it cannot apply in full: %v", err)
	}
	registerLeakValues(t, guard, map[string]string{"stripe": leakSecretOne})
	status := guard.status()
	// Three the file holds and this version cannot apply, and the Phase rule
	// the file does not hold. An id that is no identifier is counted and not
	// named.
	if status.RulesSkipped != 4 || !reflect.DeepEqual(status.SkippedRules, []string{"later-format", "phase-agent-token", "phase-user-token"}) {
		t.Fatalf("status: %d skipped, %v", status.RulesSkipped, status.SkippedRules)
	}
	reasons := map[string]string{}
	for _, skipped := range guard.skipped {
		reasons[skipped.ID] = skipped.Reason
	}
	if reasons["phase-user-token"] != leakRuleAbsent || !strings.Contains(reasons["phase-agent-token"], "validator") || len(reasons) != 4 {
		t.Fatalf("why each was left out: %v", reasons)
	}

	// Status over the control API says the same, and the proxy answers.
	proxy := inventoryProxy(t, guard)
	recorder := controlCall(proxy, http.MethodGet, "/v1/status", "", nil)
	var answer remoteapi.StatusResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &answer) != nil || answer.LeakProtection == nil {
		t.Fatalf("status: %d %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"rulesSkipped":4,"skippedRules":["later-format","phase-agent-token","phase-user-token"]`) ||
		strings.Contains(recorder.Body.String(), "Odd Rule") || strings.Contains(recorder.Body.String(), "quarantine") {
		t.Fatalf("status JSON: %s", recorder.Body.String())
	}

	// What applies still protects. On a conversation path: the registered
	// value, the Phase token rule the file holds, and the file's other rule.
	conversation := guard.inspects(envFlow, "api.anthropic.com", 443)
	body := []byte(`{"messages":[{"role":"user","content":"` + leakSecretOne + ` token ` + phaseServiceToken() + ` and acme_0123456789abcdefghijklmn and ` + phaseAgentToken() + `"}]}`)
	scan := guard.newScan(conversation, "http", guard.scanOptionsFor(conversation, "/v1/messages"))
	out := guard.readPayload(scan, body, "body")
	if out == nil || bytes.Contains(out, []byte(leakSecretOne)) || bytes.Contains(out, []byte(phaseServiceToken())) || bytes.Contains(out, []byte("acme_0123456789abcdefghijklmn")) {
		t.Fatalf("what the rule file holds was not applied: %s", out)
	}
	// The rule that could not be applied is, as reported, not applied.
	if !bytes.Contains(out, []byte(phaseAgentToken())) {
		t.Fatal("a rule that was reported as skipped was applied")
	}
	// Off the conversation paths: the registered value and the Phase token
	// rule that is held, and nothing else.
	scan = guard.newScan(conversation, "http", guard.scanOptionsFor(conversation, "/api/event_logging/batch"))
	out = guard.readPayload(scan, body, "body")
	if out == nil || bytes.Contains(out, []byte(leakSecretOne)) || bytes.Contains(out, []byte(phaseServiceToken())) || !bytes.Contains(out, []byte("acme_0123456789abcdefghijklmn")) {
		t.Fatalf("off a conversation path: %s", out)
	}
	// A Phase token in a URL still blocks.
	blocking := guard.newScan(conversation, "http", guard.scanOptionsFor(conversation, "/v1/models"))
	blocking.addFound(leakPartURL, guard.index.FindWith([]byte("/v1/models?t="+phaseServiceToken()), blocking.opts), "url")
	if !blocking.block {
		t.Fatal("a Phase token in a URL does not block")
	}
}

// A rule file with none of Phase's own token rules starts the proxy too.
func TestAFileWithoutPhaseTokenRulesStillStartsTheProxy(t *testing.T) {
	rules, err := censor.ParseRules([]byte("rules:\n  - id: acme-token\n    regex: '\\bacme_[a-z0-9]{24}\\b'\n    label: acme_token\n"))
	if err != nil {
		t.Fatal(err)
	}
	guard, err := newLeakGuardWithRules(leakModeCensor, rules)
	if err != nil {
		t.Fatalf("the guard did not start without the Phase token rules: %v", err)
	}
	registerLeakValues(t, guard, map[string]string{"stripe": leakSecretOne})
	if status := guard.status(); status.RulesSkipped != 3 || !reflect.DeepEqual(status.SkippedRules, []string{"phase-agent-token", "phase-service-token", "phase-user-token"}) {
		t.Fatalf("status: %+v", status)
	}
	if guard.limitedRules.Len() != 0 {
		t.Fatalf("%d rules run off the conversation paths", guard.limitedRules.Len())
	}
	// Registered values are found on every path all the same.
	match := guard.inspects(envFlow, "api.anthropic.com", 443)
	body := []byte(`{"events":[{"value":"` + leakSecretOne + `","note":"acme_0123456789abcdefghijklmn ` + phaseServiceToken() + `"}]}`)
	scan := guard.newScan(match, "http", guard.scanOptionsFor(match, "/api/event_logging/batch"))
	out := guard.readPayload(scan, body, "body")
	if out == nil || bytes.Contains(out, []byte(leakSecretOne)) || !bytes.Contains(out, []byte("acme_0123456789abcdefghijklmn")) {
		t.Fatalf("off a conversation path: %s", out)
	}
	scan = guard.newScan(match, "http", guard.scanOptionsFor(match, "/v1/messages"))
	if out = guard.readPayload(scan, body, "body"); out == nil || bytes.Contains(out, []byte("acme_0123456789abcdefghijklmn")) {
		t.Fatalf("on a conversation path: %s", out)
	}
}

// Nothing changes for the shipped rule file: every rule applies, and status
// says nothing of rules.
func TestTheShippedRulesAreAllApplied(t *testing.T) {
	guard := newTestLeakGuard(t, leakModeCensor)
	status := guard.status()
	if status.RulesSkipped != 0 || status.SkippedRules != nil || len(guard.skipped) != 0 {
		t.Fatalf("the shipped file has skipped rules: %+v", status)
	}
	if guard.limitedRules.Len() != len(phaseTokenRules) {
		t.Fatalf("%d of Phase's token rules run on every path, want %d", guard.limitedRules.Len(), len(phaseTokenRules))
	}
	recorder := controlCall(inventoryProxy(t, guard), http.MethodGet, "/v1/status", "", nil)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "ulesSkipped") || strings.Contains(recorder.Body.String(), "skippedRules") {
		t.Fatalf("status JSON for the shipped file: %s", recorder.Body.String())
	}
}
