package aiproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/internal/remoteapi"
)

// secondCustomConnection is another custom Connection beside the one
// customConnectionPayload builds, on its own host and with its own decoy.
func secondCustomConnection(live string) map[string]any {
	const decoy = "sk-phx-decoy-other-0123456789abcdef"
	connection := customConnectionPayload(decoy, live)
	connection["grantId"], connection["connectionId"], connection["credentialId"] = "grant-other", "connection-other", "connection-other"
	connection["connectionName"], connection["credentialName"] = "Other API", "Other API"
	connection["hosts"] = []any{map[string]any{"match": "exact", "value": "other.example.test", "port": 443}}
	connection["agentEnv"] = map[string]string{"OTHER_API_KEY": decoy}
	connection["environmentBindings"] = []any{map[string]any{
		"name": "OTHER_API_KEY", "action": "set", "source": "decoy", "sourceField": "token", "sensitive": true, "systemManaged": false,
	}}
	return connection
}

// A custom Connection's value is whatever a member typed. One that happens to
// be part of a word the proxy itself writes into every event must not turn a
// denial into the end of the session.
func TestAMemberChosenValueDoesNotEndTheSessionOnADenial(t *testing.T) {
	for _, live := range []string{"credential", "connection", "set_header", "request", "http", "denied"} {
		client, shipped := eventConsole(t)
		state := controlRuntimeState(t, client, customSessionPayload("backend-member-value", 1, customConnectionPayload(customDecoyToken, live)), "runtime-member-value")
		events, err := newEventBuffer(state, time.Hour, t.TempDir(), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		proxy := &httpProxy{state: state, transport: &recordingUpstream{}, control: &controlHandler{state: state}, events: events}

		// A swap miss, recorded with reason credential_swap_failed for provider
		// http, protocol http, event type request.
		request := httptest.NewRequest(http.MethodGet, "https://api.example.test/v1/things", nil)
		request.Header.Set("Authorization", "Bearer not-the-decoy")
		setProxyCapability(request, "runtime-member-value")
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden || recorder.Header().Get("X-Phase-Error-Code") != "agent_credential_injection_failed" {
			t.Fatalf("value %q: status=%d", live, recorder.Code)
		}
		select {
		case err := <-state.fatal:
			t.Fatalf("value %q ended the session: %v", live, err)
		default:
		}
		if state.availability() != nil {
			t.Fatalf("value %q left the session unavailable", live)
		}
		if err := events.Stop(); err != nil {
			t.Fatal(err)
		}
		recorded := shipped()
		if len(recorded) == 0 || recorded[0].Reason != "credential_swap_failed" || recorded[0].Outcome != "denied" || recorded[0].Provider != "http" {
			t.Fatalf("value %q: the denial was not recorded: %+v", live, recorded)
		}
		state.destroy()
	}
}

// The checks that matter are kept: text the Agent supplied is still compared
// with every live value, and anything the Console or the proxy issued still
// fails an event it turns up in.
func TestEventChecksStillCoverAgentTextAndIssuedSecrets(t *testing.T) {
	const live = "member-chosen-value"
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-event-checks", 1, customConnectionPayload(customDecoyToken, live)), "runtime-event-checks")
	defer state.destroy()
	events, err := newEventBuffer(state, time.Hour, t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	event := func() agentapi.Event {
		return newRequestEvent(nil, http.MethodGet, "api.example.test", 443, "/v1/things", "allow", "ok", "connection_allowed", http.StatusOK, 0, "set_header")
	}
	if safe := event(); !events.safe(&safe) {
		t.Fatal("an ordinary event was refused")
	}
	for name, mutate := range map[string]func(*agentapi.Event){
		"a live value in the path":           func(e *agentapi.Event) { e.Path = "/v1/" + live },
		"a live value in the host":           func(e *agentapi.Event) { e.Host = live + ".example.test" },
		"a live value in the method":         func(e *agentapi.Event) { e.Method = live },
		"a decoy in the reason":              func(e *agentapi.Event) { e.Reason = "leaked_" + customDecoyToken },
		"the session credential as provider": func(e *agentapi.Event) { e.Provider = "backend-event-checks" },
		"the runtime capability as grant":    func(e *agentapi.Event) { e.GrantID = "runtime-event-checks" },
		"a token shape in the action":        func(e *agentapi.Event) { e.CredentialAction = "ghp_0123456789abcdefghijABCDEFGHIJ" },
	} {
		unsafe := event()
		mutate(&unsafe)
		if events.safe(&unsafe) {
			t.Errorf("%s was accepted", name)
		}
	}
	// Agent-supplied fields are redacted before the check, so the Agent cannot
	// fail an event by naming a value: the denial is recorded without it.
	named := event()
	named.Path, named.Method = "/v1/"+live, live
	redactRequestFields(&named, state.eventSecrets())
	if named.Path != "/redacted" || named.Method != "UNKNOWN" || !events.safe(&named) {
		t.Fatalf("redacted event = %+v", named)
	}
}

// One Connection's value must not cost another Connection, or the list, its
// read: a value is compared with what the Console said about its own
// Connection, never with the words every payload is made of.
func TestAMemberChosenValueDoesNotBreakReadsOfOtherConnections(t *testing.T) {
	// Each value occurs in the response of a read below without the Console
	// having said it about the Connection: as a member name, a kind, or in the
	// request a hint offers.
	for _, live := range []string{"connections", "definition", "serviceType", "phase.ai.connection", "agent_connection.create", "schemaVersion"} {
		state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-reads", 1,
			customConnectionPayload(customDecoyToken, live), secondCustomConnection("sk-live-other-only-0123456789abcd")), "runtime-reads")
		proxy := &httpProxy{state: state, transport: &recordingUpstream{}, control: &controlHandler{state: state}, lockdown: true}

		// A blocked host leaves a hint whose request names an Authorization
		// header and an agent_connection.create action.
		blocked := httptest.NewRequest(http.MethodGet, "https://unbound.example.org/x", nil)
		result := processThrough(proxy, blocked)
		if result.failure == nil || result.failure.code != "unbound_host_blocked" {
			t.Fatalf("lockdown did not block: %+v", result.failure)
		}

		for _, path := range []string{"/v1/connections", "/v1/connections/connection-example", "/v1/connections/connection-other", "/v1/hints"} {
			recorder := controlGet(t, proxy, "runtime-reads", path)
			if recorder.Code != http.StatusOK {
				t.Errorf("value %q: %s = %d %s", live, path, recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "sk-live-other-only-0123456789abcd") {
				t.Fatalf("%s carried a live value", path)
			}
		}
		var hints remoteapi.HintsResponse
		if err := json.Unmarshal(controlGet(t, proxy, "runtime-reads", "/v1/hints").Body.Bytes(), &hints); err != nil || len(hints.Hints) != 1 || hints.Hints[0].Host != "unbound.example.org" {
			t.Fatalf("value %q: hints = %+v err=%v", live, hints.Hints, err)
		}
		state.destroy()
	}
}

// What the Console says about a Connection is still compared with that
// Connection's own value, and only that Connection's reads are refused.
func TestAConnectionDescribingItsOwnValueIsRefusedAlone(t *testing.T) {
	const live = "member-chosen-value"
	leaking := customConnectionPayload(customDecoyToken, live)
	definition := customDefinition()
	definition["fields"] = []any{map[string]any{"name": "token", "kind": "secret", "source": map[string]any{"type": "sealed"}, "note": "use " + live}}
	leaking["connectionConfig"] = definition
	// The other Connection happens to mention the same text; it holds another value.
	other := secondCustomConnection("sk-live-other-only-0123456789abcd")
	other["connectionName"] = "Other API (" + live + ")"
	state := controlRuntimeState(t, unreachableConsoleClient(t), customSessionPayload("backend-own-value", 1, leaking, other), "runtime-own-value")
	defer state.destroy()
	proxy := &httpProxy{state: state, control: &controlHandler{state: state}}

	for path, status := range map[string]int{
		"/v1/connections/connection-example": http.StatusBadGateway,
		"/v1/connections":                    http.StatusBadGateway,
		"/v1/connections/connection-other":   http.StatusOK,
	} {
		recorder := controlGet(t, proxy, "runtime-own-value", path)
		if recorder.Code != status || (status != http.StatusOK && !strings.Contains(recorder.Body.String(), "unsafe_connection_response")) {
			t.Errorf("%s = %d %s", path, recorder.Code, recorder.Body.String())
		}
		if status != http.StatusOK && strings.Contains(recorder.Body.String(), live) {
			t.Errorf("%s carried the value", path)
		}
	}
}

// A hint repeats text the Agent supplied. One that holds a live value is left
// out, and the hints beside it are still served.
func TestHintsLeaveOutAgentTextThatHoldsALiveValue(t *testing.T) {
	const live = "membervalue"
	policy := policyDocument("ask", nil)
	state, proxy, _ := policyProxy(t, customPolicyConnection(policy), secondCustomConnection(live))
	proxy.lockdown = true

	// An ask on a path that holds the value: the path is never repeated.
	withValue := httptest.NewRequest(http.MethodGet, "https://api.example.test/v1/"+live, nil)
	result := processThrough(proxy, withValue)
	if result.failure == nil || result.failure.details["path"] != "/redacted" {
		t.Fatalf("a path holding a live value was repeated: %+v", result.failure)
	}
	// A method that holds it is not repeated either.
	oddMethod := httptest.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
	oddMethod.Method = strings.ToUpper(live)
	if result := processThrough(proxy, oddMethod); result.failure == nil || result.failure.details["method"] != strings.ToUpper(live) {
		t.Fatalf("a method in another letter case than the value: %+v", result.failure)
	}
	exact := httptest.NewRequest(http.MethodGet, "https://api.example.test/v1/items", nil)
	exact.Method = live
	if result := processThrough(proxy, exact); result.failure == nil || result.failure.details["method"] != "UNKNOWN" ||
		strings.Contains(string(result.failure.details["request"].(json.RawMessage)), live) {
		t.Fatalf("a method holding a live value was repeated: %+v", result.failure)
	}
	// A blocked host whose name holds the value, and one that does not.
	for _, host := range []string{live + ".example.org", "plain.example.org"} {
		blocked := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		if result := processThrough(proxy, blocked); result.failure == nil || result.failure.code != "unbound_host_blocked" {
			t.Fatalf("%s was not blocked: %+v", host, result.failure)
		}
	}
	// The value changes to one an earlier hint holds: that hint goes too.
	recorder := controlGet(t, proxy, "runtime-policy", "/v1/hints")
	var hints remoteapi.HintsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &hints); err != nil || recorder.Code != http.StatusOK {
		t.Fatalf("hints: status=%d err=%v body=%s", recorder.Code, err, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), live) {
		t.Fatalf("hints carried the value: %s", recorder.Body.String())
	}
	hosts := map[string]bool{}
	for _, hint := range hints.Hints {
		hosts[hint.Host] = true
	}
	if !hosts["plain.example.org"] || !hosts["api.example.test"] || hosts[live+".example.org"] {
		t.Fatalf("hint hosts = %v", hosts)
	}
	rotated := secondCustomConnection("plain.example")
	session := decodeTestSession(t, customSessionPayload("", 2, customPolicyConnection(policy), rotated))
	if err := state.replaceConfig(&session.SessionConfig); err != nil {
		t.Fatal(err)
	}
	recorder = controlGet(t, proxy, "runtime-policy", "/v1/hints")
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "plain.example") {
		t.Fatalf("after the value changed: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
