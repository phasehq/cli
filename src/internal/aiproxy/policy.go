package aiproxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/phasehq/cli/internal/agentapi"
	sdkagents "github.com/phasehq/cli/internal/agentsdk"
	phaseproxy "github.com/phasehq/cli/pkg/proxy"
)

// Answers of the access policy. Both are HTTP 403 in the proxy's error
// envelope; an ask also carries a request the Agent can send as it is.
const (
	codeAccessPolicyBlocked       = "agent_access_policy_blocked"
	codeAccessPolicyAsk           = "agent_access_policy_ask"
	codeAccessPolicyUninspectable = "agent_access_policy_uninspectable"
	codeAccessPolicyUnsupported   = "agent_access_policy_unsupported"
	codeAccessExpired             = "agent_access_expired"
	codeProviderRulesMissing      = "agent_provider_rules_missing"
	codeConnectionUnsupported     = "agent_connection_unsupported"

	// An event's reason is the answer's code. A call the proxy could not
	// inspect for credential minting keeps the reason it always had.
	reasonAccessPolicyUninspectable = "access_policy_uninspectable"
	reasonCredentialMintingBlocked  = "credential_minting_blocked"
	reasonCredentialScrubbed        = "credential_response_scrubbed"

	// decisionAsk is the proxy decision of a call that needs a member's
	// approval; a blocked call is "block".
	decisionAsk = "ask"

	maxReportedPathLength = 1024
)

const requestsURL = phaseproxy.ControlURL + "/v1/requests"

// enforceSecretGuard refuses a call that would mint a new credential, before
// anything is re-signed or injected. It is always on: no policy rule and no
// temporary allow is consulted. See pkg/proxy/minting.go for the rule table.
func (p *httpProxy) enforceSecretGuard(req, upstream *http.Request, binding *binding, started time.Time) *processedResponse {
	blocked, inspectErr := phaseproxy.CredentialMintingBlocked(upstream, binding.connection)
	if blocked == nil && inspectErr == nil {
		return nil
	}
	operation := ""
	failure := &requestFailure{status: http.StatusForbidden, code: codeAccessPolicyBlocked, decision: "block", reason: codeAccessPolicyBlocked, binding: binding}
	if blocked != nil {
		operation = blocked.Operation
		failure.message = blocked.Message()
	} else {
		failure.code, failure.reason = "credential_minting_uninspectable", reasonCredentialMintingBlocked
		failure.message = "Phase could not inspect this request to rule out credential minting (the body is too large or unreadable). Split the request or use a smaller body."
	}
	failure.details = p.policyDetails(binding.connection, req, agentapi.ClassCredentialMinting, operation, phaseproxy.SecretGuardRule)
	event := makeEvent(binding, req, "block", "denied", failure.reason, failure.status, time.Since(started), binding.connection.PrimaryInjectionAction())
	event.Detail = policyEventDetail(failure.details, binding.connection)
	return &processedResponse{event: event, failure: failure}
}

// enforceAccessPolicy evaluates the grant's policy for one call, before its
// credential is swapped in or attached. It returns nil when the call may go
// on. The proxy never holds a call open waiting for approval: an ask is
// answered at once, with the request that asks a member to allow it.
func (p *httpProxy) enforceAccessPolicy(req, upstream *http.Request, binding *binding, host string, started time.Time) *processedResponse {
	connection := binding.connection
	if !phaseproxy.PolicyApplies(connection) {
		return nil
	}
	action := connection.PrimaryInjectionAction()
	calls, err := phaseproxy.ClassifyCall(upstream, connection)
	if err != nil {
		failure := &requestFailure{
			status: http.StatusForbidden, code: codeAccessPolicyUninspectable, decision: "block", reason: reasonAccessPolicyUninspectable, binding: binding,
			message: "Phase could not read which method this request asks to be run as, so it could not check it against the Connection's access rules (the form body is too large or unreadable). Use a smaller body.",
		}
		failure.details = p.policyDetails(connection, req, "", "", "default")
		event := makeEvent(binding, req, "block", "denied", failure.reason, failure.status, time.Since(started), action)
		event.Detail = policyEventDetail(failure.details, connection)
		return &processedResponse{event: event, failure: failure}
	}
	// Classifying may wait for the body, so a temporary allow is checked
	// against the time it arrived, not the time the request began.
	now := p.now()
	decision := phaseproxy.EvaluateAccessPolicy(connection.Policy, calls, upstream, now)
	if decision.Effect == agentapi.PolicyAllow {
		return nil
	}
	var rule any = "default"
	if decision.Rule != nil {
		rule = *decision.Rule
	}
	what := describeCall(p.reportableMethod(req.Method), decision)
	name := connection.ConnectionName
	if name == "" {
		name = connection.ConnectionID
	}
	failure := &requestFailure{status: http.StatusForbidden, decision: "block", binding: binding}
	failure.details = p.policyDetails(connection, req, decision.Class, "", rule)
	if decision.Effect == agentapi.PolicyAsk {
		request := p.askRequest(connection, req, host, decision)
		failure.code, failure.reason, failure.decision = codeAccessPolicyAsk, codeAccessPolicyAsk, decisionAsk
		failure.message = "Phase did not send this call: " + what + " on " + name + " needs a member's approval under this Connection's access rules. " +
			"To ask for it, send the JSON in details.request unchanged to POST " + requestsURL +
			", show the human the approvalUrl, and retry the call once the request is approved."
		failure.details["request"] = request
		p.state.hints.record(proxyHint{
			kind: hintAccessPolicyAsk, reason: codeAccessPolicyAsk, host: host, method: failure.details["method"].(string),
			path: failure.details["path"].(string), class: decision.Class,
			connectionID: connection.ConnectionID, connectionName: connection.ConnectionName, request: request,
		}, now)
	} else {
		failure.code, failure.reason = codeAccessPolicyBlocked, codeAccessPolicyBlocked
		failure.message = "Phase blocked " + blockedCallText(failure.details["method"].(string), failure.details["path"].(string), decision) +
			" on " + name + ": " + blockedBecause(decision) + " A blocked call cannot be requested yet. " +
			"If the task needs it, tell the human: a member can change this Connection's access rules in the Phase Console."
	}
	event := makeEvent(binding, req, failure.decision, "denied", failure.reason, failure.status, time.Since(started), action)
	event.Detail = policyEventDetail(failure.details, connection)
	return &processedResponse{event: event, failure: failure}
}

// policyDetails are the members a policy answer carries in the error
// envelope, beside the Connection and grant IDs every bound failure has.
func (p *httpProxy) policyDetails(connection agentapi.Connection, req *http.Request, class, operation string, rule any) map[string]any {
	details := map[string]any{
		"connectionName": connection.ConnectionName,
		"class":          class,
		"method":         p.reportableMethod(req.Method),
		"path":           p.reportablePath(req),
		"rule":           rule,
	}
	if operation != "" {
		details["operation"] = operation
	}
	return details
}

// reportablePath is the request path as it may be repeated in an answer, a
// hint or a request: without its query, bounded, and never a path that holds
// a decoy or anything shaped like a credential.
func (p *httpProxy) reportablePath(req *http.Request) string {
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if !p.pathIsReportable(path) {
		return "/redacted"
	}
	if len(path) > maxReportedPathLength {
		path = path[:maxReportedPathLength]
	}
	return path
}

func (p *httpProxy) pathIsReportable(path string) bool {
	return !containsControlCharacter(path) && safeEventText(path, p.state.eventSecrets())
}

// reportableMethod is a method name as it may be repeated in an answer, a
// hint or a request: a short token that holds nothing secret.
func (p *httpProxy) reportableMethod(method string) string {
	if method == "" || len(method) > maxEventMethodLength || !eventIdentifier.MatchString(method) ||
		!safeEventText(method, p.state.eventSecrets()) {
		return "UNKNOWN"
	}
	return method
}

// policyEventDetail is what the event for a stopped call carries: the same
// members as the answer, with the Connection's ID, and without the request an
// ask offers, which is never part of an event. The rule is "default",
// "secret_guard" or the one rule that decided.
func policyEventDetail(details map[string]any, connection agentapi.Connection) map[string]any {
	detail := map[string]any{"connectionId": connection.ConnectionID}
	for _, name := range []string{"connectionName", "class", "method", "path", "operation", "rule"} {
		if value, present := details[name]; present && value != "" {
			detail[name] = value
		}
	}
	return detail
}

func describeCall(method string, decision phaseproxy.PolicyDecision) string {
	method = strings.ToUpper(method)
	// A method override asks the service to run the request as another
	// method, and that is the call the policy stopped.
	if policyMethod(decision.Method) && decision.Method != method {
		return "this " + method + ", which asks to be run as " + decision.Method + " (" + classCall(decision.Class) + ")"
	}
	return "this " + method + " (" + classCall(decision.Class) + ")"
}

// classCall names a call by its class, with the article it takes.
func classCall(class string) string {
	if class == agentapi.ClassUpdate {
		return "an update call"
	}
	return "a " + class + " call"
}

// blockedCallText is the stopped call as a block names it: its method and
// path, and the method an override asks it to be run as.
func blockedCallText(method, path string, decision phaseproxy.PolicyDecision) string {
	if policyMethod(decision.Method) && decision.Method != strings.ToUpper(method) {
		return method + " " + path + ", which asks to be run as " + decision.Method + ","
	}
	return method + " " + path
}

// blockedBecause names, in the Phase Console's words, what blocked the call:
// an HTTP rule, the row of the call's class, or the Default that row follows.
func blockedBecause(decision phaseproxy.PolicyDecision) string {
	if decision.Rule != nil && decision.Rule.Match != nil {
		match := plainTitleText(strings.TrimSpace(strings.Join(decision.Rule.Match.Methods, ", ") + " " + decision.Rule.Match.Path))
		return "it matches this Connection's HTTP rule \"" + match + "\", which is set to Block."
	}
	call := classCall(decision.Class)
	row := decision.Class
	if row != "" {
		row = strings.ToUpper(row[:1]) + row[1:]
	}
	if decision.Rule == nil {
		return "it is " + call + ", and this Connection's " + row + " row follows its Default, which is set to Block."
	}
	return "it is " + call + ", and this Connection's " + row + " row is set to Block."
}

// askRequest builds the body an Agent sends unchanged to POST /v1/requests to
// ask a member to allow the call for a limited time. It names the narrowest
// thing that covers the call: its method and exact path, AWS calls included.
// Where the path cannot be spelled as an exact glob or must not be repeated,
// it names the class. No duration is sent, so the organisation's default
// applies; the reviewer may change it.
func (p *httpProxy) askRequest(connection agentapi.Connection, req *http.Request, host string, decision phaseproxy.PolicyDecision) json.RawMessage {
	// The allow names the method the stopped candidate runs as: the request's
	// own, or the one a method override asks for.
	method := strings.ToUpper(p.reportableMethod(req.Method))
	if policyMethod(decision.Method) {
		method = decision.Method
	}
	name := plainTitleText(connection.ConnectionName)
	if name == "" {
		name = connection.ConnectionID
	}
	reportedPath := p.reportablePath(req)
	allow := map[string]any{"class": decision.Class}
	title := "Allow " + decision.Class + " calls on " + name
	blockedCall := map[string]any{"method": method, "host": host, "path": reportedPath, "class": decision.Class}
	if glob, exact := phaseproxy.ExactPathGlob(req); exact && policyMethod(method) && p.pathIsReportable(glob) {
		allow = map[string]any{"match": map[string]any{"methods": []string{method}, "path": glob}}
		title = "Allow " + method + " " + reportedPath + " on " + name
	}
	return mustRequestBody(map[string]any{
		"kind": string(sdkagents.RequestAccessChange), "title": requestTitle(title),
		"action": map[string]any{
			"type": string(sdkagents.ActionGrantAllow), "version": sdkagents.RequestActionVersion,
			"connectionId": connection.ConnectionID,
			"allow":        allow,
			"blockedCall":  blockedCall,
		},
	})
}

// renewRequest builds the body that asks to renew time-limited access to a
// Connection, for the organisation's default duration.
func renewRequest(connectionID, connectionName string) json.RawMessage {
	name := plainTitleText(connectionName)
	if name == "" {
		name = connectionID
	}
	return mustRequestBody(map[string]any{
		"kind": string(sdkagents.RequestAccessChange), "title": requestTitle("Renew access to " + name),
		"action": map[string]any{
			"type": string(sdkagents.ActionGrantRenew), "version": sdkagents.RequestActionVersion, "connectionId": connectionID,
		},
	})
}

// policyMethod reports whether a method is one an allow may name.
func policyMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect, http.MethodTrace:
		return true
	}
	return false
}

func mustRequestBody(body map[string]any) json.RawMessage {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil
	}
	return encoded
}

// plainTitleText drops control characters and surrounding space, so a name
// can stand in a request title.
func plainTitleText(value string) string {
	return strings.TrimSpace(strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, value))
}

// requestTitle shortens a title to what a request accepts.
func requestTitle(title string) string {
	const limit = 120
	title = plainTitleText(title)
	if utf8.RuneCountInString(title) <= limit {
		return title
	}
	runes := []rune(title)
	return strings.TrimSpace(string(runes[:limit-1])) + "…"
}

// accessExpiredDetails is what a refusal for expired access carries: the
// request that asks to renew it.
func accessExpiredDetails(connection agentapi.Connection) map[string]any {
	details := map[string]any{
		"connectionName": connection.ConnectionName,
		"request":        renewRequest(connection.ConnectionID, connection.ConnectionName),
	}
	if connection.GrantExpiresAt != nil {
		details["expiredAt"] = connection.GrantExpiresAt.UTC().Format(time.RFC3339)
	}
	return details
}
