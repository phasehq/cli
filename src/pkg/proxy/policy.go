package proxy

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/phasehq/cli/internal/agentapi"
)

// Access policy enforcement.
//
// A policy lives on the Connection and says which calls
// are allowed, need a member's approval (ask), or are blocked. The proxy
// evaluates it for every request it would inject a credential into, before
// the credential is swapped in or attached:
//
//  1. Classify the call (ClassifyCall): by AWS action for the aws service;
//     for any other HTTP Connection by the Connection's operationClasses, if
//     it has any, and then the HTTP method. A request that could run as
//     something else gets that as a further candidate: a method named by a
//     method override, and an update for a protocol upgrade, whose traffic
//     the proxy does not see.
//  2. The secret guard runs first and is not part of this file's evaluation:
//     a credential-minting call never reaches it (see minting.go).
//  3. Every rule that matches is collected and the strongest effect wins:
//     block, then ask, then allow. With no matching rule the policy's default
//     applies.
//  4. An ask is turned into an allow by a temporary allow that matches the
//     call and has not expired. Expiry is read from the clock on every call.
//     A temporary allow never changes a block.
//
// A Connection without a policy, or with one that only allows, is not
// evaluated at all and behaves exactly as it did before policies existed.

// ErrCallUninspectable is returned when a call cannot be classified, for
// example an AWS query-protocol body too large to read. Callers fail closed.
var ErrCallUninspectable = errors.New("request could not be classified for the access policy")

// ClassifiedCall is one class a request may belong to. Operation names the
// AWS action ("s3:DeleteObject") when the request carries one. Method is set
// when the candidate would run as another HTTP method than the request's own,
// one named by a method override; rules are then matched against that method.
type ClassifiedCall struct {
	Class     string
	Operation string
	Method    string
}

// PolicyApplies reports whether the Connection's calls are evaluated against
// its policy: any HTTP Connection whose policy can stop something. Every
// HTTP service takes one; a service with no action-based classification is
// judged by its operationClasses and then the method.
func PolicyApplies(connection agentapi.Connection) bool {
	return connection.Protocol == "http" && connection.Policy.Restricts()
}

// ClassifyCall returns every class req could belong to on the Connection,
// most often exactly one. It may buffer a bounded form body to read an AWS
// action and always leaves req forwardable.
func ClassifyCall(req *http.Request, connection agentapi.Connection) ([]ClassifiedCall, error) {
	if req == nil || req.URL == nil {
		return nil, ErrCallUninspectable
	}
	upgrade := isUpgradeRequest(req)
	if strings.EqualFold(connection.ServiceType, "aws") {
		calls, err := classifyAWSCall(req)
		if err != nil {
			return nil, err
		}
		service := awsScopeService(req)
		for _, method := range overriddenMethods(req) {
			further := awsRESTCall(req, method, service)
			further.Method = method
			calls = appendCall(calls, further)
		}
		if upgrade {
			calls = appendCall(calls, ClassifiedCall{Class: agentapi.ClassUpdate})
		}
		return calls, nil
	}
	overrides := connection.OperationClasses.Entries
	calls, explicit := classifyHTTPCall(req, req.Method, overrides)
	// What travels over an upgraded connection is never inspected, so the
	// upgrade is also an update unless an override says what it is.
	if upgrade && !explicit {
		calls = appendCall(calls, ClassifiedCall{Class: agentapi.ClassUpdate})
	}
	for _, method := range overriddenMethods(req) {
		further, _ := classifyHTTPCall(req, method, overrides)
		for _, call := range further {
			call.Method = method
			calls = appendCall(calls, call)
		}
	}
	return calls, nil
}

func appendCall(calls []ClassifiedCall, call ClassifiedCall) []ClassifiedCall {
	for _, existing := range calls {
		if existing == call {
			return calls
		}
	}
	return append(calls, call)
}

// classifyHTTPCall applies the Connection's operationClasses for the given
// method, first match wins, then falls back to the method. It also reports
// whether an override decided the class outright. An override that may or may
// not apply only adds its class as a further candidate: one whose path cannot
// be compared with the request's (see policyPath), and one that covers the
// path only as looseGlobMatch reads it.
func classifyHTTPCall(req *http.Request, method string, overrides []agentapi.OperationClassRule) ([]ClassifiedCall, bool) {
	path, comparable := policyPath(req)
	var calls []ClassifiedCall
	add := func(class string) {
		calls = appendCall(calls, ClassifiedCall{Class: class})
	}
	for _, override := range overrides {
		if !methodMatches(override.Match.Methods, method) {
			continue
		}
		if override.Match.Path == "" {
			add(override.Class)
			return calls, true
		}
		if !comparable {
			add(override.Class)
			continue
		}
		if globMatch(override.Match.Path, path) {
			add(override.Class)
			return calls, true
		}
		if looseGlobMatch(override.Match.Path, path) {
			add(override.Class)
		}
	}
	add(classifyHTTPMethod(method))
	return calls, false
}

// methodOverrideHeaders and methodOverrideParameter are how a client asks a
// server to treat a request as another method. Whether the upstream honours
// one is not known here, so the named method is a further candidate.
var methodOverrideHeaders = []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}

const methodOverrideParameter = "_method"

// overriddenMethods returns the methods a request asks to be run as, other
// than its own, in upper case. A name that is no HTTP method is kept: it is
// classified like any unknown method, as an update.
func overriddenMethods(req *http.Request) []string {
	var methods []string
	add := func(value string) {
		for _, name := range strings.Split(value, ",") {
			name = strings.ToUpper(strings.TrimSpace(name))
			if name == "" || name == strings.ToUpper(req.Method) {
				continue
			}
			known := false
			for _, existing := range methods {
				known = known || existing == name
			}
			if !known {
				methods = append(methods, name)
			}
		}
	}
	for _, header := range methodOverrideHeaders {
		for _, value := range req.Header.Values(header) {
			add(value)
		}
	}
	query, err := url.ParseQuery(req.URL.RawQuery)
	for _, value := range query[methodOverrideParameter] {
		add(value)
	}
	// A query the proxy cannot fully parse may still carry the parameter.
	if err != nil && strings.Contains(strings.ToLower(req.URL.RawQuery), methodOverrideParameter) {
		add("UNKNOWN")
	}
	return methods
}

// isUpgradeRequest reports whether the request asks to switch protocols, as a
// WebSocket handshake does.
func isUpgradeRequest(req *http.Request) bool {
	if req.Header.Get("Upgrade") == "" {
		return false
	}
	for _, value := range req.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// PolicyDecision is the outcome of evaluating one call.
type PolicyDecision struct {
	// Effect is allow, ask or block.
	Effect string
	// Class, Operation and Method are those of the candidate that decided the
	// effect. Method is the method that candidate runs as: the request's own,
	// or one named by a method override.
	Class     string
	Operation string
	Method    string
	// Rule is the rule that decided the effect, with its position in the
	// policy; it is nil when the policy's default did.
	Rule      *agentapi.PolicyRule
	RuleIndex int
	// TemporaryAllowID names the temporary allow that turned an ask into an
	// allow.
	TemporaryAllowID string
}

// EvaluateAccessPolicy decides one call. calls holds the classes the request
// may belong to; the strongest effect across them wins, so an ambiguous
// request is judged by the most restricted thing it could be.
func EvaluateAccessPolicy(policy *agentapi.AccessPolicy, calls []ClassifiedCall, req *http.Request, now time.Time) PolicyDecision {
	if policy == nil {
		return PolicyDecision{Effect: agentapi.PolicyAllow}
	}
	if len(calls) == 0 {
		calls = []ClassifiedCall{{Class: agentapi.ClassUpdate}}
	}
	path, comparable := policyPath(req)
	var decision PolicyDecision
	for index, call := range calls {
		method := call.Method
		if method == "" {
			method = req.Method
		}
		candidate := evaluateCall(policy, call, method, path, comparable, now)
		if index == 0 || effectRank(candidate.Effect) > effectRank(decision.Effect) {
			decision = candidate
		}
	}
	return decision
}

func evaluateCall(policy *agentapi.AccessPolicy, call ClassifiedCall, method, path string, comparable bool, now time.Time) PolicyDecision {
	decision := PolicyDecision{Class: call.Class, Operation: call.Operation, Method: strings.ToUpper(method), RuleIndex: -1}
	for index := range policy.Rules {
		rule := &policy.Rules[index]
		if !ruleMatches(rule, call, method, path, comparable) {
			continue
		}
		if decision.Rule == nil || effectRank(rule.Effect) > effectRank(decision.Effect) {
			decision.Effect, decision.Rule, decision.RuleIndex = rule.Effect, rule, index
		}
	}
	if decision.Rule == nil {
		decision.Effect = policy.Default
		if decision.Effect == "" {
			decision.Effect = agentapi.PolicyAllow
		}
	}
	if decision.Effect != agentapi.PolicyAsk {
		return decision
	}
	for _, allow := range policy.TemporaryAllows {
		if !now.Before(allow.ExpiresAt) {
			continue
		}
		if targetMatches(allow.Class, allow.Match, allow.Operation, call, method, path, comparable, false) {
			decision.Effect, decision.TemporaryAllowID = agentapi.PolicyAllow, allow.ID
			break
		}
	}
	return decision
}

// ruleMatches decides whether a rule applies to the call. A path rule cannot
// be compared with a path the proxy cannot bring into canonical form. Such a
// request is then treated as matching every ask or block path rule and no
// allow path rule, so an odd spelling of a path never slips past a rule.
//
// For the same reason path globs are compared in two ways. A rule that stops
// a call (ask, block) matches loosely: letter case, one trailing slash and a
// ";params" tail are ignored, because many servers route "/v1/admin",
// "/V1/Admin/" and "/v1/admin;x" to the same place. A rule that lets a call
// through (allow) and a temporary allow match the path exactly as sent, so a
// respelled path never borrows an allow written for another one.
func ruleMatches(rule *agentapi.PolicyRule, call ClassifiedCall, method, path string, comparable bool) bool {
	if rule.Match != nil && rule.Match.Path != "" && !comparable {
		return rule.Effect != agentapi.PolicyAllow && methodMatches(rule.Match.Methods, method)
	}
	return targetMatches(rule.Class, rule.Match, rule.Operation, call, method, path, comparable, rule.Effect != agentapi.PolicyAllow)
}

// targetMatches is true when a rule's or an allow's one target (class, match
// or operation) covers the call. An operation covers only a call whose AWS
// action the proxy named, compared without regard to case; calls on any other
// service never carry one. loose selects how a path glob is compared; see
// ruleMatches.
func targetMatches(ruleClass string, match *agentapi.PolicyMatch, operation string, call ClassifiedCall, method, path string, comparable, loose bool) bool {
	if operation != "" {
		return call.Operation != "" && strings.EqualFold(operation, call.Operation)
	}
	if match == nil {
		return ruleClass != "" && ruleClass == call.Class
	}
	if !methodMatches(match.Methods, method) {
		return false
	}
	if match.Path == "" {
		return len(match.Methods) > 0
	}
	if !comparable {
		return false
	}
	if loose {
		return looseGlobMatch(match.Path, path)
	}
	return globMatch(match.Path, path)
}

func methodMatches(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	method = strings.ToUpper(method)
	for _, candidate := range methods {
		if candidate == method {
			return true
		}
	}
	return false
}

func effectRank(effect string) int {
	switch effect {
	case agentapi.PolicyBlock:
		return 3
	case agentapi.PolicyAsk:
		return 2
	default:
		return 1
	}
}

// policyPath returns the request path in the form path globs are matched
// against, the same one host rules use, and whether it could be produced.
func policyPath(req *http.Request) (string, bool) {
	if req == nil || req.URL == nil {
		return "", false
	}
	canonical, err := canonicalHTTPPath(req.URL.EscapedPath())
	if err != nil {
		return "", false
	}
	return canonical, true
}

// ExactPathGlob returns a path glob that matches exactly the request's path
// and nothing else, for the narrowest allow a blocked call can ask for. It
// reports false when the path cannot be written as one: it is not canonical,
// is longer than a glob may be, or holds a control character.
func ExactPathGlob(req *http.Request) (string, bool) {
	path, comparable := policyPath(req)
	if !comparable {
		return "", false
	}
	var escaped strings.Builder
	for _, character := range path {
		switch {
		case character < 0x20 || (character >= 0x7f && character <= 0x9f):
			return "", false
		case character == '*' || character == '?' || character == '[':
			escaped.WriteString("[" + string(character) + "]")
		default:
			escaped.WriteRune(character)
		}
	}
	if escaped.Len() > 1024 || !globMatch(escaped.String(), path) {
		return "", false
	}
	return escaped.String(), true
}
