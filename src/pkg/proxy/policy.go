package proxy

import (
	"errors"
	"net/http"
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
//     it has any, and then the HTTP method.
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
// AWS action ("s3:DeleteObject") when the request carries one.
type ClassifiedCall struct {
	Class     string
	Operation string
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
	if strings.EqualFold(connection.ServiceType, "aws") {
		return classifyAWSCall(req)
	}
	return classifyHTTPCall(req, connection.OperationClasses.Entries), nil
}

// classifyHTTPCall applies the Connection's operationClasses, first
// match wins, then falls back to the method. An override whose path cannot be
// compared with the request's (see policyPath) may or may not apply, so its
// class is kept as a further candidate rather than guessed away.
func classifyHTTPCall(req *http.Request, overrides []agentapi.OperationClassRule) []ClassifiedCall {
	path, comparable := policyPath(req)
	var calls []ClassifiedCall
	add := func(class string) {
		for _, existing := range calls {
			if existing.Class == class {
				return
			}
		}
		calls = append(calls, ClassifiedCall{Class: class})
	}
	for _, override := range overrides {
		if !methodMatches(override.Match.Methods, req.Method) {
			continue
		}
		if override.Match.Path == "" {
			add(override.Class)
			return calls
		}
		if !comparable {
			add(override.Class)
			continue
		}
		if globMatch(override.Match.Path, path) {
			add(override.Class)
			return calls
		}
	}
	add(classifyHTTPMethod(req.Method))
	return calls
}

// PolicyDecision is the outcome of evaluating one call.
type PolicyDecision struct {
	// Effect is allow, ask or block.
	Effect string
	// Class and Operation are those of the candidate that decided the effect.
	Class     string
	Operation string
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
		candidate := evaluateCall(policy, call, req.Method, path, comparable, now)
		if index == 0 || effectRank(candidate.Effect) > effectRank(decision.Effect) {
			decision = candidate
		}
	}
	return decision
}

func evaluateCall(policy *agentapi.AccessPolicy, call ClassifiedCall, method, path string, comparable bool, now time.Time) PolicyDecision {
	decision := PolicyDecision{Class: call.Class, Operation: call.Operation, RuleIndex: -1}
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
		if targetMatches(allow.Class, allow.Match, allow.Operation, call, method, path, comparable) {
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
func ruleMatches(rule *agentapi.PolicyRule, call ClassifiedCall, method, path string, comparable bool) bool {
	if rule.Match != nil && rule.Match.Path != "" && !comparable {
		return rule.Effect != agentapi.PolicyAllow && methodMatches(rule.Match.Methods, method)
	}
	return targetMatches(rule.Class, rule.Match, rule.Operation, call, method, path, comparable)
}

// targetMatches is true when a rule's or an allow's one target (class, match
// or operation) covers the call. An operation covers only a call whose AWS
// action the proxy named, compared without regard to case; calls on any other
// service never carry one.
func targetMatches(ruleClass string, match *agentapi.PolicyMatch, operation string, call ClassifiedCall, method, path string, comparable bool) bool {
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
	return comparable && globMatch(match.Path, path)
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
