package proxy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/phasehq/cli/internal/agentapi"
)

// How an AWS call is sorted into an operation class.
//
// The tables are provider-owned data from the Console's manifest and arrive
// with each AWS Connection as its actionClasses (agentapi.ActionClasses,
// scheme aws_actions). Members do not edit them and they are not part of any
// stored policy. An access policy names classes ("delete: block"), and this
// is what decides which class a call belongs to.
//
// A call's action is the operation the request names: the X-Amz-Target header
// (JSON protocols), the Action parameter of the query string or of a form
// body (query protocols), or the last segment of a Smithy RPC v2 path
// (/service/<Service>/operation/<Name>). The action is classified in this
// order:
//
//  1. Credential minting is the secret guard's and is decided in minting.go
//     before any of this runs.
//  2. An entry in Exact for "service:Action".
//  3. A read verb (ReadVerbs): the call does not change anything, in any
//     service.
//  4. A write in an admin service (AdminServices: identity, organisation,
//     account), or a write whose name ends with one of AdminSuffixes (it
//     changes who may do what: a policy, a permission, an ACL), is admin.
//  5. A create verb, then a delete verb (CreateVerbs, DeleteVerbs).
//  6. Everything else, including an action the tables have never seen, is
//     update.
//
// Action names are compared without regard to letter case, as operation rules
// are. The one exception is a read verb, which must be spelled as AWS spells
// it: an oddly cased name is never taken for a read.
//
// A request that names no action (the REST services, S3 above all) is
// classified by its HTTP method, with the S3 sub-resources that delete objects
// in bulk or change permissions called out in S3Subresources (a query
// parameter of an S3 request that is not a read, and the class it makes the
// call) and the REST calls that have an entry in Exact named in
// RESTOperations, so that such a call can still be classified, and matched by
// an operation rule, as that action.
//
// An action selector is trusted on its own only where the service acts on it:
// a query-protocol or JSON-target service. On every other service a REST call
// ignores a stray X-Amz-Target or Action, so the method and sub-resource class
// is always a further candidate there and a decoy selector hides nothing. The
// protocol lists: QueryProtocolServices take their action from a form body,
// whatever Content-Type the request claims; DualProtocolServices are
// query-protocol services that also speak a JSON or CBOR protocol, selected by
// the request's Content-Type, under which the body is not a form;
// JSONTargetServices name every action in X-Amz-Target and have no REST API
// under the same signing name; MixedServices serve a REST API under the
// signing name of an action protocol, so there a call is an action call only
// at the root path.

// classifyAWSAction returns the class of one named action of a service.
func classifyAWSAction(classes *agentapi.ActionClasses, service, action string) string {
	if class, ok := classes.ExactClass(service, action); ok {
		return class
	}
	if hasVerb(action, classes.ReadVerbs) {
		return agentapi.ClassRead
	}
	if containsString(classes.AdminServices, service) {
		return agentapi.ClassAdmin
	}
	lowered := strings.ToLower(action)
	for _, suffix := range classes.AdminSuffixes {
		if strings.HasSuffix(lowered, strings.ToLower(suffix)) {
			return agentapi.ClassAdmin
		}
	}
	if hasWriteVerb(action, classes.CreateVerbs) {
		return agentapi.ClassCreate
	}
	if hasWriteVerb(action, classes.DeleteVerbs) {
		return agentapi.ClassDelete
	}
	return agentapi.ClassUpdate
}

// hasVerb reports whether action starts with one of the verbs as a whole
// word of its CamelCase name: "List" matches ListUsers, not Listen. It is the
// test for a read, so it takes the name only as AWS spells it.
func hasVerb(action string, verbs []string) bool {
	for _, verb := range verbs {
		if rest, found := strings.CutPrefix(action, verb); found && startsNewWord(rest) {
			return true
		}
	}
	return false
}

// hasWriteVerb is hasVerb for the verbs that name a write. It also takes a
// verb in another letter case ("terminateInstances", "TERMINATEINSTANCES"):
// with the case gone there is no word boundary to look for, so the prefix
// alone decides.
func hasWriteVerb(action string, verbs []string) bool {
	for _, verb := range verbs {
		if rest, found := strings.CutPrefix(action, verb); found {
			if startsNewWord(rest) {
				return true
			}
			continue
		}
		if len(action) >= len(verb) && strings.EqualFold(action[:len(verb)], verb) {
			return true
		}
	}
	return false
}

func startsNewWord(rest string) bool {
	return rest == "" || (rest[0] >= 'A' && rest[0] <= 'Z') || (rest[0] >= '0' && rest[0] <= '9')
}

// classifyHTTPMethod is the method-based fallback: for a custom HTTP
// Connection, and for an AWS request that names no action.
func classifyHTTPMethod(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return agentapi.ClassRead
	case http.MethodPost:
		return agentapi.ClassCreate
	case http.MethodPut, http.MethodPatch:
		return agentapi.ClassUpdate
	case http.MethodDelete:
		return agentapi.ClassDelete
	default:
		return agentapi.ClassUpdate
	}
}

// classifyAWSCall returns every class the request could belong to. AWS
// services differ in which selector they act on, so each selector the request
// carries is classified and the policy is evaluated for all of them: a
// harmless selector cannot hide the one the service will run. Where the
// service may ignore selectors altogether, the REST reading of the request is
// one more candidate (see awsSelectorsDecide).
func classifyAWSCall(req *http.Request, classes *agentapi.ActionClasses) ([]ClassifiedCall, error) {
	service := awsScopeService(req)
	actions, err := awsOperations(req, service, false, classes)
	if err != nil {
		return nil, ErrCallUninspectable
	}
	if len(actions) == 0 {
		return []ClassifiedCall{awsRESTCall(req, req.Method, service, classes)}, nil
	}
	calls := make([]ClassifiedCall, 0, len(actions)+1)
	for _, action := range actions {
		operation := action
		if service != "" {
			operation = service + ":" + action
		}
		calls = appendCall(calls, ClassifiedCall{Class: classifyAWSAction(classes, service, action), Operation: operation})
	}
	if !awsSelectorsDecide(req, service, classes) {
		calls = appendCall(calls, awsRESTCall(req, req.Method, service, classes))
	}
	return calls, nil
}

// awsSelectorsDecide reports whether the action selectors alone say what the
// call does: the service is one that acts on them, and the call is not to the
// REST API some of those services have beside it.
func awsSelectorsDecide(req *http.Request, service string, classes *agentapi.ActionClasses) bool {
	if !containsString(classes.QueryProtocolServices, service) && !containsString(classes.JSONTargetServices, service) {
		return false
	}
	return !containsString(classes.MixedServices, service) || awsRootPath(req)
}

// awsQueryProtocolCall reports whether the request is a call to a
// query-protocol service's action API, which takes its Action from the body.
func awsQueryProtocolCall(req *http.Request, service string, classes *agentapi.ActionClasses) bool {
	if !containsString(classes.QueryProtocolServices, service) {
		return false
	}
	return !containsString(classes.MixedServices, service) || awsRootPath(req)
}

func awsRootPath(req *http.Request) bool {
	return req.URL.Path == "" || req.URL.Path == "/"
}

// awsRESTCall classifies the request as a REST call run with the given
// method: by a RESTOperations entry when there is one, otherwise by the method
// and, for S3, its sub-resources and grants.
func awsRESTCall(req *http.Request, method, service string, classes *agentapi.ActionClasses) ClassifiedCall {
	for _, operation := range classes.RESTOperations {
		if operation.Service == service && strings.EqualFold(operation.Method, method) && loosePathMatch(operation.Pattern, req.URL.Path) {
			return ClassifiedCall{Class: classifyAWSAction(classes, service, operation.Action), Operation: service + ":" + operation.Action}
		}
	}
	return ClassifiedCall{Class: classifyAWSRESTMethod(req, method, service, classes)}
}

func classifyAWSRESTMethod(req *http.Request, method, service string, classes *agentapi.ActionClasses) string {
	class := classifyHTTPMethod(method)
	if strings.HasPrefix(service, "s3") || service == "" {
		query, queryErr := url.ParseQuery(req.URL.RawQuery)
		// SelectObjectContent is a POST that only reads. It is taken for one
		// only when select and select-type are all the query carries, so the
		// parameter cannot be added to another POST to pass it off as a read.
		if queryErr == nil && strings.EqualFold(method, http.MethodPost) && len(query) == 2 && query.Has("select") && query.Has("select-type") {
			return agentapi.ClassRead
		}
		// A read stays a read: GET /?policy only fetches the policy.
		if class != agentapi.ClassRead {
			if s3RequestGrantsAccess(req.Header) {
				return agentapi.ClassAdmin
			}
			subresource := ""
			for name, subresourceClass := range classes.S3Subresources {
				if query.Has(name) && classRank(subresourceClass) > classRank(subresource) {
					subresource = subresourceClass
				}
			}
			if subresource != "" {
				return subresource
			}
		}
	}
	if class != agentapi.ClassRead && containsString(classes.AdminServices, service) {
		return agentapi.ClassAdmin
	}
	return class
}

// s3RequestGrantsAccess reports whether an S3 write sets an ACL in its
// headers: a canned ACL (x-amz-acl) or explicit grants (x-amz-grant-*).
func s3RequestGrantsAccess(header http.Header) bool {
	for name := range header {
		lowered := strings.ToLower(name)
		if lowered == "x-amz-acl" || strings.HasPrefix(lowered, "x-amz-grant-") {
			return true
		}
	}
	return false
}

// classRank orders classes by how much a call of that class can change, so a
// request carrying several sub-resources is classified by the heaviest one.
func classRank(class string) int {
	switch class {
	case agentapi.ClassRead:
		return 1
	case agentapi.ClassCreate:
		return 2
	case agentapi.ClassUpdate:
		return 3
	case agentapi.ClassDelete:
		return 4
	case agentapi.ClassAdmin:
		return 5
	default:
		return 0
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
