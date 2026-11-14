package proxy

import (
	"mime"
	"net/http"
	"strings"

	"github.com/phasehq/cli/internal/agentapi"
)

// How an AWS call is sorted into an operation class.
//
// This table is provider-owned data shipped with the CLI; it is not edited by
// members and is not part of any stored policy. An access policy names classes
// ("delete: block"), and this is what decides which class a call belongs to.
//
// A call's action is the operation the request names: the X-Amz-Target header
// (JSON protocols), or the Action parameter of the query string or of a form
// body (query protocols). The action is classified in this order:
//
//  1. Credential minting is the secret guard's and is decided in minting.go
//     before any of this runs.
//  2. An entry in Exact for "service:Action".
//  3. A read verb: the call does not change anything, in any service.
//  4. A write in an admin service (identity, organisation, account), or a
//     write whose name says it changes who may do what (a policy, a
//     permission, an ACL), is admin.
//  5. A create verb, then a delete verb.
//  6. Everything else, including an action this table has never seen, is
//     update.
//
// A request that names no action (the REST services, S3 above all) is
// classified by its HTTP method, with the S3 sub-resources that delete objects
// in bulk or change permissions called out in S3Subresources.
type awsClassTable struct {
	ReadVerbs     []string
	CreateVerbs   []string
	DeleteVerbs   []string
	AdminServices []string
	// AdminSuffixes: a write whose action name ends with one of these changes
	// permissions rather than data.
	AdminSuffixes []string
	Exact         map[string]string
	// S3Subresources maps a query parameter of an S3 request that is not a
	// read to the class it makes the call.
	S3Subresources map[string]string
	// QueryProtocolServices take their action from a form body, whatever
	// Content-Type the request claims.
	QueryProtocolServices []string
}

var awsClasses = awsClassTable{
	ReadVerbs: []string{
		"Get", "BatchGet", "TransactGet", "List", "Describe", "Head", "Search", "Lookup",
		"Query", "Scan", "Select", "Filter", "Check", "Validate", "Simulate", "Estimate", "Preview",
	},
	CreateVerbs: []string{"Create", "Run", "Allocate", "Register", "Import", "Launch", "Provision", "Copy"},
	DeleteVerbs: []string{"Delete", "BatchDelete", "Remove", "Terminate", "Deregister", "Purge", "Destroy", "Release"},
	AdminServices: []string{
		"iam", "organizations", "account", "sso", "sso-directory", "identitystore",
	},
	AdminSuffixes: []string{"Policy", "Policies", "Permission", "Permissions", "PublicAccessBlock", "Acl"},
	Exact: map[string]string{
		// Grants and instance profiles change who may act, without saying so in
		// a suffix.
		"kms:CreateGrant":                          agentapi.ClassAdmin,
		"kms:RevokeGrant":                          agentapi.ClassAdmin,
		"kms:RetireGrant":                          agentapi.ClassAdmin,
		"ec2:AssociateIamInstanceProfile":          agentapi.ClassAdmin,
		"ec2:ReplaceIamInstanceProfileAssociation": agentapi.ClassAdmin,
		"ec2:DisassociateIamInstanceProfile":       agentapi.ClassAdmin,
		"kms:ScheduleKeyDeletion":                  agentapi.ClassDelete,
		"dynamodb:TransactWriteItems":              agentapi.ClassUpdate,
		"dynamodb:BatchWriteItem":                  agentapi.ClassUpdate,
		// "Policy" here is a scaling, retention or lifecycle setting, not a
		// permission.
		"autoscaling:PutScalingPolicy":                agentapi.ClassUpdate,
		"autoscaling:DeletePolicy":                    agentapi.ClassDelete,
		"application-autoscaling:PutScalingPolicy":    agentapi.ClassUpdate,
		"application-autoscaling:DeleteScalingPolicy": agentapi.ClassDelete,
		"logs:PutRetentionPolicy":                     agentapi.ClassUpdate,
		"logs:DeleteRetentionPolicy":                  agentapi.ClassDelete,
		"ecr:PutLifecyclePolicy":                      agentapi.ClassUpdate,
		"ecr:DeleteLifecyclePolicy":                   agentapi.ClassDelete,
	},
	S3Subresources: map[string]string{
		"delete":            agentapi.ClassDelete, // DeleteObjects: POST /?delete
		"select":            agentapi.ClassRead,   // SelectObjectContent: POST /key?select
		"policy":            agentapi.ClassAdmin,
		"acl":               agentapi.ClassAdmin,
		"publicAccessBlock": agentapi.ClassAdmin,
		"ownershipControls": agentapi.ClassAdmin,
	},
	QueryProtocolServices: []string{
		"ec2", "iam", "sts", "sns", "sqs", "rds", "cloudformation", "autoscaling", "elasticloadbalancing",
		"elasticache", "redshift", "monitoring", "ses", "elasticbeanstalk", "cloudsearch", "sdb",
	},
}

// classifyAWSAction returns the class of one named action of a service.
func classifyAWSAction(service, action string) string {
	if class, ok := awsClasses.Exact[service+":"+action]; ok {
		return class
	}
	if hasVerb(action, awsClasses.ReadVerbs) {
		return agentapi.ClassRead
	}
	if containsString(awsClasses.AdminServices, service) {
		return agentapi.ClassAdmin
	}
	for _, suffix := range awsClasses.AdminSuffixes {
		if strings.HasSuffix(action, suffix) {
			return agentapi.ClassAdmin
		}
	}
	if hasVerb(action, awsClasses.CreateVerbs) {
		return agentapi.ClassCreate
	}
	if hasVerb(action, awsClasses.DeleteVerbs) {
		return agentapi.ClassDelete
	}
	return agentapi.ClassUpdate
}

// hasVerb reports whether action starts with one of the verbs as a whole
// word of its CamelCase name: "List" matches ListUsers, not Listen.
func hasVerb(action string, verbs []string) bool {
	for _, verb := range verbs {
		rest, found := strings.CutPrefix(action, verb)
		if !found {
			continue
		}
		if rest == "" || (rest[0] >= 'A' && rest[0] <= 'Z') || (rest[0] >= '0' && rest[0] <= '9') {
			return true
		}
	}
	return false
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
// harmless selector cannot hide the one the service will run.
func classifyAWSCall(req *http.Request) ([]ClassifiedCall, error) {
	service := awsScopeService(req)
	actions, err := awsHeaderAndQueryOperations(req)
	if err != nil {
		return nil, ErrCallUninspectable
	}
	if awsFormBodyMayNameAction(req, service) {
		fromBody, bodyErr := awsFormBodyOperations(req)
		if bodyErr != nil {
			return nil, ErrCallUninspectable
		}
		actions = append(actions, fromBody...)
	}
	if len(actions) == 0 {
		return []ClassifiedCall{{Class: classifyAWSRESTCall(req, service)}}, nil
	}
	calls := make([]ClassifiedCall, 0, len(actions))
	for _, action := range actions {
		operation := action
		if service != "" {
			operation = service + ":" + action
		}
		calls = append(calls, ClassifiedCall{Class: classifyAWSAction(service, action), Operation: operation})
	}
	return calls, nil
}

// awsFormBodyMayNameAction decides whether the body has to be read to know
// the action. A query-protocol service, or one the proxy cannot name, acts on
// a form body whatever Content-Type the request claims, so its body is always
// read. Any other service has its body read only when it says it is a form:
// an S3 upload is never buffered.
func awsFormBodyMayNameAction(req *http.Request, service string) bool {
	if !awsBodyMaySelectOperation(req) {
		return false
	}
	if service == "" || containsString(awsClasses.QueryProtocolServices, service) {
		return true
	}
	mediaType, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	return mediaType == "application/x-www-form-urlencoded"
}

func classifyAWSRESTCall(req *http.Request, service string) string {
	class := classifyHTTPMethod(req.Method)
	if service == "s3" || service == "" {
		query := req.URL.Query()
		subresource := ""
		for name, subresourceClass := range awsClasses.S3Subresources {
			if query.Has(name) && classRank(subresourceClass) > classRank(subresource) {
				subresource = subresourceClass
			}
		}
		switch {
		case subresource == "":
		case subresource == agentapi.ClassRead:
			// The sub-resource says a POST only reads (POST /key?select). On
			// any other method it changes nothing about the class.
			if req.Method == http.MethodPost {
				return agentapi.ClassRead
			}
		case class != agentapi.ClassRead:
			// A read stays a read: GET /?policy only fetches the policy.
			return subresource
		}
	}
	if class != agentapi.ClassRead && containsString(awsClasses.AdminServices, service) {
		return agentapi.ClassAdmin
	}
	return class
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
