package proxy

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/agentapi"
)

func TestAWSActionsAreSortedIntoClasses(t *testing.T) {
	tests := map[string]string{
		// Read verbs, in any service, including the admin ones.
		"sts:GetCallerIdentity":               "read",
		"s3:ListBuckets":                      "read",
		"ec2:DescribeInstances":               "read",
		"s3:HeadObject":                       "read",
		"dynamodb:BatchGetItem":               "read",
		"dynamodb:TransactGetItems":           "read",
		"dynamodb:Query":                      "read",
		"dynamodb:Scan":                       "read",
		"resource-explorer-2:Search":          "read",
		"cloudtrail:LookupEvents":             "read",
		"logs:FilterLogEvents":                "read",
		"s3:SelectObjectContent":              "read",
		"cloudformation:ValidateTemplate":     "read",
		"cloudformation:EstimateTemplateCost": "read",
		"iam:ListUsers":                       "read",
		"iam:GetRole":                         "read",
		"iam:SimulatePrincipalPolicy":         "read",
		"organizations:DescribeOrganization":  "read",
		"secretsmanager:GetSecretValue":       "read",
		"s3:GetBucketPolicy":                  "read",

		// Create.
		"ec2:RunInstances":           "create",
		"ec2:CreateVolume":           "create",
		"dynamodb:CreateTable":       "create",
		"ec2:AllocateAddress":        "create",
		"ecs:RegisterTaskDefinition": "create",
		"ec2:ImportKeyPair":          "create",
		"ec2:CopySnapshot":           "create",
		"cloudformation:CreateStack": "create",

		// Delete.
		"ec2:TerminateInstances":          "delete",
		"dynamodb:DeleteItem":             "delete",
		"dynamodb:DeleteTable":            "delete",
		"sqs:PurgeQueue":                  "delete",
		"ecs:DeregisterTaskDefinition":    "delete",
		"elasticloadbalancing:RemoveTags": "delete",
		"ec2:ReleaseAddress":              "delete",
		"ecr:BatchDeleteImage":            "delete",
		"kms:ScheduleKeyDeletion":         "delete",
		"cloudformation:DeleteStack":      "delete",

		// Admin: identity, organisation and account services, and writes
		// that change who may do what.
		"iam:CreateRole":                   "admin",
		"iam:DeleteUser":                   "admin",
		"iam:AttachRolePolicy":             "admin",
		"iam:PutRolePolicy":                "admin",
		"iam:UpdateAssumeRolePolicy":       "admin",
		"iam:TagRole":                      "admin",
		"organizations:CreateAccount":      "admin",
		"organizations:LeaveOrganization":  "admin",
		"account:PutAlternateContact":      "admin",
		"sso:CreatePermissionSet":          "admin",
		"identitystore:CreateUser":         "admin",
		"s3:PutBucketPolicy":               "admin",
		"s3:DeleteBucketPolicy":            "admin",
		"s3:PutBucketAcl":                  "admin",
		"s3:PutPublicAccessBlock":          "admin",
		"sns:AddPermission":                "admin",
		"sqs:RemovePermission":             "admin",
		"lambda:AddPermission":             "admin",
		"ecr:SetRepositoryPolicy":          "admin",
		"secretsmanager:PutResourcePolicy": "admin",
		"kms:PutKeyPolicy":                 "admin",
		"kms:CreateGrant":                  "admin",
		"kms:RevokeGrant":                  "admin",
		"lakeformation:GrantPermissions":   "admin",
		"ec2:AssociateIamInstanceProfile":  "admin",

		// "Policy" that is a setting, not a permission.
		"autoscaling:PutScalingPolicy": "update",
		"autoscaling:DeletePolicy":     "delete",
		"logs:PutRetentionPolicy":      "update",
		"ecr:DeleteLifecyclePolicy":    "delete",

		// Everything else that writes, and anything unknown, is update.
		"dynamodb:PutItem":                  "update",
		"dynamodb:UpdateItem":               "update",
		"dynamodb:BatchWriteItem":           "update",
		"dynamodb:TransactWriteItems":       "update",
		"ec2:StopInstances":                 "update",
		"ec2:StartInstances":                "update",
		"ec2:ModifyInstanceAttribute":       "update",
		"ec2:AuthorizeSecurityGroupIngress": "update",
		"sqs:SendMessage":                   "update",
		"sns:Publish":                       "update",
		"ssm:SendCommand":                   "update",
		"kms:Decrypt":                       "update",
		"cloudformation:UpdateStack":        "update",
		"ec2:TagResources":                  "update",
		"example:SomethingNeverSeenBefore":  "update",
		// A verb is a whole word of the name.
		"example:Listen":       "update",
		"example:Getaway":      "update",
		"example:Deleted":      "update",
		"example:Createdness":  "update",
		"example:Runner":       "update",
		"example:List":         "read",
		"example:Get2FAStatus": "read",
	}
	for operation, want := range tests {
		service, action, _ := strings.Cut(operation, ":")
		if got := classifyAWSAction(service, action); got != want {
			t.Errorf("%s = %s, want %s", operation, got, want)
		}
	}
}

// The table is data: every class it names is one a policy may name, every
// exact entry is spelled service:Action, and no verb sits in two lists.
func TestAWSClassTableIsWellFormed(t *testing.T) {
	userClass := map[string]bool{"read": true, "create": true, "update": true, "delete": true, "admin": true}
	for operation, class := range awsClasses.Exact {
		service, action, found := strings.Cut(operation, ":")
		if !found || service == "" || action == "" || service != strings.ToLower(service) || !userClass[class] {
			t.Errorf("exact entry %q -> %q is malformed", operation, class)
		}
	}
	for name, class := range awsClasses.S3Subresources {
		if name == "" || !userClass[class] {
			t.Errorf("S3 sub-resource %q -> %q is malformed", name, class)
		}
	}
	seen := map[string]string{}
	for list, verbs := range map[string][]string{"read": awsClasses.ReadVerbs, "create": awsClasses.CreateVerbs, "delete": awsClasses.DeleteVerbs} {
		for _, verb := range verbs {
			if verb == "" || verb[0] < 'A' || verb[0] > 'Z' {
				t.Errorf("%s verb %q is malformed", list, verb)
			}
			if other, duplicate := seen[verb]; duplicate {
				t.Errorf("verb %q is in both the %s and the %s list", verb, other, list)
			}
			seen[verb] = list
		}
	}
	// A minting action is the secret guard's and must not be reclassified as
	// something a policy could allow.
	for service, operations := range credentialMintingRules["aws"].Operations {
		for _, operation := range operations {
			if _, exact := awsClasses.Exact[service+":"+operation]; exact {
				t.Errorf("%s:%s is a credential-minting action and has an exact class", service, operation)
			}
		}
	}
}

func classesOf(t *testing.T, req *http.Request) ([]string, []string) {
	t.Helper()
	calls, err := ClassifyCall(req, agentapi.Connection{ServiceType: "aws", Protocol: "http", Injection: agentapi.Injection{Action: "aws_sigv4"}})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	classes, operations := make([]string, 0, len(calls)), make([]string, 0, len(calls))
	for _, call := range calls {
		classes = append(classes, call.Class)
		operations = append(operations, call.Operation)
	}
	return classes, operations
}

func TestAWSCallsAreClassifiedFromEverySelectorTheRequestCarries(t *testing.T) {
	// Query protocol: the action is in the form body.
	terminate := signedQueryRequest(t, "ec2.eu-central-1.amazonaws.com", "Action=TerminateInstances&InstanceId.1=i-1&Version=2016-11-15")
	classes, operations := classesOf(t, terminate)
	if !reflect.DeepEqual(classes, []string{"delete"}) || !reflect.DeepEqual(operations, []string{"ec2:TerminateInstances"}) {
		t.Fatalf("ec2 terminate = %v %v", classes, operations)
	}
	assertRequestBody(t, terminate, "Action=TerminateInstances&InstanceId.1=i-1&Version=2016-11-15")

	// A query-protocol service acts on a form body whatever it is labelled.
	mislabelled := signedQueryRequest(t, "ec2.eu-central-1.amazonaws.com", "Action=TerminateInstances&InstanceId.1=i-1")
	mislabelled.Header.Set("Content-Type", "text/plain")
	if classes, _ := classesOf(t, mislabelled); !reflect.DeepEqual(classes, []string{"delete"}) {
		t.Fatalf("mislabelled ec2 body = %v", classes)
	}

	// JSON protocol: the action is in X-Amz-Target and the body is not read.
	deleteTable := signedQueryRequest(t, "dynamodb.eu-central-1.amazonaws.com", `{"TableName":"orders"}`)
	deleteTable.Header.Set("Content-Type", "application/x-amz-json-1.0")
	deleteTable.Header.Set("X-Amz-Target", "DynamoDB_20120810.DeleteTable")
	classes, operations = classesOf(t, deleteTable)
	if !reflect.DeepEqual(classes, []string{"delete"}) || !reflect.DeepEqual(operations, []string{"dynamodb:DeleteTable"}) {
		t.Fatalf("dynamodb delete table = %v %v", classes, operations)
	}

	// The Action query parameter.
	identity, _ := http.NewRequest(http.MethodGet, "https://sts.eu-central-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", nil)
	if classes, operations := classesOf(t, identity); !reflect.DeepEqual(classes, []string{"read"}) || operations[0] != "sts:GetCallerIdentity" {
		t.Fatalf("sts identity = %v %v", classes, operations)
	}

	// A harmless selector beside the one the service acts on: both are kept,
	// so the policy judges the request by the heavier one.
	masked := signedQueryRequest(t, "ec2.eu-central-1.amazonaws.com", "Action=TerminateInstances&InstanceId.1=i-1")
	masked.Header.Set("X-Amz-Target", "AmazonEC2.DescribeInstances")
	if classes, _ := classesOf(t, masked); !reflect.DeepEqual(classes, []string{"read", "delete"}) {
		t.Fatalf("masked ec2 request = %v", classes)
	}

	// An admin service.
	attach := signedQueryRequest(t, "iam.amazonaws.com", "Action=AttachRolePolicy&RoleName=r&PolicyArn=arn%3Aaws%3Aiam%3A%3Aaws%3Apolicy%2FAdministratorAccess")
	if classes, _ := classesOf(t, attach); !reflect.DeepEqual(classes, []string{"admin"}) {
		t.Fatalf("iam attach = %v", classes)
	}
}

func TestAWSRequestsWithoutAnActionAreClassifiedByMethodAndS3Subresource(t *testing.T) {
	tests := []struct {
		method, target, class string
	}{
		{"GET", "https://bucket.s3.eu-central-1.amazonaws.com/key", "read"},
		{"HEAD", "https://bucket.s3.eu-central-1.amazonaws.com/key", "read"},
		{"PUT", "https://bucket.s3.eu-central-1.amazonaws.com/key", "update"},
		{"POST", "https://bucket.s3.eu-central-1.amazonaws.com/key?uploads", "create"},
		{"DELETE", "https://bucket.s3.eu-central-1.amazonaws.com/key", "delete"},
		{"POST", "https://bucket.s3.eu-central-1.amazonaws.com/?delete", "delete"},
		{"POST", "https://bucket.s3.eu-central-1.amazonaws.com/key?select&select-type=2", "read"},
		{"POST", "https://bucket.s3.eu-central-1.amazonaws.com/?delete&select", "delete"},
		{"DELETE", "https://bucket.s3.eu-central-1.amazonaws.com/key?select", "delete"},
		{"GET", "https://bucket.s3.eu-central-1.amazonaws.com/?policy", "read"},
		{"PUT", "https://bucket.s3.eu-central-1.amazonaws.com/?policy", "admin"},
		{"DELETE", "https://bucket.s3.eu-central-1.amazonaws.com/?policy", "admin"},
		{"PUT", "https://bucket.s3.eu-central-1.amazonaws.com/key?acl", "admin"},
		{"PUT", "https://bucket.s3.eu-central-1.amazonaws.com/?publicAccessBlock", "admin"},
		{"PUT", "https://bucket.s3.eu-central-1.amazonaws.com/?delete&policy", "admin"},
		// Other REST services: the method alone.
		{"POST", "https://lambda.eu-central-1.amazonaws.com/2015-03-31/functions/f/invocations", "create"},
		{"DELETE", "https://lambda.eu-central-1.amazonaws.com/2015-03-31/functions/f", "delete"},
		{"PATCH", "https://lambda.eu-central-1.amazonaws.com/2015-03-31/functions/f", "update"},
		{"GET", "https://lambda.eu-central-1.amazonaws.com/2015-03-31/functions?policy", "read"},
		{"PUT", "https://lambda.eu-central-1.amazonaws.com/2015-03-31/functions/f/code?policy", "update"},
	}
	for _, test := range tests {
		request, err := http.NewRequest(test.method, test.target, nil)
		if err != nil {
			t.Fatal(err)
		}
		classes, operations := classesOf(t, request)
		if !reflect.DeepEqual(classes, []string{test.class}) || operations[0] != "" {
			t.Errorf("%s %s = %v %v, want %s", test.method, test.target, classes, operations, test.class)
		}
	}
}

// An upload is never buffered to look for an action: only a query-protocol
// service, or a body that says it is a form, has its body read.
func TestAWSUploadBodiesAreNotReadForClassification(t *testing.T) {
	upload, _ := http.NewRequest(http.MethodPut, "https://bucket.s3.eu-central-1.amazonaws.com/large.bin", &failingReader{})
	upload.ContentLength = 5 << 30
	classes, _ := classesOf(t, upload)
	if !reflect.DeepEqual(classes, []string{"update"}) {
		t.Fatalf("s3 upload = %v", classes)
	}
	unknownLength, _ := http.NewRequest(http.MethodPut, "https://bucket.s3.eu-central-1.amazonaws.com/stream.bin", &failingReader{})
	unknownLength.ContentLength = -1
	unknownLength.Header.Set("Content-Type", "application/octet-stream")
	if classes, _ := classesOf(t, unknownLength); !reflect.DeepEqual(classes, []string{"update"}) {
		t.Fatalf("s3 streamed upload = %v", classes)
	}
	form, _ := http.NewRequest(http.MethodPost, "https://lambda.eu-central-1.amazonaws.com/", strings.NewReader("Action=DeleteFunction"))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if classes, operations := classesOf(t, form); !reflect.DeepEqual(classes, []string{"delete"}) || operations[0] != "lambda:DeleteFunction" {
		t.Fatalf("a form body on a REST service = %v %v", classes, operations)
	}
}

type failingReader struct{}

func (*failingReader) Read([]byte) (int, error) {
	panic("the request body was read")
}
