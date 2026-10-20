package proxy

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/phasehq/cli/internal/agentapi"
)

func mintingAWSConnection(config map[string]any) agentapi.Connection {
	return agentapi.Connection{ServiceType: "aws", Protocol: "http", ConnectionConfig: config,
		Injection: agentapi.Injection{Action: "aws_sigv4"}}
}

func signedQueryRequest(t *testing.T, host, body string) *http.Request {
	t.Helper()
	req := newAWSRequest(t, "https://"+host+"/", body)
	req.Header.Set("X-Amz-Content-Sha256", sha256Hex(body))
	service, region, _ := deriveAWSHostScope(host)
	signRequest(t, req, aws.Credentials{AccessKeyID: testExpectedAccessKeyID, SecretAccessKey: testDecoySecret}, service, region, sha256Hex(body))
	return req
}

func TestCredentialMintingBlocksAWSTokenOperationsAndRestoresBody(t *testing.T) {
	connection := mintingAWSConnection(nil)
	for _, tc := range []struct {
		host, body, operation string
	}{
		{"sts.eu-central-1.amazonaws.com", "Action=GetSessionToken&Version=2011-06-15", "sts:GetSessionToken"},
		{"sts.eu-central-1.amazonaws.com", "Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A123%3Arole%2Fx&RoleSessionName=s&Version=2011-06-15", "sts:AssumeRole"},
		{"iam.amazonaws.com", "Action=CreateAccessKey&UserName=bob&Version=2010-05-08", "iam:CreateAccessKey"},
		{"redshift.eu-central-1.amazonaws.com", "Action=GetClusterCredentials&DbUser=u&Version=2012-12-01", "redshift:GetClusterCredentials"},
	} {
		req := signedQueryRequest(t, tc.host, tc.body)
		blocked, err := CredentialMintingBlocked(req, connection)
		if err != nil || blocked == nil || blocked.Operation != tc.operation {
			t.Fatalf("%s: blocked=%#v err=%v", tc.body, blocked, err)
		}
		if !strings.Contains(blocked.Message(), tc.operation) || !strings.Contains(blocked.Message(), "mint a new credential") {
			t.Fatalf("message = %q", blocked.Message())
		}
		if req.ContentLength != int64(len(tc.body)) {
			t.Fatalf("content length changed to %d", req.ContentLength)
		}
		assertRequestBody(t, req, tc.body)
	}
}

func TestCredentialMintingAllowsOrdinaryAWSCalls(t *testing.T) {
	connection := mintingAWSConnection(nil)
	for _, tc := range []struct{ host, body string }{
		{"sts.eu-central-1.amazonaws.com", "Action=GetCallerIdentity&Version=2011-06-15"},
		{"iam.amazonaws.com", "Action=ListUsers&Version=2010-05-08"},
		{"redshift.eu-central-1.amazonaws.com", "Action=DescribeClusters&Version=2012-12-01"},
	} {
		req := signedQueryRequest(t, tc.host, tc.body)
		if blocked, err := CredentialMintingBlocked(req, connection); err != nil || blocked != nil {
			t.Fatalf("%s: blocked=%#v err=%v", tc.body, blocked, err)
		}
		assertRequestBody(t, req, tc.body)
	}
	// Services without rules never have their bodies read.
	put, err := http.NewRequest(http.MethodPut, "https://bucket.s3.eu-central-1.amazonaws.com/key", errorReader{err: errors.New("body must not be read")})
	if err != nil {
		t.Fatal(err)
	}
	put.ContentLength = 10
	put.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if blocked, err := CredentialMintingBlocked(put, connection); err != nil || blocked != nil {
		t.Fatalf("s3 put: blocked=%#v err=%v", blocked, err)
	}
}

func TestCredentialMintingResolvesTargetHeaderQueryAndPathRules(t *testing.T) {
	connection := mintingAWSConnection(nil)
	ecr, _ := http.NewRequest(http.MethodPost, "https://api.ecr.eu-central-1.amazonaws.com/", strings.NewReader("{}"))
	ecr.Header.Set("Content-Type", "application/x-amz-json-1.1")
	ecr.Header.Set("X-Amz-Target", "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken")
	if blocked, err := CredentialMintingBlocked(ecr, connection); err != nil || blocked == nil || blocked.Operation != "ecr:GetAuthorizationToken" {
		t.Fatalf("ecr target: blocked=%#v err=%v", blocked, err)
	}
	ecr.Header.Set("X-Amz-Target", "AmazonEC2ContainerRegistry_V20150921.DescribeRepositories")
	if blocked, err := CredentialMintingBlocked(ecr, connection); err != nil || blocked != nil {
		t.Fatalf("ecr describe: blocked=%#v err=%v", blocked, err)
	}
	query, _ := http.NewRequest(http.MethodGet, "https://sts.amazonaws.com/?Action=GetFederationToken&Name=x&Version=2011-06-15", nil)
	if blocked, err := CredentialMintingBlocked(query, connection); err != nil || blocked == nil || blocked.Operation != "sts:GetFederationToken" {
		t.Fatalf("query action: blocked=%#v err=%v", blocked, err)
	}
	codeartifact, _ := http.NewRequest(http.MethodPost, "https://codeartifact.eu-central-1.amazonaws.com/v1/authorization/token?domain=d", nil)
	if blocked, err := CredentialMintingBlocked(codeartifact, connection); err != nil || blocked == nil || blocked.Operation != "codeartifact:GetAuthorizationToken" {
		t.Fatalf("codeartifact path: blocked=%#v err=%v", blocked, err)
	}

	github := agentapi.Connection{ServiceType: "github", Protocol: "http"}
	installation, _ := http.NewRequest(http.MethodPost, "https://api.github.com/app/installations/42/access_tokens", nil)
	if blocked, err := CredentialMintingBlocked(installation, github); err != nil || blocked == nil || !strings.Contains(blocked.Operation, "installation access token") {
		t.Fatalf("github installation token: blocked=%#v err=%v", blocked, err)
	}
	issue, _ := http.NewRequest(http.MethodPost, "https://api.github.com/repos/o/r/issues", strings.NewReader("{}"))
	if blocked, err := CredentialMintingBlocked(issue, github); err != nil || blocked != nil {
		t.Fatalf("github issue: blocked=%#v err=%v", blocked, err)
	}
	postgres := agentapi.Connection{ServiceType: "postgres", Protocol: "postgres"}
	if blocked, err := CredentialMintingBlocked(installation, postgres); err != nil || blocked != nil {
		t.Fatalf("unguarded service: blocked=%#v err=%v", blocked, err)
	}
}

func TestCredentialMintingHonoursConnectionExemptionAndFailsClosedWhenUninspectable(t *testing.T) {
	exempt := mintingAWSConnection(map[string]any{"allowCredentialMinting": true})
	req := signedQueryRequest(t, "sts.eu-central-1.amazonaws.com", "Action=GetSessionToken&Version=2011-06-15")
	if blocked, err := CredentialMintingBlocked(req, exempt); err != nil || blocked != nil {
		t.Fatalf("exempt connection: blocked=%#v err=%v", blocked, err)
	}
	huge, _ := http.NewRequest(http.MethodPost, "https://sts.eu-central-1.amazonaws.com/", strings.NewReader("Action=GetCallerIdentity"))
	huge.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	huge.ContentLength = maximumMintingInspectionBytes + 1
	if _, err := CredentialMintingBlocked(huge, mintingAWSConnection(nil)); !errors.Is(err, ErrMintingInspectionUnavailable) {
		t.Fatalf("oversized form body error = %v", err)
	}
	unknownLength, _ := http.NewRequest(http.MethodPost, "https://sts.eu-central-1.amazonaws.com/", strings.NewReader("Action=GetCallerIdentity"))
	unknownLength.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	unknownLength.ContentLength = -1
	if _, err := CredentialMintingBlocked(unknownLength, mintingAWSConnection(nil)); !errors.Is(err, ErrMintingInspectionUnavailable) {
		t.Fatalf("unknown-length form body error = %v", err)
	}
}
