package aiproxy

import (
	"strings"
	"testing"

	"github.com/phasehq/cli/internal/agentapi"
)

func TestValidCreateRequestAcceptsOnlySetupOrCredentialUpdateShapes(t *testing.T) {
	tests := []struct {
		name    string
		request agentapi.CreateRequestRequest
		valid   bool
	}{
		{
			name: "setup",
			request: agentapi.CreateRequestRequest{
				Kind: "setup", ServiceType: "aws", CredentialProvider: "aws", CredentialName: "AWS production",
			},
			valid: true,
		},
		{
			name:    "schema v1",
			request: agentapi.CreateRequestRequest{SchemaVersion: agentapi.SchemaVersion, Kind: "setup", ServiceType: "aws", CredentialProvider: "aws_assume_role", CredentialName: "AWS deploy role"},
			valid:   true,
		},
		{
			name: "credential update",
			request: agentapi.CreateRequestRequest{
				Kind: "credential_update", ConnectionID: "aws-production", CredentialID: "credential-aws",
				CredentialProvider: "aws", CredentialName: "AWS - EC2, RDS, S3 full access",
			},
			valid: true,
		},
		{
			name:    "missing kind",
			request: agentapi.CreateRequestRequest{ConnectionID: "aws-production", CredentialID: "credential-aws", CredentialProvider: "aws", CredentialName: "AWS"},
		},
		{
			name: "setup missing provider",
			request: agentapi.CreateRequestRequest{
				Kind: "setup", CredentialName: "Postgres", ServiceType: "postgres",
			},
		},
		{
			name:    "setup missing name",
			request: agentapi.CreateRequestRequest{Kind: "setup", CredentialProvider: "aws", ServiceType: "aws"},
		},
		{
			name: "update missing target",
			request: agentapi.CreateRequestRequest{
				Kind: "credential_update", CredentialProvider: "aws", CredentialName: "AWS",
			},
		},
		{
			name: "setup has connection",
			request: agentapi.CreateRequestRequest{
				Kind: "setup", ConnectionID: "github", CredentialProvider: "github", CredentialName: "GitHub", ServiceType: "github",
			},
		},
		{
			name: "provider invalid",
			request: agentapi.CreateRequestRequest{
				Kind: "setup", CredentialProvider: "github/oauth", CredentialName: "GitHub", ServiceType: "github",
			},
		},
		{
			name: "name padded",
			request: agentapi.CreateRequestRequest{
				Kind: "setup", CredentialProvider: "github", CredentialName: " GitHub", ServiceType: "github",
			},
		},
		{
			name: "service too long",
			request: agentapi.CreateRequestRequest{
				Kind: "setup", CredentialProvider: "github", CredentialName: "GitHub", ServiceType: strings.Repeat("a", 65),
			},
		},
		{
			name: "service invalid",
			request: agentapi.CreateRequestRequest{
				Kind: "setup", CredentialProvider: "github", CredentialName: "GitHub", ServiceType: "github/enterprise",
			},
		},
		{
			name:    "unknown kind",
			request: agentapi.CreateRequestRequest{Kind: "access", ConnectionID: "aws", CredentialProvider: "aws", CredentialName: "AWS"},
		},
		{
			name:    "unknown schema",
			request: agentapi.CreateRequestRequest{SchemaVersion: 2, Kind: "setup", ServiceType: "aws", CredentialProvider: "aws", CredentialName: "AWS"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validCreateRequest(test.request); got != test.valid {
				t.Fatalf("validCreateRequest() = %t, want %t", got, test.valid)
			}
		})
	}
}
