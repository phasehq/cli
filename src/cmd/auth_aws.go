package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	"github.com/phasehq/golang-sdk/phase/network"
	"github.com/spf13/cobra"
)

func resolveRegionAndEndpoint(ctx context.Context) (string, string, error) {
	// Load the full AWS SDK config which reads env vars, ~/.aws/config,
	// EC2 IMDS, etc. — matching boto3's region resolution behavior.
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	endpoint := fmt.Sprintf("https://sts.%s.amazonaws.com", region)
	if region == "us-east-1" {
		endpoint = "https://sts.amazonaws.com"
	}

	return region, endpoint, nil
}

func signGetCallerIdentity(ctx context.Context, region, endpoint string) (string, map[string]string, string, error) {
	body := "Action=GetCallerIdentity&Version=2011-06-15"

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return "", nil, "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return "", nil, "", fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(body))
	if err != nil {
		return "", nil, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	// Compute SHA256 hash of the body for SigV4
	bodyHash := sha256.Sum256([]byte(body))
	payloadHash := hex.EncodeToString(bodyHash[:])

	signer := v4.NewSigner()
	err = signer.SignHTTP(ctx, creds, req, payloadHash, "sts", region, time.Now())
	if err != nil {
		return "", nil, "", fmt.Errorf("failed to sign request: %w", err)
	}

	signedHeaders := map[string]string{}
	for key, values := range req.Header {
		if len(values) > 0 {
			signedHeaders[key] = values[0]
		}
	}

	return endpoint, signedHeaders, body, nil
}

func runAWSIAMAuth(cmd *cobra.Command, host string) error {
	serviceAccountID, _ := cmd.Flags().GetString("service-account-id")
	if serviceAccountID == "" {
		return fmt.Errorf("--service-account-id is required for aws-iam auth mode")
	}

	ttlVal, _ := cmd.Flags().GetInt("ttl")
	var ttl *int
	if cmd.Flags().Changed("ttl") {
		ttl = &ttlVal
	}

	noStore, _ := cmd.Flags().GetBool("no-store")

	ctx := context.Background()
	region, endpoint, err := resolveRegionAndEndpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve AWS region: %w", err)
	}

	signedURL, signedHeaders, body, err := signGetCallerIdentity(ctx, region, endpoint)
	if err != nil {
		return fmt.Errorf("failed to sign AWS request: %w", err)
	}

	// Base64 encode the signed values
	encodedURL := base64.StdEncoding.EncodeToString([]byte(signedURL))
	headersJSON, _ := json.Marshal(signedHeaders)
	encodedHeaders := base64.StdEncoding.EncodeToString(headersJSON)
	encodedBody := base64.StdEncoding.EncodeToString([]byte(body))

	result, err := network.ExternalIdentityAuthAWS(host, serviceAccountID, ttl, encodedURL, encodedHeaders, encodedBody, "POST")
	if err != nil {
		return fmt.Errorf("AWS IAM authentication failed: %w", err)
	}

	if noStore {
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	// Extract token from response
	auth, ok := result["authentication"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected response format: missing 'authentication' field")
	}
	token, ok := auth["token"].(string)
	if !ok || token == "" {
		return fmt.Errorf("no token found in authentication response")
	}

	// Validate the token
	p, err := phase.NewPhase(false, token, host)
	if err != nil {
		return fmt.Errorf("invalid token received: %w", err)
	}

	if err := p.Auth(); err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}

	// Get user data
	userData, err := p.InitRaw()
	if err != nil {
		return fmt.Errorf("failed to fetch user data: %w", err)
	}

	accountID := ""
	if uid, ok := userData["user_id"].(string); ok && uid != "" {
		accountID = uid
	} else if aid, ok := userData["account_id"].(string); ok && aid != "" {
		accountID = aid
	}
	if accountID == "" {
		return fmt.Errorf("no account ID found in response")
	}

	var orgID, orgName *string
	if org, ok := userData["organisation"].(map[string]interface{}); ok && org != nil {
		if id, ok := org["id"].(string); ok {
			orgID = &id
		}
		if name, ok := org["name"].(string); ok {
			orgName = &name
		}
	}

	var wrappedKeyShare *string
	offlineEnabled, _ := userData["offline_enabled"].(bool)
	if offlineEnabled {
		if wks, ok := userData["wrapped_key_share"].(string); ok {
			wrappedKeyShare = &wks
		}
	}

	tokenSavedInKeyring := true
	if err := keyring.SetCredentials(accountID, token); err != nil {
		tokenSavedInKeyring = false
	}

	userConfig := config.UserConfig{
		Host:             host,
		ID:               accountID,
		OrganizationID:   orgID,
		OrganizationName: orgName,
		WrappedKeyShare:  wrappedKeyShare,
	}
	if !tokenSavedInKeyring {
		userConfig.Token = token
	}

	if err := config.AddUser(userConfig); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println(util.BoldGreen("✅ Authentication successful."))
	return nil
}
