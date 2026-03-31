package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	"github.com/phasehq/golang-sdk/v2/phase/network"
	"github.com/spf13/cobra"
)

func runAzureAuth(cmd *cobra.Command, host string) error {
	serviceAccountID, _ := cmd.Flags().GetString("service-account-id")
	if serviceAccountID == "" {
		return fmt.Errorf("--service-account-id is required for azure auth mode")
	}

	ttlVal, _ := cmd.Flags().GetInt("ttl")
	var ttl *int
	if cmd.Flags().Changed("ttl") {
		ttl = &ttlVal
	}

	noStore, _ := cmd.Flags().GetBool("no-store")
	resource, _ := cmd.Flags().GetString("azure-resource")

	// SDK handles everything: DefaultAzureCredential → get JWT → POST to Phase API
	result, err := network.ExternalIdentityAuthAzure(host, serviceAccountID, ttl, resource)
	if err != nil {
		return fmt.Errorf("Azure authentication failed: %w", err)
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

	if err := phase.Auth(p); err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}

	// Get user data
	userData, err := phase.Init(p)
	if err != nil {
		return fmt.Errorf("failed to fetch user data: %w", err)
	}

	accountID, err := phase.AccountID(userData)
	if err != nil {
		return err
	}

	var orgID, orgName *string
	if userData.Organisation != nil {
		orgID = &userData.Organisation.ID
		orgName = &userData.Organisation.Name
	}

	var wrappedKeyShare *string
	if userData.OfflineEnabled && userData.WrappedKeyShare != "" {
		wrappedKeyShare = &userData.WrappedKeyShare
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
