package cmd

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/manifoldco/promptui"
	"github.com/phasehq/cli/internal/agentapi"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	"github.com/phasehq/golang-sdk/v2/phase/misc"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/term"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "💻 Authenticate with Phase",
	RunE:  runAuth,
}

var authMode string

func init() {
	authCmd.Flags().StringVar(&authMode, "mode", "webauth", "Authentication mode (webauth, token, aws-iam, azure)")
	authCmd.Flags().String("service-account-id", "", "Service account ID (required for aws-iam and azure modes)")
	authCmd.Flags().Int("ttl", 0, "Token TTL in seconds (for external identity modes)")
	authCmd.Flags().Bool("no-store", false, "Print token to stdout instead of storing (for external identity modes)")
	authCmd.Flags().Bool("insecure-storage", false, "Store the token in plain text in the Phase config file when no system keystore is available")
	authCmd.Flags().String("azure-resource", "", "Azure AD resource/audience for token request (for azure mode, default: https://management.azure.com/)")
	rootCmd.AddCommand(authCmd)
}

func runAuth(cmd *cobra.Command, args []string) error {
	// Determine host
	host := os.Getenv("PHASE_HOST")
	if host == "" {
		prompt := promptui.Select{
			Label: "Choose your Phase instance type",
			Items: []string{"☁️  Phase Cloud", "🛠️  Self Hosted"},
		}
		idx, _, err := prompt.Run()
		if err != nil {
			return fmt.Errorf("prompt cancelled")
		}

		if idx == 1 {
			hostPrompt := promptui.Prompt{
				Label: "Please enter your host (URL eg. https://example.com)",
			}
			host, err = hostPrompt.Run()
			if err != nil {
				return fmt.Errorf("prompt cancelled")
			}
			host = strings.TrimSpace(host)
			if host == "" {
				return fmt.Errorf("host URL is required for self-hosted instances")
			}
			if !util.ValidateURL(host) {
				return fmt.Errorf("invalid URL. Please ensure you include the scheme (e.g., https) and domain. Keep in mind, path and port are optional")
			}
		} else {
			host = config.PhaseCloudAPIHost
		}
	} else {
		fmt.Fprintf(os.Stderr, "Using PHASE_HOST environment variable: %s\n", host)
	}

	switch authMode {
	case "webauth":
		return runWebAuth(cmd, host)
	case "aws-iam":
		return runAWSIAMAuth(cmd, host)
	case "azure":
		return runAzureAuth(cmd, host)
	case "token":
		return runTokenAuth(cmd, host)
	default:
		return fmt.Errorf("unsupported auth mode: %s. Supported modes: token, webauth, aws-iam, azure", authMode)
	}
}

func runTokenAuth(cmd *cobra.Command, host string) error {
	// Get token
	fmt.Print("Please enter Personal Access Token (PAT), Service Account Token, or Agent Token (hidden): ")
	tokenBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read token: %w", err)
	}
	fmt.Println()
	authToken := strings.TrimSpace(string(tokenBytes))
	if authToken == "" {
		return fmt.Errorf("token is required")
	}

	if strings.HasPrefix(authToken, "pss_agent:") {
		return runAgentTokenAuth(cmd, host, authToken)
	}

	isPersonalToken := strings.HasPrefix(authToken, "pss_user:")
	var userEmail string
	if isPersonalToken {
		emailPrompt := promptui.Prompt{
			Label: "Please enter your email",
		}
		userEmail, err = emailPrompt.Run()
		if err != nil {
			return fmt.Errorf("prompt cancelled")
		}
		userEmail = strings.TrimSpace(userEmail)
		if userEmail == "" {
			return fmt.Errorf("email is required for personal access tokens")
		}
	}

	// Validate token
	p, err := phase.NewPhase(false, authToken, host)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	if err := phase.Auth(p); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
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
	if userData.WrappedKeyShare != "" {
		wrappedKeyShare = &userData.WrappedKeyShare
	}

	userConfig := config.UserConfig{
		Host:             host,
		ID:               accountID,
		Email:            userEmail,
		OrganizationID:   orgID,
		OrganizationName: orgName,
		WrappedKeyShare:  wrappedKeyShare,
	}
	if err := saveUserLogin(cmd, userConfig, authToken); err != nil {
		return err
	}

	fmt.Println(util.BoldGreen("✅ Authentication successful."))
	return nil
}

func runAgentTokenAuth(cmd *cobra.Command, host, authToken string) error {
	tokenType, lookup, err := agentapi.ParseDurableToken(authToken)
	if err != nil || tokenType != agentapi.TokenAgent {
		return fmt.Errorf("invalid Agent token")
	}
	client, err := agentapi.NewClient(host, authToken, nil)
	if err != nil {
		return fmt.Errorf("invalid Agent token: %w", err)
	}
	identity, err := client.Identity(cmd.Context())
	if err != nil {
		return fmt.Errorf("resolve Agent identity: %w", err)
	}

	accountID := agentLocalAccountID(lookup)
	// An Agent token goes to the system keystore. Without one the login fails,
	// unless the person chose plain-text storage with --insecure-storage.
	insecureStorage, _ := cmd.Flags().GetBool("insecure-storage")
	userConfig := agentUserConfig(host, accountID, identity)
	var storedInConfig bool
	storedInConfig, err = storeLoginToken(keyring.SetCredentials, accountID, authToken, insecureStorage)
	if err != nil {
		return err
	}
	if storedInConfig {
		userConfig.Token = authToken
	}
	if err := config.AddUser(userConfig); err != nil {
		_ = keyring.DeleteCredentials(accountID)
		return fmt.Errorf("save Agent login metadata: %w", err)
	}
	if storedInConfig {
		fmt.Fprintln(cmd.ErrOrStderr(), "⚠️  No system keystore is available, so the Agent token is stored in plain text in the Phase config file.")
	}
	fmt.Fprintf(
		cmd.OutOrStdout(),
		"%s\n",
		util.BoldGreen(fmt.Sprintf(
			"✅ AI Agent authentication successful: %s / %s (%s). This login can use phase ai, and phase secrets, phase run, phase apps list and phase init for the apps its Workflow has access to.",
			agentDisplayName(userConfig),
			agentWorkflowDisplay(userConfig),
			organizationDisplayName(userConfig),
		)),
	)
	return nil
}

// saveUserLogin saves a personal or service login: the token goes to the
// system keystore, or to the config file only when --insecure-storage is set.
func saveUserLogin(cmd *cobra.Command, userConfig config.UserConfig, token string) error {
	insecureStorage, _ := cmd.Flags().GetBool("insecure-storage")
	storedInConfig, err := storeLoginToken(keyring.SetCredentials, userConfig.ID, token, insecureStorage)
	if err != nil {
		return err
	}
	if storedInConfig {
		userConfig.Token = token
	}
	if err := config.AddUser(userConfig); err != nil {
		_ = keyring.DeleteCredentials(userConfig.ID)
		return fmt.Errorf("failed to save config: %w", err)
	}
	if storedInConfig {
		fmt.Fprintln(cmd.ErrOrStderr(), "⚠️  No system keystore is available, so the token is stored in plain text in the Phase config file.")
	}
	return nil
}

// saveServiceAccountLogin saves a token an external identity (AWS IAM, Azure)
// was exchanged for, the same way as any other personal or service login.
func saveServiceAccountLogin(cmd *cobra.Command, host, token string, userData *misc.AppKeyResponse) error {
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
	if userData.WrappedKeyShare != "" {
		wrappedKeyShare = &userData.WrappedKeyShare
	}
	return saveUserLogin(cmd, config.UserConfig{
		Host:             host,
		ID:               accountID,
		OrganizationID:   orgID,
		OrganizationName: orgName,
		WrappedKeyShare:  wrappedKeyShare,
	}, token)
}

// storeLoginToken puts the token in the system keystore. When the keystore
// refuses it, the login fails unless plain-text storage was chosen; it then
// reports that the caller must keep the token in the config file.
func storeLoginToken(set func(accountID, token string) error, accountID, token string, insecureStorage bool) (inConfig bool, err error) {
	if err := set(accountID, token); err != nil {
		if !insecureStorage {
			return false, fmt.Errorf("store the token in the system keystore: %w; if this machine has no keystore, rerun with --insecure-storage to store the token in plain text in the Phase config file", err)
		}
		return true, nil
	}
	return false, nil
}

func agentUserConfig(host, accountID string, identity *agentapi.AgentIdentity) config.UserConfig {
	organizationID := identity.Organization.ID
	organizationName := identity.Organization.Name
	return config.UserConfig{
		Host:             host,
		ID:               accountID,
		PrincipalType:    config.PrincipalAgent,
		PrincipalID:      identity.Agent.ID,
		PrincipalName:    identity.Agent.Name,
		WorkflowID:       identity.Workflow.ID,
		WorkflowName:     identity.Workflow.Name,
		OrganizationID:   &organizationID,
		OrganizationName: &organizationName,
	}
}

func agentLocalAccountID(lookup string) string {
	digest := blake2b.Sum256([]byte("phase-agent-login:" + lookup))
	return fmt.Sprintf("agent-%x", digest[:12])
}
