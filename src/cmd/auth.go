package cmd

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/manifoldco/promptui"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	"github.com/spf13/cobra"
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
	fmt.Print("Please enter Personal Access Token (PAT) or Service Account Token (hidden): ")
	tokenBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read token: %w", err)
	}
	fmt.Println()
	authToken := strings.TrimSpace(string(tokenBytes))
	if authToken == "" {
		return fmt.Errorf("token is required")
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

	// Save credentials to keyring
	tokenSavedInKeyring := true
	if err := keyring.SetCredentials(accountID, authToken); err != nil {
		tokenSavedInKeyring = false
	}

	// Build user config
	userConfig := config.UserConfig{
		Host:             host,
		ID:               accountID,
		OrganizationID:   orgID,
		OrganizationName: orgName,
		WrappedKeyShare:  wrappedKeyShare,
	}
	if userEmail != "" {
		userConfig.Email = userEmail
	}
	if !tokenSavedInKeyring {
		userConfig.Token = authToken
	}

	// Save to config
	if err := config.AddUser(userConfig); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println(util.BoldGreen("✅ Authentication successful."))
	return nil
}
