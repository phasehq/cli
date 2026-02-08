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
	authCmd.Flags().StringVar(&authMode, "mode", "webauth", "Authentication mode (webauth, token, aws-iam)")
	authCmd.Flags().String("service-account-id", "", "Service account ID (required for aws-iam mode)")
	authCmd.Flags().Int("ttl", 0, "Token TTL in seconds (for aws-iam mode)")
	authCmd.Flags().Bool("no-store", false, "Print token to stdout instead of storing (for aws-iam mode)")
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
	case "token":
		return runTokenAuth(cmd, host)
	default:
		return fmt.Errorf("unsupported auth mode: %s. Supported modes: token, webauth, aws-iam", authMode)
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

	if err := p.Auth(); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Get user data
	userData, err := p.InitRaw()
	if err != nil {
		return fmt.Errorf("failed to fetch user data: %w", err)
	}

	// Extract account ID (support both user_id and account_id)
	accountID := ""
	if uid, ok := userData["user_id"].(string); ok && uid != "" {
		accountID = uid
	} else if aid, ok := userData["account_id"].(string); ok && aid != "" {
		accountID = aid
	}
	if accountID == "" {
		return fmt.Errorf("neither user_id nor account_id found in authentication response")
	}

	// Extract org info
	var orgID, orgName *string
	if org, ok := userData["organisation"].(map[string]interface{}); ok && org != nil {
		if id, ok := org["id"].(string); ok {
			orgID = &id
		}
		if name, ok := org["name"].(string); ok {
			orgName = &name
		}
	}

	// Extract wrapped key share
	var wrappedKeyShare *string
	offlineEnabled, _ := userData["offline_enabled"].(bool)
	if offlineEnabled {
		if wks, ok := userData["wrapped_key_share"].(string); ok {
			wrappedKeyShare = &wks
		}
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
