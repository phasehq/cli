package phase

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/phasehq/cli/pkg/ai"
	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/offline"
	"github.com/phasehq/cli/pkg/version"
	sdk "github.com/phasehq/golang-sdk/v2/phase"
	"github.com/phasehq/golang-sdk/v2/phase/misc"
	"github.com/phasehq/golang-sdk/v2/phase/network"
)

// Create new Phase client. Return host and token
func NewPhase(init bool, pss string, host string) (*sdk.Phase, error) {
	if init {
		creds, err := keyring.GetCredentials()
		if err != nil {
			return nil, err
		}
		pss = creds
		h, err := config.GetDefaultUserHost()
		if err != nil {
			return nil, err
		}
		host = h
	} else {
		if pss == "" || host == "" {
			return nil, fmt.Errorf("both pss and host must be provided when init is false")
		}
	}

	setUserAgent()

	p, err := sdk.New(pss, host, false)
	if err != nil {
		return nil, err
	}

	// Configure offline: always cache on success, only serve from cache when PHASE_OFFLINE=1
	if cacheDir := getCacheDir(); cacheDir != "" {
		p.SetOfflineConfig(&sdk.OfflineConfig{
			CacheDir: cacheDir,
			Offline:  offline.IsOffline(),
		})
	}

	return p, nil
}

func setUserAgent() {
	hostname, _ := os.Hostname()
	username := "unknown"
	if u, err := os.UserHomeDir(); err == nil {
		parts := strings.Split(u, string(os.PathSeparator))
		if len(parts) > 0 {
			username = parts[len(parts)-1]
		}
	}
	ua := fmt.Sprintf("phase-cli/%s %s %s %s@%s",
		version.Version, runtime.GOOS, runtime.GOARCH, username, hostname)

	if agent := ai.DetectAIAgent(); agent != "" {
		ua += fmt.Sprintf(" (ai-agent/%s)", agent)
	}

	network.SetUserAgent(ua)
}

func Auth(p *sdk.Phase) error {
	_, err := network.FetchAppKey(p.TokenType, p.AppToken, p.Host)
	if err != nil {
		return fmt.Errorf("invalid Phase credentials: %w", err)
	}
	return nil
}

func Init(p *sdk.Phase) (*misc.AppKeyResponse, error) {
	resp, err := network.FetchPhaseUser(p.TokenType, p.AppToken, p.Host)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userData misc.AppKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		return nil, fmt.Errorf("failed to decode user data: %w", err)
	}
	return &userData, nil
}

// AccountID returns the user_id or account_id from the response.
func AccountID(data *misc.AppKeyResponse) (string, error) {
	if data.UserID != "" {
		return data.UserID, nil
	}
	if data.AccountID != "" {
		return data.AccountID, nil
	}
	return "", fmt.Errorf("neither user_id nor account_id found in authentication response")
}

// PhaseGetContext resolves app/env context from user data, using .phase.json defaults.
func PhaseGetContext(userData *misc.AppKeyResponse, appName, envName, appID string) (string, string, string, string, string, error) {
	if appID == "" && appName == "" {
		// Find .phase.json config up to 8 dir up (current dir + 8 parent dirs)
		phaseConfig := config.FindPhaseConfig(8)
		if phaseConfig != nil {
			envName = coalesce(envName, phaseConfig.DefaultEnv)
			appID = phaseConfig.AppID
		} else {
			envName = coalesce(envName, "Development")
		}
	} else {
		envName = coalesce(envName, "Development")
	}

	return misc.PhaseGetContext(userData, appName, envName, appID)
}

// GetConfig fills in appName/envName/appID from .phase.json when not provided via flags.
func GetConfig(appName, envName, appID string) (string, string, string) {
	if appID == "" && appName == "" {
		phaseConfig := config.FindPhaseConfig(8)
		if phaseConfig != nil {
			envName = coalesce(envName, phaseConfig.DefaultEnv)
			appID = phaseConfig.AppID
		}
	}
	if envName == "" {
		envName = "Development"
	}
	return appName, envName, appID
}

// getCacheDir returns the offline cache directory for the current default user.
// Returns empty string if no user is configured (e.g. service token without config).
func getCacheDir() string {
	user, err := config.GetDefaultUser()
	if err != nil || user == nil {
		return ""
	}
	return offline.CacheDir(config.PhaseSecretsDir, user.ID)
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
