package phase

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/golang-sdk/phase/crypto"
	"github.com/phasehq/golang-sdk/phase/misc"
	"github.com/phasehq/golang-sdk/phase/network"
)

func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

type Phase struct {
	Prefix             string
	PesVersion         string
	AppToken           string
	PssUserPublicKey   string
	Keyshare0          string
	Keyshare1UnwrapKey string
	APIHost            string
	TokenType          string
	IsServiceToken     bool
	IsUserToken        bool
}

func NewPhase(init bool, pss string, host string) (*Phase, error) {
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

	p := &Phase{
		APIHost: host,
	}

	// Set user agent
	setUserAgent()

	// Determine token type
	p.IsServiceToken = misc.PssServicePattern.MatchString(pss)
	p.IsUserToken = misc.PssUserPattern.MatchString(pss)

	if !p.IsServiceToken && !p.IsUserToken {
		tokenType := "service token"
		if strings.Contains(pss, "pss_user") {
			tokenType = "user token"
		}
		return nil, fmt.Errorf("invalid Phase %s", tokenType)
	}

	// Parse token segments
	segments := strings.Split(pss, ":")
	if len(segments) != 6 {
		return nil, fmt.Errorf("invalid token format")
	}
	p.Prefix = segments[0]
	p.PesVersion = segments[1]
	p.AppToken = segments[2]
	p.PssUserPublicKey = segments[3]
	p.Keyshare0 = segments[4]
	p.Keyshare1UnwrapKey = segments[5]

	// Determine HTTP Authorization token type
	if p.IsServiceToken && p.PesVersion == "v2" {
		p.TokenType = "ServiceAccount"
	} else if p.IsServiceToken {
		p.TokenType = "Service"
	} else {
		p.TokenType = "User"
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
	ua := fmt.Sprintf("phase-cli-go/%s %s %s %s@%s",
		"0.1.0", runtime.GOOS, runtime.GOARCH, username, hostname)
	network.SetUserAgent(ua)
}

func (p *Phase) Auth() error {
	_, err := network.FetchAppKey(p.TokenType, p.AppToken, p.APIHost)
	if err != nil {
		return fmt.Errorf("invalid Phase credentials: %w", err)
	}
	return nil
}

func (p *Phase) Init() (*misc.AppKeyResponse, error) {
	resp, err := network.FetchPhaseUser(p.TokenType, p.AppToken, p.APIHost)
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

// InitRaw returns the raw JSON response for auth flow (need user_id, offline_enabled, etc.)
func (p *Phase) InitRaw() (map[string]interface{}, error) {
	resp, err := network.FetchPhaseUser(p.TokenType, p.AppToken, p.APIHost)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return result, nil
}

func (p *Phase) Decrypt(phaseCiphertext string, wrappedKeyShareData map[string]interface{}) (string, error) {
	segments := strings.Split(phaseCiphertext, ":")
	if len(segments) != 4 || segments[0] != "ph" {
		return "", fmt.Errorf("ciphertext is invalid")
	}

	wrappedKeyShare, ok := wrappedKeyShareData["wrapped_key_share"].(string)
	if !ok || wrappedKeyShare == "" {
		return "", fmt.Errorf("wrapped key share not found in the response")
	}

	// Decrypt using SDK's DecryptWrappedKeyShare which handles the full flow:
	// 1. Fetch app key (wrapped keyshare)
	// 2. Unwrap keyshare1 using keyshare1_unwrap_key
	// 3. Reconstruct app private key from keyshare0 + keyshare1
	// 4. Decrypt the ciphertext using app private key
	//
	// But that function also does a network call to fetch the wrapped key share.
	// Since we already have it in wrappedKeyShareData, we do the steps manually:

	wrappedKeyShareBytes, err := hexDecode(wrappedKeyShare)
	if err != nil {
		return "", fmt.Errorf("failed to decode wrapped key share: %w", err)
	}

	unwrapKeyBytes, err := hexDecode(p.Keyshare1UnwrapKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode keyshare1 unwrap key: %w", err)
	}

	var unwrapKey [32]byte
	copy(unwrapKey[:], unwrapKeyBytes)

	keyshare1Bytes, err := crypto.DecryptRaw(wrappedKeyShareBytes, unwrapKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt wrapped key share: %w", err)
	}

	// Reconstruct app private key
	appPrivKey, err := crypto.ReconstructSecret(p.Keyshare0, string(keyshare1Bytes))
	if err != nil {
		return "", fmt.Errorf("failed to reconstruct app private key: %w", err)
	}

	// Decrypt the ciphertext using reconstructed app private key
	plaintext, err := crypto.DecryptAsymmetric(phaseCiphertext, appPrivKey, p.PssUserPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// findMatchingEnvironmentKey finds environment key by env ID
func (p *Phase) findMatchingEnvironmentKey(userData *misc.AppKeyResponse, envID string) *misc.EnvironmentKey {
	for _, app := range userData.Apps {
		for _, envKey := range app.EnvironmentKeys {
			if envKey.Environment.ID == envID {
				return &envKey
			}
		}
	}
	return nil
}

// PhaseGetContext resolves app/env context from user data, using .phase.json defaults
func PhaseGetContext(userData *misc.AppKeyResponse, appName, envName, appID string) (string, string, string, string, string, error) {
	// If no app context provided, check .phase.json
	if appID == "" && appName == "" {
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

	// Find the app
	var application *misc.App
	if appID != "" {
		for i, app := range userData.Apps {
			if app.ID == appID {
				application = &userData.Apps[i]
				break
			}
		}
		if application == nil {
			return "", "", "", "", "", fmt.Errorf("no application found with ID: '%s'", appID)
		}
	} else if appName != "" {
		var matchingApps []misc.App
		for _, app := range userData.Apps {
			if strings.Contains(strings.ToLower(app.Name), strings.ToLower(appName)) {
				matchingApps = append(matchingApps, app)
			}
		}
		if len(matchingApps) == 0 {
			return "", "", "", "", "", fmt.Errorf("no application found with the name '%s'", appName)
		}
		// Sort by name length (shortest = most specific match) - just pick the first shortest
		shortest := matchingApps[0]
		for _, app := range matchingApps[1:] {
			if len(app.Name) < len(shortest.Name) {
				shortest = app
			}
		}
		application = &shortest
	} else {
		return "", "", "", "", "", fmt.Errorf("no application context provided. Please run 'phase init' or pass the '--app' or '--app-id' flag")
	}

	// Find the environment
	for _, envKey := range application.EnvironmentKeys {
		if strings.Contains(strings.ToLower(envKey.Environment.Name), strings.ToLower(envName)) {
			return application.Name, application.ID, envKey.Environment.Name, envKey.Environment.ID, envKey.IdentityKey, nil
		}
	}

	return "", "", "", "", "", fmt.Errorf("environment '%s' not found in application '%s'", envName, application.Name)
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
