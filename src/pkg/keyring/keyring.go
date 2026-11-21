package keyring

import (
	"fmt"
	"os"
	"sync"

	"github.com/phasehq/cli/pkg/config"
	gokeyring "github.com/zalando/go-keyring"
)

// served is the saved account the last token GetCredentials returned was
// stored for: "" when it came from the environment, or none was returned.
var served struct {
	sync.Mutex
	account string
}

// LastAccount names the saved account whose token GetCredentials last
// returned, whatever the default has become since. "" if it was no one's.
func LastAccount() string {
	served.Lock()
	defer served.Unlock()
	return served.account
}

func serve(account string) {
	served.Lock()
	served.account = account
	served.Unlock()
}

func GetCredentials() (string, error) {
	serve("")
	// 1. Check PHASE_SERVICE_TOKEN env var
	if pss := os.Getenv("PHASE_SERVICE_TOKEN"); pss != "" {
		return pss, nil
	}

	// 2. Try system keyring
	ids, err := config.GetDefaultAccountID(false)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 || ids[0] == "" {
		return "", fmt.Errorf("no default account configured")
	}
	accountID := ids[0]
	serve(accountID)
	serviceName := fmt.Sprintf("phase-cli-user-%s", accountID)

	pss, err := gokeyring.Get(serviceName, "pss")
	if err == nil && pss != "" {
		return pss, nil
	}

	// 3. Fallback to config file token: that account's, not whichever is
	// the default by now.
	return configToken(accountID)
}

func configToken(accountID string) (string, error) {
	saved, err := config.LoadConfig()
	if err != nil {
		return "", fmt.Errorf("config file not found. Please login with phase auth or supply a PHASE_SERVICE_TOKEN as an environment variable")
	}
	for _, user := range saved.PhaseUsers {
		if user.ID == accountID {
			if user.Token == "" {
				return "", fmt.Errorf("token for the default user (ID: %s) is not found in the config file", accountID)
			}
			return user.Token, nil
		}
	}
	return "", fmt.Errorf("default user not found in the config file")
}

// Login is the login a command or a proxy uses, as one look found it: the
// token, the host it is sent to, and the saved login it belongs to.
type Login struct {
	Token, Host string
	// User is the saved login, or nil for a token from the environment.
	User *config.UserConfig
}

// ActiveLogin reads the login a command uses. The file is read once, before
// the keystore is asked, so host, token and saved login are one account's.
func ActiveLogin() (Login, error) {
	host := os.Getenv("PHASE_HOST")
	if token := os.Getenv("PHASE_SERVICE_TOKEN"); token != "" {
		if host == "" {
			host = config.PhaseCloudAPIHost
		}
		return Login{Token: token, Host: host}, nil
	}
	user, err := config.GetDefaultUser()
	if err != nil {
		return Login{}, err
	}
	// A saved login's token is only ever sent to the host it was saved with,
	// as config.GetDefaultUserHost decides for a command.
	if host != "" && !config.SameHost(host, user.Host) {
		return Login{}, config.SavedLoginHostError(host, user.Host)
	}
	host = user.Host
	token, err := gokeyring.Get(fmt.Sprintf("phase-cli-user-%s", user.ID), "pss")
	if err != nil || token == "" {
		token = user.Token
	}
	if token == "" {
		return Login{}, fmt.Errorf("token for the default user (ID: %s) is not found", user.ID)
	}
	return Login{Token: token, Host: host, User: user}, nil
}

func SetCredentials(accountID, token string) error {
	serviceName := fmt.Sprintf("phase-cli-user-%s", accountID)
	return gokeyring.Set(serviceName, "pss", token)
}

func DeleteCredentials(accountID string) error {
	serviceName := fmt.Sprintf("phase-cli-user-%s", accountID)
	err := gokeyring.Delete(serviceName, "pss")
	if err == gokeyring.ErrNotFound {
		return nil // Not an error if it doesn't exist
	}
	return err
}
