package keyring

import (
	"fmt"
	"os"

	"github.com/phasehq/cli/pkg/config"
	gokeyring "github.com/zalando/go-keyring"
)

func GetCredentials() (string, error) {
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
	serviceName := fmt.Sprintf("phase-cli-user-%s", accountID)

	pss, err := gokeyring.Get(serviceName, "pss")
	if err == nil && pss != "" {
		return pss, nil
	}

	// 3. Fallback to config file token
	return config.GetDefaultUserToken()
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

// Egress proxy CA private key. This is the "forge-anything" key: a CA that can
// mint trusted leaf certs for any host. It is kept in the OS keyring, never on
// disk, and never shipped in the binary.
const (
	proxyCAService = "phase-cli-proxy"
	proxyCAKeyName = "ca-private-key"
)

func SetProxyCAKey(pemKey string) error {
	return gokeyring.Set(proxyCAService, proxyCAKeyName, pemKey)
}

func GetProxyCAKey() (string, error) {
	return gokeyring.Get(proxyCAService, proxyCAKeyName)
}

func DeleteProxyCAKey() error {
	err := gokeyring.Delete(proxyCAService, proxyCAKeyName)
	if err == gokeyring.ErrNotFound {
		return nil
	}
	return err
}
