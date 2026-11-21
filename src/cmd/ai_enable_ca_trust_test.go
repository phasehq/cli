package cmd

import (
	"bytes"
	"os"
	goruntime "runtime"
	"sync"
	"testing"

	phaseproxy "github.com/phasehq/cli/pkg/proxy"
	"github.com/spf13/cobra"
	gokeyring "github.com/zalando/go-keyring"
)

// mapKeyring keeps keystore items in memory for one test.
type mapKeyring struct {
	mu    sync.Mutex
	items map[string]string
}

func (k *mapKeyring) Get(service, user string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	value, ok := k.items[service+"\x00"+user]
	if !ok {
		return "", gokeyring.ErrNotFound
	}
	return value, nil
}

func (k *mapKeyring) Set(service, user, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.items[service+"\x00"+user] = value
	return nil
}

// The trust step trusts the certificate that was checked against the CA key,
// not whatever the public file holds once the user has answered the prompt.
func TestEnableTrustsTheVerifiedCertificateNotTheFile(t *testing.T) {
	if err := phaseproxy.UserCATrustAvailability(goruntime.GOOS); err != nil {
		t.Skipf("no user trust tool here: %v", err)
	}
	directory := t.TempDir()
	original := aiCAStore
	aiCAStore = phaseproxy.CAStore{Directory: directory, Keyring: &mapKeyring{items: map[string]string{}}}
	t.Cleanup(func() { aiCAStore = original })
	ca, paths, err := aiCAStore.Ensure()
	if err != nil || paths.MemoryOnly {
		t.Fatalf("ensure: %v (memory only %t)", err, paths.MemoryOnly)
	}
	verified := ca.CertificatePEM()

	var trusted []byte
	originalTrust := trustCAForCurrentUser
	trustCAForCurrentUser = func(path string) (phaseproxy.UserCATrustResult, error) {
		// Another process replaces the public file after the prompt.
		if err := os.WriteFile(paths.Certificate, []byte("-----BEGIN CERTIFICATE-----\nswapped\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		trusted, err = os.ReadFile(path)
		return phaseproxy.UserCATrustResult{Store: "test store"}, err
	}
	t.Cleanup(func() { trustCAForCurrentUser = originalTrust })

	cmd := &cobra.Command{}
	cmd.Flags().Bool("trust-ca", false, "")
	if err := cmd.Flags().Set("trust-ca", "true"); err != nil {
		t.Fatal(err)
	}
	if err := prepareAIEnableCA(cmd); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(trusted, verified) {
		t.Fatalf("trusted %q, want the verified certificate", trusted)
	}
}
