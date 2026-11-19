package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	gokeyring "github.com/zalando/go-keyring"
)

// A certificate authority whose key lives in one process can never be trusted by the
// programs behind the tunnel, so phase up refuses before it changes anything.
func TestUpRefusesACertificateAuthorityKeptInMemory(t *testing.T) {
	t.Run("no keystore answers", func(t *testing.T) {
		withAICAKeystore(t, errors.New("no keystore"))
		var out bytes.Buffer
		if err := ensureTunnelCATrust(&out); !errors.Is(err, errTunnelNeedsKeystore) {
			t.Fatalf("err = %v, output %q", err, out.String())
		}
		if _, err := os.Stat(filepath.Join(aiCAStore.Directory, "ca.pem")); err == nil {
			t.Fatal("a certificate was published for a certificate authority nothing can trust")
		}
	})
	t.Run("the keystore will not keep the key", func(t *testing.T) {
		withAICAKeystore(t, gokeyring.ErrNotFound)
		var out bytes.Buffer
		if err := ensureTunnelCATrust(&out); !errors.Is(err, errTunnelNeedsKeystore) {
			t.Fatalf("err = %v, output %q", err, out.String())
		}
	})
}
