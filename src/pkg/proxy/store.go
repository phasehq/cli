package proxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	gokeyring "github.com/zalando/go-keyring"
)

const (
	caKeyringService  = "phase-cli-ai-proxy-ca"
	caKeyringUser     = "private-key-v1"
	defaultCAValidity = 90 * 24 * time.Hour
	// caRenewalWindow is how long before expiry Ensure replaces the CA. Every
	// proxy start and session recycle passes through Ensure, so a long-running
	// relay renews on its own; clients bootstrapped from the old CA must be
	// re-bootstrapped and user trust stores re-trusted.
	caRenewalWindow = 14 * 24 * time.Hour
)

type PrivateKeyStore interface {
	Get(service, user string) (string, error)
	Set(service, user, value string) error
}

type OSKeyring struct{}

func (OSKeyring) Get(service, user string) (string, error) {
	return gokeyring.Get(service, user)
}

func (OSKeyring) Set(service, user, value string) error {
	return gokeyring.Set(service, user, value)
}

type CAPaths struct {
	Certificate    string
	Bundle         string
	BundleComplete bool
	// Renewed reports that Ensure replaced an existing CA that was expired or
	// within its renewal window. Callers surface it so users re-trust the CA.
	Renewed bool
	// NotAfter is the loaded or generated CA certificate's expiry.
	NotAfter time.Time
}

type CAStore struct {
	Directory string
	Keyring   PrivateKeyStore
	Validity  time.Duration
}

// renewalWindow keeps short test validities from renewing on every call.
func renewalWindow(validity time.Duration) time.Duration {
	window := caRenewalWindow
	if quarter := validity / 4; quarter < window {
		window = quarter
	}
	return window
}

func DefaultCADirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".phase", "ai"), nil
}

// Ensure loads the proxy-owned CA or creates it when absent, expired, or
// inconsistent. The private key is stored in the OS keyring when available,
// with an owner-only file fallback for headless machines. Public PEM files are
// permissioned 0600 because their location describes local proxy configuration
// even though the certificate itself is not secret.
func (s CAStore) Ensure() (*CA, CAPaths, error) {
	directory := s.Directory
	if directory == "" {
		var err error
		directory, err = DefaultCADirectory()
		if err != nil {
			return nil, CAPaths{}, err
		}
	}
	keyring := s.Keyring
	if keyring == nil {
		keyring = OSKeyring{}
	}
	validity := s.Validity
	if validity == 0 {
		validity = defaultCAValidity
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, CAPaths{}, fmt.Errorf("create Phase AI directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, CAPaths{}, fmt.Errorf("secure Phase AI directory: %w", err)
	}
	paths := CAPaths{
		Certificate: filepath.Join(directory, "ca.pem"),
		Bundle:      filepath.Join(directory, "ca-bundle.pem"),
	}
	privateKeyPath := filepath.Join(directory, "ca-key.pem")

	certPEM, certErr := os.ReadFile(paths.Certificate)
	keyCandidates := make([][]byte, 0, 2)
	if keyPEM, keyErr := keyring.Get(caKeyringService, caKeyringUser); keyErr == nil && keyPEM != "" {
		keyCandidates = append(keyCandidates, []byte(keyPEM))
	}
	if fallbackKey, fallbackErr := readOwnerOnlyPrivateKey(privateKeyPath); fallbackErr == nil {
		keyCandidates = append(keyCandidates, fallbackKey)
	} else if !errors.Is(fallbackErr, os.ErrNotExist) {
		return nil, CAPaths{}, fallbackErr
	}
	renewed := false
	if certErr == nil {
		for _, keyPEM := range keyCandidates {
			ca, err := LoadCA(certPEM, keyPEM)
			if err != nil {
				continue
			}
			// Renew inside the window, and also when the certificate outlives
			// the configured validity: that is a CA issued under an older,
			// longer policy, which must not keep its old lifetime.
			if remaining := time.Until(ca.cert.NotAfter); remaining <= renewalWindow(validity) || remaining > validity+renewalWindow(validity) {
				renewed = true
				break
			}
			if err := writePublicCAFiles(paths, certPEM); err != nil {
				return nil, CAPaths{}, err
			}
			paths.NotAfter = ca.cert.NotAfter
			return ca, paths, nil
		}
	}
	if certErr != nil && !errors.Is(certErr, os.ErrNotExist) {
		return nil, CAPaths{}, fmt.Errorf("read proxy CA certificate: %w", certErr)
	}
	if certErr == nil && !renewed {
		// A certificate exists but no usable key was found for it: the key was
		// lost or the files were tampered with. Start over rather than serve
		// a CA whose key is unknown.
		renewed = true
	}

	ca, certPEM, privatePEM, err := GenerateCA(validity)
	if err != nil {
		return nil, CAPaths{}, err
	}
	paths.Renewed = renewed
	paths.NotAfter = ca.cert.NotAfter
	if err := keyring.Set(caKeyringService, caKeyringUser, string(privatePEM)); err != nil {
		// Headless Linux builders and remote Agent machines often have no D-Bus
		// secret service. Keep the key owner-only in Phase's 0700 directory rather
		// than making those deployments depend on a desktop keyring.
		if fileErr := writeFileAtomic0600(privateKeyPath, privatePEM); fileErr != nil {
			return nil, CAPaths{}, fmt.Errorf("store proxy CA private key (keyring unavailable: %v): %w", err, fileErr)
		}
	} else if removeErr := os.Remove(privateKeyPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return nil, CAPaths{}, fmt.Errorf("remove obsolete proxy CA private key fallback: %w", removeErr)
	}
	if err := writePublicCAFiles(paths, certPEM); err != nil {
		return nil, CAPaths{}, err
	}
	return ca, paths, nil
}

func readOwnerOnlyPrivateKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("Phase AI CA private key fallback must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && (info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o400 == 0) {
		return nil, errors.New("Phase AI CA private key fallback must be owner-only (0400 or 0600)")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(payload), "PRIVATE KEY") {
		return nil, errors.New("Phase AI CA private key fallback is invalid")
	}
	return payload, nil
}

func writePublicCAFiles(paths CAPaths, certPEM []byte) error {
	if err := writeFileAtomic0600(paths.Certificate, certPEM); err != nil {
		return fmt.Errorf("write proxy CA certificate: %w", err)
	}
	bundle := append([]byte(nil), certPEM...)
	if systemBundle := readSystemCABundle(paths.Bundle); len(systemBundle) > 0 {
		if len(bundle) > 0 && bundle[len(bundle)-1] != '\n' {
			bundle = append(bundle, '\n')
		}
		bundle = append(bundle, systemBundle...)
	}
	if err := writeFileAtomic0600(paths.Bundle, bundle); err != nil {
		return fmt.Errorf("write proxy CA bundle: %w", err)
	}
	return nil
}

func writeFileAtomic0600(destination string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(destination), ".phase-ca-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, destination); err != nil {
		return err
	}
	return os.Chmod(destination, 0o600)
}

func readSystemCABundle(outputPath string) []byte {
	candidates := append([]string{os.Getenv("SSL_CERT_FILE")}, systemCABundlePaths(runtime.GOOS, os.Environ())...)
	certificates := make([][]byte, 0)
	seen := make(map[string]struct{})
	seenPaths := make(map[string]struct{})
	totalBytes := 0
	for _, candidate := range candidates {
		clean := filepath.Clean(candidate)
		if candidate == "" || clean == filepath.Clean(outputPath) {
			continue
		}
		if _, duplicate := seenPaths[clean]; duplicate {
			continue
		}
		seenPaths[clean] = struct{}{}
		blocks, err := readBoundedPublicCertificates(candidate)
		if err != nil {
			// This is a best-effort cache generated during enable. The runtime
			// builder reads every applicable source strictly before exporting a
			// replacement trust variable.
			continue
		}
		for _, certificate := range blocks {
			fingerprint := string(certificate)
			if _, duplicate := seen[fingerprint]; duplicate {
				continue
			}
			if totalBytes+len(certificate)+64 > maxMergedCABundleBytes {
				return encodeCertificateBlocks(certificates)
			}
			seen[fingerprint] = struct{}{}
			certificates = append(certificates, certificate)
			totalBytes += len(certificate) + 64
		}
	}
	return encodeCertificateBlocks(certificates)
}
