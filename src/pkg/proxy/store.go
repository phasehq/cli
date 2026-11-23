package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	gokeyring "github.com/zalando/go-keyring"
)

const (
	caKeyringService = "phase-cli-ai-proxy-ca"
	caKeyringUser    = "private-key-v1"
	// caKeystoreProbeUser names an entry that is never stored; looking it up
	// shows whether the keystore works without reading the CA key.
	caKeystoreProbeUser = "availability-probe"
	defaultCAValidity   = 90 * 24 * time.Hour
	// caRenewalWindow is how long before expiry Ensure replaces the CA. Every
	// proxy start and session recycle passes through Ensure, so a long-running
	// proxy renews on its own; user trust stores must then be re-trusted.
	caRenewalWindow = 14 * 24 * time.Hour
	// maxMemoryCertificates bounds how many certificates of in-memory CAs the
	// public trust files keep, one per recently started proxy process. Nothing
	// tells a live process's certificate from a dead one's, so the bound is
	// wide: a long-running proxy keeps its place until this many others have
	// started since it last published.
	maxMemoryCertificates = 64
	// obsoleteCAKeyFile is where earlier builds wrote the CA private key when
	// no keystore was usable. Ensure and the sweep delete it.
	obsoleteCAKeyFile = "ca-key.pem"
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

// Delete removes an entry. It is not part of PrivateKeyStore: a store that
// cannot delete has its entry replaced instead (see InventoryStore.Purge).
func (OSKeyring) Delete(service, user string) error {
	return gokeyring.Delete(service, user)
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
	// MemoryOnly reports that no system keystore could hold the private key,
	// so it lives only in this process. Certificate and Bundle then hold the
	// certificates of every recently started proxy process, and nothing should
	// install them into a user trust store.
	MemoryOnly bool
}

type CAStore struct {
	Directory string
	Keyring   PrivateKeyStore
	Validity  time.Duration
}

// memoryCAs holds the CA of each Phase AI directory whose key could not be
// stored in a keystore. A process creates it once and keeps using it, so a
// session recycle never changes the CA under long-running child processes.
var memoryCAs = struct {
	sync.Mutex
	byDirectory map[string]*CA
}{byDirectory: make(map[string]*CA)}

// NoKeystoreNotice is the one line shown to a person on a machine where the CA
// private key cannot be kept in a system keystore.
const NoKeystoreNotice = "There is no system keystore on this machine, so the Phase AI CA key is kept in memory only and a new CA is created each time the proxy starts."

// ErrKeystoreUnreachable means the system keystore did not answer, so a CA
// key it holds was not removed.
var ErrKeystoreUnreachable = errors.New("the system keystore could not be reached")

// DeleteStoredCAKey removes the CA private key from the system keystore, for a
// purge of all local data. A missing key is not an error. A keystore that
// does not answer is ErrKeystoreUnreachable: a key stored from a session that
// could reach it, such as the desktop's, is still there.
func DeleteStoredCAKey() error {
	err := gokeyring.Delete(caKeyringService, caKeyringUser)
	if err == nil || errors.Is(err, gokeyring.ErrNotFound) {
		return nil
	}
	if !(CAStore{}).KeystoreAvailable() {
		return ErrKeystoreUnreachable
	}
	return err
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

func (s CAStore) keyring() PrivateKeyStore {
	if s.Keyring == nil {
		return OSKeyring{}
	}
	return s.Keyring
}

func (s CAStore) directory() (string, error) {
	if s.Directory != "" {
		return filepath.Clean(s.Directory), nil
	}
	return DefaultCADirectory()
}

// KeystoreAvailable reports whether the system keystore answers at all. It
// asks for an entry that is never written, so the CA key is not read and a
// keystore that works answers "not found".
func (s CAStore) KeystoreAvailable() bool {
	_, err := s.keyring().Get(caKeyringService, caKeystoreProbeUser)
	return err == nil || errors.Is(err, gokeyring.ErrNotFound)
}

// Ensure loads the proxy-owned CA or creates it when absent, expired, or
// inconsistent. The private key is kept in the OS keystore. When there is no
// usable keystore it is kept only in this process's memory and never written
// to disk. The public PEM files are permissioned 0600 because their location
// describes local proxy configuration even though they are not secret.
func (s CAStore) Ensure() (*CA, CAPaths, error) {
	directory, err := s.directory()
	if err != nil {
		return nil, CAPaths{}, err
	}
	keyring := s.keyring()
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
	// Runtimes and enable can run Ensure at once. One lock across load,
	// renewal and publication keeps the stored key and certificate a pair.
	unlock, err := lockCAFile(filepath.Join(directory, "ca.lock"))
	if err != nil {
		return nil, CAPaths{}, fmt.Errorf("lock proxy CA: %w", err)
	}
	defer unlock()
	paths := CAPaths{
		Certificate: filepath.Join(directory, "ca.pem"),
		Bundle:      filepath.Join(directory, "ca-bundle.pem"),
	}
	if err := removeObsoleteCAKey(directory); err != nil {
		return nil, CAPaths{}, err
	}
	if ca := memoryCA(directory); ca != nil {
		return s.publishMemoryCA(ca, paths)
	}

	certPEM, certErr := os.ReadFile(paths.Certificate)
	if certErr != nil && !errors.Is(certErr, os.ErrNotExist) {
		return nil, CAPaths{}, fmt.Errorf("read proxy CA certificate: %w", certErr)
	}
	keyPEM, keyErr := keyring.Get(caKeyringService, caKeyringUser)
	keystoreUsable := keyErr == nil || errors.Is(keyErr, gokeyring.ErrNotFound)
	if certErr == nil && keyErr == nil && keyPEM != "" {
		if ca, err := LoadCA(certPEM, []byte(keyPEM)); err == nil {
			// Renew inside the window, and also when the certificate outlives
			// the configured validity: that is a CA issued under an older,
			// longer policy, which must not keep its old lifetime.
			if remaining := time.Until(ca.cert.NotAfter); remaining > renewalWindow(validity) && remaining <= validity+renewalWindow(validity) {
				if err := writePublicCAFiles(paths, certPEM); err != nil {
					return nil, CAPaths{}, err
				}
				paths.NotAfter = ca.cert.NotAfter
				return ca, paths, nil
			}
		}
	}
	// A certificate whose key is unknown, expired or due for renewal is
	// replaced rather than served.
	renewed := certErr == nil

	ca, certPEM, privatePEM, err := GenerateCA(validity)
	if err != nil {
		return nil, CAPaths{}, err
	}
	if keystoreUsable {
		keystoreUsable = keyring.Set(caKeyringService, caKeyringUser, string(privatePEM)) == nil
	}
	clear(privatePEM)
	if !keystoreUsable {
		setMemoryCA(directory, ca)
		return s.publishMemoryCA(ca, paths)
	}
	paths.Renewed = renewed
	paths.NotAfter = ca.cert.NotAfter
	if err := writePublicCAFiles(paths, certPEM); err != nil {
		return nil, CAPaths{}, err
	}
	return ca, paths, nil
}

func memoryCA(directory string) *CA {
	memoryCAs.Lock()
	defer memoryCAs.Unlock()
	ca := memoryCAs.byDirectory[directory]
	if ca == nil || !time.Now().Before(ca.cert.NotAfter) {
		return nil
	}
	return ca
}

func setMemoryCA(directory string, ca *CA) {
	memoryCAs.Lock()
	defer memoryCAs.Unlock()
	memoryCAs.byDirectory[directory] = ca
}

// publishMemoryCA writes this process's certificate first, followed by the
// still-valid certificates other processes published, so one proxy starting
// never drops another live proxy's CA from the files its children trust.
// Called with ca.lock held.
func (s CAStore) publishMemoryCA(ca *CA, paths CAPaths) (*CA, CAPaths, error) {
	certificates := [][]byte{ca.der}
	if existing, err := os.ReadFile(paths.Certificate); err == nil {
		now := time.Now()
		for _, certificate := range parsePEMCertificates(existing) {
			if len(certificates) == maxMemoryCertificates {
				break
			}
			if !isPhaseOwnedRoot(certificate) || !now.Before(certificate.NotAfter) || bytes.Equal(certificate.Raw, ca.der) {
				continue
			}
			certificates = append(certificates, certificate.Raw)
		}
	}
	if err := writePublicCAFiles(paths, encodeCertificateBlocks(certificates)); err != nil {
		return nil, CAPaths{}, err
	}
	paths.NotAfter = ca.cert.NotAfter
	paths.MemoryOnly = true
	return ca, paths, nil
}

// removeObsoleteCAKey deletes a CA private key an earlier build wrote to disk.
func removeObsoleteCAKey(directory string) error {
	path := filepath.Join(directory, obsoleteCAKeyFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect obsolete proxy CA private key: %w", err)
	}
	if info.IsDir() {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove obsolete proxy CA private key: %w", err)
	}
	return nil
}

// obsoleteCAFiles are names earlier builds wrote beside the CA that nothing
// reads any more: the plaintext key, the Java trust stores, and the CA copy
// the removed sandbox bootstrap wrote.
var obsoleteCAFiles = []string{obsoleteCAKeyFile, "java-truststore.p12", "runtime-java-truststore.p12", "phase-ca.pem"}

// SweepCAFiles removes obsolete CA files and the temporary files an
// interrupted CA publication left behind. Every writer of those temporary
// files holds ca.lock, so under the lock any of them is stale. Only regular
// files directly in directory are removed; symlinks and other names are left.
func SweepCAFiles(directory string) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() {
		return err
	}
	unlock, err := lockCAFile(filepath.Join(directory, "ca.lock"))
	if err != nil {
		return fmt.Errorf("lock proxy CA: %w", err)
	}
	defer unlock()
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !(slices.Contains(obsoleteCAFiles, name) || strings.HasPrefix(name, ".phase-ca-")) {
			continue
		}
		if err := os.Remove(filepath.Join(directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
