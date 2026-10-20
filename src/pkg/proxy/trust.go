package proxy

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const phaseAITrustNickname = "Phase AI Proxy CA"

const windowsPhaseCARotationScript = `$ErrorActionPreference='Stop'; $desired='__PHASE_SHA256__'; $phaseRoots=Get-ChildItem -Path Cert:\CurrentUser\Root | Where-Object { $_.Subject -eq $_.Issuer -and $_.Subject -match '(^|,\s*)CN=Phase AI Proxy CA(,|$)' -and $_.Subject -match '(^|,\s*)O=Phase(,|$)' -and ($_.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' -and $_.CertificateAuthority }) }; if ($phaseRoots | Where-Object { $_.GetCertHashString('SHA256').ToUpperInvariant() -eq $desired }) { Write-Output 'PHASE_CA_CURRENT'; exit 0 }; $phaseRoots | ForEach-Object { Remove-Item -LiteralPath $_.PSPath -Force }`

// ErrUserCATrustUnsupported means Phase cannot safely modify a trust store for
// only the current user on this operating system. Callers can continue with
// process-scoped CA environment variables instead.
var ErrUserCATrustUnsupported = errors.New("current-user CA trust is not supported on this platform")

// UserCATrustNotice tells the user, before Phase touches the trust store, which
// system dialog to expect and why. It is empty where no dialog appears.
func UserCATrustNotice(goos string) string {
	switch goos {
	case "darwin":
		return "macOS asks for your login password or Touch ID once: the public Phase AI CA is added to your login keychain's trust settings. No sudo, nothing system-wide."
	case "windows":
		return "Windows shows one security warning to confirm adding the public Phase AI CA to your user Root store. Nothing system-wide."
	default:
		return ""
	}
}

// UserCATrustResult describes where the public Phase AI CA was trusted. It
// never contains private key material.
type UserCATrustResult struct {
	Store          string
	AlreadyTrusted bool
}

type trustCommandRunner interface {
	LookPath(file string) (string, error)
	Run(name string, args ...string) ([]byte, error)
}

type osTrustCommandRunner struct{}

func (osTrustCommandRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (osTrustCommandRunner) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

type userCATrustInstaller struct {
	GOOS     string
	Home     string
	Runner   trustCommandRunner
	MkdirAll func(string, os.FileMode) error
	Chmod    func(string, os.FileMode) error
	Stat     func(string) (os.FileInfo, error)
	ReadFile func(string) ([]byte, error)
	Now      func() time.Time
}

// TrustCAForCurrentUser validates the public CA and adds it only to the
// current user's trust store. It never invokes sudo, requests elevation, or
// writes a system-wide trust location.
func TrustCAForCurrentUser(certificatePath string) (UserCATrustResult, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return UserCATrustResult{}, fmt.Errorf("resolve home directory for CA trust: %w", err)
	}
	return (userCATrustInstaller{
		GOOS:     runtime.GOOS,
		Home:     home,
		Runner:   osTrustCommandRunner{},
		MkdirAll: os.MkdirAll,
		Chmod:    os.Chmod,
		Stat:     os.Stat,
		ReadFile: os.ReadFile,
		Now:      time.Now,
	}).Trust(certificatePath)
}

func (i userCATrustInstaller) Trust(certificatePath string) (UserCATrustResult, error) {
	i = i.withDefaults()
	certificatePEM, err := i.ReadFile(certificatePath)
	if err != nil {
		return UserCATrustResult{}, fmt.Errorf("read Phase AI CA for user trust: %w", err)
	}
	certificate, err := parsePublicCA(certificatePEM, i.Now())
	if err != nil {
		return UserCATrustResult{}, fmt.Errorf("validate Phase AI CA for user trust: %w", err)
	}

	switch i.GOOS {
	case "darwin":
		return i.trustDarwin(certificatePath, certificate)
	case "windows":
		return i.trustWindows(certificatePath, certificate)
	case "linux":
		return i.trustLinuxNSS(certificatePath, certificate)
	default:
		return UserCATrustResult{}, fmt.Errorf("%w: %s", ErrUserCATrustUnsupported, i.GOOS)
	}
}

func (i userCATrustInstaller) withDefaults() userCATrustInstaller {
	if i.Runner == nil {
		i.Runner = osTrustCommandRunner{}
	}
	if i.MkdirAll == nil {
		i.MkdirAll = os.MkdirAll
	}
	if i.Chmod == nil {
		i.Chmod = os.Chmod
	}
	if i.Stat == nil {
		i.Stat = os.Stat
	}
	if i.ReadFile == nil {
		i.ReadFile = os.ReadFile
	}
	if i.Now == nil {
		i.Now = time.Now
	}
	return i
}

func (i userCATrustInstaller) trustDarwin(certificatePath string, certificate *x509.Certificate) (UserCATrustResult, error) {
	security, err := i.Runner.LookPath("security")
	if err != nil {
		return UserCATrustResult{}, fmt.Errorf("find macOS security tool: %w", err)
	}
	keychain := filepath.Join(i.Home, "Library", "Keychains", "login.keychain-db")
	if output, runErr := i.Runner.Run(security, "default-keychain", "-d", "user"); runErr == nil {
		if configured := strings.Trim(strings.TrimSpace(string(output)), `"`); configured != "" {
			keychain = configured
		}
	}

	if output, runErr := i.Runner.Run(security, "find-certificate", "-a", "-p", "-c", phaseAITrustNickname, keychain); runErr == nil {
		phaseRoots := make([]*x509.Certificate, 0)
		for _, existing := range parsePEMCertificates(output) {
			if isPhaseOwnedRoot(existing) {
				phaseRoots = append(phaseRoots, existing)
			}
		}
		// Preserve the already-trusted fast path even if an older Phase root
		// also exists later or earlier in the keychain result.
		for _, existing := range phaseRoots {
			if bytes.Equal(existing.Raw, certificate.Raw) {
				return UserCATrustResult{Store: "macOS current-user keychain", AlreadyTrusted: true}, nil
			}
		}
		for _, existing := range phaseRoots {
			fingerprint := sha256.Sum256(existing.Raw)
			fingerprintHex := strings.ToUpper(hex.EncodeToString(fingerprint[:]))
			// Deliberately without -t: deleting the obsolete certificate itself
			// needs no authorization, while removing its user trust setting
			// would raise a second macOS password/Touch ID dialog. The orphaned
			// setting is inert: it names a certificate that no longer exists in
			// the keychain and whose signing key Phase has already replaced.
			// The one dialog users see belongs to add-trusted-cert below.
			deleteOutput, deleteErr := i.Runner.Run(security, "delete-certificate", "-Z", fingerprintHex, keychain)
			if deleteErr != nil {
				return UserCATrustResult{}, trustCommandError("remove obsolete Phase AI CA from macOS current-user keychain", deleteErr, deleteOutput)
			}
		}
	}

	// Omitting security(1)'s -d flag is intentional: -d targets the admin
	// trust domain. The explicit user keychain keeps this operation scoped to
	// the current user and never requires sudo. macOS still asks the user to
	// authorize the trust-settings change once.
	output, err := i.Runner.Run(security, "add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", keychain, certificatePath)
	if err != nil {
		return UserCATrustResult{}, trustCommandError("trust Phase AI CA in macOS current-user keychain", err, output)
	}
	return UserCATrustResult{Store: "macOS current-user keychain"}, nil
}

func (i userCATrustInstaller) trustWindows(certificatePath string, certificate *x509.Certificate) (UserCATrustResult, error) {
	powershell, err := i.Runner.LookPath("powershell.exe")
	if err != nil {
		return UserCATrustResult{}, fmt.Errorf("find Windows PowerShell for safe Phase CA rotation: %w", err)
	}
	certutil, err := i.Runner.LookPath("certutil")
	if err != nil {
		return UserCATrustResult{}, fmt.Errorf("find Windows certutil: %w", err)
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	fingerprintHex := strings.ToUpper(hex.EncodeToString(fingerprint[:]))
	rotationScript := strings.Replace(windowsPhaseCARotationScript, "__PHASE_SHA256__", fingerprintHex, 1)
	rotationOutput, rotationErr := i.Runner.Run(
		powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
		"-Command", rotationScript,
	)
	if rotationErr != nil {
		return UserCATrustResult{}, trustCommandError("inspect and rotate Phase AI CA in Windows current-user Root store", rotationErr, rotationOutput)
	}
	if strings.Contains(string(rotationOutput), "PHASE_CA_CURRENT") {
		return UserCATrustResult{Store: "Windows current-user Root store", AlreadyTrusted: true}, nil
	}
	// -user is the security boundary: without it certutil targets the local
	// machine store and may elevate. -f makes re-enabling idempotent.
	output, err := i.Runner.Run(certutil, "-user", "-addstore", "-f", "Root", certificatePath)
	if err != nil {
		return UserCATrustResult{}, trustCommandError("trust Phase AI CA in Windows current-user Root store", err, output)
	}
	return UserCATrustResult{Store: "Windows current-user Root store"}, nil
}

func parsePEMCertificates(payload []byte) []*x509.Certificate {
	result := make([]*x509.Certificate, 0)
	rest := payload
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			result = append(result, certificate)
		}
	}
	return result
}

func isPhaseOwnedRoot(certificate *x509.Certificate) bool {
	if certificate == nil || certificate.Subject.CommonName != phaseAITrustNickname ||
		certificate.Subject.String() != certificate.Issuer.String() || !certificate.IsCA ||
		!certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
		certificate.CheckSignatureFrom(certificate) != nil {
		return false
	}
	for _, organisation := range certificate.Subject.Organization {
		if organisation == "Phase" {
			return true
		}
	}
	return false
}

func (i userCATrustInstaller) trustLinuxNSS(certificatePath string, certificate *x509.Certificate) (UserCATrustResult, error) {
	certutil, err := i.Runner.LookPath("certutil")
	if err != nil {
		return UserCATrustResult{}, fmt.Errorf("find NSS certutil (install your distribution's libnss3-tools/nss-tools package, or decline CA trust): %w", err)
	}
	databaseDirectory := filepath.Join(i.Home, ".pki", "nssdb")
	if err := i.MkdirAll(databaseDirectory, 0o700); err != nil {
		return UserCATrustResult{}, fmt.Errorf("create current-user NSS trust directory: %w", err)
	}
	if err := i.Chmod(databaseDirectory, 0o700); err != nil {
		return UserCATrustResult{}, fmt.Errorf("secure current-user NSS trust directory: %w", err)
	}
	database := "sql:" + databaseDirectory
	if _, err := i.Stat(filepath.Join(databaseDirectory, "cert9.db")); errors.Is(err, os.ErrNotExist) {
		output, runErr := i.Runner.Run(certutil, "-N", "--empty-password", "-d", database)
		if runErr != nil {
			return UserCATrustResult{}, trustCommandError("initialize current-user NSS trust database", runErr, output)
		}
	} else if err != nil {
		return UserCATrustResult{}, fmt.Errorf("inspect current-user NSS trust database: %w", err)
	}

	if output, runErr := i.Runner.Run(certutil, "-L", "-d", database, "-n", phaseAITrustNickname, "-a"); runErr == nil {
		if existing, parseErr := parsePublicCA(output, i.Now()); parseErr == nil && bytes.Equal(existing.Raw, certificate.Raw) {
			return UserCATrustResult{Store: "Linux current-user NSS database", AlreadyTrusted: true}, nil
		}
		// The nickname belongs to Phase. Remove an obsolete Phase CA before
		// replacing it so rotation does not leave our old root trusted.
		deleteOutput, deleteErr := i.Runner.Run(certutil, "-D", "-d", database, "-n", phaseAITrustNickname)
		if deleteErr != nil {
			return UserCATrustResult{}, trustCommandError("replace obsolete Phase AI CA in current-user NSS database", deleteErr, deleteOutput)
		}
	}

	output, err := i.Runner.Run(certutil, "-A", "-d", database, "-n", phaseAITrustNickname, "-t", "C,,", "-i", certificatePath)
	if err != nil {
		return UserCATrustResult{}, trustCommandError("trust Phase AI CA in current-user NSS database", err, output)
	}
	return UserCATrustResult{Store: "Linux current-user NSS database"}, nil
}

func trustCommandError(action string, err error, output []byte) error {
	detail := strings.TrimSpace(string(output))
	if len(detail) > 1024 {
		detail = detail[:1024] + "…"
	}
	if detail == "" {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: %w: %s", action, err, detail)
}

func parsePublicCA(certificatePEM []byte, now time.Time) (*x509.Certificate, error) {
	block, rest := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("Phase proxy CA is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("Phase proxy CA is invalid")
	}
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return nil, errors.New("Phase proxy CA is expired or not yet valid")
	}
	return certificate, nil
}
