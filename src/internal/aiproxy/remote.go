package aiproxy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/phasehq/cli/internal/remoteapi"
)

type remoteTLSIdentity struct {
	certificate *tls.Certificate
	host        string
	fingerprint string
}

func (e *Engine) validateRemoteConfiguration() (*remoteTLSIdentity, error) {
	if !e.Remote {
		if e.AdvertiseHost != "" || e.TLSCertificatePath != "" || e.TLSPrivateKeyPath != "" {
			return nil, errors.New("remote proxy settings require remote mode (phase relay start)")
		}
		for label, address := range map[string]string{"PostgreSQL proxy": e.PostgresListenAddress} {
			if address == "" {
				continue
			}
			if err := validateExplicitListenPort(address, "local "+label+" listener"); err != nil {
				return nil, err
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil || !isLoopbackHost(host) {
				return nil, fmt.Errorf("local %s listener must bind to loopback", label)
			}
		}
		return nil, nil
	}
	host, err := normalizeAdvertisedDNS(e.AdvertiseHost)
	if err != nil {
		return nil, err
	}
	if err := validateNonLoopbackBind(e.ListenAddress, "HTTP proxy"); err != nil {
		return nil, err
	}
	for label, address := range map[string]string{"PostgreSQL proxy": e.PostgresListenAddress} {
		if address != "" {
			if err := validateNonLoopbackBind(address, label); err != nil {
				return nil, err
			}
		}
	}
	if e.TLSCertificatePath == "" || e.TLSPrivateKeyPath == "" {
		return nil, errors.New("phase relay start requires --tls-cert and --tls-key")
	}
	if err := validatePrivateKeyFile(e.TLSPrivateKeyPath); err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(e.TLSCertificatePath, e.TLSPrivateKeyPath)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, errors.New("remote Phase AI TLS certificate or private key is invalid")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA {
		return nil, errors.New("remote Phase AI TLS leaf certificate is invalid")
	}
	pair.Leaf = leaf
	if err := leaf.VerifyHostname(host); err != nil {
		return nil, fmt.Errorf("remote Phase AI TLS certificate does not cover advertised host %q", host)
	}
	roots := e.RemoteRootCAs
	if roots == nil {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, errors.New("system trust store is unavailable for remote Phase AI TLS validation")
		}
	}
	intermediates := x509.NewCertPool()
	for _, raw := range pair.Certificate[1:] {
		certificate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return nil, errors.New("remote Phase AI TLS certificate chain is invalid")
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, errors.New("remote Phase AI TLS certificate is not trusted for the advertised host")
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	return &remoteTLSIdentity{certificate: &pair, host: host, fingerprint: hex.EncodeToString(fingerprint[:])}, nil
}

func normalizeAdvertisedDNS(value string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil || !strings.Contains(host, ".") || isLoopbackHost(host) {
		return "", errors.New("remote Phase AI proxy requires an explicit non-loopback advertised DNS host")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("remote Phase AI advertised host is invalid")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", errors.New("remote Phase AI advertised host is invalid")
			}
		}
	}
	return host, nil
}

func validateNonLoopbackBind(address, label string) error {
	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("remote %s listen address must be explicit", label)
	}
	if err := validateExplicitListenPort(address, "remote "+label+" listener"); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" || isLoopbackHost(host) {
		return fmt.Errorf("remote %s must bind explicitly outside loopback", label)
	}
	return nil
}

func validatePrivateKeyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("remote Phase AI TLS key must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && (info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o400 == 0) {
		return errors.New("remote Phase AI TLS key permissions must be owner-only (0400 or 0600)")
	}
	return nil
}

func listenerIsNonLoopback(listener net.Listener) bool {
	address, ok := listener.Addr().(*net.TCPAddr)
	return ok && !address.IP.IsLoopback()
}

func advertisedEndpoint(host string, listener net.Listener) (remoteapi.Endpoint, error) {
	_, portRaw, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return remoteapi.Endpoint{}, err
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return remoteapi.Endpoint{}, err
	}
	return remoteapi.Endpoint{Host: host, Port: port, TLS: true, TLSServerName: host}, nil
}
