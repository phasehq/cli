package proxy

import (
	"bytes"
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	leafCertificateValidity = 24 * time.Hour
	leafCacheCapacity       = 1024
)

// CAErrorCode identifies a certificate-authority failure without exposing key
// material in logs or user-facing diagnostics.
type CAErrorCode string

const (
	CAErrorInvalidValidity CAErrorCode = "invalid_validity"
	CAErrorKeyGeneration   CAErrorCode = "key_generation_failed"
	CAErrorCertificate     CAErrorCode = "invalid_certificate"
	CAErrorPrivateKey      CAErrorCode = "invalid_private_key"
	CAErrorKeyMismatch     CAErrorCode = "key_mismatch"
	CAErrorInvalidHost     CAErrorCode = "invalid_host"
	CAErrorExpired         CAErrorCode = "expired"
	CAErrorLeafGeneration  CAErrorCode = "leaf_generation_failed"
)

// CAError is a typed, redacted error returned by CA operations.
type CAError struct {
	Code CAErrorCode
	err  error
}

func (e *CAError) Error() string {
	switch e.Code {
	case CAErrorInvalidValidity:
		return "proxy CA validity must be greater than zero"
	case CAErrorKeyGeneration:
		return "proxy CA key generation failed"
	case CAErrorCertificate:
		return "proxy CA certificate is invalid"
	case CAErrorPrivateKey:
		return "proxy CA private key is invalid"
	case CAErrorKeyMismatch:
		return "proxy CA certificate and private key do not match"
	case CAErrorInvalidHost:
		return "proxy leaf certificate host is invalid"
	case CAErrorExpired:
		return "proxy CA certificate is expired or not yet valid"
	case CAErrorLeafGeneration:
		return "proxy leaf certificate generation failed"
	default:
		return "proxy certificate operation failed"
	}
}

func (e *CAError) Unwrap() error { return e.err }

type cachedLeaf struct {
	host string
	cert *tls.Certificate
}

// CA is the proxy's certificate authority. It mints and caches leaf
// certificates by normalized SNI host. The private key is expected to live in
// the OS keyring; this type does not persist it.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte

	mu        sync.Mutex
	leaves    map[string]*list.Element
	leavesLRU *list.List
	leafLimit int
	now       func() time.Time
}

// CertificateForHost returns a short-lived leaf certificate for a normalized
// SNI host. It is the only CA operation needed by the executable MITM layer;
// callers never receive the CA private key.
func (ca *CA) CertificateForHost(host string) (*tls.Certificate, error) {
	return ca.leafFor(host)
}

// CertificatePEM returns only the public proxy CA certificate. It is safe to
// distribute to a remote Agent client; the signing key remains encapsulated.
func (ca *CA) CertificatePEM() []byte {
	if ca == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: append([]byte(nil), ca.der...)})
}

// GenerateCA creates a fresh P-256 CA and returns the in-memory CA alongside
// PEM-encoded certificate and private key. certPEM is public; keyPEM must be
// treated as secret material.
func GenerateCA(validity time.Duration) (ca *CA, certPEM, keyPEM []byte, err error) {
	if validity <= 0 {
		return nil, nil, nil, &CAError{Code: CAErrorInvalidValidity}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, &CAError{Code: CAErrorKeyGeneration, err: err}
	}
	serial, err := randomSerial(128)
	if err != nil {
		return nil, nil, nil, &CAError{Code: CAErrorCertificate, err: err}
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Phase AI Proxy CA", Organization: []string{"Phase"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, &CAError{Code: CAErrorCertificate, err: err}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, &CAError{Code: CAErrorCertificate, err: err}
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, &CAError{Code: CAErrorPrivateKey, err: err}
	}

	ca = newCA(cert, key, der)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return ca, certPEM, keyPEM, nil
}

// LoadCA reconstructs a CA from a PEM certificate and a matching PEM P-256
// private key. SEC1 and PKCS#8 private keys are accepted for compatibility.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, certRest := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(certRest)) != 0 {
		return nil, &CAError{Code: CAErrorCertificate}
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, &CAError{Code: CAErrorCertificate, err: err}
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, &CAError{Code: CAErrorCertificate}
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, &CAError{Code: CAErrorCertificate, err: err}
	}

	keyBlock, keyRest := pem.Decode(keyPEM)
	if keyBlock == nil || len(bytes.TrimSpace(keyRest)) != 0 {
		return nil, &CAError{Code: CAErrorPrivateKey}
	}
	key, err := parseECDSAPrivateKey(keyBlock)
	if err != nil {
		return nil, &CAError{Code: CAErrorPrivateKey, err: err}
	}
	if key.Curve != elliptic.P256() {
		return nil, &CAError{Code: CAErrorPrivateKey}
	}
	certPublicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certPublicKey.Equal(&key.PublicKey) {
		return nil, &CAError{Code: CAErrorKeyMismatch}
	}

	now := time.Now().UTC()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, &CAError{Code: CAErrorExpired}
	}
	return newCA(cert, key, certBlock.Bytes), nil
}

func newCA(cert *x509.Certificate, key *ecdsa.PrivateKey, der []byte) *CA {
	return &CA{
		cert:      cert,
		key:       key,
		der:       append([]byte(nil), der...),
		leaves:    make(map[string]*list.Element),
		leavesLRU: list.New(),
		leafLimit: leafCacheCapacity,
		now:       func() time.Time { return time.Now().UTC() },
	}
}

func parseECDSAPrivateKey(block *pem.Block) (*ecdsa.PrivateKey, error) {
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 key is not ECDSA")
		}
		return ecdsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
	}
}

func randomSerial(bits uint) (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), bits)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

// leafFor mints (and caches) a leaf certificate for host. DNS names are placed
// in DNS SANs and IP literals in IP SANs for modern TLS clients.
func (ca *CA) leafFor(host string) (*tls.Certificate, error) {
	normalizedHost, ip, err := normalizeCertificateHost(host)
	if err != nil {
		return nil, &CAError{Code: CAErrorInvalidHost, err: err}
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()

	now := ca.now()
	if now.Before(ca.cert.NotBefore) || !now.Before(ca.cert.NotAfter) {
		return nil, &CAError{Code: CAErrorExpired}
	}
	if elem, ok := ca.leaves[normalizedHost]; ok {
		cached := elem.Value.(*cachedLeaf).cert
		if cached.Leaf != nil && !now.Before(cached.Leaf.NotBefore) && now.Before(cached.Leaf.NotAfter) {
			ca.leavesLRU.MoveToFront(elem)
			return cached, nil
		}
		delete(ca.leaves, normalizedHost)
		ca.leavesLRU.Remove(elem)
	}

	leafNotAfter := now.Add(leafCertificateValidity)
	if leafNotAfter.After(ca.cert.NotAfter) {
		leafNotAfter = ca.cert.NotAfter
	}
	if !leafNotAfter.After(now) {
		return nil, &CAError{Code: CAErrorExpired}
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &CAError{Code: CAErrorLeafGeneration, err: err}
	}
	serial, err := randomSerial(128)
	if err != nil {
		return nil, &CAError{Code: CAErrorLeafGeneration, err: err}
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: normalizedHost},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     leafNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{normalizedHost}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, &CAError{Code: CAErrorLeafGeneration, err: err}
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &CAError{Code: CAErrorLeafGeneration, err: err}
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, append([]byte(nil), ca.der...)},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}

	elem := ca.leavesLRU.PushFront(&cachedLeaf{host: normalizedHost, cert: cert})
	ca.leaves[normalizedHost] = elem
	if ca.leavesLRU.Len() > ca.leafLimit {
		oldest := ca.leavesLRU.Back()
		delete(ca.leaves, oldest.Value.(*cachedLeaf).host)
		ca.leavesLRU.Remove(oldest)
	}
	return cert, nil
}

func normalizeCertificateHost(host string) (string, net.IP, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", nil, errors.New("empty host")
	}

	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return "", nil, errors.New("invalid bracketed host")
		}
		if end+1 < len(host) {
			if host[end+1] != ':' {
				return "", nil, errors.New("invalid bracketed host suffix")
			}
			if !validPort(host[end+2:]) {
				return "", nil, errors.New("invalid host port")
			}
		}
		host = host[1:end]
	} else if parsedHost, port, err := net.SplitHostPort(host); err == nil {
		if !validPort(port) {
			return "", nil, errors.New("invalid host port")
		}
		host = parsedHost
	} else if strings.Count(host, ":") == 1 {
		return "", nil, errors.New("invalid host port")
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), ip, nil
	}
	if len(host) > 253 || strings.ContainsAny(host, "/\\@%") {
		return "", nil, errors.New("invalid DNS name")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", nil, errors.New("invalid DNS label")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", nil, errors.New("invalid DNS label character")
			}
		}
	}
	return host, nil, nil
}

func validPort(port string) bool {
	portNumber, err := strconv.ParseUint(port, 10, 16)
	return err == nil && portNumber != 0
}
