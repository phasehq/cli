package proxy

import (
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestGenerateLoadAndMintLeaf(t *testing.T) {
	ca, certPEM, keyPEM, err := GenerateCA(48 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ca.key.Curve != elliptic.P256() {
		t.Fatalf("CA key uses %T, want P-256", ca.key.Curve)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("expected PEM-encoded certificate and key")
	}

	loaded, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := loaded.leafFor("STS.AMAZONAWS.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Leaf == nil {
		t.Fatal("leaf certificate was not parsed")
	}
	if got := leaf.Leaf.DNSNames; len(got) != 1 || got[0] != "sts.amazonaws.com" {
		t.Fatalf("DNS SANs = %v, want sts.amazonaws.com", got)
	}
	if leaf.Leaf.NotAfter.After(loaded.cert.NotAfter) {
		t.Fatal("leaf outlives its issuing CA")
	}

	roots := x509.NewCertPool()
	roots.AddCert(loaded.cert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{
		DNSName: "sts.amazonaws.com",
		Roots:   roots,
	}); err != nil {
		t.Fatalf("verify generated leaf: %v", err)
	}

	cached, err := loaded.leafFor("sts.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	if cached != leaf {
		t.Fatal("normalized host did not reuse cached leaf")
	}
}

func TestLeafForIPUsesIPSAN(t *testing.T) {
	ca, _, _, err := GenerateCA(48 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.leafFor("[2001:db8::1]:443")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Leaf.DNSNames) != 0 || len(leaf.Leaf.IPAddresses) != 1 ||
		leaf.Leaf.IPAddresses[0].String() != "2001:db8::1" {
		t.Fatalf("unexpected SANs: DNS=%v IP=%v", leaf.Leaf.DNSNames, leaf.Leaf.IPAddresses)
	}
}

func TestLoadCAAcceptsPKCS8(t *testing.T) {
	_, certPEM, keyPEM, err := GenerateCA(48 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := LoadCA(certPEM, pkcs8PEM); err != nil {
		t.Fatalf("LoadCA(PKCS#8): %v", err)
	}
}

func TestLoadCARejectsMismatchedKey(t *testing.T) {
	_, certPEM, _, err := GenerateCA(48 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, _, otherKeyPEM, err := GenerateCA(48 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LoadCA(certPEM, otherKeyPEM)
	assertCAError(t, err, CAErrorKeyMismatch)
}

func TestCAFailuresAreTyped(t *testing.T) {
	_, _, _, err := GenerateCA(0)
	assertCAError(t, err, CAErrorInvalidValidity)

	_, err = LoadCA([]byte("not pem"), []byte("also not pem"))
	assertCAError(t, err, CAErrorCertificate)

	ca, _, _, err := GenerateCA(48 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"", "bad host", "*.example.com", "example.com:not-a-port", "-bad.example"} {
		t.Run(host, func(t *testing.T) {
			_, err := ca.leafFor(host)
			assertCAError(t, err, CAErrorInvalidHost)
		})
	}

	ca.now = func() time.Time { return ca.cert.NotAfter.Add(time.Second) }
	_, err = ca.leafFor("example.com")
	assertCAError(t, err, CAErrorExpired)
}

func TestLeafCacheIsBoundedLRU(t *testing.T) {
	ca, _, _, err := GenerateCA(48 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca.leafLimit = 2
	first, err := ca.leafFor("one.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.leafFor("two.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.leafFor("three.example.com"); err != nil {
		t.Fatal(err)
	}
	if len(ca.leaves) != 2 {
		t.Fatalf("leaf cache size = %d, want 2", len(ca.leaves))
	}
	firstAgain, err := ca.leafFor("one.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if firstAgain == first {
		t.Fatal("least-recently-used leaf was not evicted")
	}
}

func TestLeafCacheDoesNotReturnExpiredCertificate(t *testing.T) {
	ca, _, _, err := GenerateCA(72 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	ca.now = func() time.Time { return first.Leaf.NotAfter.Add(time.Second) }
	second, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("expired cached leaf was reused")
	}
}

func TestLeafForIsConcurrencySafe(t *testing.T) {
	ca, _, _, err := GenerateCA(48 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 20
	certificates := make(chan *tls.Certificate, workers)
	errorsFound := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cert, err := ca.leafFor("concurrent.example.com")
			if err != nil {
				errorsFound <- err
				return
			}
			certificates <- cert
		}()
	}
	wg.Wait()
	close(certificates)
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
	var first *tls.Certificate
	for certificate := range certificates {
		if first == nil {
			first = certificate
			continue
		}
		if certificate != first {
			t.Fatal("concurrent callers received different cached certificates")
		}
	}
}

func assertCAError(t *testing.T, err error, code CAErrorCode) {
	t.Helper()
	var typed *CAError
	if !errors.As(err, &typed) {
		t.Fatalf("error %v has type %T, want *CAError", err, err)
	}
	if typed.Code != code {
		t.Fatalf("CA error code = %q, want %q", typed.Code, code)
	}
}
