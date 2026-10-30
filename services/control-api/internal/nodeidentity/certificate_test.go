package nodeidentity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateSignedCertificateChecksFullLifetimeAndUsage(t *testing.T) {
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	notBefore, notAfter := now.Add(-time.Minute), now.Add(24*time.Hour)
	nodeID := uuid.New()
	csrDER := testCSR(t, false)
	csr, _, _, err := validateCSR(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	valid := signCertificateFixture(t, csr, nodeID, notBefore, notAfter, now.Add(48*time.Hour), x509.KeyUsageDigitalSignature)
	if _, err := validateSignedCertificate(valid, csr, nodeID, notBefore, notAfter, 6*time.Hour); err != nil {
		t.Fatalf("validateSignedCertificate(valid) error = %v", err)
	}
	withoutSignatureUsage := signCertificateFixture(t, csr, nodeID, notBefore, notAfter, now.Add(48*time.Hour), x509.KeyUsageKeyEncipherment)
	if _, err := validateSignedCertificate(withoutSignatureUsage, csr, nodeID, notBefore, notAfter, 6*time.Hour); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("missing DigitalSignature error = %v", err)
	}
	expiringIssuer := signCertificateFixture(t, csr, nodeID, notBefore, notAfter, now.Add(12*time.Hour), x509.KeyUsageDigitalSignature)
	if _, err := validateSignedCertificate(expiringIssuer, csr, nodeID, notBefore, notAfter, 6*time.Hour); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("issuer expiring during leaf lifetime error = %v", err)
	}
}

func signCertificateFixture(t *testing.T, csr *x509.CertificateRequest, nodeID uuid.UUID, notBefore, notAfter, rootNotAfter time.Time, usage x509.KeyUsage) SignedCertificate {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"},
		NotBefore: notBefore.Add(-time.Hour), NotAfter: rootNotAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse(NodeSPIFFEPrefix + nodeID.String())
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: nodeID.String()},
		NotBefore: notBefore, NotAfter: notAfter, URIs: []*url.URL{uri}, BasicConstraintsValid: true,
		KeyUsage: usage, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, csr.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return SignedCertificate{LeafCertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		IssuingChainPEM: [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})}}
}
