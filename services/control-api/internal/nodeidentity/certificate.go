package nodeidentity

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"github.com/google/uuid"
)

func validateSignedCertificate(
	signed SignedCertificate,
	csr *x509.CertificateRequest,
	nodeID uuid.UUID,
	notBefore, notAfter time.Time,
	renewBefore time.Duration,
) (persistedCertificate, error) {
	leaf, err := parseSinglePEMCertificate(signed.LeafCertificatePEM)
	if err != nil || len(signed.IssuingChainPEM) < 1 || len(signed.IssuingChainPEM) > 8 || leaf.IsCA ||
		leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 || !leaf.NotBefore.Equal(notBefore) || !leaf.NotAfter.Equal(notAfter) ||
		len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 1 {
		return persistedCertificate{}, ErrCertificateInvalid
	}
	expectedURI := NodeSPIFFEPrefix + nodeID.String()
	if leaf.URIs[0].String() != expectedURI || !hasClientAuthUsage(leaf.ExtKeyUsage) || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return persistedCertificate{}, ErrCertificateInvalid
	}
	csrPublic, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return persistedCertificate{}, ErrCertificateInvalid
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(csrPublic, certificatePublic) {
		return persistedCertificate{}, ErrCertificateInvalid
	}

	chain := make([]*x509.Certificate, len(signed.IssuingChainPEM))
	chainPEM := make([][]byte, len(signed.IssuingChainPEM))
	for index, encoded := range signed.IssuingChainPEM {
		if len(encoded) > 65536 {
			return persistedCertificate{}, ErrCertificateInvalid
		}
		chain[index], err = parseSinglePEMCertificate(encoded)
		if err != nil || !chain[index].IsCA {
			return persistedCertificate{}, ErrCertificateInvalid
		}
		chainPEM[index] = bytes.Clone(encoded)
	}
	if leaf.CheckSignatureFrom(chain[0]) != nil {
		return persistedCertificate{}, ErrCertificateInvalid
	}
	for index := 0; index < len(chain)-1; index++ {
		if chain[index].CheckSignatureFrom(chain[index+1]) != nil {
			return persistedCertificate{}, ErrCertificateInvalid
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(chain[len(chain)-1])
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[:len(chain)-1] {
		intermediates.AddCert(certificate)
	}
	for _, verificationTime := range []time.Time{notBefore.Add(time.Second), notAfter.Add(-time.Second)} {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: intermediates, CurrentTime: verificationTime,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			return persistedCertificate{}, ErrCertificateInvalid
		}
	}

	renewalAt := notAfter.Add(-renewBefore)
	if !renewalAt.After(notBefore) {
		return persistedCertificate{}, ErrCertificateInvalid
	}
	serial := strings.ToLower(leaf.SerialNumber.Text(16))
	if !validSerial(serial) {
		return persistedCertificate{}, ErrCertificateInvalid
	}
	publicHash := sha256.Sum256(certificatePublic)
	leafHash := sha256.Sum256(signed.LeafCertificatePEM)
	leafDERHash := sha256.Sum256(leaf.Raw)
	issuerCAHash := sha256.Sum256(chain[0].Raw)
	return persistedCertificate{
		Certificate: Certificate{NodeID: nodeID, LeafCertificatePEM: bytes.Clone(signed.LeafCertificatePEM),
			IssuingChainPEM: chainPEM, SerialNumber: serial, NotBefore: notBefore, NotAfter: notAfter, RenewalAt: renewalAt},
		PublicKeyHash: publicHash, URISAN: expectedURI, LeafHash: leafHash,
		LeafDERHash: leafDERHash, IssuerCAHash: issuerCAHash,
	}, nil
}

func parseSinglePEMCertificate(value []byte) (*x509.Certificate, error) {
	if len(value) == 0 || len(value) > 65536 {
		return nil, ErrCertificateInvalid
	}
	block, remainder := pem.Decode(value)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, ErrCertificateInvalid
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrCertificateInvalid
	}
	return certificate, nil
}

func hasClientAuthUsage(values []x509.ExtKeyUsage) bool {
	for _, value := range values {
		if value == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}
