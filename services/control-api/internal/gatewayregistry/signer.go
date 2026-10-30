package gatewayregistry

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
)

// CA is one issuing CA: the Gateway client CA (ControlInternal trusts it) or
// the installation root CA (nodes trust it for the Gateway server name).
type CA struct {
	Certificate *x509.Certificate
	Key         crypto.Signer
}

// LoadCA reads a PEM certificate and its PEM private key (PKCS#1, PKCS#8 or
// SEC 1, as the installer's openssl writes them).
func LoadCA(certificateFile, keyFile string) (CA, error) {
	certificatePEM, err := os.ReadFile(certificateFile)
	if err != nil {
		return CA{}, fmt.Errorf("read CA certificate: %w", err)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return CA{}, errors.New("CA certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return CA{}, errors.New("CA certificate is invalid")
	}
	info, err := os.Stat(keyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return CA{}, errors.New("CA private key must be a regular file readable only by its owner")
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return CA{}, fmt.Errorf("read CA private key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return CA{}, errors.New("CA private key is not PEM")
	}
	var parsed any
	if parsed, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
		if parsed, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err != nil {
			if parsed, err = x509.ParseECPrivateKey(keyBlock.Bytes); err != nil {
				return CA{}, errors.New("CA private key is invalid")
			}
		}
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok || !publicKeysEqual(signer.Public(), certificate.PublicKey) {
		return CA{}, errors.New("CA private key does not match the certificate")
	}
	return CA{Certificate: certificate, Key: signer}, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	left, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	right, err := x509.MarshalPKIXPublicKey(b)
	return err == nil && string(left) == string(right)
}

// Signer issues Gateway certificates.
type Signer struct {
	Client CA // Gateway client CA
	Server CA // installation root CA
}

type issued struct {
	serial          string
	der             []byte
	pem             string
	certificateHash [32]byte
	publicKeyHash   [32]byte
	notBefore       time.Time
	notAfter        time.Time
}

// parseCSR checks the CSR signature and the key type of the certificate kind:
// client Ed25519, server ECDSA P-256 (accepted by every CDN origin check).
func parseCSR(der []byte, kind string) (*x509.CertificateRequest, [32]byte, error) {
	if len(der) == 0 || len(der) > 8192 {
		return nil, [32]byte{}, ErrInvalidInput
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return nil, [32]byte{}, ErrInvalidInput
	}
	switch key := csr.PublicKey.(type) {
	case ed25519.PublicKey:
		if kind != KindClient {
			return nil, [32]byte{}, ErrInvalidInput
		}
	case *ecdsa.PublicKey:
		if kind != KindServer || key.Curve != elliptic.P256() {
			return nil, [32]byte{}, ErrInvalidInput
		}
	default:
		return nil, [32]byte{}, ErrInvalidInput
	}
	spki, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, [32]byte{}, ErrInvalidInput
	}
	return csr, sha256.Sum256(spki), nil
}

func (s Signer) issue(gatewayID uuid.UUID, kind, host string, csr *x509.CertificateRequest, now time.Time) (issued, error) {
	ca, ttl := s.Client, ClientCertTTL
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "cdnca-agent-gateway-" + gatewayID.String()},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if kind == KindClient {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.URIs = []*url.URL{{Scheme: "spiffe", Host: "cdn-platform", Path: "/gateway/" + gatewayID.String()}}
	} else {
		ca, ttl = s.Server, ServerCertTTL
		template.Subject.CommonName = host
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = []net.IP{ip}
		} else {
			template.DNSNames = []string{host}
		}
	}
	if ca.Certificate == nil || ca.Key == nil {
		return issued{}, ErrUnavailable
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return issued{}, err
	}
	serial.Add(serial, big.NewInt(1))
	template.SerialNumber = serial
	template.NotBefore = now.Add(-certificateBackdate).UTC().Truncate(time.Second)
	template.NotAfter = now.Add(ttl).UTC().Truncate(time.Second)
	if template.NotAfter.After(ca.Certificate.NotAfter) {
		template.NotAfter = ca.Certificate.NotAfter
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, csr.PublicKey, ca.Key)
	if err != nil {
		return issued{}, fmt.Errorf("sign gateway certificate: %w", err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	return issued{
		// Text(16): no leading zeros, as ControlInternal reads leaf.SerialNumber.
		serial: serial.Text(16), der: der,
		pem:             string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		certificateHash: sha256.Sum256(der), publicKeyHash: sha256.Sum256(spki),
		notBefore: template.NotBefore, notAfter: template.NotAfter,
	}, nil
}

// renewAt is the half-life of a certificate (ADR 0013 §3.2: renew at half).
func renewAt(notBefore, notAfter time.Time) time.Time {
	return notBefore.Add(notAfter.Sub(notBefore) / 2)
}
