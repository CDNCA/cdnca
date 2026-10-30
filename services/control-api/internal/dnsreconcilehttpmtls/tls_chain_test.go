package dnsreconcilehttpmtls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadTLSValidatesIncludedServerCertificateChain(t *testing.T) {
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	root, rootKey := issueTLSChainCertificate(t, certificateTemplate{
		serial: 1, commonName: "root", notBefore: now.Add(-24 * time.Hour), notAfter: now.Add(365 * 24 * time.Hour), ca: true,
	}, nil, nil)
	intermediate, intermediateKey := issueTLSChainCertificate(t, certificateTemplate{
		serial: 2, commonName: "intermediate", notBefore: now.Add(-time.Hour), notAfter: now.Add(30 * 24 * time.Hour), ca: true,
	}, root, rootKey)
	leaf, leafKey := issueTLSChainCertificate(t, certificateTemplate{
		serial: 3, commonName: "server", notBefore: now.Add(-time.Hour), notAfter: now.Add(48 * time.Hour), server: true,
	}, intermediate, intermediateKey)
	unrelated, _ := issueTLSChainCertificate(t, certificateTemplate{
		serial: 4, commonName: "unrelated", notBefore: now.Add(-time.Hour), notAfter: now.Add(30 * 24 * time.Hour), ca: true,
	}, root, rootKey)
	expired, expiredKey := issueTLSChainCertificate(t, certificateTemplate{
		serial: 5, commonName: "expired", notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Hour), ca: true,
	}, root, rootKey)
	expiredLeaf, expiredLeafKey := issueTLSChainCertificate(t, certificateTemplate{
		serial: 6, commonName: "expired-chain-server", notBefore: now.Add(-time.Hour), notAfter: now.Add(48 * time.Hour), server: true,
	}, expired, expiredKey)
	future, futureKey := issueTLSChainCertificate(t, certificateTemplate{
		serial: 7, commonName: "future", notBefore: now.Add(time.Hour), notAfter: now.Add(30 * 24 * time.Hour), ca: true,
	}, root, rootKey)
	futureLeaf, futureLeafKey := issueTLSChainCertificate(t, certificateTemplate{
		serial: 8, commonName: "future-chain-server", notBefore: now.Add(-time.Hour), notAfter: now.Add(48 * time.Hour), server: true,
	}, future, futureKey)

	for _, test := range []struct {
		name        string
		chain       []*x509.Certificate
		key         ed25519.PrivateKey
		wantInvalid bool
	}{
		{name: "valid included intermediate", chain: []*x509.Certificate{leaf, intermediate}, key: leafKey},
		{name: "leaf only remains supported", chain: []*x509.Certificate{leaf}, key: leafKey},
		{name: "unrelated included issuer", chain: []*x509.Certificate{leaf, unrelated}, key: leafKey, wantInvalid: true},
		{name: "wrong chain order", chain: []*x509.Certificate{leaf, root, intermediate}, key: leafKey, wantInvalid: true},
		{name: "expired included issuer", chain: []*x509.Certificate{expiredLeaf, expired}, key: expiredLeafKey, wantInvalid: true},
		{name: "not yet valid included issuer", chain: []*x509.Certificate{futureLeaf, future}, key: futureLeafKey, wantInvalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := writeTLSChainConfig(t, root, test.chain, test.key)
			loaded, err := loadTLS(&config, func() time.Time { return now })
			if test.wantInvalid {
				if err == nil || loaded != nil {
					t.Fatalf("loadTLS() = (%v, %v), want invalid configuration", loaded, err)
				}
				return
			}
			if err != nil || loaded == nil || len(loaded.Certificates) != 1 {
				t.Fatalf("loadTLS() = (%v, %v)", loaded, err)
			}
		})
	}
}

type certificateTemplate struct {
	serial              int64
	commonName          string
	notBefore, notAfter time.Time
	ca, server          bool
}

func issueTLSChainCertificate(t *testing.T, input certificateTemplate, parent *x509.Certificate,
	parentKey ed25519.PrivateKey,
) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(input.serial), Subject: pkix.Name{CommonName: input.commonName},
		NotBefore: input.notBefore, NotAfter: input.notAfter, BasicConstraintsValid: true,
		IsCA: input.ca, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if input.ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if input.server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if parent == nil {
		parent, parentKey = template, privateKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, privateKey
}

func writeTLSChainConfig(t *testing.T, clientCA *x509.Certificate, chain []*x509.Certificate,
	privateKey ed25519.PrivateKey,
) Config {
	t.Helper()
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")
	clientCAPath := filepath.Join(directory, "client-ca.crt")
	var certificatePEM []byte
	for _, certificate := range chain {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientCAPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCA.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.ServerCertificateFile = certificatePath
	config.ServerPrivateKeyFile = keyPath
	config.ClientCAFile = clientCAPath
	config.MinimumCertificateValidity = time.Hour
	return config
}
