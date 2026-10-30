package nodeca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadSignerFromFilesAcceptsSupportedRestrictedPKCS8Keys(t *testing.T) {
	tests := []struct {
		name string
		key  func(*testing.T) crypto.Signer
	}{
		{name: "RSA", key: func(t *testing.T) crypto.Signer {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "ECDSA", key: func(t *testing.T) crypto.Signer {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "Ed25519", key: func(t *testing.T) crypto.Signer {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := test.key(t)
			now := time.Now().UTC()
			root := newSelfSignedCA(t, key, now.Add(-time.Hour), now.Add(24*time.Hour), nil)
			chainPath, keyPath := writeSignerMaterial(t, []*x509.Certificate{root}, key)

			signer, err := LoadSignerFromFiles(chainPath, keyPath)
			if err != nil || signer == nil {
				t.Fatalf("LoadSignerFromFiles() = (%v, %v)", signer, err)
			}
		})
	}
}

func TestLoadSignerFromFilesRequiresIssuerFirstCompleteChain(t *testing.T) {
	now := time.Now().UTC()
	rootKey := newPrivateKey(t, "ed25519")
	root := newSelfSignedCA(t, rootKey, now.Add(-time.Hour), now.Add(24*time.Hour), nil)
	issuerKey := newPrivateKey(t, "ed25519")
	issuer := issueCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, root, issuerKey.Public(), rootKey)

	chainPath, keyPath := writeSignerMaterial(t, []*x509.Certificate{issuer, root}, issuerKey)
	if _, err := LoadSignerFromFiles(chainPath, keyPath); err != nil {
		t.Fatalf("valid issuer-first chain error = %v", err)
	}
	writeCertificateChain(t, chainPath, []*x509.Certificate{root, issuer})
	if _, err := LoadSignerFromFiles(chainPath, keyPath); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("reversed chain error = %v", err)
	}
}

func TestLoadSignerFromFilesRejectsUnsafeOrAmbiguousPrivateKey(t *testing.T) {
	key := newPrivateKey(t, "ed25519")
	now := time.Now().UTC()
	root := newSelfSignedCA(t, key, now.Add(-time.Hour), now.Add(24*time.Hour), nil)
	chainPath, keyPath := writeSignerMaterial(t, []*x509.Certificate{root}, key)

	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSignerFromFiles(chainPath, keyPath); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("group-readable key error = %v", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, append(encoded, encoded...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSignerFromFiles(chainPath, keyPath); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("multiple key blocks error = %v", err)
	}
}

func TestLoadSignerFromFilesErrorsDoNotDisclosePathsOrContents(t *testing.T) {
	directory := t.TempDir()
	secretPath := filepath.Join(directory, "super-secret-node-ca-key.pem")
	secret := "private-key-secret-marker"
	if err := os.WriteFile(secretPath, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadSignerFromFiles(filepath.Join(directory, "missing-chain.pem"), secretPath)
	if !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), directory) || strings.Contains(err.Error(), secret) {
		t.Fatalf("error disclosed material: %q", err)
	}
}

func writeSignerMaterial(t *testing.T, chain []*x509.Certificate, key crypto.Signer) (string, string) {
	t.Helper()
	directory := t.TempDir()
	chainPath := filepath.Join(directory, "node-ca-chain.pem")
	keyPath := filepath.Join(directory, "node-ca-key.pem")
	writeCertificateChain(t, chainPath, chain)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return chainPath, keyPath
}

func writeCertificateChain(t *testing.T, path string, chain []*x509.Certificate) {
	t.Helper()
	var encoded bytes.Buffer
	for _, certificate := range chain {
		if err := pem.Encode(&encoded, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, encoded.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
