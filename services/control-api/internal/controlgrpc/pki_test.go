package controlgrpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var testNow = time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)

type testPKI struct {
	directory      string
	root           *x509.Certificate
	rootKey        *ecdsa.PrivateKey
	rootFile       string
	serverFile     string
	serverKeyFile  string
	gatewayFile    string
	gatewayKeyFile string
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	directory := t.TempDir()
	rootKey := newTestPrivateKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ControlInternal test root"},
		NotBefore:             testNow.Add(-365 * 24 * time.Hour),
		NotAfter:              testNow.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	pki := testPKI{
		directory: directory,
		root:      root,
		rootKey:   rootKey,
		rootFile:  writeTestPEM(t, directory, "gateway-root.pem", "CERTIFICATE", rootDER),
	}
	pki.serverFile, pki.serverKeyFile = pki.issueLeaf(
		t, "control-server", 2, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		testNow.Add(-365*24*time.Hour), testNow.Add(365*24*time.Hour), nil,
	)
	gatewayURI, err := url.Parse("spiffe://cdn-platform/gateway/control")
	if err != nil {
		t.Fatal(err)
	}
	pki.gatewayFile, pki.gatewayKeyFile = pki.issueLeaf(
		t, "gateway", 3, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		testNow.Add(-365*24*time.Hour), testNow.Add(365*24*time.Hour), []*url.URL{gatewayURI},
	)
	return pki
}

func (p testPKI) config(t *testing.T) Config {
	t.Helper()
	config := DefaultConfig()
	config.ListenAddress = unusedAddress(t)
	config.ServerCertificateFile = p.serverFile
	config.ServerPrivateKeyFile = p.serverKeyFile
	config.GatewayClientCAFile = p.rootFile
	return config
}

func (p testPKI) issueLeaf(t *testing.T, name string, serial int64, usages []x509.ExtKeyUsage, notBefore, notAfter time.Time, uris []*url.URL) (string, string) {
	t.Helper()
	key := newTestPrivateKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{"localhost"},
		URIs:         uris,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.root, &key.PublicKey, p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writeTestPEM(t, p.directory, name+".pem", "CERTIFICATE", der),
		writeTestPEM(t, p.directory, name+"-key.pem", "PRIVATE KEY", keyDER)
}

func newTestPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeTestPEM(t *testing.T, directory, name, blockType string, contents []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: contents}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
