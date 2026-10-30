package marketruntime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

// CDNCA_MARKET_CA_FILE (cross-process e2e only) replaces the system pool
// with the named PEM bundle; unset keeps the system pool.
func TestRootCAsMarketCAFile(t *testing.T) {
	t.Setenv(MarketCAFileEnv, "")
	system, err := RootCAs()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := x509.SystemCertPool()
	if !system.Equal(want) {
		t.Fatal("unset: the system pool")
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "market e2e CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(MarketCAFileEnv, file)
	pool, err := RootCAs()
	if err != nil {
		t.Fatal(err)
	}
	only := x509.NewCertPool()
	only.AddCert(ca)
	if !pool.Equal(only) {
		t.Fatal("set: exactly the file's CA")
	}

	empty := filepath.Join(t.TempDir(), "empty.pem")
	_ = os.WriteFile(empty, []byte("not a certificate"), 0o600)
	for _, path := range []string{empty, filepath.Join(t.TempDir(), "missing.pem"), "relative.pem"} {
		t.Setenv(MarketCAFileEnv, path)
		if _, err := RootCAs(); err == nil {
			t.Fatalf("%s: want an error", path)
		}
	}
}
