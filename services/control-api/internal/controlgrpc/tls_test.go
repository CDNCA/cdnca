package controlgrpc

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadTLSBuildsFixedTLS13MutualAuthenticationPolicy(t *testing.T) {
	pki := newTestPKI(t)
	config := pki.config(t)
	tlsConfig, err := LoadTLS(config, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 || tlsConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS versions = %d..%d, want TLS 1.3 only", tlsConfig.MinVersion, tlsConfig.MaxVersion)
	}
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.ClientCAs == nil {
		t.Fatal("Gateway client certificate verification is not required")
	}
	if len(tlsConfig.Certificates) != 1 || tlsConfig.Certificates[0].Leaf == nil {
		t.Fatal("server certificate was not loaded and parsed")
	}
	if tlsConfig.GetCertificate != nil || tlsConfig.GetConfigForClient != nil {
		t.Fatal("dynamic TLS hooks must remain disabled")
	}
}

func TestLoadTLSRejectsInvalidServerCertificate(t *testing.T) {
	pki := newTestPKI(t)
	wrongUsageFile, wrongUsageKey := pki.issueLeaf(
		t, "wrong-usage", 10, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		testNow.Add(-time.Hour), testNow.Add(48*time.Hour), nil,
	)
	expiredFile, expiredKey := pki.issueLeaf(
		t, "expired", 11, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		testNow.Add(-48*time.Hour), testNow.Add(-time.Minute), nil,
	)
	soonFile, soonKey := pki.issueLeaf(
		t, "soon", 12, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		testNow.Add(-time.Hour), testNow.Add(30*time.Minute), nil,
	)
	futureFile, futureKey := pki.issueLeaf(
		t, "future", 13, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		testNow.Add(time.Minute), testNow.Add(48*time.Hour), nil,
	)

	tests := []struct {
		name            string
		certificateFile string
		keyFile         string
	}{
		{name: "wrong usage", certificateFile: wrongUsageFile, keyFile: wrongUsageKey},
		{name: "expired", certificateFile: expiredFile, keyFile: expiredKey},
		{name: "expiring soon", certificateFile: soonFile, keyFile: soonKey},
		{name: "not yet valid", certificateFile: futureFile, keyFile: futureKey},
		{name: "key mismatch", certificateFile: pki.serverFile, keyFile: pki.gatewayKeyFile},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := pki.config(t)
			config.ServerCertificateFile = test.certificateFile
			config.ServerPrivateKeyFile = test.keyFile
			_, err := LoadTLS(config, func() time.Time { return testNow })
			if !errors.Is(err, ErrInvalidTLSMaterial) {
				t.Fatalf("LoadTLS error = %v, want ErrInvalidTLSMaterial", err)
			}
			assertSanitizedTLSError(t, err, pki.directory)
		})
	}
}

func TestLoadTLSRejectsMalformedOrNonCABundle(t *testing.T) {
	pki := newTestPKI(t)
	malformed := filepath.Join(pki.directory, "malformed-ca.pem")
	if err := os.WriteFile(malformed, []byte("not a PEM bundle\nSECRET-CONTENTS"), 0o600); err != nil {
		t.Fatal(err)
	}
	mixed := filepath.Join(pki.directory, "mixed-ca.pem")
	rootContents, err := os.ReadFile(pki.rootFile)
	if err != nil {
		t.Fatal(err)
	}
	leafContents, err := os.ReadFile(pki.gatewayFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mixed, append(rootContents, leafContents...), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(pki.directory, "empty-ca.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{malformed, mixed, empty, pki.gatewayFile, pki.directory} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			config := pki.config(t)
			config.GatewayClientCAFile = path
			_, err := LoadTLS(config, func() time.Time { return testNow })
			if !errors.Is(err, ErrInvalidTLSMaterial) {
				t.Fatalf("LoadTLS error = %v, want ErrInvalidTLSMaterial", err)
			}
			assertSanitizedTLSError(t, err, pki.directory)
		})
	}
}

func TestLoadTLSRequiresOwnerOnlyPrivateKeyPermissions(t *testing.T) {
	pki := newTestPKI(t)
	keyContents, err := os.ReadFile(pki.serverKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o644} {
		t.Run(mode.String(), func(t *testing.T) {
			keyFile := filepath.Join(pki.directory, "server-key-"+mode.String()+".pem")
			if err := os.WriteFile(keyFile, keyContents, mode); err != nil {
				t.Fatal(err)
			}
			config := pki.config(t)
			config.ServerPrivateKeyFile = keyFile
			_, err := LoadTLS(config, func() time.Time { return testNow })
			if !errors.Is(err, ErrInvalidTLSMaterial) {
				t.Fatalf("LoadTLS error = %v, want ErrInvalidTLSMaterial", err)
			}
			assertSanitizedTLSError(t, err, pki.directory)
		})
	}
}

func TestLoadTLSAcceptsWorldReadablePublicCertificates(t *testing.T) {
	pki := newTestPKI(t)
	if err := os.Chmod(pki.serverFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pki.rootFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTLS(pki.config(t), func() time.Time { return testNow }); err != nil {
		t.Fatalf("public certificate permissions rejected: %v", err)
	}
}

func TestClearBytesRemovesPrivateKeyMaterial(t *testing.T) {
	contents := []byte("private-key-material")
	clearBytes(contents)
	for index, value := range contents {
		if value != 0 {
			t.Fatalf("byte %d was not cleared", index)
		}
	}
}

func TestLoadCAPoolRejectsExpiredClientCAAndLoadTLSRejectsInvalidClock(t *testing.T) {
	pki := newTestPKI(t)
	config := pki.config(t)
	if _, err := loadCAPool(pki.rootFile, testNow.Add(400*24*time.Hour)); !errors.Is(err, ErrInvalidTLSMaterial) {
		t.Fatalf("expired CA error = %v, want ErrInvalidTLSMaterial", err)
	}
	if _, err := LoadTLS(config, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil clock error = %v, want ErrInvalidConfig", err)
	}
	if _, err := LoadTLS(config, func() time.Time { return time.Time{} }); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("zero clock error = %v, want ErrInvalidConfig", err)
	}
}

func assertSanitizedTLSError(t *testing.T, err error, directory string) {
	t.Helper()
	message := err.Error()
	if strings.Contains(message, directory) || strings.Contains(message, "SECRET-CONTENTS") || strings.Contains(message, "BEGIN PRIVATE KEY") {
		t.Fatalf("TLS error leaked sensitive path or material: %q", message)
	}
}
