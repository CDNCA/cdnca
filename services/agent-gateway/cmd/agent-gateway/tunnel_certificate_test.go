package main

import (
	"crypto/x509"
	"strings"
	"testing"
)

// --server-cert/--server-key: a public certificate (serverAuth+clientAuth is
// common for public CAs) for the CDN-facing tunnel TLS only.
func TestLoadTunnelCertificateIsOptionalAndNeedsServerAuth(t *testing.T) {
	pki := createTestPKI(t)
	if certificate, err := loadTunnelCertificate(config{}); certificate != nil || err != nil {
		t.Fatalf("unset = %v %v", certificate, err)
	}
	dir := t.TempDir()
	cert, key := createTestLeafWithUsages(t, dir, "public", 90, pki.ca, pki.caKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, nil)
	certificate, err := loadTunnelCertificate(config{tunnelCertificateFile: cert, tunnelKeyFile: key})
	if err != nil || certificate == nil || certificate.Leaf == nil {
		t.Fatalf("public certificate rejected: %v", err)
	}
	clientOnlyCert, clientOnlyKey := createTestLeafWithUsages(t, dir, "client-only", 91, pki.ca, pki.caKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	if _, err := loadTunnelCertificate(config{tunnelCertificateFile: clientOnlyCert, tunnelKeyFile: clientOnlyKey}); err == nil {
		t.Fatal("client-only certificate accepted")
	}
	if _, err := loadTunnelCertificate(config{tunnelCertificateFile: cert, tunnelKeyFile: pki.serverKey}); err == nil {
		t.Fatal("mismatched key accepted")
	}
}

func TestReadConfigTunnelCertificatePair(t *testing.T) {
	env := validEnvironment()
	env["CDNCA_GATEWAY_TUNNEL_TLS_CERT_FILE"] = "/etc/cdnca-gateway/public.pem"
	if _, err := readConfig(mapLookup(env)); err == nil || !strings.Contains(err.Error(), "set together") {
		t.Fatalf("certificate without key: %v", err)
	}
	env["CDNCA_GATEWAY_TUNNEL_TLS_KEY_FILE"] = "relative.pem"
	if _, err := readConfig(mapLookup(env)); err == nil {
		t.Fatal("relative key path accepted")
	}
	env["CDNCA_GATEWAY_TUNNEL_TLS_KEY_FILE"] = "/etc/cdnca-gateway/public-key.pem"
	cfg, err := readConfig(mapLookup(env))
	if err != nil || cfg.tunnelCertificateFile != "/etc/cdnca-gateway/public.pem" || cfg.tunnelKeyFile != "/etc/cdnca-gateway/public-key.pem" {
		t.Fatalf("pair = %+v %v", cfg, err)
	}
}
