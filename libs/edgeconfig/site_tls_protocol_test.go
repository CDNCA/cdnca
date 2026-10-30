package edgeconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func siteTLSProtocolSpec(t *testing.T, protocols []string, http2 bool) Spec {
	t.Helper()
	certificate, privateKey := siteTLSTestCertificate(t, "secure.example.com")
	spec := Spec{
		ConfigVersionID: "site-tls-v1",
		StateRoot:       "/var/lib/cdnca-edge",
		HealthPort:      18080,
		Sites: []Site{{
			Domain: "secure.example.com", ListenPort: 443, Protocol: ProtocolHTTPS,
			Balance: BalanceRoundRobin, FailoverTries: 1,
			ConnectTimeout: 250 * time.Millisecond, ReadTimeout: 2 * time.Second,
			Origins: []Origin{{Host: "127.0.0.1", Port: 19001, Weight: 1}},
			ACL:     ACLPolicy{DefaultAction: ACLAllow},
		}},
	}
	spec.Sites[0].Domain = "secure.example.com"
	spec.Sites[0].ListenPort = 443
	spec.Sites[0].Protocol = ProtocolHTTPS
	spec.Sites[0].HTTP2 = http2
	spec.Sites[0].TLS = &TLSConfig{
		CertificatePEM: certificate,
		PrivateKeyPEM:  privateKey,
		Protocols:      protocols,
	}
	return spec
}

func siteTLSTestCertificate(t *testing.T, domain string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4102444800, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
