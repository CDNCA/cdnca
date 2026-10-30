package edgeconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func validSpec() Spec {
	return Spec{
		ConfigVersionID: "cfg-v1",
		StateRoot:       "/var/lib/cdnca-edge",
		HealthPort:      18080,
		Sites: []Site{{
			Domain: "www.example.com", ListenPort: 18081, Protocol: ProtocolHTTP, Balance: BalanceRoundRobin,
			FailoverTries: 1, ConnectTimeout: 250 * time.Millisecond, ReadTimeout: 2 * time.Second,
			Origins: []Origin{{Host: "127.0.0.1", Port: 19001, Weight: 1}}, ACL: ACLPolicy{DefaultAction: ACLAllow},
		}},
	}
}

func testCertificate(t *testing.T, domain string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(4102444800, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func methodDomain(method BalanceMethod) string {
	return strings.ReplaceAll(string(method), "_", "-") + ".example.com"
}
