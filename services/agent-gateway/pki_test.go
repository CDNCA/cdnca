package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

type testPKI struct {
	caCertificate *x509.Certificate
	caKey         *ecdsa.PrivateKey
	server        tls.Certificate
	rootPool      *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	now := time.Now()
	caKey := newECDSAKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCertificate)
	pki := &testPKI{caCertificate: caCertificate, caKey: caKey, rootPool: rootPool}
	pki.server = pki.issue(t, 2, "localhost", nil, now.Add(-time.Hour), now.Add(12*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	return pki
}

func (p *testPKI) client(t *testing.T, serial int64, uri string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	return p.issue(t, serial, "node", []*url.URL{parsed}, notBefore, notAfter, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

func (p *testPKI) issue(t *testing.T, serial int64, commonName string, uris []*url.URL, notBefore, notAfter time.Time, usages []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key := newECDSAKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
		URIs:         uris,
		DNSNames:     []string{commonName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.caCertificate, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	certificate, err := tls.X509KeyPair(certificatePEM, privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
