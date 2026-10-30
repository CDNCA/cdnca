package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc"
)

type renewalCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newRenewalCA(t *testing.T) renewalCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour * 24 * 365)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return renewalCA{cert: cert, key: key}
}

func (ca renewalCA) sign(t *testing.T, public any, uri string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	parsed, _ := url.Parse(uri)
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "gw"},
		NotBefore: notBefore, NotAfter: notAfter, URIs: []*url.URL{parsed}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, public, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type renewClient struct {
	controlv1.ControlInternalServiceClient
	respond func(*controlv1.RenewGatewayCertificateRequest) []byte
	calls   int
}

func (c *renewClient) RenewGatewayCertificate(_ context.Context, request *controlv1.RenewGatewayCertificateRequest, _ ...grpc.CallOption) (*controlv1.RenewGatewayCertificateResponse, error) {
	c.calls++
	return &controlv1.RenewGatewayCertificateResponse{CertificatePem: c.respond(request)}, nil
}

func TestBoundGatewayCertificateRenewal(t *testing.T) {
	ca := newRenewalCA(t)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	const uri = "spiffe://cdn-platform/gateway/11111111-1111-4111-8111-111111111111"
	now := time.Now()
	der := ca.sign(t, public, uri, now.Add(-20*24*time.Hour), now.Add(10*24*time.Hour))
	leaf, _ := x509.ParseCertificate(der)
	file := filepath.Join(t.TempDir(), "client.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o444); err != nil {
		t.Fatal(err)
	}
	certificate := newReloadableCertificate(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: leaf}, file, "client")
	if !certificate.due(now) || certificate.due(now.Add(-6*24*time.Hour)) {
		t.Fatal("half-life threshold is wrong")
	}

	client := &renewClient{respond: func(request *controlv1.RenewGatewayCertificateRequest) []byte {
		csr, err := x509.ParseCertificateRequest(request.GetCertificateSigningRequestDer())
		if err != nil || csr.CheckSignature() != nil || request.GetKind() != "client" {
			t.Fatalf("CSR = %v %v", err, request.GetKind())
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.sign(t, csr.PublicKey, uri, now, now.Add(30*24*time.Hour))})
	}}
	if err := certificate.renew(t.Context(), client, "11111111-1111-4111-8111-111111111111"); err != nil {
		t.Fatal(err)
	}
	if certificate.due(now) {
		t.Fatal("renewed certificate still due")
	}
	written, _ := os.ReadFile(file)
	block, _ := pem.Decode(written)
	if block == nil || string(block.Bytes) != string(certificate.current.Load().Certificate[0]) {
		t.Fatal("certificate file was not replaced with the renewed certificate")
	}

	// A certificate for another key or another identity is refused and the
	// current one stays.
	before := certificate.current.Load()
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, respond := range map[string]func(*controlv1.RenewGatewayCertificateRequest) []byte{
		"other key": func(*controlv1.RenewGatewayCertificateRequest) []byte {
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.sign(t, otherPublic, uri, now, now.Add(time.Hour))})
		},
		"other identity": func(request *controlv1.RenewGatewayCertificateRequest) []byte {
			csr, _ := x509.ParseCertificateRequest(request.GetCertificateSigningRequestDer())
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.sign(t, csr.PublicKey, "spiffe://cdn-platform/gateway/control", now, now.Add(time.Hour))})
		},
		"not PEM": func(*controlv1.RenewGatewayCertificateRequest) []byte { return []byte("x") },
	} {
		client.respond = respond
		if err := certificate.renew(t.Context(), client, "11111111-1111-4111-8111-111111111111"); err == nil {
			t.Errorf("%s accepted", name)
		}
		if certificate.current.Load() != before {
			t.Errorf("%s replaced the certificate", name)
		}
	}
}

func TestOnlyBoundGatewaysRenew(t *testing.T) {
	for uri, want := range map[string]bool{
		"spiffe://cdn-platform/gateway/control":                              false,
		"spiffe://cdn-platform/gateway/11111111-1111-4111-8111-111111111111": true,
		"spiffe://cdnca/runtime-smoke":                                       false,
	} {
		if got := boundGateway(config{controlClientWorkloadURISAN: uri}); got != want {
			t.Errorf("%s = %v", uri, got)
		}
	}
}
