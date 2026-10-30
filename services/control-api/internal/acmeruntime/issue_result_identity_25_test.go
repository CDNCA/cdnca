package acmeruntime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
)

func TestValidIssueResultBindsLeafIdentityAndRequestedSANs25(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*acmeworker.IssueRequest, *acmeworker.IssuedCertificate)
	}{
		{name: "malformed leaf DER", mutate: func(_ *acmeworker.IssueRequest, certificate *acmeworker.IssuedCertificate) {
			certificate.LeafDER = []byte{1}
		}},
		{name: "malformed certificate PEM", mutate: func(_ *acmeworker.IssueRequest, certificate *acmeworker.IssuedCertificate) {
			certificate.CertificatePEM = []byte("not a certificate")
		}},
		{name: "request SAN mismatch", mutate: func(request *acmeworker.IssueRequest, _ *acmeworker.IssuedCertificate) {
			request.Domains = []string{"other.example.test"}
		}},
		{name: "reported SAN mismatch", mutate: func(_ *acmeworker.IssueRequest, certificate *acmeworker.IssuedCertificate) {
			certificate.DNSNames = []string{"other.example.test"}
		}},
		{name: "fingerprint mismatch", mutate: func(_ *acmeworker.IssueRequest, certificate *acmeworker.IssuedCertificate) {
			certificate.LeafFingerprint = "sha256:" + hex.EncodeToString(make([]byte, sha256.Size))
		}},
		{name: "SPKI mismatch", mutate: func(_ *acmeworker.IssueRequest, certificate *acmeworker.IssuedCertificate) {
			certificate.PublicKeySPKISHA256 = "sha256:" + hex.EncodeToString(make([]byte, sha256.Size))
		}},
		{name: "validity mismatch", mutate: func(_ *acmeworker.IssueRequest, certificate *acmeworker.IssuedCertificate) {
			certificate.NotAfter = certificate.NotAfter.Add(time.Second)
		}},
	}

	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			request, result := validIssueResultFixture25(t)
			mutation.mutate(&request, &result.Certificate)
			if validIssueResult(result, request) {
				t.Fatal("issuer result with mismatched durable identity was accepted")
			}
		})
	}
}

func validIssueResultFixture25(t *testing.T) (acmeworker.IssueRequest, acmeworker.IssueResult) {
	t.Helper()
	requestDomains := []string{"example.test", "www.example.test"}
	leafDomains := []string{"www.example.test", "example.test"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Date(2026, time.August, 7, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(25), Subject: pkix.Name{CommonName: requestDomains[0]},
		DNSNames: leafDomains, NotBefore: notBefore, NotAfter: notBefore.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	request := acmeworker.IssueRequest{
		CertificateKeyRef: "certificate-key", Domains: slices.Clone(requestDomains),
	}
	return request, acmeworker.IssueResult{Certificate: acmeworker.IssuedCertificate{
		RequestDigest: "sha256:request", CertificateKeyRef: request.CertificateKeyRef,
		PublicKeySPKISHA256: "sha256:" + hex.EncodeToString(spki[:]),
		LeafDER:             slices.Clone(leaf.Raw),
		ChainDER:            [][]byte{slices.Clone(leaf.Raw)},
		CertificatePEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		SerialNumber:        leaf.SerialNumber.String(),
		DNSNames:            slices.Clone(requestDomains),
		NotBefore:           leaf.NotBefore,
		NotAfter:            leaf.NotAfter,
		CertificateURL:      "https://ca.example.test/certificate/25",
		LeafFingerprint:     "sha256:" + hex.EncodeToString(fingerprint[:]),
	}}
}
