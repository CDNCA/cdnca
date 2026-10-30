package certificateasset

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

var certificateTestNow = time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)

type testEnvelopeCipher struct {
	mu        sync.Mutex
	plaintext []byte
	err       error
}

func (enveloper *testEnvelopeCipher) Seal(_ context.Context, request PrivateKeySealRequest) (PrivateKeyEnvelope, error) {
	enveloper.mu.Lock()
	defer enveloper.mu.Unlock()
	enveloper.plaintext = append(enveloper.plaintext[:0], request.PlaintextPKCS8...)
	if enveloper.err != nil {
		return PrivateKeyEnvelope{}, enveloper.err
	}
	return sealTestEnvelope(request.Context, request.PlaintextPKCS8, "test-kek-v1")
}

func (enveloper *testEnvelopeCipher) SealOpaque(
	_ context.Context,
	request OpaquePrivateKeySealRequest,
) (PrivateKeyEnvelope, error) {
	enveloper.mu.Lock()
	defer enveloper.mu.Unlock()
	if enveloper.err != nil {
		return PrivateKeyEnvelope{}, enveloper.err
	}
	return sealTestEnvelope(request.Context, request.WrappedKeyMaterial, "test-kek-v1")
}

func (enveloper *testEnvelopeCipher) Unseal(
	_ context.Context,
	request PrivateKeyUnsealRequest,
) ([]byte, error) {
	enveloper.mu.Lock()
	defer enveloper.mu.Unlock()
	if enveloper.err != nil {
		return nil, enveloper.err
	}
	aad, err := request.Context.CanonicalAAD()
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte("certificate-asset-test-envelope-key:" + request.Envelope.KeyID))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, request.Envelope.Nonce, request.Envelope.Ciphertext, aad)
}

func (enveloper *testEnvelopeCipher) Rewrap(
	ctx context.Context,
	request PrivateKeyRewrapRequest,
) (PrivateKeyEnvelope, error) {
	plaintext, err := enveloper.Unseal(ctx, PrivateKeyUnsealRequest{
		Context: request.Context, Envelope: request.Envelope,
	})
	if err != nil {
		return PrivateKeyEnvelope{}, err
	}
	defer zeroBytes(plaintext)
	return sealTestEnvelope(request.Context, plaintext, request.TargetKeyID)
}

func sealTestEnvelope(
	envelopeContext PrivateKeyEnvelopeContext,
	plaintext []byte,
	keyID string,
) (PrivateKeyEnvelope, error) {
	aad, err := envelopeContext.CanonicalAAD()
	if err != nil {
		return PrivateKeyEnvelope{}, err
	}
	key := sha256.Sum256([]byte("certificate-asset-test-envelope-key:" + keyID))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return PrivateKeyEnvelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return PrivateKeyEnvelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return PrivateKeyEnvelope{}, err
	}
	return PrivateKeyEnvelope{
		KeyID: keyID, Ciphertext: aead.Seal(nil, nonce, plaintext, aad), Nonce: nonce,
		Metadata: []byte(`{"algorithm":"aes-256-gcm","provider":"test-only"}`),
	}, nil
}

type certificateFixture struct {
	certificatePEM  []byte
	privateKeyPEM   []byte
	leaf            *x509.Certificate
	leafKey         crypto.Signer
	intermediate    *x509.Certificate
	intermediateKey crypto.Signer
	root            *x509.Certificate
	rootKey         crypto.Signer
}

type leafOptions struct {
	domains             []string
	leafKey             crypto.Signer
	rsaBits             int
	notBefore           time.Time
	notAfter            time.Time
	extKeyUsage         []x509.ExtKeyUsage
	isCA                bool
	signatureAlgorithm  x509.SignatureAlgorithm
	intermediateRSABits int
}

func TestPrepareCertificateAcceptsRSAAndECDSA(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		leafKey   func(*testing.T) crypto.Signer
		algorithm string
		bits      int
	}{
		{name: "rsa", leafKey: func(t *testing.T) crypto.Signer { return mustRSAKey(t, 2048) }, algorithm: "rsa", bits: 2048},
		{name: "ecdsa", leafKey: func(t *testing.T) crypto.Signer {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}, algorithm: "ecdsa", bits: 256},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCertificateFixture(t, leafOptions{
				domains: []string{"Example.COM", "*.example.com"}, leafKey: test.leafKey(t),
			})
			prepared, err := prepareCertificate(fixture.certificatePEM,
				fixture.privateKeyPEM, nil, certificateTestNow)
			if err != nil {
				t.Fatal(err)
			}
			defer zeroBytes(prepared.CanonicalPrivateKey)
			if prepared.PublicKeyAlgorithm != test.algorithm || prepared.PublicKeyBits != test.bits {
				t.Fatalf("public key facts = %s/%d", prepared.PublicKeyAlgorithm, prepared.PublicKeyBits)
			}
			if prepared.SANs[0] != "example.com" || prepared.SANs[1] != "*.example.com" {
				t.Fatalf("normalized SANs = %#v", prepared.SANs)
			}
			if len(prepared.CanonicalPrivateKey) == 0 || prepared.PrivateKeyReference == "" {
				t.Fatal("prepared private key lacks canonical material or public reference")
			}
			leafFingerprint := sha256.Sum256(fixture.leaf.Raw)
			if prepared.Fingerprint != leafFingerprint {
				t.Fatal("fingerprint is not canonical leaf DER SHA-256")
			}
		})
	}
}

func TestPrepareCertificateAcceptsOpaqueWrappedKeyReference(t *testing.T) {
	t.Parallel()
	fixture := newCertificateFixture(t, leafOptions{domains: []string{"opaque.example.com"}})
	prepared, err := prepareCertificate(fixture.certificatePEM, nil, &OpaquePrivateKey{
		KeyReference:       "kms-signer:opaque-test-key",
		PublicKeySPKIDER:   append([]byte(nil), fixture.leaf.RawSubjectPublicKeyInfo...),
		WrappedKeyMaterial: bytes.Repeat([]byte{0x41}, 64),
		Metadata:           []byte(`{"provider":"test-kms","format":"wrapped-key-v1"}`),
	}, certificateTestNow)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(prepared.OpaquePrivateKey.WrappedKeyMaterial)
	if len(prepared.CanonicalPrivateKey) != 0 || prepared.OpaquePrivateKey == nil ||
		prepared.PrivateKeyReference != "kms-signer:opaque-test-key" {
		t.Fatalf("opaque prepared certificate = %#v", prepared)
	}
	other := newCertificateFixture(t, leafOptions{domains: []string{"opaque.example.com"}})
	if _, err := prepareCertificate(fixture.certificatePEM, nil, &OpaquePrivateKey{
		KeyReference:       "kms-signer:wrong-key",
		PublicKeySPKIDER:   append([]byte(nil), other.leaf.RawSubjectPublicKeyInfo...),
		WrappedKeyMaterial: bytes.Repeat([]byte{0x42}, 64),
		Metadata:           []byte(`{"provider":"test-kms"}`),
	}, certificateTestNow); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("opaque public-key mismatch error = %v", err)
	}
}

func TestPrepareCertificateRejectsInvalidMaterial(t *testing.T) {
	t.Parallel()
	valid := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	other := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})

	weakRSA := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}, rsaBits: 1024})
	weakSignature := newCertificateFixture(t, leafOptions{
		domains: []string{"www.example.com"}, signatureAlgorithm: x509.SHA1WithRSA,
	})
	weakIntermediate := newCertificateFixture(t, leafOptions{
		domains: []string{"www.example.com"}, intermediateRSABits: 1024,
	})
	expired := newCertificateFixture(t, leafOptions{
		domains: []string{"www.example.com"}, notBefore: certificateTestNow.Add(-48 * time.Hour),
		notAfter: certificateTestNow.Add(-time.Hour),
	})
	notYetValid := newCertificateFixture(t, leafOptions{
		domains: []string{"www.example.com"}, notBefore: certificateTestNow.Add(time.Hour),
		notAfter: certificateTestNow.Add(48 * time.Hour),
	})
	caLeaf := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}, isCA: true})
	clientOnly := newCertificateFixture(t, leafOptions{
		domains: []string{"www.example.com"}, extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	invalidSAN := newCertificateFixture(t, leafOptions{domains: []string{"www.*.example.com"}})
	manySANs := make([]string, MaxCertificateSANs+1)
	for index := range manySANs {
		manySANs[index] = fmt.Sprintf("host-%d.example.com", index)
	}
	tooManySANs := newCertificateFixture(t, leafOptions{domains: manySANs})

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: valid.leaf.Raw})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: valid.root.Raw})
	intermediatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: valid.intermediate.Raw})
	outOfOrder := append(append(append([]byte(nil), leafPEM...), rootPEM...), intermediatePEM...)
	duplicateChain := append(append([]byte(nil), valid.certificatePEM...), intermediatePEM...)

	tests := []struct {
		name        string
		certificate []byte
		privateKey  []byte
		want        error
	}{
		{name: "key mismatch", certificate: valid.certificatePEM, privateKey: other.privateKeyPEM, want: ErrKeyMismatch},
		{name: "weak RSA", certificate: weakRSA.certificatePEM, privateKey: weakRSA.privateKeyPEM, want: ErrWeakPublicKey},
		{name: "weak signature", certificate: weakSignature.certificatePEM, privateKey: weakSignature.privateKeyPEM, want: ErrWeakSignature},
		{name: "weak intermediate", certificate: weakIntermediate.certificatePEM, privateKey: weakIntermediate.privateKeyPEM, want: ErrWeakPublicKey},
		{name: "expired", certificate: expired.certificatePEM, privateKey: expired.privateKeyPEM, want: ErrCertificateExpired},
		{name: "not yet valid", certificate: notYetValid.certificatePEM, privateKey: notYetValid.privateKeyPEM, want: ErrCertificateNotYetValid},
		{name: "CA leaf", certificate: caLeaf.certificatePEM, privateKey: caLeaf.privateKeyPEM, want: ErrCertificateAuthority},
		{name: "no server auth", certificate: clientOnly.certificatePEM, privateKey: clientOnly.privateKeyPEM, want: ErrServerAuthRequired},
		{name: "invalid SAN", certificate: invalidSAN.certificatePEM, privateKey: invalidSAN.privateKeyPEM, want: ErrInvalidSAN},
		{name: "too many SANs", certificate: tooManySANs.certificatePEM, privateKey: tooManySANs.privateKeyPEM, want: ErrInvalidSAN},
		{name: "incomplete chain", certificate: leafPEM, privateKey: valid.privateKeyPEM, want: ErrChainIncomplete},
		{name: "wrong parent", certificate: append(append([]byte(nil), leafPEM...), rootPEM...), privateKey: valid.privateKeyPEM, want: ErrChainIncomplete},
		{name: "out of order", certificate: outOfOrder, privateKey: valid.privateKeyPEM, want: ErrChainOrder},
		{name: "duplicate certificate", certificate: duplicateChain, privateKey: valid.privateKeyPEM, want: ErrInvalidCertificatePEM},
		{name: "certificate control", certificate: append(append([]byte(nil), valid.certificatePEM...), 0), privateKey: valid.privateKeyPEM, want: ErrInvalidCertificatePEM},
		{name: "private key control", certificate: valid.certificatePEM, privateKey: append(append([]byte(nil), valid.privateKeyPEM...), 0), want: ErrInvalidPrivateKeyPEM},
		{name: "certificate oversized", certificate: bytes.Repeat([]byte{'x'}, MaxCertificatePEMBytes+1), privateKey: valid.privateKeyPEM, want: ErrInvalidCertificatePEM},
		{name: "private key oversized", certificate: valid.certificatePEM, privateKey: bytes.Repeat([]byte{'x'}, MaxPrivateKeyPEMBytes+1), want: ErrInvalidPrivateKeyPEM},
		{name: "certificate prefix", certificate: append([]byte("not-pem\n"), valid.certificatePEM...), privateKey: valid.privateKeyPEM, want: ErrInvalidCertificatePEM},
		{name: "private key prefix", certificate: valid.certificatePEM, privateKey: append([]byte("not-pem\n"), valid.privateKeyPEM...), want: ErrInvalidPrivateKeyPEM},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := prepareCertificate(test.certificate, test.privateKey, nil, certificateTestNow)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}

	t.Run("envelope errors are redacted", func(t *testing.T) {
		secret := "PRIVATE-KEY-MATERIAL-MUST-NOT-LEAK"
		prepared, prepareErr := prepareCertificate(valid.certificatePEM, valid.privateKeyPEM, nil, certificateTestNow)
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		defer zeroBytes(prepared.CanonicalPrivateKey)
		_, err := (&Store{enveloper: &testEnvelopeCipher{err: errors.New(secret)}}).sealPrivateKey(
			context.Background(), testEnvelopeContext(prepared), prepared)
		if !errors.Is(err, ErrEnvelopeUnavailable) || bytes.Contains([]byte(err.Error()), []byte(secret)) {
			t.Fatalf("envelope error leaked detail: %v", err)
		}
	})
	t.Run("plaintext envelope is rejected", func(t *testing.T) {
		prepared, prepareErr := prepareCertificate(valid.certificatePEM, valid.privateKeyPEM, nil, certificateTestNow)
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		defer zeroBytes(prepared.CanonicalPrivateKey)
		_, err := (&Store{enveloper: plaintextEnvelopeCipher{}}).sealPrivateKey(
			context.Background(), testEnvelopeContext(prepared), prepared)
		if !errors.Is(err, ErrEnvelopeUnavailable) {
			t.Fatalf("plaintext envelope error = %v", err)
		}
	})
}

type plaintextEnvelopeCipher struct{}

func (plaintextEnvelopeCipher) Seal(_ context.Context, request PrivateKeySealRequest) (PrivateKeyEnvelope, error) {
	return PrivateKeyEnvelope{
		KeyID: "plaintext-test", Ciphertext: append([]byte(nil), request.PlaintextPKCS8...),
		Nonce: bytes.Repeat([]byte{1}, 12), Metadata: []byte(`{"algorithm":"none"}`),
	}, nil
}

func (plaintextEnvelopeCipher) SealOpaque(context.Context, OpaquePrivateKeySealRequest) (PrivateKeyEnvelope, error) {
	return PrivateKeyEnvelope{}, errors.New("not implemented")
}

func (plaintextEnvelopeCipher) Unseal(context.Context, PrivateKeyUnsealRequest) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (plaintextEnvelopeCipher) Rewrap(context.Context, PrivateKeyRewrapRequest) (PrivateKeyEnvelope, error) {
	return PrivateKeyEnvelope{}, errors.New("not implemented")
}

func testEnvelopeContext(prepared preparedCertificate) PrivateKeyEnvelopeContext {
	return PrivateKeyEnvelopeContext{
		TenantScopeID: uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		AssetID:       uuid.MustParse("00000000-0000-0000-0000-000000000002"),
		VersionID:     uuid.MustParse("00000000-0000-0000-0000-000000000003"),
		Version:       1, CertificateFingerprintSHA256: prepared.Fingerprint,
		CertificatePublicKeySHA256: prepared.PublicKeySHA256,
		PrivateKeyReference:        prepared.PrivateKeyReference,
	}
}

func TestCertificateDomainCoverage(t *testing.T) {
	t.Parallel()
	sans := []string{"example.com", "*.example.com", "*.api.example.com"}
	for _, domain := range []string{"example.com", "www.example.com", "a.api.example.com"} {
		if !CoversDomain(sans, domain) {
			t.Fatalf("expected coverage for %q", domain)
		}
	}
	for _, domain := range []string{"a.b.example.com", "other.example.net", "bad_domain.example.com"} {
		if CoversDomain(sans, domain) {
			t.Fatalf("unexpected coverage for %q", domain)
		}
	}
	if err := RequireCoverage(sans, []string{"www.example.com", "a.api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := RequireCoverage(sans, []string{"*.example.com"}); err != nil {
		t.Fatalf("literal wildcard coverage: %v", err)
	}
	if err := RequireCoverage(sans, []string{"a.b.example.com"}); !errors.Is(err, ErrDomainNotCovered) {
		t.Fatalf("coverage error = %v", err)
	}
}

func newCertificateFixture(t *testing.T, options leafOptions) certificateFixture {
	t.Helper()
	if len(options.domains) == 0 {
		options.domains = []string{"www.example.com"}
	}
	if options.notBefore.IsZero() {
		options.notBefore = certificateTestNow.Add(-24 * time.Hour)
	}
	if options.notAfter.IsZero() {
		options.notAfter = certificateTestNow.Add(90 * 24 * time.Hour)
	}
	if options.extKeyUsage == nil {
		options.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	rootKey := mustRSAKey(t, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Certificate Asset Test Root"},
		NotBefore: certificateTestNow.Add(-48 * time.Hour), NotAfter: certificateTestNow.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 2,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	root := createCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)

	intermediateBits := options.intermediateRSABits
	if intermediateBits == 0 {
		intermediateBits = 2048
	}
	intermediateKey := mustRSAKey(t, intermediateBits)
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Certificate Asset Test Intermediate"},
		NotBefore: certificateTestNow.Add(-36 * time.Hour), NotAfter: certificateTestNow.Add(300 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	intermediate := createCertificate(t, intermediateTemplate, root, intermediateKey.Public(), rootKey)

	leafKey := options.leafKey
	if leafKey == nil {
		bits := options.rsaBits
		if bits == 0 {
			bits = 2048
		}
		leafKey = mustRSAKey(t, bits)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: options.domains[0]},
		DNSNames: options.domains, NotBefore: options.notBefore, NotAfter: options.notAfter,
		BasicConstraintsValid: true, IsCA: options.isCA,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: options.extKeyUsage, SignatureAlgorithm: options.signatureAlgorithm,
	}
	if options.isCA {
		leafTemplate.KeyUsage |= x509.KeyUsageCertSign
	}
	leaf := createCertificate(t, leafTemplate, intermediate, leafKey.Public(), intermediateKey)
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Raw})...)
	return certificateFixture{
		certificatePEM: certificatePEM,
		privateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		leaf:           leaf, leafKey: leafKey, intermediate: intermediate, intermediateKey: intermediateKey,
		root: root, rootKey: rootKey,
	}
}

func createCertificate(t *testing.T, template, parent *x509.Certificate, publicKey any, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func mustRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
