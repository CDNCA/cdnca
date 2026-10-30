package nodeca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
)

func TestSignerSignsAllowedCSRAlgorithms(t *testing.T) {
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	fixture := newCAFixture(t, now)
	signer, err := newSigner(fixture.issuerKey, fixture.issuer, fixture.chain(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	for _, algorithm := range []string{"rsa", "ecdsa", "ed25519"} {
		t.Run(algorithm, func(t *testing.T) {
			csrDER, csr := newCSR(t, algorithm, nil)
			nodeID := uuid.New()
			request := validRequest(now, nodeID, csrDER)
			if algorithm == "ed25519" {
				request.IssuanceKind = "renewal"
			}
			result, err := signer.SignNodeCertificate(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			leaf := parsePEMCertificate(t, result.LeafCertificatePEM)
			assertLeaf(t, leaf, csr, request, fixture)
			assertChain(t, result.IssuingChainPEM, fixture.chain())

			firstSerial := leaf.SerialNumber.String()
			result.IssuingChainPEM[0][0] ^= 0xff
			repeated, err := signer.SignNodeCertificate(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if serial := parsePEMCertificate(t, repeated.LeafCertificatePEM).SerialNumber.String(); serial == firstSerial {
				t.Fatalf("serial was reused: %s", serial)
			}
			assertChain(t, repeated.IssuingChainPEM, fixture.chain())
		})
	}
}

func TestSignerSupportsStandardCASignerAlgorithms(t *testing.T) {
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	csrDER, _ := newCSR(t, "ecdsa", nil)
	for _, algorithm := range []string{"rsa", "ecdsa", "ed25519"} {
		t.Run(algorithm, func(t *testing.T) {
			key := newPrivateKey(t, algorithm)
			root := newSelfSignedCA(t, key, now.Add(-time.Hour), now.Add(48*time.Hour), nil)
			signer, err := newSigner(key, root, []*x509.Certificate{root}, rand.Reader, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			request := validRequest(now, uuid.New(), csrDER)
			result, err := signer.SignNodeCertificate(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			leaf := parsePEMCertificate(t, result.LeafCertificatePEM)
			if err := leaf.CheckSignatureFrom(root); err != nil {
				t.Fatalf("leaf signature: %v", err)
			}
		})
	}
}

func TestNewSignerRejectsInvalidConfigurationAndChain(t *testing.T) {
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	fixture := newCAFixture(t, now)
	otherKey := newPrivateKey(t, "ecdsa")
	otherRoot := newSelfSignedCA(t, otherKey, now.Add(-time.Hour), now.Add(48*time.Hour), nil)

	tests := []struct {
		name    string
		key     crypto.Signer
		issuer  *x509.Certificate
		chain   []*x509.Certificate
		wantErr error
	}{
		{name: "nil signer", issuer: fixture.issuer, chain: fixture.chain(), wantErr: ErrInvalidConfiguration},
		{name: "typed nil signer", key: (*ecdsa.PrivateKey)(nil), issuer: fixture.issuer, chain: fixture.chain(), wantErr: ErrInvalidConfiguration},
		{name: "nil issuer", key: fixture.issuerKey, chain: fixture.chain(), wantErr: ErrInvalidConfiguration},
		{name: "empty chain", key: fixture.issuerKey, issuer: fixture.issuer, wantErr: ErrInvalidConfiguration},
		{name: "key mismatch", key: otherKey, issuer: fixture.issuer, chain: fixture.chain(), wantErr: ErrKeyMismatch},
		{name: "issuer not first", key: fixture.issuerKey, issuer: fixture.issuer, chain: []*x509.Certificate{fixture.root}, wantErr: ErrInvalidChain},
		{name: "reverse order", key: fixture.issuerKey, issuer: fixture.issuer, chain: []*x509.Certificate{fixture.root, fixture.issuer}, wantErr: ErrInvalidChain},
		{name: "duplicate", key: fixture.issuerKey, issuer: fixture.issuer, chain: []*x509.Certificate{fixture.issuer, fixture.issuer}, wantErr: ErrInvalidChain},
		{name: "broken chain", key: fixture.issuerKey, issuer: fixture.issuer, chain: []*x509.Certificate{fixture.issuer, otherRoot}, wantErr: ErrInvalidChain},
		{name: "non self-signed root", key: fixture.issuerKey, issuer: fixture.issuer, chain: []*x509.Certificate{fixture.issuer}, wantErr: ErrInvalidChain},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newSigner(test.key, test.issuer, test.chain, rand.Reader, func() time.Time { return now })
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}

	for _, test := range []struct {
		name      string
		key       crypto.Signer
		notBefore time.Time
		notAfter  time.Time
		mutate    func(*x509.Certificate)
	}{
		{name: "expired", notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Second)},
		{name: "not yet valid", notBefore: now.Add(time.Second), notAfter: now.Add(48 * time.Hour)},
		{name: "not a CA", notBefore: now.Add(-time.Hour), notAfter: now.Add(48 * time.Hour), mutate: func(cert *x509.Certificate) { cert.IsCA = false }},
		{name: "basic constraints missing", notBefore: now.Add(-time.Hour), notAfter: now.Add(48 * time.Hour), mutate: func(cert *x509.Certificate) { cert.BasicConstraintsValid = false }},
		{name: "cert sign usage missing", notBefore: now.Add(-time.Hour), notAfter: now.Add(48 * time.Hour), mutate: func(cert *x509.Certificate) { cert.KeyUsage = x509.KeyUsageCRLSign }},
		{name: "weak RSA CA key", key: newRSAKey(t, 1024), notBefore: now.Add(-time.Hour), notAfter: now.Add(48 * time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := test.key
			if key == nil {
				key = newPrivateKey(t, "ecdsa")
			}
			certificate := newSelfSignedCA(t, key, test.notBefore, test.notAfter, test.mutate)
			_, err := newSigner(key, certificate, []*x509.Certificate{certificate}, rand.Reader, func() time.Time { return now })
			if !errors.Is(err, ErrInvalidChain) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestSignerRejectsInvalidRequests(t *testing.T) {
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	fixture := newCAFixture(t, now)
	signer, err := newSigner(fixture.issuerKey, fixture.issuer, fixture.chain(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	csrDER, _ := newCSR(t, "ecdsa", nil)
	base := validRequest(now, uuid.New(), csrDER)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signer.SignNodeCertificate(canceled, base); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v", err)
	}
	if _, err := signer.SignNodeCertificate(nil, base); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil context error = %v", err)
	}

	withSAN, _ := newCSR(t, "ecdsa", func(template *x509.CertificateRequest) {
		uri, parseErr := url.Parse("spiffe://attacker/node")
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		template.URIs = []*url.URL{uri}
	})
	weakRSA, _ := newCSRWithKey(t, newRSAKey(t, 1024), nil)
	p384, _ := newCSRWithKey(t, newECDSAKey(t, elliptic.P384()), nil)
	corrupt := bytes.Clone(csrDER)
	corrupt[len(corrupt)-1] ^= 0xff
	tooLarge := make([]byte, maxCSRBytes+1)

	tests := []struct {
		name   string
		mutate func(*nodeidentity.SignRequest)
	}{
		{name: "nil node", mutate: func(request *nodeidentity.SignRequest) { request.NodeID = uuid.Nil }},
		{name: "wrong URI", mutate: func(request *nodeidentity.SignRequest) { request.URISAN += "/extra" }},
		{name: "noncanonical URI UUID", mutate: func(request *nodeidentity.SignRequest) {
			request.URISAN = nodeidentity.NodeSPIFFEPrefix + strings.ToUpper(request.NodeID.String())
		}},
		{name: "empty CSR", mutate: func(request *nodeidentity.SignRequest) { request.CertificateSigningRequestDER = nil }},
		{name: "oversized CSR", mutate: func(request *nodeidentity.SignRequest) { request.CertificateSigningRequestDER = tooLarge }},
		{name: "malformed CSR", mutate: func(request *nodeidentity.SignRequest) { request.CertificateSigningRequestDER = []byte("not DER") }},
		{name: "invalid CSR signature", mutate: func(request *nodeidentity.SignRequest) { request.CertificateSigningRequestDER = corrupt }},
		{name: "CSR SAN", mutate: func(request *nodeidentity.SignRequest) { request.CertificateSigningRequestDER = withSAN }},
		{name: "weak RSA", mutate: func(request *nodeidentity.SignRequest) { request.CertificateSigningRequestDER = weakRSA }},
		{name: "unsupported ECDSA curve", mutate: func(request *nodeidentity.SignRequest) { request.CertificateSigningRequestDER = p384 }},
		{name: "unknown issuance", mutate: func(request *nodeidentity.SignRequest) { request.IssuanceKind = "replacement" }},
		{name: "zero not before", mutate: func(request *nodeidentity.SignRequest) { request.NotBefore = time.Time{} }},
		{name: "reversed lifetime", mutate: func(request *nodeidentity.SignRequest) { request.NotAfter = request.NotBefore }},
		{name: "fractional lifetime", mutate: func(request *nodeidentity.SignRequest) { request.NotAfter = request.NotAfter.Add(time.Nanosecond) }},
		{name: "future lifetime", mutate: func(request *nodeidentity.SignRequest) { request.NotBefore = now.Add(time.Second) }},
		{name: "expired lifetime", mutate: func(request *nodeidentity.SignRequest) { request.NotAfter = now }},
		{name: "starts before issuer", mutate: func(request *nodeidentity.SignRequest) {
			request.NotBefore = fixture.issuer.NotBefore.Add(-time.Second)
		}},
		{name: "ends after issuer", mutate: func(request *nodeidentity.SignRequest) { request.NotAfter = fixture.issuer.NotAfter.Add(time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			test.mutate(&request)
			_, err := signer.SignNodeCertificate(context.Background(), request)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestSignerContainsRandomAndSigningFailures(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newCAFixture(t, now)
	csrDER, _ := newCSR(t, "ecdsa", nil)
	request := validRequest(now, uuid.New(), csrDER)

	randomSecret := "random-secret-must-not-leak"
	randomSigner, err := NewSignerWithRandom(fixture.issuerKey, fixture.issuer, fixture.chain(), failingReader{err: errors.New(randomSecret)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = randomSigner.SignNodeCertificate(context.Background(), request)
	if !errors.Is(err, ErrRandomSource) || strings.Contains(err.Error(), randomSecret) || strings.Contains(err.Error(), string(csrDER)) {
		t.Fatalf("random error leaked sensitive input: %v", err)
	}
	zeroSigner, err := NewSignerWithRandom(fixture.issuerKey, fixture.issuer, fixture.chain(), bytes.NewReader(make([]byte, serialBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zeroSigner.SignNodeCertificate(context.Background(), request); !errors.Is(err, ErrRandomSource) {
		t.Fatalf("all-zero random source error = %v", err)
	}

	signingSecret := "private-signing-material-must-not-leak"
	wrapped := &failingCryptoSigner{signer: fixture.issuerKey, err: errors.New(signingSecret)}
	failingSigner, err := newSigner(wrapped, fixture.issuer, fixture.chain(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	_, err = failingSigner.SignNodeCertificate(context.Background(), request)
	if !errors.Is(err, ErrSigning) || strings.Contains(err.Error(), signingSecret) || strings.Contains(err.Error(), string(csrDER)) {
		t.Fatalf("signing error leaked sensitive input: %v", err)
	}
}

func TestSignerCancellationWhileWaitingDoesNotUseSignerOrRandom(t *testing.T) {
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	fixture := newCAFixture(t, now)
	controlled := newBlockingCryptoSigner(fixture.issuerKey)
	countedRandom := &countingReader{reader: rand.Reader}
	signer, err := newSigner(controlled, fixture.issuer, fixture.chain(), countedRandom, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	csrDER, _ := newCSR(t, "ecdsa", nil)
	request := validRequest(now, uuid.New(), csrDER)

	firstDone := make(chan error, 1)
	go func() {
		_, signErr := signer.SignNodeCertificate(context.Background(), request)
		firstDone <- signErr
	}()
	select {
	case <-controlled.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first signing call did not reach crypto signer")
	}
	readsBefore := countedRandom.reads.Load()

	ctx, cancel := context.WithCancel(context.Background())
	secondDone := make(chan error, 1)
	go func() {
		_, signErr := signer.SignNodeCertificate(ctx, request)
		secondDone <- signErr
	}()
	select {
	case err := <-secondDone:
		t.Fatalf("second call returned before cancellation: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("second error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting signing call ignored cancellation")
	}
	if got := controlled.calls.Load(); got != 1 {
		t.Fatalf("crypto signer calls = %d, want 1", got)
	}
	if got := countedRandom.reads.Load(); got != readsBefore {
		t.Fatalf("random reads while waiting = %d, want %d", got, readsBefore)
	}

	close(controlled.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first signing call: %v", err)
	}
}

func TestSignerCancellationDuringSigningReturnsNoCertificate(t *testing.T) {
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	fixture := newCAFixture(t, now)
	controlled := newBlockingCryptoSigner(fixture.issuerKey)
	signer, err := newSigner(controlled, fixture.issuer, fixture.chain(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	csrDER, _ := newCSR(t, "ecdsa", nil)
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		certificate nodeidentity.SignedCertificate
		err         error
	}
	done := make(chan result, 1)
	go func() {
		certificate, signErr := signer.SignNodeCertificate(ctx, validRequest(now, uuid.New(), csrDER))
		done <- result{certificate, signErr}
	}()
	<-controlled.started
	cancel()
	close(controlled.release)
	got := <-done
	if !errors.Is(got.err, context.Canceled) || len(got.certificate.LeafCertificatePEM) != 0 || len(got.certificate.IssuingChainPEM) != 0 {
		t.Fatalf("result after cancellation = (%d leaf bytes, %d chain entries, %v)", len(got.certificate.LeafCertificatePEM), len(got.certificate.IssuingChainPEM), got.err)
	}
}

func TestSignerConcurrentCallsHaveUniqueValidSerials(t *testing.T) {
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	fixture := newCAFixture(t, now)
	signer, err := newSigner(fixture.issuerKey, fixture.issuer, fixture.chain(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	csrDER, _ := newCSR(t, "ed25519", nil)
	request := validRequest(now, uuid.New(), csrDER)

	const count = 32
	serials := make(chan string, count)
	errorsFound := make(chan error, count)
	var group sync.WaitGroup
	for range count {
		group.Add(1)
		go func() {
			defer group.Done()
			result, signErr := signer.SignNodeCertificate(context.Background(), request)
			if signErr != nil {
				errorsFound <- signErr
				return
			}
			block, remainder := pem.Decode(result.LeafCertificatePEM)
			if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(remainder)) != 0 {
				errorsFound <- errors.New("invalid leaf PEM")
				return
			}
			certificate, parseErr := x509.ParseCertificate(block.Bytes)
			if parseErr != nil || certificate.CheckSignatureFrom(fixture.issuer) != nil {
				errorsFound <- errors.New("invalid leaf certificate")
				return
			}
			serials <- certificate.SerialNumber.String()
		}()
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
	close(serials)
	seen := make(map[string]struct{}, count)
	for serial := range serials {
		if _, duplicate := seen[serial]; duplicate {
			t.Fatalf("duplicate serial %s", serial)
		}
		seen[serial] = struct{}{}
	}
	if len(seen) != count {
		t.Fatalf("serial count = %d, want %d", len(seen), count)
	}
}

type caFixture struct {
	root      *x509.Certificate
	issuer    *x509.Certificate
	issuerKey crypto.Signer
}

func newCAFixture(t *testing.T, now time.Time) caFixture {
	t.Helper()
	rootKey := newPrivateKey(t, "ecdsa")
	root := newSelfSignedCA(t, rootKey, now.Add(-48*time.Hour), now.Add(30*24*time.Hour), func(certificate *x509.Certificate) {
		certificate.Subject = pkix.Name{CommonName: "node identity root"}
		certificate.MaxPathLen = 1
	})
	issuerKey := newPrivateKey(t, "ecdsa")
	issuerTemplate := caTemplate(now.Add(-24*time.Hour), now.Add(7*24*time.Hour))
	issuerTemplate.Subject = pkix.Name{CommonName: "node identity issuing CA"}
	issuerTemplate.MaxPathLen = 0
	issuerTemplate.MaxPathLenZero = true
	issuer := issueCertificate(t, issuerTemplate, root, issuerKey.Public(), rootKey)
	return caFixture{root: root, issuer: issuer, issuerKey: issuerKey}
}

func (fixture caFixture) chain() []*x509.Certificate {
	return []*x509.Certificate{fixture.issuer, fixture.root}
}

func newSelfSignedCA(t *testing.T, key crypto.Signer, notBefore, notAfter time.Time, mutate func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	template := caTemplate(notBefore, notAfter)
	template.Subject = pkix.Name{CommonName: "self-signed node CA"}
	if mutate != nil {
		mutate(template)
	}
	return issueCertificate(t, template, template, key.Public(), key)
}

func caTemplate(notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
}

func issueCertificate(t *testing.T, template, parent *x509.Certificate, publicKey crypto.PublicKey, privateKey crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func newPrivateKey(t *testing.T, algorithm string) crypto.Signer {
	t.Helper()
	switch algorithm {
	case "rsa":
		return newRSAKey(t, 2048)
	case "ecdsa":
		return newECDSAKey(t, elliptic.P256())
	case "ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	default:
		t.Fatalf("unknown key algorithm %q", algorithm)
		return nil
	}
}

func newRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newCSR(t *testing.T, algorithm string, mutate func(*x509.CertificateRequest)) ([]byte, *x509.CertificateRequest) {
	t.Helper()
	return newCSRWithKey(t, newPrivateKey(t, algorithm), mutate)
}

func newCSRWithKey(t *testing.T, key crypto.Signer, mutate func(*x509.CertificateRequest)) ([]byte, *x509.CertificateRequest) {
	t.Helper()
	template := &x509.CertificateRequest{}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, csr
}

func validRequest(now time.Time, nodeID uuid.UUID, csrDER []byte) nodeidentity.SignRequest {
	return nodeidentity.SignRequest{
		NodeID: nodeID, CertificateSigningRequestDER: bytes.Clone(csrDER),
		URISAN:    nodeidentity.NodeSPIFFEPrefix + nodeID.String(),
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IssuanceKind: "initial",
	}
}

func parsePEMCertificate(t *testing.T, encoded []byte) *x509.Certificate {
	t.Helper()
	block, remainder := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(remainder)) != 0 {
		t.Fatal("certificate is not one PEM CERTIFICATE block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func assertLeaf(t *testing.T, leaf *x509.Certificate, csr *x509.CertificateRequest, request nodeidentity.SignRequest, fixture caFixture) {
	t.Helper()
	if leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.BitLen() > 159 {
		t.Fatalf("invalid serial %v", leaf.SerialNumber)
	}
	if !leaf.NotBefore.Equal(request.NotBefore) || !leaf.NotAfter.Equal(request.NotAfter) {
		t.Fatalf("lifetime = %s..%s", leaf.NotBefore, leaf.NotAfter)
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 {
		t.Fatalf("unexpected leaf constraints: is_ca=%t basic=%t key=%v eku=%v unknown_eku=%v", leaf.IsCA, leaf.BasicConstraintsValid, leaf.KeyUsage, leaf.ExtKeyUsage, leaf.UnknownExtKeyUsage)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != request.URISAN || len(leaf.DNSNames) != 0 ||
		len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 {
		t.Fatalf("unexpected leaf SAN: uris=%v dns=%v email=%v ip=%v", leaf.URIs, leaf.DNSNames, leaf.EmailAddresses, leaf.IPAddresses)
	}
	wantPublic, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	gotPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(gotPublic, wantPublic) {
		t.Fatal("leaf public key does not match CSR")
	}
	if err := leaf.CheckSignatureFrom(fixture.issuer); err != nil {
		t.Fatalf("leaf signature: %v", err)
	}
	if err := verifyLeafChain(leaf, fixture.chain(), request.NotBefore, request.NotAfter); err != nil {
		t.Fatalf("leaf chain: %v", err)
	}
}

func assertChain(t *testing.T, encoded [][]byte, want []*x509.Certificate) {
	t.Helper()
	if len(encoded) != len(want) {
		t.Fatalf("chain length = %d, want %d", len(encoded), len(want))
	}
	for index := range want {
		certificate := parsePEMCertificate(t, encoded[index])
		if !bytes.Equal(certificate.Raw, want[index].Raw) {
			t.Fatalf("chain certificate %d does not match", index)
		}
	}
}

type failingReader struct{ err error }

func (reader failingReader) Read([]byte) (int, error) { return 0, reader.err }

type failingCryptoSigner struct {
	signer crypto.Signer
	err    error
}

func (signer *failingCryptoSigner) Public() crypto.PublicKey { return signer.signer.Public() }
func (signer *failingCryptoSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, signer.err
}

type blockingCryptoSigner struct {
	signer  crypto.Signer
	started chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int64
}

func newBlockingCryptoSigner(signer crypto.Signer) *blockingCryptoSigner {
	return &blockingCryptoSigner{signer: signer, started: make(chan struct{}), release: make(chan struct{})}
}

func (signer *blockingCryptoSigner) Public() crypto.PublicKey { return signer.signer.Public() }
func (signer *blockingCryptoSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	signer.calls.Add(1)
	signer.once.Do(func() { close(signer.started) })
	<-signer.release
	return signer.signer.Sign(random, digest, options)
}

type countingReader struct {
	reader io.Reader
	reads  atomic.Int64
}

func (reader *countingReader) Read(value []byte) (int, error) {
	reader.reads.Add(1)
	return reader.reader.Read(value)
}
