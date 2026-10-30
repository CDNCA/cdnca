package acmeworker

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type replayRejectingTransport struct {
	calls int
}

func (transport *replayRejectingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls++
	return nil, errors.New("unexpected ACME HTTP request")
}

type completedReplayFixture struct {
	worker       *Worker
	protocol     *protocolServer
	records      *challengeRecords
	certificates *memoryCertificates
	transport    *replayRejectingTransport
	request      IssueRequest
	certificate  IssuedCertificate
	operation    *memoryOperation
}

func TestIssueCompletedReplayRejectsCertificateIdentityDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *completedReplayFixture)
	}{
		{
			name: "checkpoint fingerprint drift",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.operation.lease.State.LeafFingerprint = "sha256:" + strings.Repeat("0", 64)
			},
		},
		{
			name: "checkpoint certificate URL drift",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.operation.lease.State.CertificateURL = "https://ca.example.test/certificate/other"
			},
		},
		{
			name: "loaded metadata fingerprint drift",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.LeafFingerprint = "sha256:" + strings.Repeat("1", 64)
			},
		},
		{
			name: "actual leaf DER fingerprint drift",
			mutate: func(t *testing.T, fixture *completedReplayFixture) {
				signer := fixture.worker.deps.Signers.(*memorySigners).keys[fixture.request.CertificateKeyRef]
				other := newReplayCertificate(t, signer, 2)
				fixture.certificate.LeafDER = other.LeafDER
				fixture.certificate.ChainDER = other.ChainDER
				fixture.certificate.CertificatePEM = other.CertificatePEM
			},
		},
		{
			name: "actual leaf SPKI drift",
			mutate: func(t *testing.T, fixture *completedReplayFixture) {
				other := newReplayCertificate(t, mustKey(t), 3)
				fixture.certificate.LeafDER = other.LeafDER
				fixture.certificate.ChainDER = other.ChainDER
				fixture.certificate.CertificatePEM = other.CertificatePEM
				fixture.certificate.LeafFingerprint = other.LeafFingerprint
				fixture.operation.lease.State.LeafFingerprint = other.LeafFingerprint
			},
		},
		{
			name: "malformed actual leaf DER",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.LeafDER = []byte{0x30, 0x01, 0x00}
			},
		},
		{
			name: "empty checkpoint certificate URL",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.operation.lease.State.CertificateURL = ""
			},
		},
		{
			name: "empty checkpoint leaf fingerprint",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.operation.lease.State.LeafFingerprint = ""
			},
		},
		{
			name: "empty checkpoint certificate SPKI digest",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.operation.lease.State.CertificateSPKIDigest = ""
			},
		},
		{
			name: "empty loaded certificate URL",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.CertificateURL = ""
			},
		},
		{
			name: "empty loaded leaf fingerprint",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.LeafFingerprint = ""
			},
		},
		{
			name: "empty loaded public key SPKI digest",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.PublicKeySPKISHA256 = ""
			},
		},
		{
			name: "empty certificate chain",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.ChainDER = nil
				fixture.certificate.CertificatePEM = nil
			},
		},
		{
			name: "certificate chain leaf differs from LeafDER",
			mutate: func(t *testing.T, fixture *completedReplayFixture) {
				signer := fixture.worker.deps.Signers.(*memorySigners).keys[fixture.request.CertificateKeyRef]
				other := newReplayCertificate(t, signer, 4)
				fixture.certificate.ChainDER[0] = other.LeafDER
				fixture.certificate.CertificatePEM = replayCertificatePEM(fixture.certificate.ChainDER)
			},
		},
		{
			name: "malformed later chain certificate",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.ChainDER[1] = []byte{0x30, 0x01, 0x00}
				fixture.certificate.CertificatePEM = replayCertificatePEM(fixture.certificate.ChainDER)
			},
		},
		{
			name: "non-certificate DER in later chain entry",
			mutate: func(t *testing.T, fixture *completedReplayFixture) {
				privateDER, err := x509.MarshalPKCS8PrivateKey(mustKey(t))
				if err != nil {
					t.Fatal(err)
				}
				fixture.certificate.ChainDER[1] = privateDER
				fixture.certificate.CertificatePEM = replayCertificatePEM(fixture.certificate.ChainDER)
			},
		},
		{
			name: "empty certificate PEM",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.CertificatePEM = nil
			},
		},
		{
			name: "malformed certificate PEM",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.CertificatePEM = []byte("-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n")
			},
		},
		{
			name: "trailing certificate PEM data",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.CertificatePEM = append(fixture.certificate.CertificatePEM, []byte("trailing")...)
			},
		},
		{
			name: "certificate PEM leaf differs from LeafDER and chain",
			mutate: func(t *testing.T, fixture *completedReplayFixture) {
				signer := fixture.worker.deps.Signers.(*memorySigners).keys[fixture.request.CertificateKeyRef]
				other := newReplayCertificate(t, signer, 5)
				fixture.certificate.CertificatePEM = replayCertificatePEM([][]byte{
					other.LeafDER, fixture.certificate.ChainDER[1],
				})
			},
		},
		{
			name: "certificate PEM missing issuer block",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.CertificatePEM = replayCertificatePEM(fixture.certificate.ChainDER[:1])
			},
		},
		{
			name: "certificate PEM has extra certificate block",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.CertificatePEM = append(fixture.certificate.CertificatePEM,
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.certificate.ChainDER[1]})...)
			},
		},
		{
			name: "certificate PEM blocks reordered",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.CertificatePEM = replayCertificatePEM([][]byte{
					fixture.certificate.ChainDER[1], fixture.certificate.ChainDER[0],
				})
			},
		},
		{
			name: "certificate PEM has non-certificate block",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.CertificatePEM = append(fixture.certificate.CertificatePEM,
					pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-key")})...)
			},
		},
		{
			name: "certificate chain exceeds issuance limit",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				for len(fixture.certificate.ChainDER) < 6 {
					fixture.certificate.ChainDER = append(fixture.certificate.ChainDER,
						fixture.certificate.ChainDER[len(fixture.certificate.ChainDER)-1])
				}
				fixture.certificate.CertificatePEM = replayCertificatePEM(fixture.certificate.ChainDER)
			},
		},
		{
			name: "certificate chain issuer signature mismatch",
			mutate: func(t *testing.T, fixture *completedReplayFixture) {
				signer := fixture.worker.deps.Signers.(*memorySigners).keys[fixture.request.CertificateKeyRef]
				other := newReplayCertificate(t, signer, 20)
				fixture.certificate.ChainDER[1] = other.ChainDER[1]
				fixture.certificate.CertificatePEM = replayCertificatePEM(fixture.certificate.ChainDER)
			},
		},
		{
			name: "serial number metadata drift",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.SerialNumber = "999999"
			},
		},
		{
			name: "DNS names metadata drift",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.DNSNames = []string{"other.example.test"}
			},
		},
		{
			name: "not before metadata drift",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.NotBefore = fixture.certificate.NotBefore.Add(time.Second)
			},
		},
		{
			name: "not after metadata drift",
			mutate: func(_ *testing.T, fixture *completedReplayFixture) {
				fixture.certificate.NotAfter = fixture.certificate.NotAfter.Add(time.Second)
			},
		},
		{
			name: "request domains differ from certificate",
			mutate: func(t *testing.T, fixture *completedReplayFixture) {
				fixture.setRequestDomains(t, []string{"other.example.test"})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCompletedReplayFixture(t)
			test.mutate(t, fixture)
			fixture.storeCertificate()
			operationBefore := fixture.operation.lease

			result, err := fixture.worker.Issue(context.Background(), fixture.request)
			if ErrorCodeOf(err) != CodeCertificateStoreFailed || err.Error() != string(CodeCertificateStoreFailed) {
				t.Fatalf("Issue() error = %v, want stable %s", err, CodeCertificateStoreFailed)
			}
			if result.Reused {
				t.Fatalf("Issue() Reused = true for invalid durable certificate identity")
			}
			fixture.assertNoMutationSideEffects(t, operationBefore)
		})
	}
}

func TestIssueCompletedReplayAcceptsExactDurableCertificateIdentity(t *testing.T) {
	fixture := newCompletedReplayFixture(t)
	fixture.storeCertificate()
	operationBefore := fixture.operation.lease

	result, err := fixture.worker.Issue(context.Background(), fixture.request)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if !result.Reused || result.Certificate.CertificateURL != fixture.certificate.CertificateURL ||
		result.Certificate.LeafFingerprint != fixture.certificate.LeafFingerprint ||
		result.Certificate.PublicKeySPKISHA256 != fixture.certificate.PublicKeySPKISHA256 ||
		len(result.Certificate.ChainDER) != len(fixture.certificate.ChainDER) ||
		string(result.Certificate.LeafDER) != string(fixture.certificate.LeafDER) ||
		string(result.Certificate.CertificatePEM) != string(fixture.certificate.CertificatePEM) {
		t.Fatalf("Issue() result = %+v, want exact reused certificate", result)
	}
	fixture.assertNoMutationSideEffects(t, operationBefore)
}

func newCompletedReplayFixture(t *testing.T) *completedReplayFixture {
	t.Helper()
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{}
	certificates := &memoryCertificates{items: make(map[string]IssuedCertificate)}
	worker := newTestWorker(t, protocol, records, records, certificates, nil)
	transport := &replayRejectingTransport{}
	worker.config.HTTPClient = &http.Client{Transport: transport}
	request := validIssueRequest(ChallengeHTTP01, "completed-replay.example.test")
	canonicalRequest := request
	domains, err := normalizeIssueRequest(&canonicalRequest)
	if err != nil {
		t.Fatal(err)
	}
	canonicalRequest.Domains = domains
	canonicalRequest.DirectoryURL = worker.config.DirectoryURL
	digest := issueRequestDigest(canonicalRequest)
	signer := worker.deps.Signers.(*memorySigners).keys[request.CertificateKeyRef]
	certificate := newReplayCertificate(t, signer, 1)
	certificate.RequestDigest = digest
	certificate.CertificateKeyRef = request.CertificateKeyRef
	certificate.CertificateURL = "https://ca.example.test/certificate/1"
	operations := newMemoryOperations()
	operation := &memoryOperation{
		request: canonicalRequest,
		digest:  digest,
		lease: OperationLease{
			TenantID: request.TenantID, ScopeID: request.ScopeID, OperationID: request.OperationID,
			Request: canonicalRequest, Digest: digest,
			State: OperationState{
				Phase: PhaseCompleted, Status: OperationCompleted,
				AccountURI:            "https://ca.example.test/account/1",
				OrderURL:              "https://ca.example.test/order/1",
				CertificateURL:        certificate.CertificateURL,
				CertificateSPKIDigest: certificate.PublicKeySPKISHA256,
				LeafFingerprint:       certificate.LeafFingerprint,
			},
		},
	}
	operations.items[operationKey(request.ScopeID, request.OperationID)] = operation
	worker.deps.Operations = operations
	return &completedReplayFixture{
		worker: worker, protocol: protocol, records: records, certificates: certificates,
		transport: transport, request: request, certificate: certificate, operation: operation,
	}
}

func newReplayCertificate(t *testing.T, signer crypto.Signer, serial int64) IssuedCertificate {
	t.Helper()
	issuerKey := mustKey(t)
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1000 + serial),
		Subject:               pkix.Name{CommonName: "completed replay test issuer"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(180 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	issuerDER, err := x509.CreateCertificate(
		rand.Reader, issuerTemplate, issuerTemplate, issuerKey.Public(), issuerKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "completed-replay.example.test"},
		DNSNames:     []string{"completed-replay.example.test"},
		NotBefore:    testNow.Add(-time.Minute),
		NotAfter:     testNow.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, signer.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(leafDER)
	publicDigest := sha256.Sum256(publicDER)
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	chainDER := [][]byte{leafDER, issuerDER}
	return IssuedCertificate{
		LeafDER:             leafDER,
		ChainDER:            chainDER,
		CertificatePEM:      replayCertificatePEM(chainDER),
		SerialNumber:        leaf.SerialNumber.String(),
		DNSNames:            append([]string(nil), leaf.DNSNames...),
		NotBefore:           leaf.NotBefore,
		NotAfter:            leaf.NotAfter,
		LeafFingerprint:     fmt.Sprintf("sha256:%x", fingerprint),
		PublicKeySPKISHA256: fmt.Sprintf("sha256:%x", publicDigest),
	}
}

func replayCertificatePEM(chainDER [][]byte) []byte {
	var result []byte
	for _, certificateDER := range chainDER {
		result = append(result, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})...)
	}
	return result
}

func (fixture *completedReplayFixture) storeCertificate() {
	key := operationKey(fixture.request.ScopeID, fixture.request.OperationID)
	fixture.certificates.items[key] = cloneCertificate(fixture.certificate)
}

func (fixture *completedReplayFixture) setRequestDomains(t *testing.T, domains []string) {
	t.Helper()
	fixture.request.Domains = domains
	canonical := fixture.request
	normalized, err := normalizeIssueRequest(&canonical)
	if err != nil {
		t.Fatal(err)
	}
	canonical.Domains = normalized
	canonical.DirectoryURL = fixture.worker.config.DirectoryURL
	digest := issueRequestDigest(canonical)
	fixture.operation.request = canonical
	fixture.operation.digest = digest
	fixture.operation.lease.Request = canonical
	fixture.operation.lease.Digest = digest
	fixture.certificate.RequestDigest = digest
}

func (fixture *completedReplayFixture) assertNoMutationSideEffects(t *testing.T, operationBefore OperationLease) {
	t.Helper()
	if fixture.certificates.saveCalls != 0 {
		t.Fatalf("certificate Save calls = %d, want 0", fixture.certificates.saveCalls)
	}
	if fixture.transport.calls != 0 || fixture.protocol.newAccountAttempts != 0 ||
		fixture.protocol.newOrderAttempts != 0 || fixture.protocol.postFinalizePolls != 0 {
		t.Fatalf("ACME side effects: HTTP=%d accounts=%d orders=%d polls=%d",
			fixture.transport.calls, fixture.protocol.newAccountAttempts,
			fixture.protocol.newOrderAttempts, fixture.protocol.postFinalizePolls)
	}
	if len(fixture.records.published) != 0 || len(fixture.records.waited) != 0 || len(fixture.records.deleted) != 0 {
		t.Fatalf("challenge side effects: published=%v waited=%v deleted=%v",
			fixture.records.published, fixture.records.waited, fixture.records.deleted)
	}
	if !reflect.DeepEqual(fixture.operation.lease, operationBefore) {
		t.Fatalf("operation mutation = %#v, want unchanged %#v", fixture.operation.lease, operationBefore)
	}
}
