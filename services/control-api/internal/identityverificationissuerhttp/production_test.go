package identityverificationissuerhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	identityverificationhttp "github.com/cdnca/cdnca/services/control-api/internal/identityverificationhttp"
	"github.com/google/uuid"
)

func TestMTLSAuthenticatorUsesOnlyRegisteredVerifiedClientCertificate(t *testing.T) {
	now := time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
	const workloadURI = "spiffe://control.cdnca.local/workload/identity-verification/issuer-1"
	authenticator, err := NewMTLSAuthenticator([]WorkloadIdentity{{URI: workloadURI, WorkloadID: "kyc-issuer-1"}},
		func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := verifiedWorkloadRequest(t, workloadURI, now)
	principal, err := authenticator.Authenticate(request)
	if err != nil || !principal.Valid() || principal.WorkloadID != "kyc-issuer-1" ||
		principal.Audience != WorkloadAudience || principal.CertificateFingerprint != sha256.Sum256(request.TLS.VerifiedChains[0][0].Raw) {
		t.Fatalf("principal=%#v err=%v", principal, err)
	}
	tests := map[string]func(*http.Request){
		"bearer": func(request *http.Request) { request.Header.Set("Authorization", "Bearer forbidden") },
		"cookie": func(request *http.Request) { request.Header.Set("Cookie", "session=forbidden") },
		"unregistered uri": func(request *http.Request) {
			request.TLS.VerifiedChains[0][0].URIs = []*url.URL{mustURL(t, "spiffe://control.cdnca.local/workload/identity-verification/other")}
		},
		"dns san": func(request *http.Request) { request.TLS.VerifiedChains[0][0].DNSNames = []string{"issuer.local"} },
		"expired": func(request *http.Request) { request.TLS.VerifiedChains[0][0].NotAfter = now },
		"server auth only": func(request *http.Request) {
			request.TLS.VerifiedChains[0][0].ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		},
		"different verified leaf": func(request *http.Request) {
			other := *request.TLS.VerifiedChains[0][0]
			other.Raw = []byte("other-certificate")
			request.TLS.VerifiedChains = append(request.TLS.VerifiedChains, []*x509.Certificate{&other})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := verifiedWorkloadRequest(t, workloadURI, now)
			mutate(candidate)
			if principal, err := authenticator.Authenticate(candidate); !errors.Is(err, ErrUnauthenticated) || principal.Valid() {
				t.Fatalf("principal=%#v err=%v", principal, err)
			}
		})
	}
}

func TestKMSMaterialEnvelopeSealerBindsAllObjectFacts(t *testing.T) {
	client := &kmsEncryptStub{output: &kms.EncryptOutput{KeyId: aws.String("arn:aws:kms:region:account:key/identity"),
		CiphertextBlob: bytes.Repeat([]byte{0x51}, 48)}}
	sealer, err := NewKMSMaterialEnvelopeSealer(client)
	if err != nil {
		t.Fatal(err)
	}
	request := testMaterialEnvelopeRequest()
	result, err := sealer.Seal(t.Context(), request)
	if err != nil || result.Provider != "aws-kms" || result.KeyID != *client.output.KeyId ||
		!bytes.Equal(result.Ciphertext, client.output.CiphertextBlob) || result.AADSHA256 == ([sha256.Size]byte{}) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if client.input == nil || aws.ToString(client.input.KeyId) != request.EncryptionKeyID ||
		client.input.EncryptionContext["tenant_scope_id"] != request.TenantScopeID.String() ||
		client.input.EncryptionContext["upload_id"] != request.UploadID.String() ||
		!bytes.Contains(client.plaintext, []byte(request.ObjectVersion)) ||
		!bytes.Contains(client.plaintext, []byte(request.ObjectKey)) {
		t.Fatalf("kms input=%#v plaintext=%q", client.input, client.plaintext)
	}
	changed := request
	changed.UploadID = uuid.New()
	_, aad, _, err := materialEnvelopePayload(request)
	if err != nil {
		t.Fatal(err)
	}
	_, changedAAD, _, err := materialEnvelopePayload(changed)
	if err != nil || bytes.Equal(aad, changedAAD) {
		t.Fatal("material envelope AAD did not bind the upload")
	}
	client.err = errors.New("kms secret detail")
	if _, err := sealer.Seal(t.Context(), request); !errors.Is(err, ErrEvidenceUnavailable) ||
		bytes.Contains([]byte(err.Error()), []byte("secret")) {
		t.Fatalf("sanitized error=%v", err)
	}
}

func TestResolvedProviderEvidenceBuildsCompleteEnterpriseClaim(t *testing.T) {
	principal := identityverificationhttp.RuntimeEvidencePrincipal{TenantScopeID: uuid.New(), ActorUserID: uuid.New(), SessionID: uuid.New()}
	snapshot := providerEvidenceSnapshot{Principal: principal, SessionID: uuid.New(), Kind: identityverification.KindEnterprise,
		SubjectFingerprint: bytesToArray(0x11), OrganizationName: "Example Corporation",
		LegalPersonFingerprint: bytesToArray(0x12), AgentFingerprint: bytesToArray(0x13),
		AgentRelationship: identityverification.RelationshipEmployee, NormalizedDigest: bytesToArray(0x14),
		RetentionUntil: time.Date(2027, 8, 8, 9, 0, 0, 0, time.UTC)}
	for index, kind := range []string{identityverification.MaterialBusinessLicense, identityverification.MaterialLegalIdentity,
		identityverification.MaterialAgentIdentity, identityverification.MaterialAuthorization} {
		snapshot.Uploads = append(snapshot.Uploads, providerEvidenceUpload{ID: uuid.New(), MaterialKind: kind,
			ObjectKey:     "identity-verification/11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222/33333333-3333-4333-8333-333333333333/" + uuid.New().String(),
			ObjectVersion: "version-1", ObjectSHA256: bytesToArray(byte(0x20 + index)), SizeBytes: 1024,
			MIMEType: "image/png", EncryptionKeyID: "kms/identity/key-1"})
	}
	envelopes := make([]persistedMaterialEnvelope, len(snapshot.Uploads))
	for index, upload := range snapshot.Uploads {
		envelopes[index] = persistedMaterialEnvelope{UploadID: upload.ID, Provider: "aws-kms",
			KeyID: "arn:aws:kms:region:account:key/identity", Ciphertext: bytes.Repeat([]byte{byte(0x30 + index)}, 48),
			AADSHA256: bytesToArray(byte(0x40 + index))}
	}
	expiresAt := time.Date(2026, 8, 8, 9, 5, 0, 0, time.UTC)
	request := EvidenceResolveRequest{WorkloadID: "kyc-issuer-1", Audience: WorkloadAudience,
		Kind: snapshot.Kind, EvidenceReference: "opaque-ref", ExpiresAt: expiresAt,
		IdempotencyKey: "idem-1", RequestID: "request-1", RequestDigest: sha256.Sum256([]byte("request"))}
	resolved, err := resolvedProviderEvidence(snapshot, envelopes, request)
	if err != nil || resolved.Principal != principal || resolved.Kind != snapshot.Kind ||
		resolved.Evidence.OrganizationName != snapshot.OrganizationName ||
		len(resolved.Evidence.Materials) != len(snapshot.Uploads) || resolved.EvidenceClaimDigest == ([sha256.Size]byte{}) ||
		resolved.PrivateEnvelopeDigest == ([sha256.Size]byte{}) || !resolved.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	originalDigest := resolved.EvidenceClaimDigest
	snapshot.OrganizationName = "Other Corporation"
	changed, err := resolvedProviderEvidence(snapshot, envelopes, request)
	if err != nil || changed.EvidenceClaimDigest == originalDigest {
		t.Fatal("enterprise claim digest did not bind organization facts")
	}
}

type kmsEncryptStub struct {
	input     *kms.EncryptInput
	plaintext []byte
	output    *kms.EncryptOutput
	err       error
}

func (client *kmsEncryptStub) Encrypt(_ context.Context, input *kms.EncryptInput,
	_ ...func(*kms.Options),
) (*kms.EncryptOutput, error) {
	client.input = input
	client.plaintext = append([]byte(nil), input.Plaintext...)
	return client.output, client.err
}

func verifiedWorkloadRequest(t *testing.T, rawURI string, now time.Time) *http.Request {
	t.Helper()
	leaf := &x509.Certificate{Raw: []byte("client-certificate"), URIs: []*url.URL{mustURL(t, rawURI)},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	request, err := http.NewRequest(http.MethodPost, "https://control.internal"+IssuePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	return request
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func testMaterialEnvelopeRequest() MaterialEnvelopeSealRequest {
	return MaterialEnvelopeSealRequest{TenantScopeID: uuid.New(), ActorUserID: uuid.New(), SessionID: uuid.New(),
		UploadID: uuid.New(), MaterialKind: identityverification.MaterialIdentityDocument,
		ObjectKey:     "identity-verification/11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222/33333333-3333-4333-8333-333333333333/44444444-4444-4444-8444-444444444444",
		ObjectVersion: "version-1", ObjectSHA256: bytesToArray(0x61), MIMEType: "image/png", SizeBytes: 1024,
		EncryptionKeyID: "kms/identity/key-1"}
}

func bytesToArray(marker byte) [sha256.Size]byte {
	var result [sha256.Size]byte
	for index := range result {
		result[index] = marker
	}
	return result
}
