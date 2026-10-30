package identityverification

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestMapStoreErrorHidesDatabaseDetailsAndPreservesBusinessErrors(t *testing.T) {
	for _, code := range []string{"40001", "40P01", "55P03", "XX999"} {
		t.Run(code, func(t *testing.T) {
			err := mapStoreError(&pgconn.PgError{Code: code, Message: "secret database detail",
				ConstraintName: "identity_verified_persons_pkey"})
			if !errors.Is(err, ErrUnavailable) || err.Error() != ErrUnavailable.Error() {
				t.Fatalf("mapStoreError(%s) = %v, want stable unavailable", code, err)
			}
			joined := mapStoreError(errors.Join(ErrPermissionDenied,
				&pgconn.PgError{Code: code, Message: "secret joined database detail"}))
			if !errors.Is(joined, ErrUnavailable) || joined.Error() != ErrUnavailable.Error() {
				t.Fatalf("mapStoreError(joined %s) = %v, want stable unavailable", code, joined)
			}
		})
	}
	for _, businessErr := range []error{
		ErrPermissionDenied, ErrNotFound, ErrRevisionConflict, ErrInvalidTransition,
		ErrIdempotencyConflict, ErrActiveReview, ErrIdentityMismatch, ErrAlreadyVerified,
	} {
		if mapped := mapStoreError(businessErr); !errors.Is(mapped, businessErr) {
			t.Fatalf("mapStoreError(%v) = %v", businessErr, mapped)
		}
	}
}

func TestIAMSessionTxAuthorizerRejectsMissingIAM(t *testing.T) {
	if _, err := newIAMSessionTxAuthorizer(nil); !errors.Is(err, ErrInvalidService) {
		t.Fatalf("newIAMSessionTxAuthorizer(nil) error = %v", err)
	}
}

func TestSessionActorSealsRawSessionAndPublicIdentity(t *testing.T) {
	rawSession := "signed-control-session-secret-token"
	actor, err := NewSessionActor(uuid.New(), uuid.New(), "tenant", uuid.New(), rawSession)
	if err != nil || !actor.Valid() {
		t.Fatalf("NewSessionActor() = %#v, %v", actor, err)
	}
	if strings.Contains(actor.String(), rawSession) || strings.Contains(actor.GoString(), rawSession) {
		t.Fatal("Actor string representation leaked raw session")
	}
	if encoded, err := json.Marshal(actor); err == nil || len(encoded) != 0 {
		t.Fatalf("Actor JSON = %q, %v; want serialization rejection", encoded, err)
	}
	mutated := actor
	mutated.UserID = uuid.New()
	if mutated.Valid() {
		t.Fatal("public Actor mutation remained valid against sealed session binding")
	}
}

func TestNormalizeDraftAndMaterialValidation(t *testing.T) {
	request := validPersonalDraft(KindPersonalInitial, bytesOf(32, 1), "draft-1")
	normalized, err := normalizeDraft(request)
	if err != nil {
		t.Fatal(err)
	}
	request.SubjectFingerprint[0] = 9
	request.Materials[0].EncryptedEnvelope[0] = 9
	if normalized.SubjectFingerprint[0] != 1 || normalized.Materials[0].EncryptedEnvelope[0] != 1 {
		t.Fatal("normalized request aliases caller-owned sensitive buffers")
	}

	tests := []struct {
		name   string
		mutate func(*CreateDraftRequest)
	}{
		{"missing fingerprint", func(value *CreateDraftRequest) { value.SubjectFingerprint = nil }},
		{"personal enterprise fields", func(value *CreateDraftRequest) { value.OrganizationName = "Example" }},
		{"missing liveness", func(value *CreateDraftRequest) { value.Materials = value.Materials[:1] }},
		{"plaintext-like object reference", func(value *CreateDraftRequest) { value.Materials[0].ObjectReference = "object with spaces" }},
		{"unsupported MIME", func(value *CreateDraftRequest) { value.Materials[0].MIMEType = "text/plain" }},
		{"small envelope", func(value *CreateDraftRequest) { value.Materials[0].EncryptedEnvelope = []byte("cipher") }},
		{"invalid idempotency key", func(value *CreateDraftRequest) { value.IdempotencyKey = "contains space" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := validPersonalDraft(KindPersonalInitial, bytesOf(32, 1), "draft-invalid")
			test.mutate(&candidate)
			if _, err := normalizeDraft(candidate); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalizeDraft() error = %v", err)
			}
		})
	}
}

func TestNormalizeDraftRequiresEvidenceSettlementBinding(t *testing.T) {
	request := validPersonalDraft(KindPersonalInitial, bytesOf(32, 1), "draft-settlement")
	request.ResolverName = ""
	if _, err := normalizeDraft(request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing resolver name error = %v", err)
	}
	request = validPersonalDraft(KindPersonalInitial, bytesOf(32, 1), "draft-settlement")
	request.ResolverReference = ""
	if _, err := normalizeDraft(request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing resolver reference error = %v", err)
	}
	request = validPersonalDraft(KindPersonalInitial, bytesOf(32, 1), "draft-settlement")
	request.EvidenceClaimDigest = [32]byte{}
	if _, err := normalizeDraft(request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing evidence claim digest error = %v", err)
	}
}

func TestReviewRejectsFreeTextReasonBeforePersistence(t *testing.T) {
	service := &Service{}
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	_, err := service.Review(context.Background(), actor, ReviewRequest{CaseID: uuid.New(), ExpectedRevision: 3,
		Decision: DecisionReject, ReasonCode: "document_123456789_rejected", IdempotencyKey: "review-pii",
		RequestID: "review-pii-request"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Review(PII reason) error = %v", err)
	}
}

func TestEnterpriseDraftRequiresRelationshipEvidence(t *testing.T) {
	request := validEnterpriseDraft(bytesOf(32, 2), bytesOf(32, 3), bytesOf(32, 4), "enterprise-1")
	if _, err := normalizeDraft(request); err != nil {
		t.Fatal(err)
	}
	request.Materials = request.Materials[:3]
	if _, err := normalizeDraft(request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing authorization error = %v", err)
	}
	legal := validEnterpriseDraft(bytesOf(32, 2), bytesOf(32, 3), bytesOf(32, 3), "enterprise-legal")
	legal.AgentRelationship = RelationshipLegalPerson
	legal.Materials = legal.Materials[:3]
	if _, err := normalizeDraft(legal); err != nil {
		t.Fatalf("legal person draft error = %v", err)
	}
	legal.AgentFingerprint = bytesOf(32, 5)
	if _, err := normalizeDraft(legal); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("legal person mismatch error = %v", err)
	}
}

func TestDefaultRedactionAndRetention(t *testing.T) {
	now := time.Date(2033, 7, 22, 0, 0, 0, 0, time.UTC)
	rawFingerprint := bytesOf(32, 0xab)
	rawReference := "tenant/private/identity/original-object-name"
	stored := storedCase{
		Case: Case{Status: StatusApproved, Materials: []Material{{
			EnvelopeKeyID: maskReference("kms/identity/tenant-key"), ObjectReference: maskReference(rawReference),
			EnvelopeSHA256Hint: fingerprintHint(bytesOf(32, 0xcd)),
			ObjectSHA256Hint:   fingerprintHint(bytesOf(32, 0xef)), EncryptedEnvelopePresent: true,
		}}},
		subjectFingerprint: rawFingerprint,
		retentionUntil:     now.Add(-time.Second),
	}
	redacted := redactCase(stored, now)
	encoded, err := json.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, rawReference) || strings.Contains(text, strings.Repeat("ab", 32)) ||
		strings.Contains(text, strings.Repeat("cd", 32)) || !redacted.Materials[0].EncryptedEnvelopePresent {
		t.Fatalf("redacted response leaked sensitive metadata: %s", text)
	}
	if !redacted.Retention.Eligible || redacted.Retention.ReasonCode != "eligible_for_evidence_erasure" {
		t.Fatalf("retention = %#v", redacted.Retention)
	}
	active := retentionStatus(StatusReviewing, now.Add(-time.Hour), now)
	if active.Eligible || active.ReasonCode != "case_not_terminal" {
		t.Fatalf("active retention = %#v", active)
	}
}

func validPersonalDraft(kind string, fingerprint []byte, key string) CreateDraftRequest {
	return CreateDraftRequest{Kind: kind, SubjectFingerprint: fingerprint, Materials: []MaterialInput{
		material(MaterialIdentityDocument, 1), material(MaterialLivenessEvidence, 2),
	}, ResolverName: "test-resolver", ResolverReference: "reservation-" + key,
		EvidenceClaimDigest: sha256.Sum256([]byte("claim-" + key)),
		IdempotencyKey:      key, RequestID: key + "-request"}
}

func validEnterpriseDraft(subject, legal, agent []byte, key string) CreateDraftRequest {
	return CreateDraftRequest{Kind: KindEnterprise, SubjectFingerprint: subject,
		OrganizationName: "Example Network Co., Ltd.", LegalPersonFingerprint: legal,
		AgentFingerprint: agent, AgentRelationship: RelationshipAuthorizedRepresentative,
		Materials: []MaterialInput{material(MaterialBusinessLicense, 1), material(MaterialLegalIdentity, 2),
			material(MaterialAgentIdentity, 3), material(MaterialAuthorization, 4)},
		ResolverName: "test-resolver", ResolverReference: "reservation-" + key,
		EvidenceClaimDigest: sha256.Sum256([]byte("claim-" + key)),
		IdempotencyKey:      key, RequestID: key + "-request"}
}

func material(kind string, marker byte) MaterialInput {
	return MaterialInput{Kind: kind, EnvelopeProvider: "kms", EnvelopeKeyID: "kms/identity/key-01",
		EncryptedEnvelope: bytesOf(32, marker), ObjectReference: "identity/object-" + string(rune('a'+marker)),
		ObjectSHA256: bytesOf(32, marker+10), MIMEType: "image/jpeg", SizeBytes: 1024}
}

func bytesOf(length int, value byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}
