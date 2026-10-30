package identityverificationhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

func TestNewServiceRequiresTrustedEvidenceResolver(t *testing.T) {
	_, err := newService(&coreStub{}, &readerStub{}, nil,
		ServiceConfig{CursorKey: []byte("0123456789abcdef0123456789abcdef")})
	if !errors.Is(err, ErrTrustedEvidenceResolverRequired) {
		t.Fatalf("newService() error = %v", err)
	}
}

func TestGenericServiceConstructorFailsClosed(t *testing.T) {
	service, err := NewService(&coreStub{}, &readerStub{}, resolverStub{configured: true},
		ServiceConfig{CursorKey: []byte("0123456789abcdef0123456789abcdef")})
	if service != nil || !errors.Is(err, ErrInvalidService) {
		t.Fatalf("NewService() = (%T,%v), want nil ErrInvalidService", service, err)
	}
}

func TestCreateDraftUsesTrustedEvidenceAndRedactsCoreResponse(t *testing.T) {
	actor := testActor()
	secretFingerprint := bytesOf(32, 0x91)
	secretEnvelope := bytesOf(32, 0x92)
	secretHash := bytesOf(32, 0x93)
	secretReference := "tenant/private/identity/original-object"
	organizationName := "Sensitive Organization Name"
	resolved := ResolvedEvidence{Kind: identityverification.KindEnterprise,
		SubjectFingerprint: secretFingerprint, OrganizationName: organizationName,
		LegalPersonFingerprint: bytesOf(32, 0x94), AgentFingerprint: bytesOf(32, 0x95),
		AgentRelationship: identityverification.RelationshipAuthorizedRepresentative,
		Materials: []identityverification.MaterialInput{{Kind: identityverification.MaterialBusinessLicense,
			EnvelopeProvider: "kms", EnvelopeKeyID: "key/private", EncryptedEnvelope: secretEnvelope,
			ObjectReference: secretReference, ObjectSHA256: secretHash, MIMEType: "image/png", SizeBytes: 2048}},
	}
	core := &coreStub{create: func(_ context.Context, actualActor identityverification.Actor,
		request identityverification.CreateDraftRequest,
	) (identityverification.Case, error) {
		if actualActor != actor || request.Kind != resolved.Kind || request.OrganizationName != organizationName ||
			!equalBytes(request.SubjectFingerprint, secretFingerprint) || request.Materials[0].ObjectReference != secretReference ||
			request.IdempotencyKey != "create-1" || request.RequestID != "request-1" {
			t.Fatalf("unexpected trusted request: %#v", request)
		}
		item := testCase(actor, request.Kind, identityverification.StatusDraft, 1)
		item.OrganizationName = organizationName
		item.SubjectFingerprintHint = fmt.Sprintf("%x", secretFingerprint)
		item.LegalFingerprintHint = fmt.Sprintf("%x", resolved.LegalPersonFingerprint)
		item.AgentFingerprintHint = fmt.Sprintf("%x", resolved.AgentFingerprint)
		item.AgentRelationship = resolved.AgentRelationship
		item.Materials[0].EnvelopeKeyID = "********private"
		item.Materials[0].EnvelopeSHA256Hint = fmt.Sprintf("%x", secretEnvelope)
		item.Materials[0].ObjectReference = secretReference
		item.Materials[0].ObjectSHA256Hint = fmt.Sprintf("%x", secretHash)
		return item, nil
	}}
	resolver := resolverStub{resolve: func(_ context.Context, actualActor identityverification.Actor,
		reference EvidenceReference,
	) (ResolvedEvidence, error) {
		if actualActor != actor || reference.Kind != resolved.Kind || reference.Token != strings.Repeat("a", 32) {
			t.Fatalf("resolver input = %#v / %#v", actualActor, reference)
		}
		return resolved, nil
	}}
	service := testService(t, core, &readerStub{}, resolver)
	result, err := service.CreateDraft(context.Background(), actor,
		CreateDraftInput{Kind: resolved.Kind, EvidenceToken: strings.Repeat("a", 32)},
		WriteMetadata{IdempotencyKey: "create-1", RequestID: "request-1"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, prohibited := range []string{organizationName, secretReference, "EnvelopeKeyID", "FingerprintHint",
		fmt.Sprintf("%x", secretFingerprint), fmt.Sprintf("%x", secretEnvelope), fmt.Sprintf("%x", secretHash),
		base64.StdEncoding.EncodeToString(secretFingerprint), base64.StdEncoding.EncodeToString(secretEnvelope)} {
		if strings.Contains(text, prohibited) {
			t.Fatalf("safe response leaked %q: %s", prohibited, text)
		}
	}
	if result.AgentRelationship != identityverification.RelationshipAuthorizedRepresentative ||
		len(result.Materials) != 1 || !result.Materials[0].EncryptedEnvelopePresent {
		t.Fatalf("safe response = %#v", result)
	}
}

func TestCreateDraftAuthorizesBeforeEvidenceReservation(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "permission denied", err: identityverification.ErrPermissionDenied,
			want: identityverification.ErrPermissionDenied},
		{name: "IAM unavailable", err: identityverification.ErrUnavailable, want: ErrStoreUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			actor := testActor()
			reserveCalls, createCalls := 0, 0
			core := &coreStub{
				authorizeCreate: func(context.Context, identityverification.Actor) error { return test.err },
				create: func(context.Context, identityverification.Actor,
					identityverification.CreateDraftRequest,
				) (identityverification.Case, error) {
					createCalls++
					return identityverification.Case{}, errUnexpectedCall
				},
			}
			resolver := resolverStub{reserve: func(context.Context, identityverification.Actor,
				EvidenceReference, string, [32]byte,
			) (EvidenceReservation, error) {
				reserveCalls++
				return EvidenceReservation{}, errUnexpectedCall
			}}
			service := testService(t, core, &readerStub{}, resolver)
			_, err := service.CreateDraft(t.Context(), actor,
				CreateDraftInput{Kind: identityverification.KindPersonalInitial,
					EvidenceToken: strings.Repeat("a", 32)},
				WriteMetadata{IdempotencyKey: "create-preflight", RequestID: "request-preflight"})
			if !errors.Is(err, test.want) || reserveCalls != 0 || createCalls != 0 {
				t.Fatalf("CreateDraft() = %v, reserve=%d create=%d", err, reserveCalls, createCalls)
			}
		})
	}
}

func TestCreateDraftRejectsResolverKindAndCoreMaterialValidation(t *testing.T) {
	actor := testActor()
	coreCalled := false
	core := &coreStub{create: func(context.Context, identityverification.Actor,
		identityverification.CreateDraftRequest,
	) (identityverification.Case, error) {
		coreCalled = true
		return identityverification.Case{}, identityverification.ErrInvalidInput
	}}
	service := testService(t, core, &readerStub{}, resolverStub{resolve: func(context.Context,
		identityverification.Actor, EvidenceReference,
	) (ResolvedEvidence, error) {
		return ResolvedEvidence{Kind: identityverification.KindEnterprise}, nil
	}})
	_, err := service.CreateDraft(context.Background(), actor,
		CreateDraftInput{Kind: identityverification.KindPersonalInitial, EvidenceToken: strings.Repeat("b", 32)},
		WriteMetadata{IdempotencyKey: "create-kind", RequestID: "request-kind"})
	if !errors.Is(err, ErrInvalidEvidence) || coreCalled {
		t.Fatalf("kind mismatch = %v, core called=%t", err, coreCalled)
	}

	service.resolver = resolverStub{resolve: func(context.Context, identityverification.Actor,
		EvidenceReference,
	) (ResolvedEvidence, error) {
		return ResolvedEvidence{Kind: identityverification.KindPersonalInitial}, nil
	}}
	_, err = service.CreateDraft(context.Background(), actor,
		CreateDraftInput{Kind: identityverification.KindPersonalInitial, EvidenceToken: strings.Repeat("c", 32)},
		WriteMetadata{IdempotencyKey: "create-material", RequestID: "request-material"})
	if !errors.Is(err, identityverification.ErrInvalidInput) || !coreCalled {
		t.Fatalf("invalid material = %v, core called=%t", err, coreCalled)
	}
}

func TestCreateDraftSameKeyReplayDoesNotConsumeEvidenceHandle(t *testing.T) {
	actor := testActor()
	item := testCase(actor, identityverification.KindPersonalInitial, identityverification.StatusDraft, 1)
	token := strings.Repeat("r", 32)
	resolver := newReservationRegistry()
	resolver.add(actor, token, personalResolvedEvidence(0xa1))
	calls := 0
	core := &coreStub{create: func(context.Context, identityverification.Actor,
		identityverification.CreateDraftRequest,
	) (identityverification.Case, error) {
		calls++
		result := item
		result.Replayed = calls > 1
		return result, nil
	}}
	service := testService(t, core, &readerStub{}, resolver)
	input := CreateDraftInput{Kind: identityverification.KindPersonalInitial, EvidenceToken: token}
	metadata := WriteMetadata{IdempotencyKey: "create-replay-reservation", RequestID: "request-replay-reservation"}
	if _, err := service.CreateDraft(context.Background(), actor, input, metadata); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateDraft(context.Background(), actor, input, metadata); err != nil {
		t.Fatalf("same-key replay lost reserved evidence: %v", err)
	}
}

func TestCreateDraftCoreFailureCanRetryReservedEvidence(t *testing.T) {
	actor := testActor()
	token := strings.Repeat("f", 32)
	resolver := newReservationRegistry()
	resolver.add(actor, token, personalResolvedEvidence(0xb1))
	coreCalls := 0
	core := &coreStub{create: func(context.Context, identityverification.Actor,
		identityverification.CreateDraftRequest,
	) (identityverification.Case, error) {
		coreCalls++
		if coreCalls == 1 {
			return identityverification.Case{}, errors.New("injected core failure")
		}
		return testCase(actor, identityverification.KindPersonalInitial, identityverification.StatusDraft, 1), nil
	}}
	service := testService(t, core, &readerStub{}, resolver)
	input := CreateDraftInput{Kind: identityverification.KindPersonalInitial, EvidenceToken: token}
	metadata := WriteMetadata{IdempotencyKey: "create-abort-retry", RequestID: "request-abort-retry"}
	if _, err := service.CreateDraft(context.Background(), actor, input, metadata); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("first core failure = %v", err)
	}
	if _, err := service.CreateDraft(context.Background(), actor, input, metadata); err != nil {
		t.Fatalf("retry after core failure lost reserved evidence: %v", err)
	}
}

func TestGetReviewerDoesNotTrustAuthorizationFromEarlierTransaction(t *testing.T) {
	actor := testActor()
	caseID := uuid.New()
	readerCalled := false
	reader := &readerStub{authorize: func(context.Context, identityverification.Actor) error {
		readerCalled = true
		return nil
	}}
	core := &coreStub{getReviewer: func(context.Context, identityverification.Actor, uuid.UUID) (identityverification.Case, error) {
		return identityverification.Case{}, identityverification.ErrPermissionDenied
	}}
	service := testService(t, core, reader, resolverStub{})
	_, err := service.GetReviewer(context.Background(), actor, caseID)
	if readerCalled || !errors.Is(err, identityverification.ErrPermissionDenied) {
		t.Fatalf("reviewer GET used split authorization: error=%v reader_called=%t", err, readerCalled)
	}
}

func TestReviewerWritesDoNotTrustAuthorizationFromEarlierTransaction(t *testing.T) {
	actor := testActor()
	caseID := uuid.New()
	for _, test := range []struct {
		name string
		core *coreStub
		call func(*Service) error
	}{
		{name: "claim", core: &coreStub{mutation: func(string, context.Context,
			identityverification.Actor, identityverification.MutationRequest,
		) (identityverification.Case, error) {
			return identityverification.Case{}, identityverification.ErrPermissionDenied
		}}, call: func(service *Service) error {
			_, err := service.Claim(context.Background(), actor, MutationInput{CaseID: caseID,
				ExpectedRevision: 1, WriteMetadata: WriteMetadata{IdempotencyKey: "claim-auth",
					RequestID: "claim-auth-request"}})
			return err
		}},
		{name: "decision", core: &coreStub{review: func(context.Context,
			identityverification.Actor, identityverification.ReviewRequest,
		) (identityverification.Case, error) {
			return identityverification.Case{}, identityverification.ErrPermissionDenied
		}}, call: func(service *Service) error {
			_, err := service.Decide(context.Background(), actor, DecisionInput{CaseID: caseID,
				ExpectedRevision: 1, Decision: identityverification.DecisionReject,
				ReasonCode: identityverification.ReasonEvidenceUnreadable,
				WriteMetadata: WriteMetadata{IdempotencyKey: "decision-auth",
					RequestID: "decision-auth-request"}})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			readerCalled := false
			reader := &readerStub{authorize: func(context.Context, identityverification.Actor) error {
				readerCalled = true
				return nil
			}}
			service := testService(t, test.core, reader, resolverStub{})
			err := test.call(service)
			if readerCalled || !errors.Is(err, ErrNotFound) {
				t.Fatalf("reviewer write used split authorization: error=%v reader_called=%t", err, readerCalled)
			}
		})
	}
}

func TestCreateDraftLeavesCommitToSettlementWorker(t *testing.T) {
	actor := testActor()
	token := strings.Repeat("c", 32)
	resolver := newReservationRegistry()
	resolver.add(actor, token, personalResolvedEvidence(0xc1))
	resolver.failNextCommit()
	item := testCase(actor, identityverification.KindPersonalInitial, identityverification.StatusDraft, 1)
	coreCalls := 0
	core := &coreStub{create: func(context.Context, identityverification.Actor,
		identityverification.CreateDraftRequest,
	) (identityverification.Case, error) {
		coreCalls++
		result := item
		result.Replayed = coreCalls > 1
		return result, nil
	}}
	service := testService(t, core, &readerStub{}, resolver)
	input := CreateDraftInput{Kind: identityverification.KindPersonalInitial, EvidenceToken: token}
	metadata := WriteMetadata{IdempotencyKey: "create-commit-retry", RequestID: "request-commit-retry"}
	if _, err := service.CreateDraft(context.Background(), actor, input, metadata); err != nil {
		t.Fatalf("create with unavailable synchronous commit path = %v", err)
	}
	result, err := service.CreateDraft(context.Background(), actor, input, metadata)
	if err != nil || !result.Replayed || result.ID != item.ID {
		t.Fatalf("same-key database replay = %#v, %v", result, err)
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.commitFailures != 1 {
		t.Fatalf("HTTP consumed settlement worker commit failure: remaining=%d", resolver.commitFailures)
	}
}

func TestCreateDraftQuarantinesReservationAfterCoreTransactionStarts(t *testing.T) {
	actor := testActor()
	quarantined, aborted := 0, 0
	resolver := resolverStub{
		resolve: func(context.Context, identityverification.Actor, EvidenceReference) (ResolvedEvidence, error) {
			return personalResolvedEvidence(0xcf), nil
		},
		abort:      func(context.Context, string) error { aborted++; return nil },
		quarantine: func(context.Context, string) error { quarantined++; return nil },
	}
	core := &coreStub{createOutcome: func(context.Context, identityverification.Actor,
		identityverification.CreateDraftRequest,
	) (identityverification.CreateDraftOutcome, error) {
		return identityverification.CreateDraftOutcome{TransactionStarted: true, AuthorizationPassed: true},
			errors.New("injected transaction failure")
	}}
	service := testService(t, core, &readerStub{}, resolver)
	_, err := service.CreateDraft(context.Background(), actor,
		CreateDraftInput{Kind: identityverification.KindPersonalInitial, EvidenceToken: strings.Repeat("q", 32)},
		WriteMetadata{IdempotencyKey: "create-quarantine", RequestID: "request-quarantine"})
	if !errors.Is(err, ErrStoreUnavailable) || quarantined != 1 || aborted != 0 {
		t.Fatalf("transaction failure = %v, quarantined=%d aborted=%d", err, quarantined, aborted)
	}
}

func TestCreateDraftPreservesReservationWhenCoreOutcomeMayBeDurable(t *testing.T) {
	for _, test := range []struct {
		name    string
		outcome identityverification.CreateDraftOutcome
		err     error
	}{
		{name: "commit outcome unknown", outcome: identityverification.CreateDraftOutcome{
			TransactionStarted: true, AuthorizationPassed: true},
			err: identityverification.ErrCommitOutcomeUnknown},
		{name: "durable binding", outcome: identityverification.CreateDraftOutcome{
			TransactionStarted: true, AuthorizationPassed: true, SettlementBound: true},
			err: identityverification.ErrPermissionDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			actor := testActor()
			quarantined, aborted := 0, 0
			resolver := resolverStub{
				resolve: func(context.Context, identityverification.Actor, EvidenceReference) (ResolvedEvidence, error) {
					return personalResolvedEvidence(0xcd), nil
				},
				abort:      func(context.Context, string) error { aborted++; return nil },
				quarantine: func(context.Context, string) error { quarantined++; return nil },
			}
			core := &coreStub{createOutcome: func(context.Context, identityverification.Actor,
				identityverification.CreateDraftRequest,
			) (identityverification.CreateDraftOutcome, error) {
				return test.outcome, test.err
			}}
			service := testService(t, core, &readerStub{}, resolver)
			_, err := service.CreateDraft(context.Background(), actor,
				CreateDraftInput{Kind: identityverification.KindPersonalInitial,
					EvidenceToken: strings.Repeat("u", 32)},
				WriteMetadata{IdempotencyKey: "create-unknown", RequestID: "request-unknown"})
			if !errors.Is(err, test.err) && !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("unknown create outcome error = %v", err)
			}
			if quarantined != 0 || aborted != 0 {
				t.Fatalf("possibly durable reservation released: quarantined=%d aborted=%d",
					quarantined, aborted)
			}
		})
	}
}

func TestCreateDraftPreservesDurableReservationOnInvalidSuccessOutcome(t *testing.T) {
	for _, outcome := range []identityverification.CreateDraftOutcome{
		{SettlementBound: true},
		{AuthorizationPassed: true, SettlementBound: true},
	} {
		actor := testActor()
		aborted, quarantined := 0, 0
		resolver := resolverStub{
			resolve: func(context.Context, identityverification.Actor, EvidenceReference) (ResolvedEvidence, error) {
				return personalResolvedEvidence(0xd3), nil
			},
			abort:      func(context.Context, string) error { aborted++; return nil },
			quarantine: func(context.Context, string) error { quarantined++; return nil },
		}
		core := &coreStub{createOutcome: func(context.Context, identityverification.Actor,
			identityverification.CreateDraftRequest,
		) (identityverification.CreateDraftOutcome, error) {
			return outcome, nil
		}}
		service := testService(t, core, &readerStub{}, resolver)
		_, err := service.CreateDraft(t.Context(), actor,
			CreateDraftInput{Kind: identityverification.KindPersonalInitial,
				EvidenceToken: strings.Repeat("s", 32)},
			WriteMetadata{IdempotencyKey: "create-invalid-outcome", RequestID: "request-invalid-outcome"})
		if !errors.Is(err, ErrStoreUnavailable) || aborted != 0 || quarantined != 0 {
			t.Fatalf("CreateDraft(%#v) = %v, aborted=%d quarantined=%d",
				outcome, err, aborted, quarantined)
		}
	}
}

func TestCreateDraftAbortsReservationBeforeCoreTransactionStarts(t *testing.T) {
	actor := testActor()
	quarantined, aborted := 0, 0
	resolver := resolverStub{
		resolve: func(context.Context, identityverification.Actor, EvidenceReference) (ResolvedEvidence, error) {
			return personalResolvedEvidence(0xce), nil
		},
		abort:      func(context.Context, string) error { aborted++; return nil },
		quarantine: func(context.Context, string) error { quarantined++; return nil },
	}
	core := &coreStub{createOutcome: func(context.Context, identityverification.Actor,
		identityverification.CreateDraftRequest,
	) (identityverification.CreateDraftOutcome, error) {
		return identityverification.CreateDraftOutcome{}, identityverification.ErrInvalidInput
	}}
	service := testService(t, core, &readerStub{}, resolver)
	_, err := service.CreateDraft(context.Background(), actor,
		CreateDraftInput{Kind: identityverification.KindPersonalInitial, EvidenceToken: strings.Repeat("p", 32)},
		WriteMetadata{IdempotencyKey: "create-pretransaction", RequestID: "request-pretransaction"})
	if !errors.Is(err, identityverification.ErrInvalidInput) || aborted != 1 || quarantined != 0 {
		t.Fatalf("pretransaction failure = %v, aborted=%d quarantined=%d", err, aborted, quarantined)
	}
}

func TestCreateDraftAbortsReservationWhenTransactionReauthorizationFails(t *testing.T) {
	actor := testActor()
	aborted, quarantined := 0, 0
	resolver := resolverStub{
		resolve: func(context.Context, identityverification.Actor, EvidenceReference) (ResolvedEvidence, error) {
			return personalResolvedEvidence(0xd2), nil
		},
		abort:      func(context.Context, string) error { aborted++; return nil },
		quarantine: func(context.Context, string) error { quarantined++; return nil },
	}
	core := &coreStub{createOutcome: func(context.Context, identityverification.Actor,
		identityverification.CreateDraftRequest,
	) (identityverification.CreateDraftOutcome, error) {
		return identityverification.CreateDraftOutcome{TransactionStarted: true},
			identityverification.ErrPermissionDenied
	}}
	service := testService(t, core, &readerStub{}, resolver)
	_, err := service.CreateDraft(t.Context(), actor,
		CreateDraftInput{Kind: identityverification.KindPersonalInitial,
			EvidenceToken: strings.Repeat("r", 32)},
		WriteMetadata{IdempotencyKey: "create-reauthorize", RequestID: "request-reauthorize"})
	if !errors.Is(err, identityverification.ErrPermissionDenied) || aborted != 1 || quarantined != 0 {
		t.Fatalf("CreateDraft() = %v, aborted=%d quarantined=%d", err, aborted, quarantined)
	}
}

func TestCreateDraftReleasesReservationAfterRequestCancellation(t *testing.T) {
	for _, test := range []struct {
		name           string
		outcome        identityverification.CreateDraftOutcome
		wantAbort      int
		wantQuarantine int
	}{
		{name: "before transaction authorization", outcome: identityverification.CreateDraftOutcome{
			TransactionStarted: true}, wantAbort: 1},
		{name: "after transaction authorization", outcome: identityverification.CreateDraftOutcome{
			TransactionStarted: true, AuthorizationPassed: true}, wantQuarantine: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			actor := testActor()
			ctx, cancel := context.WithCancel(context.Background())
			aborted, quarantined := 0, 0
			assertCleanupContext := func(cleanupCtx context.Context) {
				t.Helper()
				if cleanupCtx.Err() != nil {
					t.Fatalf("cleanup context inherited cancellation: %v", cleanupCtx.Err())
				}
				deadline, ok := cleanupCtx.Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > reservationReleaseTimeout {
					t.Fatalf("cleanup deadline = %v, present=%t", deadline, ok)
				}
			}
			resolver := resolverStub{
				reserve: func(context.Context, identityverification.Actor, EvidenceReference, string,
					[32]byte,
				) (EvidenceReservation, error) {
					return reservationResult("reservation-cancelled-0000000000", personalResolvedEvidence(0xd4)), nil
				},
				abort: func(cleanupCtx context.Context, _ string) error {
					assertCleanupContext(cleanupCtx)
					aborted++
					return nil
				},
				quarantine: func(cleanupCtx context.Context, _ string) error {
					assertCleanupContext(cleanupCtx)
					quarantined++
					return nil
				},
			}
			core := &coreStub{createOutcome: func(context.Context, identityverification.Actor,
				identityverification.CreateDraftRequest,
			) (identityverification.CreateDraftOutcome, error) {
				cancel()
				return test.outcome, context.Canceled
			}}
			service := testService(t, core, &readerStub{}, resolver)
			_, err := service.CreateDraft(ctx, actor,
				CreateDraftInput{Kind: identityverification.KindPersonalInitial,
					EvidenceToken: strings.Repeat("t", 32)},
				WriteMetadata{IdempotencyKey: "create-cancel-release", RequestID: "request-cancel-release"})
			if !errors.Is(err, context.Canceled) || aborted != test.wantAbort ||
				quarantined != test.wantQuarantine {
				t.Fatalf("CreateDraft() = %v, aborted=%d quarantined=%d", err, aborted, quarantined)
			}
		})
	}
}

func TestEvidenceSettlementPendingPublicErrorIsStable(t *testing.T) {
	status, code, message := publicError(identityverification.ErrEvidenceSettlementPending)
	if status != 409 || code != "identity_verification_evidence_settlement_pending" ||
		message != "trusted evidence settlement is pending" {
		t.Fatalf("public settlement pending error = %d/%s/%s", status, code, message)
	}
}

func TestEvidenceReservationBindingAndConcurrentIdempotency(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	actor := testActor()
	other := actor
	other.UserID = uuid.New()
	token := strings.Repeat("b", 32)
	otherToken := strings.Repeat("d", 32)
	registry := newReservationRegistry()
	evidence := personalResolvedEvidence(0xd1)
	registry.add(actor, token, evidence)
	registry.add(actor, otherToken, evidence)
	reference := EvidenceReference{Kind: evidence.Kind, Token: token}
	digest := evidenceRequestDigest(CreateDraftInput{Kind: evidence.Kind, EvidenceToken: token})
	reservation, err := registry.Reserve(ctx, actor, reference, "binding-key", digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Reserve(ctx, actor, reference, "different-key", digest); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("different key stole reservation: %v", err)
	}
	mutatedDigest := digest
	mutatedDigest[0] ^= 1
	if _, err := registry.Reserve(ctx, actor, reference, "binding-key", mutatedDigest); !errors.Is(err, ErrEvidenceReservationConflict) {
		t.Fatalf("different digest reused reservation: %v", err)
	}
	if _, err := registry.Reserve(ctx, other, reference, "binding-key", digest); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("different user stole reservation: %v", err)
	}
	otherDigest := evidenceRequestDigest(CreateDraftInput{Kind: evidence.Kind, EvidenceToken: otherToken})
	if _, err := registry.Reserve(ctx, actor,
		EvidenceReference{Kind: evidence.Kind, Token: otherToken}, "binding-key", otherDigest); !errors.Is(err, ErrEvidenceReservationConflict) {
		t.Fatalf("different digest reused idempotency key: %v", err)
	}
	if err := registry.Abort(ctx, reservation.ID); err != nil {
		t.Fatal(err)
	}
	if err := registry.Abort(ctx, reservation.ID); err != nil {
		t.Fatalf("duplicate abort: %v", err)
	}
	caseID := uuid.New()
	start := make(chan struct{})
	errorsByCall := make(chan error, 16)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(start) }) }
	reserveCollected := 0
	defer func() {
		cancel()
		release()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
		defer cleanupCancel()
		for reserveCollected < 16 {
			select {
			case <-errorsByCall:
				reserveCollected++
			case <-cleanupCtx.Done():
				return
			}
		}
	}()
	for range 16 {
		go func() {
			select {
			case <-start:
			case <-ctx.Done():
				errorsByCall <- ctx.Err()
				return
			}
			repeated, reserveErr := registry.Reserve(ctx, actor, reference, "binding-key", digest)
			if reserveErr == nil && repeated.ID != reservation.ID {
				reserveErr = errors.New("reservation ID changed")
			}
			if reserveErr == nil {
				reserveErr = registry.Commit(ctx, reservation.ID, caseID)
			}
			errorsByCall <- reserveErr
		}()
	}
	release()
	for range 16 {
		var workerErr error
		select {
		case workerErr = <-errorsByCall:
			reserveCollected++
		case <-ctx.Done():
			t.Fatalf("concurrent reserve/commit workers did not finish: %v", ctx.Err())
		}
		if workerErr != nil {
			t.Fatalf("concurrent reserve/commit: %v", workerErr)
		}
	}
	if err := registry.Commit(ctx, reservation.ID, caseID); err != nil {
		t.Fatalf("duplicate commit: %v", err)
	}
	abortErrors := make(chan error, 16)
	abortCollected := 0
	defer func() {
		cancel()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
		defer cleanupCancel()
		for abortCollected < 16 {
			select {
			case <-abortErrors:
				abortCollected++
			case <-cleanupCtx.Done():
				return
			}
		}
	}()
	for range 16 {
		go func() {
			abortErrors <- registry.Abort(ctx, reservation.ID)
		}()
	}
	for range 16 {
		var workerErr error
		select {
		case workerErr = <-abortErrors:
			abortCollected++
		case <-ctx.Done():
			t.Fatalf("concurrent abort workers did not finish: %v", ctx.Err())
		}
		if workerErr != nil {
			t.Fatalf("concurrent abort: %v", workerErr)
		}
	}
	if err := registry.Commit(ctx, reservation.ID, uuid.New()); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("reservation rebound to another case: %v", err)
	}
}

func TestSelfReadHidesOtherUsersAndCrossTenantMutation(t *testing.T) {
	actor := testActor()
	other := actor
	other.UserID = uuid.New()
	caseID := uuid.New()
	core := &coreStub{
		get: func(context.Context, identityverification.Actor, uuid.UUID) (identityverification.Case, error) {
			item := testCase(other, identityverification.KindPersonalInitial, identityverification.StatusDraft, 1)
			item.ID, item.TenantScopeID = caseID, actor.ScopeID
			return item, nil
		},
		mutation: func(string, context.Context, identityverification.Actor,
			identityverification.MutationRequest,
		) (identityverification.Case, error) {
			return identityverification.Case{}, identityverification.ErrPermissionDenied
		},
	}
	service := testService(t, core, &readerStub{}, resolverStub{})
	if _, err := service.GetSelf(context.Background(), actor, caseID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSelf(other) error = %v", err)
	}
	_, err := service.Submit(context.Background(), actor, MutationInput{CaseID: caseID, ExpectedRevision: 1,
		WriteMetadata: WriteMetadata{IdempotencyKey: "submit-cross", RequestID: "request-cross"}})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Submit(cross tenant/user) error = %v", err)
	}
}

func TestReviewerCursorIsStableBoundAndTamperEvident(t *testing.T) {
	actor := testActor()
	created := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	firstID := uuid.MustParse("ffffffff-ffff-4fff-8fff-ffffffffffff")
	secondID := uuid.MustParse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	calls := 0
	reader := &readerStub{list: func(_ context.Context, actual identityverification.Actor,
		query CasePageQuery,
	) ([]CaseSummary, error) {
		calls++
		if actual != actor || query.Kind != identityverification.KindPersonalInitial ||
			query.Status != identityverification.StatusSubmitted || query.Limit != 2 {
			t.Fatalf("list query = %#v / %#v", actual, query)
		}
		if calls == 1 {
			return []CaseSummary{
				{ID: firstID, ApplicantUserID: uuid.New(), Kind: query.Kind, Status: query.Status,
					Revision: 2, CreatedAt: created, StateChangedAt: created},
				{ID: secondID, ApplicantUserID: uuid.New(), Kind: query.Kind, Status: query.Status,
					Revision: 2, CreatedAt: created, StateChangedAt: created},
			}, nil
		}
		if query.AfterCreatedAt == nil || !query.AfterCreatedAt.Equal(created) || query.AfterID == nil ||
			*query.AfterID != firstID {
			t.Fatalf("decoded cursor query = %#v", query)
		}
		return []CaseSummary{}, nil
	}}
	service := testService(t, &coreStub{}, reader, resolverStub{})
	input := PageInput{Limit: 1, Kind: identityverification.KindPersonalInitial,
		Status: identityverification.StatusSubmitted}
	page, err := service.ListReviewerCases(context.Background(), actor, input)
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("first page = %#v, %v", page, err)
	}
	input.Cursor = page.NextCursor
	second, err := service.ListReviewerCases(context.Background(), actor, input)
	if err != nil || len(second.Items) != 0 {
		t.Fatalf("second page = %#v, %v", second, err)
	}
	tamperedCursors := []struct {
		name string
		raw  string
	}{
		{"different legal tail character", switchCursorTailCharacter(t, page.NextCursor)},
		{"decoded payload byte flip", flipCursorPayloadByte(t, page.NextCursor)},
		{"MAC byte flip", flipCursorMACByte(t, page.NextCursor)},
		{"non-canonical trailing bits", nonCanonicalCursorMAC(t, page.NextCursor)},
		{"bad alphabet", page.NextCursor[:len(page.NextCursor)-1] + "!"},
		{"truncation", page.NextCursor[:len(page.NextCursor)-1]},
	}
	for _, tampered := range tamperedCursors {
		t.Run(tampered.name, func(t *testing.T) {
			if tampered.raw == page.NextCursor {
				t.Fatal("tampered cursor did not change")
			}
			before := calls
			candidate := input
			candidate.Cursor = tampered.raw
			if _, err := service.ListReviewerCases(context.Background(), actor, candidate); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("tampered cursor error = %v", err)
			}
			if calls != before {
				t.Fatalf("reader calls changed from %d to %d", before, calls)
			}
		})
	}
	otherTenant := actor
	otherTenant.ScopeID = uuid.New()
	before := calls
	if _, err := service.ListReviewerCases(context.Background(), otherTenant, input); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("cross tenant cursor error = %v", err)
	}
	if calls != before {
		t.Fatalf("cross tenant cursor reached reader: %d -> %d", before, calls)
	}
	changedFilter := input
	changedFilter.Status = identityverification.StatusReviewing
	before = calls
	if _, err := service.ListReviewerCases(context.Background(), actor, changedFilter); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("changed filter cursor error = %v", err)
	}
	if calls != before {
		t.Fatalf("changed filter cursor reached reader: %d -> %d", before, calls)
	}
}

func switchCursorTailCharacter(t *testing.T, raw string) string {
	t.Helper()
	payload, signature, ok := strings.Cut(raw, ".")
	if !ok || len(signature) == 0 {
		t.Fatalf("invalid fixture cursor %q", raw)
	}
	replacement := byte('A')
	if signature[len(signature)-1] == replacement {
		replacement = 'E'
	}
	mutated := signature[:len(signature)-1] + string(replacement)
	originalBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	mutatedBytes, err := base64.RawURLEncoding.DecodeString(mutated)
	if err != nil || equalBytes(originalBytes, mutatedBytes) {
		t.Fatalf("tail mutation did not change decoded MAC: %v", err)
	}
	return payload + "." + mutated
}

func flipCursorPayloadByte(t *testing.T, raw string) string {
	t.Helper()
	payload, signature, ok := strings.Cut(raw, ".")
	if !ok {
		t.Fatalf("invalid fixture cursor %q", raw)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || len(decoded) == 0 {
		t.Fatalf("decode payload: %v", err)
	}
	decoded[len(decoded)/2] ^= 1
	return base64.RawURLEncoding.EncodeToString(decoded) + "." + signature
}

func flipCursorMACByte(t *testing.T, raw string) string {
	t.Helper()
	payload, signature, ok := strings.Cut(raw, ".")
	if !ok {
		t.Fatalf("invalid fixture cursor %q", raw)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(decoded) == 0 {
		t.Fatalf("decode MAC: %v", err)
	}
	decoded[len(decoded)/2] ^= 1
	return payload + "." + base64.RawURLEncoding.EncodeToString(decoded)
}

func nonCanonicalCursorMAC(t *testing.T, raw string) string {
	t.Helper()
	payload, signature, ok := strings.Cut(raw, ".")
	if !ok || len(signature) == 0 {
		t.Fatalf("invalid fixture cursor %q", raw)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	index := strings.IndexByte(alphabet, signature[len(signature)-1])
	if index < 0 || index%4 != 0 || index == len(alphabet)-1 {
		t.Fatalf("fixture MAC has unexpected final base64 symbol %q", signature[len(signature)-1])
	}
	mutated := signature[:len(signature)-1] + string(alphabet[index+1])
	originalBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	mutatedBytes, err := base64.RawURLEncoding.DecodeString(mutated)
	if err != nil || !equalBytes(originalBytes, mutatedBytes) {
		t.Fatalf("non-canonical encoding changed decoded MAC: %v", err)
	}
	return payload + "." + mutated
}

func TestServiceNormalizesCancellationAndStorageFailures(t *testing.T) {
	actor := testActor()
	caseID := uuid.New()
	core := &coreStub{get: func(context.Context, identityverification.Actor, uuid.UUID) (identityverification.Case, error) {
		return identityverification.Case{}, errors.New("sql: secret table and raw pii")
	}}
	service := testService(t, core, &readerStub{}, resolverStub{})
	if _, err := service.GetSelf(context.Background(), actor, caseID); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("storage error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.GetSelf(ctx, actor, caseID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
}

func bytesOf(length int, marker byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = marker
	}
	return result
}

func personalResolvedEvidence(marker byte) ResolvedEvidence {
	return ResolvedEvidence{Kind: identityverification.KindPersonalInitial, SubjectFingerprint: bytesOf(32, marker),
		Materials: []identityverification.MaterialInput{
			{Kind: identityverification.MaterialIdentityDocument, EnvelopeProvider: "kms", EnvelopeKeyID: "key/identity",
				EncryptedEnvelope: bytesOf(32, marker+1), ObjectReference: "identity/private/document",
				ObjectSHA256: bytesOf(32, marker+2), MIMEType: "image/jpeg", SizeBytes: 1024},
			{Kind: identityverification.MaterialLivenessEvidence, EnvelopeProvider: "kms", EnvelopeKeyID: "key/liveness",
				EncryptedEnvelope: bytesOf(32, marker+3), ObjectReference: "identity/private/liveness",
				ObjectSHA256: bytesOf(32, marker+4), MIMEType: "image/jpeg", SizeBytes: 1024},
		}}
}

func equalBytes(left, right []byte) bool {
	return string(left) == string(right)
}
