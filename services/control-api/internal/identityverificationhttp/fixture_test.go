package identityverificationhttp

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

var errUnexpectedCall = errors.New("unexpected test call")

type coreStub struct {
	authorizeCreate func(context.Context, identityverification.Actor) error
	create          func(context.Context, identityverification.Actor, identityverification.CreateDraftRequest) (identityverification.Case, error)
	createOutcome   func(context.Context, identityverification.Actor, identityverification.CreateDraftRequest) (identityverification.CreateDraftOutcome, error)
	mutation        func(string, context.Context, identityverification.Actor, identityverification.MutationRequest) (identityverification.Case, error)
	review          func(context.Context, identityverification.Actor, identityverification.ReviewRequest) (identityverification.Case, error)
	get             func(context.Context, identityverification.Actor, uuid.UUID) (identityverification.Case, error)
	getReviewer     func(context.Context, identityverification.Actor, uuid.UUID) (identityverification.Case, error)
	status          func(context.Context, identityverification.Actor) (identityverification.SelfStatus, error)
}

func (stub *coreStub) CurrentStatus(ctx context.Context, actor identityverification.Actor) (identityverification.SelfStatus, error) {
	if stub.status == nil {
		return identityverification.SelfStatus{}, errUnexpectedCall
	}
	return stub.status(ctx, actor)
}

func (stub *coreStub) AuthorizeCreateDraft(ctx context.Context, actor identityverification.Actor) error {
	if stub.authorizeCreate == nil {
		return nil
	}
	return stub.authorizeCreate(ctx, actor)
}

func (stub *coreStub) CreateDraftWithSettlement(ctx context.Context, actor identityverification.Actor, request identityverification.CreateDraftRequest) (identityverification.CreateDraftOutcome, error) {
	if stub.createOutcome != nil {
		return stub.createOutcome(ctx, actor, request)
	}
	if stub.create == nil {
		return identityverification.CreateDraftOutcome{}, errUnexpectedCall
	}
	item, err := stub.create(ctx, actor, request)
	if err != nil {
		return identityverification.CreateDraftOutcome{}, err
	}
	return identityverification.CreateDraftOutcome{Case: item, TransactionStarted: true,
		AuthorizationPassed: true, SettlementBound: true}, nil
}

func (stub *coreStub) Submit(ctx context.Context, actor identityverification.Actor, request identityverification.MutationRequest) (identityverification.Case, error) {
	return stub.mutate("submit", ctx, actor, request)
}

func (stub *coreStub) StartReview(ctx context.Context, actor identityverification.Actor, request identityverification.MutationRequest) (identityverification.Case, error) {
	return stub.mutate("claim", ctx, actor, request)
}

func (stub *coreStub) Review(ctx context.Context, actor identityverification.Actor, request identityverification.ReviewRequest) (identityverification.Case, error) {
	if stub.review == nil {
		return identityverification.Case{}, errUnexpectedCall
	}
	return stub.review(ctx, actor, request)
}

func (stub *coreStub) Withdraw(ctx context.Context, actor identityverification.Actor, request identityverification.MutationRequest) (identityverification.Case, error) {
	return stub.mutate("withdraw", ctx, actor, request)
}

func (stub *coreStub) Expire(ctx context.Context, actor identityverification.Actor, request identityverification.MutationRequest) (identityverification.Case, error) {
	return stub.mutate("expire", ctx, actor, request)
}

func (stub *coreStub) Get(ctx context.Context, actor identityverification.Actor, caseID uuid.UUID) (identityverification.Case, error) {
	if stub.get == nil {
		return identityverification.Case{}, errUnexpectedCall
	}
	return stub.get(ctx, actor, caseID)
}

func (stub *coreStub) GetForReview(ctx context.Context, actor identityverification.Actor, caseID uuid.UUID) (identityverification.Case, error) {
	if stub.getReviewer != nil {
		return stub.getReviewer(ctx, actor, caseID)
	}
	return stub.Get(ctx, actor, caseID)
}

func (stub *coreStub) mutate(operation string, ctx context.Context, actor identityverification.Actor,
	request identityverification.MutationRequest,
) (identityverification.Case, error) {
	if stub.mutation == nil {
		return identityverification.Case{}, errUnexpectedCall
	}
	return stub.mutation(operation, ctx, actor, request)
}

type readerStub struct {
	authorize func(context.Context, identityverification.Actor) error
	list      func(context.Context, identityverification.Actor, CasePageQuery) ([]CaseSummary, error)
	listAdmin func(context.Context, identityverification.PlatformAdmin, CasePageQuery) ([]AdminCaseSummary, error)
}

func (stub *readerStub) ListAdminCases(ctx context.Context, admin identityverification.PlatformAdmin,
	query CasePageQuery,
) ([]AdminCaseSummary, error) {
	if stub.listAdmin == nil {
		return nil, nil
	}
	return stub.listAdmin(ctx, admin, query)
}

func (stub *readerStub) AuthorizeReviewer(ctx context.Context, actor identityverification.Actor) error {
	if stub.authorize == nil {
		return nil
	}
	return stub.authorize(ctx, actor)
}

func (stub *readerStub) ListCases(ctx context.Context, actor identityverification.Actor, query CasePageQuery) ([]CaseSummary, error) {
	if stub.list == nil {
		return nil, nil
	}
	return stub.list(ctx, actor, query)
}

type resolverStub struct {
	configured      bool
	configuredCheck func() bool
	resolve         func(context.Context, identityverification.Actor, EvidenceReference) (ResolvedEvidence, error)
	reserve         func(context.Context, identityverification.Actor, EvidenceReference, string, [32]byte) (EvidenceReservation, error)
	commit          func(context.Context, string, uuid.UUID) error
	abort           func(context.Context, string) error
	quarantine      func(context.Context, string) error
}

func (stub resolverStub) Configured() bool {
	if stub.configuredCheck != nil {
		return stub.configuredCheck()
	}
	return stub.configured
}

type reservationSource struct {
	actor    identityverification.Actor
	evidence ResolvedEvidence
}

type reservationBinding struct {
	id          string
	actor       identityverification.Actor
	reference   EvidenceReference
	key         string
	digest      [32]byte
	caseID      uuid.UUID
	committed   bool
	quarantined bool
}

type reservationRegistry struct {
	mu             sync.Mutex
	sources        map[string]reservationSource
	bindings       map[string]*reservationBinding
	byActorKey     map[string]string
	byHandle       map[string]string
	commitFailures int
}

func (registry *reservationRegistry) Configured() bool {
	return registry != nil
}

func newReservationRegistry() *reservationRegistry {
	return &reservationRegistry{sources: map[string]reservationSource{}, bindings: map[string]*reservationBinding{},
		byActorKey: map[string]string{}, byHandle: map[string]string{}}
}

func (registry *reservationRegistry) add(actor identityverification.Actor, token string, evidence ResolvedEvidence) {
	registry.mu.Lock()
	registry.sources[token] = reservationSource{actor: actor, evidence: cloneReservationEvidence(evidence)}
	registry.mu.Unlock()
}

func (registry *reservationRegistry) failNextCommit() {
	registry.mu.Lock()
	registry.commitFailures++
	registry.mu.Unlock()
}

func (registry *reservationRegistry) Reserve(_ context.Context, actor identityverification.Actor,
	reference EvidenceReference, key string, digest [32]byte,
) (EvidenceReservation, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	source, ok := registry.sources[reference.Token]
	if !ok || source.actor != actor || source.evidence.Kind != reference.Kind {
		return EvidenceReservation{}, ErrInvalidEvidence
	}
	actorKey := actor.ScopeID.String() + "/" + actor.UserID.String() + "/" + key
	boundByKey, keyExists := registry.byActorKey[actorKey]
	boundByHandle, handleExists := registry.byHandle[reference.Token]
	if keyExists {
		binding := registry.bindings[boundByKey]
		if binding != nil && binding.actor == actor && binding.key == key &&
			(binding.reference != reference || binding.digest != digest) {
			return EvidenceReservation{}, ErrEvidenceReservationConflict
		}
	}
	if keyExists || handleExists {
		if !keyExists || !handleExists || boundByKey != boundByHandle {
			return EvidenceReservation{}, ErrInvalidEvidence
		}
		binding := registry.bindings[boundByKey]
		if binding == nil || binding.actor != actor || binding.reference != reference ||
			binding.key != key || binding.digest != digest || binding.quarantined {
			return EvidenceReservation{}, ErrInvalidEvidence
		}
		return reservationResult(binding.id, source.evidence), nil
	}
	id := uuid.NewString()
	binding := &reservationBinding{id: id, actor: actor, reference: reference, key: key, digest: digest}
	registry.bindings[id] = binding
	registry.byActorKey[actorKey] = id
	registry.byHandle[reference.Token] = id
	return reservationResult(id, source.evidence), nil
}

func (registry *reservationRegistry) Commit(_ context.Context, reservationID string, caseID uuid.UUID) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	binding := registry.bindings[reservationID]
	if binding == nil || caseID == uuid.Nil || binding.committed && binding.caseID != caseID {
		return ErrInvalidEvidence
	}
	if registry.commitFailures > 0 {
		registry.commitFailures--
		return ErrEvidenceUnavailable
	}
	binding.caseID = caseID
	binding.committed = true
	return nil
}

func (registry *reservationRegistry) Abort(_ context.Context, reservationID string) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.bindings[reservationID] == nil {
		return ErrInvalidEvidence
	}
	return nil
}

func (registry *reservationRegistry) Quarantine(_ context.Context, reservationID string) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	binding := registry.bindings[reservationID]
	if binding == nil {
		return ErrInvalidEvidence
	}
	binding.quarantined = true
	return nil
}

func reservationResult(id string, evidence ResolvedEvidence) EvidenceReservation {
	return EvidenceReservation{ID: id, ResolverName: "test-resolver", ResolverReference: id,
		EvidenceClaimDigest: sha256.Sum256([]byte("evidence-claim-" + id)),
		Evidence:            cloneReservationEvidence(evidence)}
}

func cloneReservationEvidence(value ResolvedEvidence) ResolvedEvidence {
	value.SubjectFingerprint = append([]byte(nil), value.SubjectFingerprint...)
	value.LegalPersonFingerprint = append([]byte(nil), value.LegalPersonFingerprint...)
	value.AgentFingerprint = append([]byte(nil), value.AgentFingerprint...)
	materials := make([]identityverification.MaterialInput, len(value.Materials))
	for index, material := range value.Materials {
		materials[index] = material
		materials[index].EncryptedEnvelope = append([]byte(nil), material.EncryptedEnvelope...)
		materials[index].ObjectSHA256 = append([]byte(nil), material.ObjectSHA256...)
	}
	value.Materials = materials
	return value
}

func (stub resolverStub) Reserve(ctx context.Context, actor identityverification.Actor, reference EvidenceReference,
	key string, digest [32]byte,
) (EvidenceReservation, error) {
	if stub.reserve != nil {
		return stub.reserve(ctx, actor, reference, key, digest)
	}
	if stub.resolve != nil {
		evidence, err := stub.resolve(ctx, actor, reference)
		return reservationResult("reservation-00000000000000000000", evidence), err
	}
	return EvidenceReservation{}, errUnexpectedCall
}

func (stub resolverStub) Commit(ctx context.Context, reservationID string, caseID uuid.UUID) error {
	if stub.commit == nil {
		return nil
	}
	return stub.commit(ctx, reservationID, caseID)
}

func (stub resolverStub) Abort(ctx context.Context, reservationID string) error {
	if stub.abort == nil {
		return nil
	}
	return stub.abort(ctx, reservationID)
}

func (stub resolverStub) Quarantine(ctx context.Context, reservationID string) error {
	if stub.quarantine == nil {
		return nil
	}
	return stub.quarantine(ctx, reservationID)
}

func testActor() identityverification.Actor {
	actor, err := identityverification.NewSessionActor(uuid.New(), uuid.New(), "tenant", uuid.New(),
		"unit-test-session")
	if err != nil {
		panic(err)
	}
	return actor
}

func testCase(actor identityverification.Actor, kind, status string, revision int64) identityverification.Case {
	now := time.Date(2034, 7, 23, 1, 2, 3, 0, time.UTC)
	return identityverification.Case{
		ID: uuid.New(), TenantScopeID: actor.ScopeID, ApplicantUserID: actor.UserID,
		Kind: kind, Status: status, Revision: revision, CreatedAt: now, StateChangedAt: now,
		Retention: identityverification.Retention{EligibleAt: now.Add(24 * time.Hour), ReasonCode: "case_not_terminal"},
		Materials: []identityverification.Material{{ID: uuid.New(), Kind: identityverification.MaterialIdentityDocument,
			EncryptedEnvelopePresent: true, MIMEType: "image/jpeg", SizeBytes: 1024, CreatedAt: now}},
	}
}

func testService(t *testing.T, core CoreService, reader ReviewReadStore, resolver TrustedEvidenceResolver) *Service {
	t.Helper()
	service, err := newService(core, reader, resolver, ServiceConfig{CursorKey: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testHandler(t *testing.T, service *Service, actor identityverification.Actor) *Handler {
	t.Helper()
	handler, err := newHandler(service, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: actor.SessionID(), Principal: identity.Principal{
			UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind,
		}}, nil
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func setTestAuthorization(request *http.Request) {
	request.Header.Set("Authorization", "Bearer unit-test-session")
}
