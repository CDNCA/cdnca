package identityverificationhttp

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrTrustedEvidenceSourceRequired = errors.New("trusted evidence source with atomic reservations is required")

// RuntimeEvidenceSourceCapabilities are mandatory guarantees, not optional
// optimizations. Production assembly rejects a source missing any guarantee.
type RuntimeEvidenceSourceCapabilities struct {
	TrustedFacts          bool
	DurableReservations   bool
	ActorRequestBinding   bool
	AtomicTransitions     bool
	IdempotentTransitions bool
}

type RuntimeEvidenceReserveRequest struct {
	TenantScopeID         uuid.UUID
	ActorUserID           uuid.UUID
	SessionID             uuid.UUID
	Kind                  string
	Token                 string
	IdempotencyKey        string
	EvidenceRequestDigest [32]byte
}

type RuntimeEvidenceReserveResult struct {
	ReservationID       string
	ResolverReference   string
	EvidenceClaimDigest [32]byte
	Evidence            ResolvedEvidence
}

type RuntimeEvidencePublishRequest struct {
	ResolverReference   string
	TenantScopeID       uuid.UUID
	ActorUserID         uuid.UUID
	CaseID              uuid.UUID
	IdempotencyKey      string
	CoreRequestDigest   [32]byte
	EvidenceClaimDigest [32]byte
}

// RuntimeEvidenceSource is the minimal cross-ownership contract required from
// the future upload/KYC fact owner. Reserve must bind EvidenceRequestDigest
// (kind plus opaque token), return the same immutable fact for an identical
// actor/key/request binding, and reject conflicting reuse. EvidenceClaimDigest
// links that reservation to Publish; CoreRequestDigest is the distinct digest
// of the normalized core create command and must not be compared as if it were
// EvidenceRequestDigest.
// Abort and Quarantine must be idempotent terminal transitions. Publish must
// atomically bind one reservation to one case, and an identical retry after an
// unknown outcome must succeed without changing that binding. Implementations
// return ErrEvidenceReservationConflict for a different binding,
// ErrInvalidEvidence for an invalid or incompatible terminal reservation, and
// ErrEvidenceUnavailable for retryable dependency failure.
type RuntimeEvidenceSource interface {
	Capabilities() RuntimeEvidenceSourceCapabilities
	Reserve(context.Context, RuntimeEvidenceReserveRequest) (RuntimeEvidenceReserveResult, error)
	Abort(context.Context, string) error
	Quarantine(context.Context, string) error
	Publish(context.Context, RuntimeEvidencePublishRequest) error
}

type RuntimeEvidenceConfig struct {
	ResolverName string
}

type RuntimeEvidenceAdapter struct {
	resolverName string
	source       RuntimeEvidenceSource
}

func NewRuntimeEvidenceAdapter(config RuntimeEvidenceConfig,
	source RuntimeEvidenceSource,
) (*RuntimeEvidenceAdapter, error) {
	if !resolverNamePattern.MatchString(config.ResolverName) || !configuredEvidenceSource(source) {
		return nil, ErrTrustedEvidenceSourceRequired
	}
	return &RuntimeEvidenceAdapter{resolverName: config.ResolverName, source: source}, nil
}

func (adapter *RuntimeEvidenceAdapter) Configured() bool {
	return adapter != nil && adapter.source != nil && resolverNamePattern.MatchString(adapter.resolverName)
}

func (adapter *RuntimeEvidenceAdapter) Reserve(ctx context.Context, actor identityverification.Actor,
	reference EvidenceReference, idempotencyKey string, requestDigest [32]byte,
) (EvidenceReservation, error) {
	if !adapter.Configured() || ctx == nil || !actor.Valid() || !validKind(reference.Kind) ||
		!tokenPattern.MatchString(reference.Token) || !metadataPattern.MatchString(idempotencyKey) ||
		requestDigest == ([32]byte{}) {
		return EvidenceReservation{}, ErrInvalidEvidence
	}
	result, err := adapter.source.Reserve(ctx, RuntimeEvidenceReserveRequest{
		TenantScopeID: actor.ScopeID, ActorUserID: actor.UserID, SessionID: actor.SessionID(),
		Kind: reference.Kind, Token: reference.Token, IdempotencyKey: idempotencyKey,
		EvidenceRequestDigest: requestDigest,
	})
	if err != nil {
		return EvidenceReservation{}, normalizeEvidenceReserveError(ctx, err)
	}
	if !tokenPattern.MatchString(result.ReservationID) ||
		!resolverReferencePattern.MatchString(result.ResolverReference) ||
		result.EvidenceClaimDigest == ([32]byte{}) || result.Evidence.Kind != reference.Kind {
		return EvidenceReservation{}, ErrInvalidEvidence
	}
	return EvidenceReservation{ID: result.ReservationID, ResolverName: adapter.resolverName,
		ResolverReference: result.ResolverReference, EvidenceClaimDigest: result.EvidenceClaimDigest,
		Evidence: cloneRuntimeEvidence(result.Evidence)}, nil
}

func (adapter *RuntimeEvidenceAdapter) Abort(ctx context.Context, reservationID string) error {
	if !adapter.Configured() || ctx == nil || !tokenPattern.MatchString(reservationID) {
		return ErrInvalidEvidence
	}
	return normalizeEvidenceReleaseError(ctx, adapter.source.Abort(ctx, reservationID))
}

func (adapter *RuntimeEvidenceAdapter) Quarantine(ctx context.Context, reservationID string) error {
	if !adapter.Configured() || ctx == nil || !tokenPattern.MatchString(reservationID) {
		return ErrInvalidEvidence
	}
	return normalizeEvidenceReleaseError(ctx, adapter.source.Quarantine(ctx, reservationID))
}

func (adapter *RuntimeEvidenceAdapter) Publish(ctx context.Context,
	request identityverification.SettlementCommitRequest,
) (identityverification.SettlementCommitResult, error) {
	if !adapter.Configured() || ctx == nil {
		return retryEvidenceSettlement(), nil
	}
	if request.ResolverName != adapter.resolverName {
		return permanentEvidenceSettlement("resolver_not_supported"), nil
	}
	if !resolverReferencePattern.MatchString(request.ResolverReference) ||
		request.TenantScopeID == uuid.Nil || request.ActorUserID == uuid.Nil || request.CaseID == uuid.Nil ||
		!metadataPattern.MatchString(request.IdempotencyKey) || request.RequestDigest == ([32]byte{}) ||
		request.EvidenceClaimDigest == ([32]byte{}) {
		return permanentEvidenceSettlement("settlement_binding_invalid"), nil
	}
	err := adapter.source.Publish(ctx, RuntimeEvidencePublishRequest{
		ResolverReference: request.ResolverReference, TenantScopeID: request.TenantScopeID,
		ActorUserID: request.ActorUserID, CaseID: request.CaseID,
		IdempotencyKey: request.IdempotencyKey, CoreRequestDigest: request.RequestDigest,
		EvidenceClaimDigest: request.EvidenceClaimDigest,
	})
	if err == nil {
		return identityverification.SettlementCommitResult{
			Outcome: identityverification.SettlementCommitSucceeded,
		}, nil
	}
	if ctx.Err() != nil {
		return identityverification.SettlementCommitResult{}, ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return identityverification.SettlementCommitResult{}, err
	}
	switch {
	case errors.Is(err, ErrEvidenceReservationConflict):
		return permanentEvidenceSettlement("reservation_conflict"), nil
	case errors.Is(err, ErrInvalidEvidence):
		return permanentEvidenceSettlement("reservation_invalid"), nil
	default:
		return retryEvidenceSettlement(), nil
	}
}

type ProductionRuntimeConfig struct {
	Runtime  RuntimeConfig
	Evidence RuntimeEvidenceConfig
}

type ProductionRuntimeDependencies struct {
	Pool           *pgxpool.Pool
	Identity       *identity.Service
	IAM            *iamlock.Authorizer
	EvidenceSource RuntimeEvidenceSource
	PrivateObjects PrivateObjectStore
	KYCProvider    KYCProvider
	Clock          identityverification.Clock
}

func NewProductionRuntime(config ProductionRuntimeConfig,
	dependencies ProductionRuntimeDependencies,
) (*Runtime, error) {
	if !config.Runtime.Enabled {
		return NewRuntime(config.Runtime, RuntimeDependencies{})
	}
	adapter, err := NewRuntimeEvidenceAdapter(config.Evidence, dependencies.EvidenceSource)
	if err != nil {
		return nil, err
	}
	return NewRuntime(config.Runtime, RuntimeDependencies{Pool: dependencies.Pool,
		Identity: dependencies.Identity, IAM: dependencies.IAM, Resolver: adapter,
		SettlementPublisher: adapter, PrivateObjects: dependencies.PrivateObjects,
		KYCProvider: dependencies.KYCProvider, Clock: dependencies.Clock})
}

func configuredEvidenceSource(source RuntimeEvidenceSource) (configured bool) {
	if isNilDependency(source) {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	capabilities := source.Capabilities()
	return capabilities.TrustedFacts && capabilities.DurableReservations &&
		capabilities.ActorRequestBinding && capabilities.AtomicTransitions &&
		capabilities.IdempotentTransitions
}

func normalizeEvidenceReserveError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	switch {
	case errors.Is(err, ErrInvalidEvidence), errors.Is(err, ErrEvidenceReservationConflict),
		errors.Is(err, ErrEvidenceUnavailable), errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return ErrEvidenceUnavailable
	}
}

func normalizeEvidenceReleaseError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	switch {
	case errors.Is(err, ErrInvalidEvidence):
		return ErrInvalidEvidence
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return ErrEvidenceUnavailable
	}
}

func retryEvidenceSettlement() identityverification.SettlementCommitResult {
	return identityverification.SettlementCommitResult{Outcome: identityverification.SettlementCommitRetry,
		FailureCode: "resolver_unavailable"}
}

func permanentEvidenceSettlement(failureCode string) identityverification.SettlementCommitResult {
	return identityverification.SettlementCommitResult{Outcome: identityverification.SettlementCommitPermanent,
		FailureCode: failureCode}
}

func cloneRuntimeEvidence(value ResolvedEvidence) ResolvedEvidence {
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
