package edgedeployment

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CertificateActorReference struct {
	UserRevision         int64
	TargetTenantID       uuid.UUID
	TargetTenantRevision int64
}

type CertificatePublicationReceiptState string

const (
	CertificatePublicationReceiptPending   CertificatePublicationReceiptState = "pending"
	CertificatePublicationReceiptSucceeded CertificatePublicationReceiptState = "succeeded"
	CertificatePublicationReceiptFailed    CertificatePublicationReceiptState = "failed"
)

type CertificatePublicationReceiptRequest struct {
	Actor                Actor
	ConfigurationScopeID uuid.UUID
	ActorReference       CertificateActorReference
	RolloutID            uuid.UUID
	ConfigVersionID      uuid.UUID
	RolloutRevision      int64
}

type CertificatePublicationReceipt struct {
	RolloutID            uuid.UUID
	ConfigurationScopeID uuid.UUID
	ConfigVersionID      uuid.UUID
	RolloutRevision      int64
	State                CertificatePublicationReceiptState
	Total                int
	Pending              int
	Running              int
	Succeeded            int
	Failed               int
	Cancelled            int
}

type CertificatePublisherAuthorizer interface {
	AuthorizeCertificatePublication(
		context.Context,
		pgx.Tx,
		Actor,
		uuid.UUID,
		CertificateActorReference,
	) (uuid.UUID, uuid.UUID, error)
}

type CertificatePublisherStore struct {
	core       *Store
	authorizer CertificatePublisherAuthorizer
}

func NewCertificatePublisherStore(
	core *Store,
	authorizer CertificatePublisherAuthorizer,
) (*CertificatePublisherStore, error) {
	if core == nil || authorizer == nil || nilInterface(authorizer) {
		return nil, ErrInvalidInput
	}
	return &CertificatePublisherStore{core: core, authorizer: authorizer}, nil
}

func (store *CertificatePublisherStore) ReplaceSecretRollout(
	ctx context.Context,
	request SecretReplacementRequest,
	source SecretReplacementSource,
) (SecretReplacementResult, error) {
	if store == nil || store.core == nil {
		return SecretReplacementResult{}, ErrUnavailable
	}
	return store.core.ReplaceSecretRollout(ctx, request, source)
}

func (store *CertificatePublisherStore) CreateCertificateSecretRolloutFromSourceTx(
	ctx context.Context,
	tx pgx.Tx,
	request SecretRolloutRequest,
	reference CertificateActorReference,
	domainRequestDigest [sha256.Size]byte,
	source CertificateSecretRolloutSource,
) (CreateRolloutResult, error) {
	if store == nil || store.core == nil || store.authorizer == nil || nilInterface(store.authorizer) {
		return CreateRolloutResult{}, ErrUnavailable
	}
	if err := store.core.protectedOperationError(); err != nil {
		return CreateRolloutResult{}, err
	}
	if ctx == nil || tx == nil || source == nil || len(request.CanonicalSnapshot) != 0 ||
		request.PayloadDigest != ([sha256.Size]byte{}) || domainRequestDigest == ([sha256.Size]byte{}) ||
		!validCertificateActorReference(reference) || request.GeneratorName != certificateGeneratorName ||
		request.GeneratorVersion != certificateGeneratorVersion {
		return CreateRolloutResult{}, ErrInvalidInput
	}
	now := store.core.now().UTC().Truncate(time.Microsecond)
	normalized, err := normalizeSecretRolloutFixedRequest(request, now)
	if err != nil {
		return CreateRolloutResult{}, err
	}
	actorUserID, authenticationScopeID, err := store.authorizer.AuthorizeCertificatePublication(
		ctx, tx, normalized.Actor, normalized.ConfigurationScopeID, reference,
	)
	if err != nil {
		return CreateRolloutResult{}, stableSecretOperationError(err)
	}
	if actorUserID != normalized.Actor.UserID || authenticationScopeID != normalized.Actor.ScopeID {
		return CreateRolloutResult{}, ErrUnauthenticated
	}
	permissions := []string{certificateManagePermission}
	normalized.Digest, err = secretRolloutSourceDigest(normalized, domainRequestDigest, permissions)
	if err != nil {
		return CreateRolloutResult{}, err
	}
	if err := lockSecretRolloutIdempotency(ctx, tx, normalized.ConfigurationScopeID, normalized.IdempotencyKey); err != nil {
		return CreateRolloutResult{}, err
	}
	if replay, found, replayErr := loadSecretRolloutReplay(ctx, tx, normalized); replayErr != nil {
		return CreateRolloutResult{}, replayErr
	} else if found {
		return CreateRolloutResult{Rollout: replay, Replayed: true}, nil
	}

	material, err := callCertificateSecretRolloutSource(ctx, tx, source)
	if err != nil {
		clearBytes(material.CanonicalSnapshot)
		return CreateRolloutResult{}, err
	}
	materialRequest := normalized.SecretRolloutRequest
	materialRequest.CanonicalSnapshot = material.CanonicalSnapshot
	materialRequest.PayloadDigest = material.PayloadDigest
	full, normalizeErr := normalizeSecretRolloutRequest(materialRequest, now)
	clearBytes(material.CanonicalSnapshot)
	if normalizeErr != nil || material.Builder == nil {
		if normalizeErr != nil {
			return CreateRolloutResult{}, normalizeErr
		}
		return CreateRolloutResult{}, ErrInvalidInput
	}
	full.Digest = normalized.Digest
	defer clearBytes(full.CanonicalSnapshot)
	return store.core.persistSecretRollout(
		ctx, tx, full, actorUserID, authenticationScopeID, material.Builder, now,
	)
}

func (store *CertificatePublisherStore) ResolveCertificatePublicationReceipt(
	ctx context.Context,
	request CertificatePublicationReceiptRequest,
) (CertificatePublicationReceipt, error) {
	if store == nil || store.core == nil || store.authorizer == nil || nilInterface(store.authorizer) {
		return CertificatePublicationReceipt{}, ErrUnavailable
	}
	if err := store.core.protectedOperationError(); err != nil {
		return CertificatePublicationReceipt{}, err
	}
	if ctx == nil || !validActor(request.Actor) || request.ConfigurationScopeID == uuid.Nil ||
		!validCertificateActorReference(request.ActorReference) || request.RolloutID == uuid.Nil ||
		request.ConfigVersionID == uuid.Nil || request.RolloutRevision < 1 {
		return CertificatePublicationReceipt{}, ErrInvalidInput
	}
	var receipt CertificatePublicationReceipt
	err := pgx.BeginTxFunc(ctx, store.core.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		actorUserID, authenticationScopeID, err := store.authorizer.AuthorizeCertificatePublication(
			ctx, tx, request.Actor, request.ConfigurationScopeID, request.ActorReference,
		)
		if err != nil {
			return stableSecretOperationError(err)
		}
		if actorUserID != request.Actor.UserID || authenticationScopeID != request.Actor.ScopeID {
			return ErrUnauthenticated
		}
		now := store.core.now().UTC().Truncate(time.Microsecond)
		snapshot, err := loadRolloutSnapshot(
			ctx, tx, request.ConfigurationScopeID, request.RolloutID, now,
		)
		if err != nil {
			return err
		}
		if snapshot.ConfigVersionID != request.ConfigVersionID || snapshot.Revision != request.RolloutRevision {
			return ErrRevisionConflict
		}
		receipt, err = certificatePublicationReceiptFromSnapshot(snapshot)
		return err
	})
	if err != nil {
		return CertificatePublicationReceipt{}, stableSecretOperationError(err)
	}
	return receipt, nil
}

func certificatePublicationReceiptFromSnapshot(
	snapshot RolloutSnapshot,
) (CertificatePublicationReceipt, error) {
	progress := snapshot.Progress
	observed := progress.Pending + progress.Running + progress.Succeeded + progress.Failed + progress.Cancelled
	if snapshot.ID == uuid.Nil || snapshot.ConfigurationScopeID == uuid.Nil || snapshot.ConfigVersionID == uuid.Nil ||
		snapshot.Revision < 1 || progress.Total < 1 || observed != progress.Total {
		return CertificatePublicationReceipt{}, ErrUnavailable
	}
	receipt := CertificatePublicationReceipt{
		RolloutID: snapshot.ID, ConfigurationScopeID: snapshot.ConfigurationScopeID,
		ConfigVersionID: snapshot.ConfigVersionID, RolloutRevision: snapshot.Revision,
		Total: progress.Total, Pending: progress.Pending, Running: progress.Running,
		Succeeded: progress.Succeeded, Failed: progress.Failed, Cancelled: progress.Cancelled,
	}
	switch snapshot.State {
	case RolloutStateQueued, RolloutStateRunning:
		if progress.Succeeded+progress.Failed+progress.Cancelled == progress.Total {
			return CertificatePublicationReceipt{}, ErrUnavailable
		}
		receipt.State = CertificatePublicationReceiptPending
	case RolloutStateSucceeded:
		if progress.Succeeded != progress.Total {
			return CertificatePublicationReceipt{}, ErrUnavailable
		}
		receipt.State = CertificatePublicationReceiptSucceeded
	case RolloutStateFailed, RolloutStatePartialFailed, RolloutStateCancelled:
		if progress.Succeeded+progress.Failed+progress.Cancelled != progress.Total ||
			progress.Failed+progress.Cancelled == 0 {
			return CertificatePublicationReceipt{}, ErrUnavailable
		}
		receipt.State = CertificatePublicationReceiptFailed
	default:
		return CertificatePublicationReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

const (
	certificateGeneratorName    = "cdnca-certificatepublish"
	certificateGeneratorVersion = "1.0.0"
	certificateManagePermission = "certificates.manage"
)

func callCertificateSecretRolloutSource(
	ctx context.Context,
	tx pgx.Tx,
	source CertificateSecretRolloutSource,
) (SecretRolloutMaterial, error) {
	return callSecretRolloutSource(ctx, tx, SecretRolloutSource(source))
}

func validCertificateActorReference(reference CertificateActorReference) bool {
	return reference.UserRevision > 0 && reference.TargetTenantID != uuid.Nil &&
		reference.TargetTenantRevision > 0
}
