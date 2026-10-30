package identityverification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	SettlementCommitPending   = "commit_pending"
	SettlementLeased          = "leased"
	SettlementRetryWait       = "retry_wait"
	SettlementSettled         = "settled"
	SettlementPermanentFailed = "permanent_failed"

	SettlementCommitSucceeded = "settled"
	SettlementCommitRetry     = "retry"
	SettlementCommitPermanent = "permanent_failed"

	defaultSettlementLease      = time.Minute
	defaultSettlementRetryDelay = time.Minute
	defaultSettlementAttempts   = 8
)

type SettlementCommitRequest struct {
	ResolverName        string
	ResolverReference   string
	TenantScopeID       uuid.UUID
	ActorUserID         uuid.UUID
	CaseID              uuid.UUID
	IdempotencyKey      string
	RequestDigest       [32]byte
	EvidenceClaimDigest [32]byte
}

type SettlementCommitResult struct {
	Outcome     string
	FailureCode string
}

type SettlementCommitter interface {
	Commit(context.Context, SettlementCommitRequest) (SettlementCommitResult, error)
}

type SettlementWorkerConfig struct {
	Clock         Clock
	NewID         IDGenerator
	LeaseDuration time.Duration
	RetryDelay    time.Duration
	MaxAttempts   int
}

type SettlementWorker struct {
	pool          *pgxpool.Pool
	auditor       AuditAppender
	committer     SettlementCommitter
	now           Clock
	newID         IDGenerator
	leaseDuration time.Duration
	retryDelay    time.Duration
	maxAttempts   int
}

type settlementClaim struct {
	id                  uuid.UUID
	tenantScopeID       uuid.UUID
	actorUserID         uuid.UUID
	caseID              uuid.UUID
	idempotencyKey      string
	requestDigest       [32]byte
	evidenceClaimDigest [32]byte
	resolverName        string
	resolverReference   string
	revision            int64
	attemptCount        int
	availableAt         time.Time
	leaseToken          *uuid.UUID
	leaseExpiresAt      *time.Time
}

func NewSettlementWorker(pool *pgxpool.Pool, auditor AuditAppender, committer SettlementCommitter,
	config SettlementWorkerConfig,
) (*SettlementWorker, error) {
	if pool == nil || auditor == nil || committer == nil {
		return nil, ErrInvalidService
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.NewID == nil {
		config.NewID = uuid.NewV7
	}
	if config.LeaseDuration == 0 {
		config.LeaseDuration = defaultSettlementLease
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = defaultSettlementRetryDelay
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = defaultSettlementAttempts
	}
	if config.LeaseDuration <= 0 || config.RetryDelay <= 0 || config.MaxAttempts < 1 {
		return nil, ErrInvalidService
	}
	return &SettlementWorker{pool: pool, auditor: auditor, committer: committer, now: config.Clock,
		newID: config.NewID, leaseDuration: config.LeaseDuration, retryDelay: config.RetryDelay,
		maxAttempts: config.MaxAttempts}, nil
}

func (worker *SettlementWorker) RunOnce(ctx context.Context) (bool, error) {
	claim, found, err := worker.claim(ctx)
	if err != nil {
		return found, fmt.Errorf("claim identity verification settlement: %w", mapStoreError(err))
	}
	if !found {
		return false, nil
	}
	result, commitErr := worker.committer.Commit(ctx, SettlementCommitRequest{
		ResolverName: claim.resolverName, ResolverReference: claim.resolverReference,
		TenantScopeID: claim.tenantScopeID, ActorUserID: claim.actorUserID, CaseID: claim.caseID,
		IdempotencyKey: claim.idempotencyKey, RequestDigest: claim.requestDigest,
		EvidenceClaimDigest: claim.evidenceClaimDigest,
	})
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if commitErr != nil {
		result = SettlementCommitResult{Outcome: SettlementCommitRetry, FailureCode: "resolver_unavailable"}
	}
	if err := worker.finish(ctx, claim, result); err != nil {
		return true, fmt.Errorf("complete identity verification settlement: %w", mapStoreError(err))
	}
	return true, nil
}

func (worker *SettlementWorker) claim(ctx context.Context) (settlementClaim, bool, error) {
	now := storeTime(worker.now())
	tx, err := worker.pool.Begin(ctx)
	if err != nil {
		return settlementClaim{}, false, fmt.Errorf("begin identity verification settlement claim: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var claim settlementClaim
	var requestDigest, evidenceClaimDigest []byte
	err = tx.QueryRow(ctx, `SELECT id,tenant_scope_id,actor_user_id,case_id,idempotency_key,
		request_digest,evidence_claim_digest,resolver_name,resolver_reference,
		revision,attempt_count,available_at,lease_token,lease_expires_at
		FROM identity_verification_evidence_settlements
		WHERE (state IN ('commit_pending','retry_wait') AND available_at <= $1)
		   OR (state='leased' AND lease_expires_at <= $1)
		ORDER BY CASE WHEN state='leased' THEN lease_expires_at ELSE available_at END, id
		FOR UPDATE SKIP LOCKED LIMIT 1`, now).Scan(&claim.id, &claim.tenantScopeID, &claim.actorUserID,
		&claim.caseID, &claim.idempotencyKey, &requestDigest, &evidenceClaimDigest,
		&claim.resolverName, &claim.resolverReference, &claim.revision,
		&claim.attemptCount, &claim.availableAt, &claim.leaseToken, &claim.leaseExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return settlementClaim{}, false, nil
	}
	if err != nil {
		return settlementClaim{}, false, fmt.Errorf("select identity verification settlement claim: %w", err)
	}
	if len(requestDigest) != len(claim.requestDigest) ||
		len(evidenceClaimDigest) != len(claim.evidenceClaimDigest) {
		return settlementClaim{}, false, errors.New("select identity verification settlement claim: invalid digest")
	}
	copy(claim.requestDigest[:], requestDigest)
	copy(claim.evidenceClaimDigest[:], evidenceClaimDigest)
	token, err := worker.newID()
	if err != nil {
		return settlementClaim{}, false, fmt.Errorf("generate identity verification settlement lease: %w", err)
	}
	if token == uuid.Nil {
		return settlementClaim{}, false, errors.New("generate identity verification settlement lease: nil UUID")
	}
	leaseExpiresAt := now.Add(worker.leaseDuration)
	command, err := tx.Exec(ctx, `UPDATE identity_verification_evidence_settlements
		SET state='leased',revision=revision+1,attempt_count=attempt_count+1,
			lease_token=$3,lease_expires_at=$4,last_failure_code=NULL,updated_at=$5
		WHERE id=$1 AND revision=$2`, claim.id, claim.revision, token, leaseExpiresAt, now)
	if err != nil {
		return settlementClaim{}, false, fmt.Errorf("lease identity verification settlement: %w", err)
	}
	if command.RowsAffected() != 1 {
		return settlementClaim{}, false, ErrSettlementClaimLost
	}
	if err := tx.Commit(ctx); err != nil {
		return settlementClaim{}, false, fmt.Errorf("commit identity verification settlement lease: %w", err)
	}
	claim.revision++
	claim.attemptCount++
	claim.leaseToken = &token
	claim.leaseExpiresAt = &leaseExpiresAt
	return claim, true, nil
}

func (worker *SettlementWorker) finish(ctx context.Context, claim settlementClaim,
	result SettlementCommitResult,
) error {
	now := storeTime(worker.now())
	state, failureCode := result.Outcome, result.FailureCode
	switch state {
	case SettlementCommitSucceeded:
		failureCode = ""
	case SettlementCommitRetry, SettlementCommitPermanent:
		if !validFailureCode(failureCode) {
			failureCode = "resolver_invalid_result"
		}
	default:
		state, failureCode = SettlementCommitRetry, "resolver_invalid_result"
	}
	if state == SettlementCommitRetry && claim.attemptCount >= worker.maxAttempts {
		state, failureCode = SettlementCommitPermanent, "settlement_attempts_exhausted"
	}

	tx, err := worker.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin identity verification settlement completion: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var command pgconnCommandTag
	switch state {
	case SettlementCommitSucceeded:
		command, err = execSettlementCAS(ctx, tx, claim, `state='settled',lease_token=NULL,
			lease_expires_at=NULL,last_failure_code=NULL,updated_at=$4,settled_at=$4`, now)
	case SettlementCommitPermanent:
		command, err = execSettlementCAS(ctx, tx, claim, `state='permanent_failed',lease_token=NULL,
			lease_expires_at=NULL,last_failure_code=$5,updated_at=$4,permanent_failed_at=$4`, now, failureCode)
	default:
		command, err = execSettlementCAS(ctx, tx, claim, `state='retry_wait',lease_token=NULL,
			lease_expires_at=NULL,last_failure_code=$5,available_at=$6,updated_at=$4`, now,
			failureCode, now.Add(worker.retryDelay))
	}
	if err != nil {
		return fmt.Errorf("finish identity verification settlement: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrSettlementClaimLost
	}
	if state == SettlementCommitSucceeded || state == SettlementCommitPermanent {
		action := "identity_verification.evidence_settlement.settled"
		storedState := SettlementSettled
		if state == SettlementCommitPermanent {
			action = "identity_verification.evidence_settlement.permanent_failed"
			storedState = SettlementPermanentFailed
		}
		if err := appendSettlementAudit(ctx, tx, worker.auditor, claim.tenantScopeID, nil, claim.id,
			action, "settlement-worker", storedState, claim.revision+1, claim.attemptCount,
			failureCode); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit identity verification settlement completion: %w", err)
	}
	return nil
}

type pgconnCommandTag interface {
	RowsAffected() int64
}

func execSettlementCAS(ctx context.Context, tx pgx.Tx, claim settlementClaim, assignments string,
	now time.Time, args ...any,
) (pgconnCommandTag, error) {
	query := `UPDATE identity_verification_evidence_settlements SET ` + assignments + `,revision=revision+1
		WHERE id=$1 AND revision=$2 AND state='leased' AND lease_token=$3`
	values := []any{claim.id, claim.revision, *claim.leaseToken, now}
	values = append(values, args...)
	return tx.Exec(ctx, query, values...)
}

func (s *Service) RequeueSettlement(ctx context.Context, actor Actor,
	request RequeueSettlementRequest,
) (EvidenceSettlement, error) {
	if !validActor(actor) || request.SettlementID == uuid.Nil || request.ExpectedRevision < 1 ||
		len(request.ReasonCode) > 64 || !reasonPattern.MatchString(request.ReasonCode) ||
		len(request.RequestID) > 128 || !metadataPattern.MatchString(request.RequestID) {
		return EvidenceSettlement{}, ErrInvalidInput
	}
	var result EvidenceSettlement
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeWrite(ctx, tx, actor, actor.ScopeID, permissionSettlementRequeue); err != nil {
			return err
		}
		var state string
		err := tx.QueryRow(ctx, `SELECT id,tenant_scope_id,case_id,state,revision,attempt_count,
			available_at,updated_at FROM identity_verification_evidence_settlements
			WHERE id=$1 FOR UPDATE`, request.SettlementID).Scan(&result.ID, &result.TenantScopeID,
			&result.CaseID, &state, &result.Revision, &result.AttemptCount, &result.AvailableAt,
			&result.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if result.TenantScopeID != actor.ScopeID {
			return ErrPermissionDenied
		}
		if result.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if state != SettlementPermanentFailed {
			return ErrInvalidTransition
		}
		now := storeTime(s.now())
		command, err := tx.Exec(ctx, `UPDATE identity_verification_evidence_settlements
			SET state='retry_wait',revision=revision+1,attempt_count=0,available_at=$3,
				lease_token=NULL,lease_expires_at=NULL,last_failure_code=NULL,updated_at=$3,
				settled_at=NULL,permanent_failed_at=NULL
			WHERE id=$1 AND revision=$2 AND state='permanent_failed'`, result.ID, result.Revision, now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result.State = SettlementRetryWait
		result.Revision++
		result.AttemptCount = 0
		result.AvailableAt = now
		result.UpdatedAt = now
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action:       "identity_verification.evidence_settlement.requeued",
			ResourceType: "identity_verification_evidence_settlement", ResourceID: result.ID.String(),
			RequestID: request.RequestID, Result: "success", Payload: map[string]any{
				"state": result.State, "revision": result.Revision, "attempt_count": result.AttemptCount,
				"reason_code": request.ReasonCode,
			}})
	})
	if err != nil {
		return EvidenceSettlement{}, fmt.Errorf("requeue identity verification evidence settlement: %w", mapStoreError(err))
	}
	return result, nil
}

func appendSettlementAudit(ctx context.Context, tx pgx.Tx, auditor AuditAppender, scopeID uuid.UUID,
	actorUserID *uuid.UUID, settlementID uuid.UUID, action, requestID, state string, revision int64,
	attemptCount int, failureCode string,
) error {
	payload := map[string]any{"state": state, "revision": revision, "attempt_count": attemptCount}
	if failureCode != "" {
		payload["failure_code"] = failureCode
	}
	return auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, ActorUserID: actorUserID,
		Action: action, ResourceType: "identity_verification_evidence_settlement",
		ResourceID: settlementID.String(), RequestID: requestID, Result: "success", Payload: payload})
}

func validFailureCode(value string) bool {
	return len(value) <= 64 && reasonPattern.MatchString(value)
}
