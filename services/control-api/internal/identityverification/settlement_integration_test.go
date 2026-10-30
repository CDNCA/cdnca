//go:build integration

package identityverification

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type scriptedSettlementCommitter struct {
	mu      sync.Mutex
	results []SettlementCommitResult
	errors  []error
	calls   []SettlementCommitRequest
}

func (committer *scriptedSettlementCommitter) Commit(_ context.Context,
	request SettlementCommitRequest,
) (SettlementCommitResult, error) {
	committer.mu.Lock()
	defer committer.mu.Unlock()
	committer.calls = append(committer.calls, request)
	index := len(committer.calls) - 1
	var result SettlementCommitResult
	if index < len(committer.results) {
		result = committer.results[index]
	}
	var err error
	if index < len(committer.errors) {
		err = committer.errors[index]
	}
	return result, err
}

func TestEvidenceSettlementSubmitGateReplayConflictAndRollback(t *testing.T) {
	fixture := newVerificationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	request := validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xd1), "settlement-create")
	outcome, err := fixture.service.CreateDraftWithSettlement(ctx, fixture.applicant.Actor, request)
	if err != nil || !outcome.TransactionStarted || !outcome.AuthorizationPassed || !outcome.SettlementBound {
		t.Fatalf("CreateDraftWithSettlement() = %#v, %v", outcome, err)
	}
	if _, err := fixture.service.Submit(ctx, fixture.applicant.Actor,
		mutation(outcome.Case, "settlement-pending-submit")); !errors.Is(err, ErrEvidenceSettlementPending) {
		t.Fatalf("Submit(before settlement) error = %v", err)
	}

	replayed, err := fixture.service.CreateDraftWithSettlement(ctx, fixture.applicant.Actor, request)
	if err != nil || !replayed.Case.Replayed || replayed.Case.ID != outcome.Case.ID ||
		!replayed.AuthorizationPassed || !replayed.SettlementBound {
		t.Fatalf("CreateDraftWithSettlement(replay) = %#v, %v", replayed, err)
	}
	assertSettlementCount(t, fixture, request.IdempotencyKey, 1)

	conflict := request
	conflict.ResolverReference += "-different"
	if _, err := fixture.service.CreateDraftWithSettlement(ctx, fixture.applicant.Actor, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same-key binding conflict error = %v", err)
	}
	stolen := request
	stolen.IdempotencyKey = "settlement-stolen-reference"
	stolen.RequestID = "settlement-stolen-reference-request"
	if _, err := fixture.service.CreateDraftWithSettlement(ctx, fixture.applicant.Actor, stolen); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("resolver reference reuse error = %v", err)
	}

	before := counts(t, fixture.pool, "identity_verification_cases",
		"identity_verification_evidence_settlements", "identity_verification_write_requests", "audit_events")
	failingService := newAuthorizedTestService(t, fixture.pool, failingAudit{}, Config{
		Clock: fixture.clock.now, ReviewTTL: 2 * time.Hour, RetentionPeriod: 24 * time.Hour,
	})
	failedRequest := validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xd2), "settlement-rollback")
	failed, err := failingService.CreateDraftWithSettlement(ctx, fixture.applicant.Actor, failedRequest)
	if !errors.Is(err, ErrUnavailable) || !failed.TransactionStarted || !failed.AuthorizationPassed ||
		failed.SettlementBound {
		t.Fatalf("CreateDraftWithSettlement(audit failure) = %#v, %v", failed, err)
	}
	after := counts(t, fixture.pool, "identity_verification_cases",
		"identity_verification_evidence_settlements", "identity_verification_write_requests", "audit_events")
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("atomic create rollback counts before=%v after=%v", before, after)
	}

	concurrentRequest := validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xd3), "settlement-concurrent")
	start := make(chan struct{})
	type createResult struct {
		outcome CreateDraftOutcome
		err     error
	}
	results := make(chan createResult, 2)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(start) }) }
	collected := 0
	defer func() {
		cancel()
		release()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cleanupCancel()
		for collected < 2 {
			select {
			case <-results:
				collected++
			case <-cleanupCtx.Done():
				return
			}
		}
	}()
	for range 2 {
		go func() {
			select {
			case <-start:
			case <-ctx.Done():
				results <- createResult{err: ctx.Err()}
				return
			}
			value, callErr := fixture.service.CreateDraftWithSettlement(ctx, fixture.applicant.Actor,
				concurrentRequest)
			results <- createResult{value, callErr}
		}()
	}
	release()
	var first, second createResult
	select {
	case first = <-results:
		collected++
	case <-ctx.Done():
		t.Fatalf("first concurrent create worker did not finish: %v", ctx.Err())
	}
	select {
	case second = <-results:
		collected++
	case <-ctx.Done():
		t.Fatalf("second concurrent create worker did not finish: %v", ctx.Err())
	}
	if first.err != nil || second.err != nil || first.outcome.Case.ID != second.outcome.Case.ID ||
		first.outcome.Case.Replayed == second.outcome.Case.Replayed {
		t.Fatalf("concurrent create results = %#v/%v %#v/%v", first.outcome, first.err,
			second.outcome, second.err)
	}
	assertSettlementCount(t, fixture, concurrentRequest.IdempotencyKey, 1)
}

func TestEvidenceSettlementWorkerRetryLeaseExpiryExhaustionAndRequeue(t *testing.T) {
	fixture := newVerificationFixture(t)
	ctx := context.Background()
	request := validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xe1), "settlement-worker")
	draft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor, request)
	if err != nil {
		t.Fatal(err)
	}
	committer := &scriptedSettlementCommitter{
		results: []SettlementCommitResult{{}, {Outcome: SettlementCommitSucceeded}},
		errors:  []error{errors.New("resolver object secret-123 unavailable")},
	}
	worker := newTestSettlementWorker(t, fixture, committer, 3)
	if processed, err := worker.RunOnce(ctx); err != nil || !processed {
		t.Fatalf("RunOnce(retry) = %t, %v", processed, err)
	}
	assertSettlementState(t, fixture, draft.ID, SettlementRetryWait, 1, 3)
	var failureCode string
	if err := fixture.pool.QueryRow(ctx, `SELECT last_failure_code
		FROM identity_verification_evidence_settlements WHERE case_id=$1`, draft.ID).Scan(&failureCode); err != nil {
		t.Fatal(err)
	}
	if failureCode != "resolver_unavailable" {
		t.Fatalf("unknown resolver failure code = %q", failureCode)
	}
	assertSQLRejected(t, fixture.pool, "evidence settlement is not available", `
		UPDATE identity_verification_evidence_settlements
		SET state='leased',revision=revision+1,attempt_count=attempt_count+1,
			lease_token=$2,lease_expires_at=$3,last_failure_code=NULL,updated_at=$4
		WHERE case_id=$1`, draft.ID, uuid.New(), fixture.clock.now().Add(time.Minute), fixture.clock.now())
	fixture.clock.set(fixture.clock.now().Add(time.Minute))
	if processed, err := worker.RunOnce(ctx); err != nil || !processed {
		t.Fatalf("RunOnce(settle) = %t, %v", processed, err)
	}
	settlementID, _ := assertSettlementState(t, fixture, draft.ID, SettlementSettled, 2, 5)
	if _, err := fixture.service.Submit(ctx, fixture.applicant.Actor,
		mutation(draft, "settlement-worker-submit")); err != nil {
		t.Fatalf("Submit(after settlement) error = %v", err)
	}
	assertSettlementAudit(t, fixture, settlementID,
		"identity_verification.evidence_settlement.settled", 1)

	expiredRequest := validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xe2), "settlement-expired-lease")
	expiredDraft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor, expiredRequest)
	if err != nil {
		t.Fatal(err)
	}
	expiredCommitter := &scriptedSettlementCommitter{results: []SettlementCommitResult{{
		Outcome: SettlementCommitSucceeded,
	}}}
	expiredWorker := newTestSettlementWorker(t, fixture, expiredCommitter, 3)
	claim, found, err := expiredWorker.claim(ctx)
	if err != nil || !found || claim.caseID != expiredDraft.ID || claim.attemptCount != 1 {
		t.Fatalf("claim(expiring lease) = %#v, %t, %v", claim, found, err)
	}
	fixture.clock.set(fixture.clock.now().Add(2 * time.Minute))
	if processed, err := expiredWorker.RunOnce(ctx); err != nil || !processed {
		t.Fatalf("RunOnce(expired lease) = %t, %v", processed, err)
	}
	assertSettlementState(t, fixture, expiredDraft.ID, SettlementSettled, 2, 4)

	exhaustedRequest := validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xe3), "settlement-exhausted")
	exhaustedDraft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor, exhaustedRequest)
	if err != nil {
		t.Fatal(err)
	}
	exhaustedCommitter := &scriptedSettlementCommitter{results: []SettlementCommitResult{{
		Outcome: SettlementCommitRetry, FailureCode: "resolver_timeout",
	}}}
	exhaustedWorker := newTestSettlementWorker(t, fixture, exhaustedCommitter, 1)
	if processed, err := exhaustedWorker.RunOnce(ctx); err != nil || !processed {
		t.Fatalf("RunOnce(exhausted) = %t, %v", processed, err)
	}
	exhaustedID, exhaustedRevision := assertSettlementState(t, fixture, exhaustedDraft.ID,
		SettlementPermanentFailed, 1, 3)
	assertSettlementAudit(t, fixture, exhaustedID,
		"identity_verification.evidence_settlement.permanent_failed", 1)

	if _, err := fixture.service.RequeueSettlement(ctx, fixture.applicant.Actor,
		RequeueSettlementRequest{SettlementID: exhaustedID, ExpectedRevision: exhaustedRevision,
			ReasonCode: "operator_retry", RequestID: "settlement-requeue-denied"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("unauthorized RequeueSettlement error = %v", err)
	}
	requeuer := insertActor(t, fixture.pool, fixture.applicant.ScopeID, "settlement-requeuer",
		permissionSettlementRequeue)
	if _, err := fixture.service.RequeueSettlement(ctx, requeuer.Actor,
		RequeueSettlementRequest{SettlementID: exhaustedID, ExpectedRevision: exhaustedRevision - 1,
			ReasonCode: "operator_retry", RequestID: "settlement-requeue-stale"}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale RequeueSettlement error = %v", err)
	}
	requeued, err := fixture.service.RequeueSettlement(ctx, requeuer.Actor,
		RequeueSettlementRequest{SettlementID: exhaustedID, ExpectedRevision: exhaustedRevision,
			ReasonCode: "operator_retry", RequestID: "settlement-requeue"})
	if err != nil || requeued.State != SettlementRetryWait || requeued.AttemptCount != 0 ||
		requeued.Revision != exhaustedRevision+1 {
		t.Fatalf("RequeueSettlement() = %#v, %v", requeued, err)
	}
	assertSettlementAudit(t, fixture, exhaustedID,
		"identity_verification.evidence_settlement.requeued", 1)
	var auditedReason string
	var failureCodePresent bool
	if err := fixture.pool.QueryRow(ctx, `SELECT payload->>'reason_code', payload ? 'failure_code'
		FROM audit_events WHERE resource_type='identity_verification_evidence_settlement'
		  AND resource_id=$1 AND action='identity_verification.evidence_settlement.requeued'`,
		exhaustedID.String()).Scan(&auditedReason, &failureCodePresent); err != nil {
		t.Fatal(err)
	}
	if auditedReason != "operator_retry" || failureCodePresent {
		t.Fatalf("requeue audit reason=%q failure_code_present=%t", auditedReason, failureCodePresent)
	}

}

func TestEvidenceSettlementCommitSuccessFinalizeFailureRecoversAfterLeaseExpiry(t *testing.T) {
	fixture := newVerificationFixture(t)
	ctx := context.Background()
	draft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xeb), "settlement-finalize-recovery"))
	if err != nil {
		t.Fatal(err)
	}
	committer := &scriptedSettlementCommitter{results: []SettlementCommitResult{
		{Outcome: SettlementCommitSucceeded}, {Outcome: SettlementCommitSucceeded},
	}}
	failingWorker, err := NewSettlementWorker(fixture.pool, failingAudit{}, committer,
		SettlementWorkerConfig{Clock: fixture.clock.now, LeaseDuration: time.Minute,
			RetryDelay: time.Minute, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := failingWorker.RunOnce(ctx); !processed || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("RunOnce(finalize audit failure) = %t, %v", processed, err)
	}
	assertSettlementState(t, fixture, draft.ID, SettlementLeased, 1, 2)
	fixture.clock.set(fixture.clock.now().Add(2 * time.Minute))
	recoveryWorker := newTestSettlementWorker(t, fixture, committer, 1)
	if processed, err := recoveryWorker.RunOnce(ctx); err != nil || !processed {
		t.Fatalf("RunOnce(finalize recovery) = %t, %v", processed, err)
	}
	settlementID, _ := assertSettlementState(t, fixture, draft.ID, SettlementSettled, 2, 4)
	committer.mu.Lock()
	calls := len(committer.calls)
	committer.mu.Unlock()
	if calls != 2 {
		t.Fatalf("idempotent Commit calls after finalize failure = %d", calls)
	}
	assertSettlementAudit(t, fixture, settlementID,
		"identity_verification.evidence_settlement.settled", 1)
}

func TestEvidenceSettlementDatabaseTamperAndEraseGuards(t *testing.T) {
	fixture := newVerificationFixture(t)
	draft, err := fixture.service.CreateDraft(context.Background(), fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xf1), "settlement-tamper"))
	if err != nil {
		t.Fatal(err)
	}
	assertSQLRejected(t, fixture.pool, "payload is immutable", `
		UPDATE identity_verification_evidence_settlements
		SET resolver_reference=resolver_reference || '-tampered',revision=revision+1
		WHERE case_id=$1`, draft.ID)
	assertSQLRejected(t, fixture.pool, "settlements cannot be deleted", `
		DELETE FROM identity_verification_evidence_settlements WHERE case_id=$1`, draft.ID)
	assertSQLRejected(t, fixture.pool, "settlements cannot be truncated", `
		TRUNCATE identity_verification_evidence_settlements CASCADE`)
}

func TestEvidenceSettlementDeferredBindingAndConcurrentWorkers(t *testing.T) {
	fixture := newVerificationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	now := fixture.clock.now()
	tx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	writeID, caseID := uuid.New(), uuid.New()
	digest := bytesOf(32, 0xa1)
	if _, err := tx.Exec(ctx, `INSERT INTO identity_verification_write_requests (
		id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at
	) VALUES($1,$2,$3,'identity_verification.create_draft','deferred-mismatch',$4,$5)`,
		writeID, fixture.applicant.ScopeID, fixture.applicant.UserID, digest, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO identity_verification_cases (
		id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,
		revision,created_at,state_changed_at,retention_until
	) VALUES($1,$2,$3,'personal_initial','draft',$4,1,$5,$5,$6)`, caseID,
		fixture.applicant.ScopeID, fixture.applicant.UserID, bytesOf(32, 0xa2), now,
		now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	insertRawMaterial(t, tx, fixture.applicant.Actor, caseID, now, 1, MaterialIdentityDocument, 0xa3)
	insertRawMaterial(t, tx, fixture.applicant.Actor, caseID, now, 2, MaterialLivenessEvidence, 0xa4)
	insertRawCreationEvent(t, tx, fixture.applicant.Actor, caseID, now)
	if _, err := tx.Exec(ctx, `INSERT INTO identity_verification_evidence_settlements (
		id,tenant_scope_id,actor_user_id,case_id,write_request_id,operation,idempotency_key,
		request_digest,evidence_claim_digest,resolver_name,resolver_reference,state,revision,
		attempt_count,available_at,created_at,updated_at
	) VALUES($1,$2,$3,$4,$5,'identity_verification.create_draft','deferred-mismatch',$6,$7,
		'test-resolver','deferred-mismatch-reference','commit_pending',1,0,$8,$8,$8)`, uuid.New(),
		fixture.applicant.ScopeID, fixture.applicant.UserID, caseID, writeID, digest,
		bytesOf(32, 0xa5), now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE identity_verification_write_requests
		SET response_body=jsonb_build_object('id',$2::text),completed_at=$3 WHERE id=$1`,
		writeID, uuid.New(), now); err != nil {
		t.Fatal(err)
	}
	assertCommitRejected(t, tx, "evidence settlement binding is incomplete")

	fkTx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fkCaseID := uuid.New()
	if _, err := fkTx.Exec(ctx, `INSERT INTO identity_verification_cases (
		id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,
		revision,created_at,state_changed_at,retention_until
	) VALUES($1,$2,$3,'personal_initial','draft',$4,1,$5,$5,$6)`, fkCaseID,
		fixture.applicant.ScopeID, fixture.applicant.UserID, bytesOf(32, 0xa7), now,
		now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, fkErr := fkTx.Exec(ctx, `INSERT INTO identity_verification_evidence_settlements (
		id,tenant_scope_id,actor_user_id,case_id,write_request_id,operation,idempotency_key,
		request_digest,evidence_claim_digest,resolver_name,resolver_reference,state,revision,
		attempt_count,available_at,created_at,updated_at
	) VALUES($1,$2,$3,$4,$5,'identity_verification.create_draft','fk-mismatch',$6,$7,
		'test-resolver','fk-mismatch-reference','commit_pending',1,0,$8,$8,$8)`, uuid.New(),
		fixture.applicant.ScopeID, fixture.applicant.UserID, fkCaseID, uuid.New(), bytesOf(32, 0xa8),
		bytesOf(32, 0xa9), now)
	var pgErr *pgconn.PgError
	if !errors.As(fkErr, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("settlement composite FK error = %v, want SQLSTATE 23503", fkErr)
	}
	_ = fkTx.Rollback(ctx)

	draft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xa6), "concurrent-worker"))
	if err != nil {
		t.Fatal(err)
	}
	committer := &scriptedSettlementCommitter{results: []SettlementCommitResult{{
		Outcome: SettlementCommitSucceeded,
	}}}
	worker := newTestSettlementWorker(t, fixture, committer, 3)
	start := make(chan struct{})
	type workerResult struct {
		processed bool
		err       error
	}
	results := make(chan workerResult, 2)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(start) }) }
	collected := 0
	defer func() {
		cancel()
		release()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cleanupCancel()
		for collected < 2 {
			select {
			case <-results:
				collected++
			case <-cleanupCtx.Done():
				return
			}
		}
	}()
	for range 2 {
		go func() {
			select {
			case <-start:
			case <-ctx.Done():
				results <- workerResult{err: ctx.Err()}
				return
			}
			processed, runErr := worker.RunOnce(ctx)
			results <- workerResult{processed: processed, err: runErr}
		}()
	}
	release()
	var first, second workerResult
	select {
	case first = <-results:
		collected++
	case <-ctx.Done():
		t.Fatalf("first settlement worker did not finish: %v", ctx.Err())
	}
	select {
	case second = <-results:
		collected++
	case <-ctx.Done():
		t.Fatalf("second settlement worker did not finish: %v", ctx.Err())
	}
	processed := 0
	for _, result := range []workerResult{first, second} {
		if result.err != nil {
			t.Fatalf("concurrent worker error = %v", result.err)
		}
		if result.processed {
			processed++
		}
	}
	committer.mu.Lock()
	calls := len(committer.calls)
	committer.mu.Unlock()
	if processed != 1 || calls != 1 {
		t.Fatalf("concurrent workers processed=%d commit calls=%d", processed, calls)
	}
	assertSettlementState(t, fixture, draft.ID, SettlementSettled, 1, 3)
}

func newTestSettlementWorker(t *testing.T, fixture *verificationFixture,
	committer SettlementCommitter, maxAttempts int,
) *SettlementWorker {
	t.Helper()
	worker, err := NewSettlementWorker(fixture.pool, audit.New(fixture.pool), committer,
		SettlementWorkerConfig{Clock: fixture.clock.now, LeaseDuration: time.Minute,
			RetryDelay: time.Minute, MaxAttempts: maxAttempts})
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func assertSettlementState(t *testing.T, fixture *verificationFixture, caseID uuid.UUID,
	state string, attempts int, revision int64,
) (uuid.UUID, int64) {
	t.Helper()
	var id uuid.UUID
	var actualState string
	var actualAttempts int
	var actualRevision int64
	if err := fixture.pool.QueryRow(context.Background(), `SELECT id,state,attempt_count,revision
		FROM identity_verification_evidence_settlements WHERE case_id=$1`, caseID).Scan(
		&id, &actualState, &actualAttempts, &actualRevision); err != nil {
		t.Fatal(err)
	}
	if actualState != state || actualAttempts != attempts || actualRevision != revision {
		t.Fatalf("settlement state = %s/%d/%d, want %s/%d/%d", actualState, actualAttempts,
			actualRevision, state, attempts, revision)
	}
	return id, actualRevision
}

func assertSettlementCount(t *testing.T, fixture *verificationFixture, key string, expected int) {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*)
		FROM identity_verification_evidence_settlements
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3`,
		fixture.applicant.ScopeID, fixture.applicant.UserID, key).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("settlement count for %s = %d, want %d", key, count, expected)
	}
}

func assertSettlementAudit(t *testing.T, fixture *verificationFixture, settlementID uuid.UUID,
	action string, expected int,
) {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND resource_type='identity_verification_evidence_settlement'
		  AND resource_id=$2 AND action=$3`, fixture.applicant.ScopeID, settlementID.String(), action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("settlement audit %s count = %d, want %d", action, count, expected)
	}
}
