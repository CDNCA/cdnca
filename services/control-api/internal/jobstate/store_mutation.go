package jobstate

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type VoluntaryYieldInput struct {
	TenantID  uuid.UUID
	JobID     uuid.UUID
	Kind      string
	Attempt   uint32
	LeaseID   uuid.UUID
	WorkerID  string
	YieldedAt time.Time
	NotBefore time.Time
}

func VoluntaryYieldTx(ctx context.Context, tx pgx.Tx, input VoluntaryYieldInput) error {
	if ctx == nil || tx == nil || input.JobID == uuid.Nil || input.Attempt == 0 || input.LeaseID == uuid.Nil ||
		validateLeaseFields(input.TenantID, input.Kind, input.WorkerID, 1, time.Second) != nil ||
		input.YieldedAt.IsZero() || !input.NotBefore.After(input.YieldedAt) ||
		input.NotBefore.After(input.YieldedAt.Add(time.Hour)) {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Every statement shares these arguments; the ones a statement does not
	// otherwise use are typed explicitly so the extended protocol can bind them.
	arguments := []any{uuid.New(), input.TenantID, input.JobID, input.Kind, input.Attempt,
		input.LeaseID, input.WorkerID, input.YieldedAt, input.NotBefore}
	command, err := tx.Exec(ctx, `
		INSERT INTO background_job_yield_facts_115(
			id,tenant_id,job_id,kind,attempt,lease_id,worker_id,reason,yielded_at,not_before,yield_xact_id
		)
		SELECT $1,$2,$3,$4,$5,$6,$7,'provider_retry_after',$8,$9,pg_current_xact_id()
		FROM background_jobs job
		JOIN background_job_attempts attempt
		  ON attempt.tenant_id=job.tenant_id AND attempt.job_id=job.id AND attempt.attempt=job.attempt
		WHERE job.tenant_id=$2 AND job.id=$3 AND job.kind=$4 AND job.state='running'
		  AND job.attempt=$5 AND job.lease_id=$6 AND job.lease_owner=$7
		  AND job.attempt<job.max_attempts AND job.lease_expires_at>$8 AND attempt.state='running'
		  AND attempt.attempt=$5 AND attempt.lease_id=$6 AND attempt.worker_id=$7
		  AND attempt.lease_expires_at=job.lease_expires_at`, arguments...)
	if err != nil {
		return fmt.Errorf("record background job voluntary yield: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrClaimLost
	}
	command, err = tx.Exec(ctx, `
		UPDATE background_jobs job
		SET state='queued',lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,
		    claimable_at=$9,last_error_code=NULL,completed_at=NULL,updated_at=$8
		WHERE job.tenant_id=$2 AND job.id=$3 AND job.kind=$4 AND job.state='running'
		  AND job.attempt=$5 AND job.lease_id=$6 AND job.lease_owner=$7
		  AND job.lease_expires_at>$8 AND $1::uuid IS NOT NULL`, arguments...)
	if err != nil {
		return fmt.Errorf("yield background job claim: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrClaimLost
	}
	command, err = tx.Exec(ctx, `
		UPDATE background_job_attempts attempt
		SET state='deferred',completed_at=$8,error_code='provider_retry_after'
		WHERE attempt.tenant_id=$2 AND attempt.job_id=$3 AND attempt.state='running'
		  AND attempt.attempt=$5 AND attempt.lease_id=$6 AND attempt.worker_id=$7
		  AND attempt.lease_expires_at>$8
		  AND $1::uuid IS NOT NULL AND $4::text IS NOT NULL AND $9::timestamptz IS NOT NULL`, arguments...)
	if err != nil {
		return fmt.Errorf("complete deferred background job attempt: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrClaimLost
	}
	return nil
}

func (store *Store) finalizeExhausted(ctx context.Context, tx pgx.Tx, input ClaimInput, now time.Time) error {
	rows, err := tx.Query(ctx, `
		SELECT id, attempt, lease_expires_at
		FROM background_jobs
		WHERE tenant_id=$1 AND kind=$2 AND state='running'
		  AND claimable_at <= $3 AND attempt >= max_attempts
		ORDER BY claimable_at, created_at, id
		FOR UPDATE SKIP LOCKED
		LIMIT $4`, input.TenantID, input.Kind, now, input.Limit)
	if err != nil {
		return fmt.Errorf("select exhausted background jobs: %w", err)
	}
	type exhaustedJob struct {
		id             uuid.UUID
		attempt        uint32
		leaseExpiresAt time.Time
	}
	jobs := make([]exhaustedJob, 0, input.Limit)
	for rows.Next() {
		var job exhaustedJob
		var attempt int
		if err := rows.Scan(&job.id, &attempt, &job.leaseExpiresAt); err != nil {
			rows.Close()
			return fmt.Errorf("scan exhausted background job: %w", err)
		}
		job.attempt = uint32(attempt)
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate exhausted background jobs: %w", err)
	}
	rows.Close()

	for _, job := range jobs {
		itemRows, err := tx.Query(ctx, `
			SELECT item_id FROM background_job_items
			WHERE tenant_id=$1 AND job_id=$2 AND state='pending'
			ORDER BY ordinal FOR UPDATE`, input.TenantID, job.id)
		if err != nil {
			return fmt.Errorf("select exhausted background job items: %w", err)
		}
		itemIDs := make([]string, 0)
		for itemRows.Next() {
			var itemID string
			if err := itemRows.Scan(&itemID); err != nil {
				itemRows.Close()
				return fmt.Errorf("scan exhausted background job item: %w", err)
			}
			itemIDs = append(itemIDs, itemID)
		}
		if err := itemRows.Err(); err != nil {
			itemRows.Close()
			return fmt.Errorf("iterate exhausted background job items: %w", err)
		}
		itemRows.Close()
		for _, itemID := range itemIDs {
			if _, err := tx.Exec(ctx, `
				INSERT INTO background_job_results (
					id, tenant_id, job_id, item_id, attempt, sequence,
					state, error_code, source, reported_at
				) VALUES ($1,$2,$3,$4,$5,0,'failed',$6,'system',$7)`,
				uuid.New(), input.TenantID, job.id, itemID, job.attempt,
				CodeRetriesExhausted, job.leaseExpiresAt); err != nil {
				return fmt.Errorf("record exhausted background job result: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `
			WITH counts AS (
				SELECT count(*)::integer AS completed,
				       count(*) FILTER (WHERE state = 'succeeded')::integer AS succeeded,
				       count(*) FILTER (WHERE state IN ('failed','pending'))::integer AS failed,
				       count(*) FILTER (WHERE state = 'cancelled')::integer AS cancelled
				FROM background_job_items WHERE tenant_id=$1 AND job_id=$2
			)
			UPDATE background_jobs job
			SET state=CASE WHEN counts.failed=job.total_count THEN 'failed' ELSE 'partial_failed' END,
			    completed_count=counts.completed, succeeded_count=counts.succeeded,
			    failed_count=counts.failed, cancelled_count=counts.cancelled,
			    lease_id=NULL, lease_owner=NULL, lease_expires_at=NULL, claimable_at=NULL,
			    last_error_code=$3, completed_at=$4, updated_at=$4
			FROM counts WHERE job.tenant_id=$1 AND job.id=$2`,
			input.TenantID, job.id, CodeRetriesExhausted, now); err != nil {
			return fmt.Errorf("finalize exhausted background job: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE background_job_items
			SET state='failed', attempt=$3, sequence=0, error_code=$4, completed_at=$5
			WHERE tenant_id=$1 AND job_id=$2 AND state='pending'`,
			input.TenantID, job.id, job.attempt, CodeRetriesExhausted, job.leaseExpiresAt); err != nil {
			return fmt.Errorf("fail exhausted background job items: %w", err)
		}
		if err := expireAttempt(ctx, tx, input.TenantID, job.id, job.attempt, now); err != nil {
			return err
		}
		var failedItems int
		if err := tx.QueryRow(ctx, `SELECT failed_count FROM background_jobs
				WHERE tenant_id=$1 AND id=$2`, input.TenantID, job.id).Scan(&failedItems); err != nil {
			return fmt.Errorf("read exhausted background job failed count: %w", err)
		}
		if err := insertDeadLetter(ctx, tx, input.TenantID, job.id, job.attempt,
			CodeRetriesExhausted, failedItems, "lease_expiry", now); err != nil {
			return err
		}
		if err := runTerminalHook(ctx, tx, input.TenantID, job.id, input.Kind, CodeRetriesExhausted, now); err != nil {
			return err
		}
	}
	return nil
}

func (store *Store) Heartbeat(ctx context.Context, input HeartbeatInput) (time.Time, error) {
	if ctx == nil || validateHeartbeat(input) != nil {
		return time.Time{}, ErrInvalidRequest
	}
	now := store.timestamp()
	leaseExpiresAt := now.Add(input.LeaseDuration)
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var state string
		var attempt int
		var leaseID *uuid.UUID
		var owner *string
		var currentExpiry *time.Time
		err := tx.QueryRow(ctx, `
			SELECT state, attempt, lease_id, lease_owner, lease_expires_at
			FROM background_jobs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
			input.TenantID, input.JobID).Scan(&state, &attempt, &leaseID, &owner, &currentExpiry)
		if err == pgx.ErrNoRows {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock heartbeat background job: %w", err)
		}
		if state != string(StateRunning) || uint32(attempt) != input.Attempt || leaseID == nil || *leaseID != input.LeaseID ||
			owner == nil || *owner != input.WorkerID || currentExpiry == nil || !currentExpiry.After(now) {
			return ErrClaimLost
		}
		if _, err := tx.Exec(ctx, `
			UPDATE background_jobs
			SET lease_expires_at=$3, claimable_at=$3, updated_at=$4
			WHERE tenant_id=$1 AND id=$2`, input.TenantID, input.JobID, leaseExpiresAt, now); err != nil {
			return fmt.Errorf("heartbeat background job: %w", err)
		}
		command, err := tx.Exec(ctx, `
			UPDATE background_job_attempts
			SET last_heartbeat_at=$6, lease_expires_at=$7
			WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND lease_id=$4
			  AND worker_id=$5 AND state='running'`, input.TenantID, input.JobID, input.Attempt,
			input.LeaseID, input.WorkerID, now, leaseExpiresAt)
		if err != nil {
			return fmt.Errorf("record background job heartbeat: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrClaimLost
		}
		return nil
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("persist background job heartbeat: %w", err)
	}
	return leaseExpiresAt, nil
}

func (store *Store) Report(ctx context.Context, input ReportInput) (ReportResult, error) {
	if ctx == nil || validateStoreReport(input) != nil {
		return ReportResult{}, ErrInvalidReport
	}
	now := store.timestamp()
	var result ReportResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var err error
		result, err = ReportTx(ctx, tx, input, now)
		return err
	})
	if err != nil {
		return ReportResult{}, fmt.Errorf("persist background job result: %w", err)
	}
	return result, nil
}

func insertDeadLetter(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, jobID uuid.UUID,
	attempt uint32,
	reason string,
	failedItems int,
	source string,
	createdAt time.Time,
) error {
	if _, err := tx.Exec(ctx, `INSERT INTO background_job_dead_letters (
		tenant_id,job_id,attempt,reason_code,failed_item_count,source,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, tenantID, jobID, attempt, reason,
		failedItems, source, createdAt); err != nil {
		return fmt.Errorf("record background job dead letter: %w", err)
	}
	return nil
}

// aggregateState settles a completed job. fix-cacheflow2: an item its
// producer stopped is cancelled, neither success nor failure, the same rule
// the cache operation rollup uses; a mix with no failure is partial_failed
// with code cancelled (nothing to retry, no dead letter).
func aggregateState(total, succeeded, failed, cancelled int) (State, string) {
	switch {
	case succeeded == total:
		return StateSucceeded, ""
	case failed == total:
		return StateFailed, CodeAllItemsFailed
	case cancelled == total:
		return StateCancelled, CodeCancelled
	case failed > 0:
		return StatePartialFailed, CodeItemFailed
	default:
		return StatePartialFailed, CodeCancelled
	}
}
