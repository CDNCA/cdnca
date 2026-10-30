package jobstate

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	initialRetryDelay = 5 * time.Second
	maximumRetryDelay = 5 * time.Minute
)

func (store *Store) Cancel(ctx context.Context, tenantID, jobID uuid.UUID) (StoredJob, error) {
	if ctx == nil || tenantID == uuid.Nil || jobID == uuid.Nil {
		return StoredJob{}, ErrInvalidRequest
	}
	now := store.timestamp()
	var result StoredJob
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var err error
		result, err = CancelTx(ctx, tx, tenantID, jobID, now)
		return err
	})
	if err != nil {
		return StoredJob{}, fmt.Errorf("persist background job cancellation: %w", err)
	}
	return result, nil
}

func CancelTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, jobID uuid.UUID,
	now time.Time,
) (StoredJob, error) {
	if ctx == nil || tx == nil || tenantID == uuid.Nil || jobID == uuid.Nil || now.IsZero() {
		return StoredJob{}, ErrInvalidRequest
	}
	var state, kind string
	var attempt int
	err := tx.QueryRow(ctx, `
			SELECT state, kind, attempt FROM background_jobs
			WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, jobID).Scan(&state, &kind, &attempt)
	if err == pgx.ErrNoRows {
		return StoredJob{}, ErrNotFound
	}
	if err != nil {
		return StoredJob{}, fmt.Errorf("lock background job cancellation: %w", err)
	}
	if state != string(StateQueued) && state != string(StateRunning) {
		return StoredJob{}, ErrInvalidTransition
	}
	var total, succeeded, failed, cancelled, pending int
	if err := tx.QueryRow(ctx, `
			SELECT count(*)::integer,
			       count(*) FILTER (WHERE state = 'succeeded')::integer,
			       count(*) FILTER (WHERE state = 'failed')::integer,
			       count(*) FILTER (WHERE state = 'cancelled')::integer,
			       count(*) FILTER (WHERE state = 'pending')::integer
			FROM background_job_items WHERE tenant_id=$1 AND job_id=$2`, tenantID, jobID).Scan(
		&total, &succeeded, &failed, &cancelled, &pending); err != nil {
		return StoredJob{}, fmt.Errorf("aggregate cancelled background job: %w", err)
	}
	if _, err := tx.Exec(ctx, `
			UPDATE background_jobs
			SET state='cancelled', cancel_requested_at=$3,
			    completed_count=$4, succeeded_count=$5, failed_count=$6, cancelled_count=$7,
			    lease_id=NULL, lease_owner=NULL, lease_expires_at=NULL, claimable_at=NULL,
			    last_error_code=$8, completed_at=$3, updated_at=$3
			WHERE tenant_id=$1 AND id=$2`, tenantID, jobID, now, total, succeeded,
		failed, cancelled+pending, CodeCancelled); err != nil {
		return StoredJob{}, fmt.Errorf("cancel background job: %w", err)
	}
	if _, err := tx.Exec(ctx, `
			UPDATE background_job_items
			SET state='cancelled', attempt=$3, sequence=0, error_code=$4, completed_at=$5
			WHERE tenant_id=$1 AND job_id=$2 AND state='pending'`,
		tenantID, jobID, attempt, CodeCancelled, now); err != nil {
		return StoredJob{}, fmt.Errorf("cancel background job items: %w", err)
	}
	if state == string(StateRunning) {
		command, err := tx.Exec(ctx, `
				UPDATE background_job_attempts
				SET state='cancelled', completed_at=$4, error_code=$5
				WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND state='running'`,
			tenantID, jobID, attempt, now, CodeCancelled)
		if err != nil {
			return StoredJob{}, fmt.Errorf("cancel background job attempt: %w", err)
		}
		if command.RowsAffected() != 1 {
			return StoredJob{}, ErrClaimLost
		}
	}
	if err := runTerminalHook(ctx, tx, tenantID, jobID, kind, CodeCancelled, now); err != nil {
		return StoredJob{}, err
	}
	return loadStoredJob(ctx, tx, tenantID, jobID, false)
}

func (store *Store) Retry(ctx context.Context, tenantID, jobID uuid.UUID) (StoredJob, error) {
	if ctx == nil || tenantID == uuid.Nil || jobID == uuid.Nil {
		return StoredJob{}, ErrInvalidRequest
	}
	now := store.timestamp()
	var result StoredJob
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var err error
		result, err = RetryTx(ctx, tx, tenantID, jobID, now)
		return err
	})
	if err != nil {
		return StoredJob{}, fmt.Errorf("persist background job retry: %w", err)
	}
	return result, nil
}

func RetryTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, jobID uuid.UUID,
	now time.Time,
) (StoredJob, error) {
	if ctx == nil || tx == nil || tenantID == uuid.Nil || jobID == uuid.Nil || now.IsZero() {
		return StoredJob{}, ErrInvalidRequest
	}
	var state string
	var attempt, maximum, total int
	err := tx.QueryRow(ctx, `
			SELECT state, attempt, max_attempts, total_count FROM background_jobs
			WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, jobID).Scan(&state, &attempt, &maximum, &total)
	if err == pgx.ErrNoRows {
		return StoredJob{}, ErrNotFound
	}
	if err != nil {
		return StoredJob{}, fmt.Errorf("lock background job retry: %w", err)
	}
	if state != string(StateFailed) && state != string(StatePartialFailed) {
		return StoredJob{}, ErrInvalidTransition
	}
	if attempt >= maximum {
		return StoredJob{}, ErrRetriesExhausted
	}
	claimableAt := now.Add(retryDelay(uint32(attempt)))
	var succeeded, cancelled int
	if err := tx.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE state = 'succeeded')::integer,
			       count(*) FILTER (WHERE state = 'cancelled')::integer
			FROM background_job_items WHERE tenant_id=$1 AND job_id=$2`, tenantID, jobID).Scan(&succeeded, &cancelled); err != nil {
		return StoredJob{}, fmt.Errorf("aggregate retried background job: %w", err)
	}
	if succeeded+cancelled == total {
		// A mix of success and producer cancellation has nothing to retry.
		return StoredJob{}, ErrInvalidTransition
	}
	// Only failed items run again; succeeded and producer-cancelled items stay final.
	if _, err := tx.Exec(ctx, `
			UPDATE background_jobs
			SET state='queued', completed_count=$3, succeeded_count=$4,
			    failed_count=0, cancelled_count=$7, claimable_at=$5,
			    last_error_code=NULL, completed_at=NULL, updated_at=$6
		WHERE tenant_id=$1 AND id=$2`, tenantID, jobID, succeeded+cancelled, succeeded, claimableAt, now, cancelled); err != nil {
		return StoredJob{}, fmt.Errorf("retry background job: %w", err)
	}
	if _, err := tx.Exec(ctx, `
			UPDATE background_job_items
			SET state='pending', attempt=0, sequence=0, error_code=NULL, completed_at=NULL
		WHERE tenant_id=$1 AND job_id=$2 AND state='failed'`, tenantID, jobID); err != nil {
		return StoredJob{}, fmt.Errorf("queue failed background job items: %w", err)
	}
	return loadStoredJob(ctx, tx, tenantID, jobID, false)
}

func ReplayTx(ctx context.Context, tx pgx.Tx, input ReplayInput, now time.Time) (StoredJob, error) {
	if ctx == nil || tx == nil || input.TenantID == uuid.Nil || input.JobID == uuid.Nil ||
		input.ActorScopeID == uuid.Nil || input.ActorUserID == uuid.Nil ||
		!validIdempotencyKey(input.IdempotencyKey) ||
		!validSafeText(input.RequestID, maxRequestIDRunes, false) ||
		len(input.RequestDigest) != 32 || now.IsZero() {
		return StoredJob{}, ErrInvalidRequest
	}
	var state string
	var attempt, maximum int
	if err := tx.QueryRow(ctx, `SELECT state,attempt,max_attempts FROM background_jobs
		WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, input.TenantID, input.JobID).Scan(
		&state, &attempt, &maximum); err == pgx.ErrNoRows {
		return StoredJob{}, ErrNotFound
	} else if err != nil {
		return StoredJob{}, fmt.Errorf("lock background job replay: %w", err)
	}
	if (state != string(StateFailed) && state != string(StatePartialFailed)) || attempt < maximum {
		return StoredJob{}, ErrInvalidTransition
	}
	if maximum >= maxAttempts {
		return StoredJob{}, ErrRetriesExhausted
	}
	var deadLetterAttempt int
	if err := tx.QueryRow(ctx, `SELECT attempt FROM background_job_dead_letters
		WHERE tenant_id=$1 AND job_id=$2 ORDER BY attempt DESC LIMIT 1 FOR SHARE`,
		input.TenantID, input.JobID).Scan(&deadLetterAttempt); err == pgx.ErrNoRows {
		return StoredJob{}, ErrInvalidTransition
	} else if err != nil {
		return StoredJob{}, fmt.Errorf("read background job dead letter: %w", err)
	}
	if deadLetterAttempt != attempt {
		return StoredJob{}, ErrInvalidTransition
	}
	newMaximum := maximum + 1
	if _, err := tx.Exec(ctx, `INSERT INTO background_job_replay_facts (
		tenant_id,job_id,dead_letter_attempt,actor_scope_id,actor_user_id,
		idempotency_key,request_digest,request_id,old_max_attempts,new_max_attempts,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, input.TenantID, input.JobID,
		deadLetterAttempt, input.ActorScopeID, input.ActorUserID, input.IdempotencyKey,
		input.RequestDigest, input.RequestID, maximum, newMaximum, now); err != nil {
		return StoredJob{}, fmt.Errorf("record background job replay: %w", err)
	}
	var succeeded, cancelled int
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='succeeded')::integer,
		count(*) FILTER (WHERE state='cancelled')::integer
		FROM background_job_items WHERE tenant_id=$1 AND job_id=$2`, input.TenantID, input.JobID).Scan(&succeeded, &cancelled); err != nil {
		return StoredJob{}, fmt.Errorf("aggregate replayed background job: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE background_jobs SET state='queued',max_attempts=$3,
		completed_count=$4,succeeded_count=$6,failed_count=0,cancelled_count=$7,
		claimable_at=$5,last_error_code=NULL,completed_at=NULL,updated_at=$5
		WHERE tenant_id=$1 AND id=$2`, input.TenantID, input.JobID, newMaximum, succeeded+cancelled, now,
		succeeded, cancelled); err != nil {
		return StoredJob{}, fmt.Errorf("replay background job: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE background_job_items
		SET state='pending',attempt=0,sequence=0,error_code=NULL,completed_at=NULL
		WHERE tenant_id=$1 AND job_id=$2 AND state='failed'`, input.TenantID, input.JobID); err != nil {
		return StoredJob{}, fmt.Errorf("queue replayed background job items: %w", err)
	}
	return loadStoredJob(ctx, tx, input.TenantID, input.JobID, false)
}

func retryDelay(attempt uint32) time.Duration {
	delay := initialRetryDelay
	for current := uint32(1); current < attempt && delay < maximumRetryDelay; current++ {
		delay *= 2
		if delay > maximumRetryDelay {
			return maximumRetryDelay
		}
	}
	return delay
}
