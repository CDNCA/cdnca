package jobstate

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func CreateTx(ctx context.Context, tx pgx.Tx, input CreateInput, now time.Time) (CreateResult, error) {
	if ctx == nil || tx == nil || now.IsZero() || validateCreate(input) != nil {
		return CreateResult{}, ErrInvalidRequest
	}
	digest, err := digestCreate(input)
	if err != nil {
		return CreateResult{}, err
	}
	jobID := input.JobID
	if jobID == uuid.Nil {
		jobID = uuid.New()
	}
	var tenantExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id=$1)`, input.TenantID).Scan(&tenantExists); err != nil {
		return CreateResult{}, fmt.Errorf("read background job tenant: %w", err)
	}
	if !tenantExists {
		return CreateResult{}, ErrNotFound
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO background_jobs (
			id, tenant_id, kind, subject, idempotency_key, request_digest,
			request_id, trace_id, state, attempt, max_attempts, claimable_at,
			total_count, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'queued',0,$9,$10,$11,$10,$10)
		ON CONFLICT (tenant_id, idempotency_key) DO NOTHING`,
		jobID, input.TenantID, input.Kind, input.Subject, input.IdempotencyKey, digest[:],
		input.RequestID, input.TraceID, input.MaxAttempts, now, len(input.Items))
	if err != nil {
		return CreateResult{}, fmt.Errorf("create background job: %w", err)
	}
	result := CreateResult{}
	if command.RowsAffected() == 0 {
		var existingID uuid.UUID
		var existingDigest []byte
		if err := tx.QueryRow(ctx, `
			SELECT id, request_digest FROM background_jobs
			WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE`,
			input.TenantID, input.IdempotencyKey).Scan(&existingID, &existingDigest); err != nil {
			return CreateResult{}, fmt.Errorf("read idempotent background job: %w", err)
		}
		if !bytes.Equal(existingDigest, digest[:]) || (input.JobID != uuid.Nil && existingID != input.JobID) {
			return CreateResult{}, ErrIdempotencyConflict
		}
		jobID = existingID
		result.Replayed = true
	} else {
		rows := make([][]any, len(input.Items))
		for index, item := range input.Items {
			rows[index] = []any{input.TenantID, jobID, index + 1, item.ItemID, item.NodeID, string(ItemPending)}
		}
		inserted, err := tx.CopyFrom(ctx, pgx.Identifier{"background_job_items"},
			[]string{"tenant_id", "job_id", "ordinal", "item_id", "node_id", "state"}, pgx.CopyFromRows(rows))
		if err != nil {
			return CreateResult{}, fmt.Errorf("create background job items: %w", err)
		}
		if inserted != int64(len(input.Items)) {
			return CreateResult{}, fmt.Errorf("create background job items: inserted %d of %d", inserted, len(input.Items))
		}
	}
	result.Job, err = loadStoredJob(ctx, tx, input.TenantID, jobID, false)
	return result, err
}

// StartTx starts or heartbeats one producer-owned job inside the producer's transaction.
func StartTx(ctx context.Context, tx pgx.Tx, input StartInput, now time.Time) (Claim, error) {
	if ctx == nil || tx == nil || input.JobID == uuid.Nil || now.IsZero() ||
		validateLeaseFields(input.TenantID, input.Kind, input.WorkerID, 1, input.LeaseDuration) != nil {
		return Claim{}, ErrInvalidRequest
	}
	var state string
	var attempt, maximum int
	var leaseID *uuid.UUID
	var owner *string
	var leaseExpiresAt *time.Time
	var updatedAt time.Time
	err := tx.QueryRow(ctx, `SELECT state,attempt,max_attempts,lease_id,lease_owner,lease_expires_at,updated_at
		FROM background_jobs WHERE tenant_id=$1 AND id=$2 AND kind=$3 FOR UPDATE`,
		input.TenantID, input.JobID, input.Kind).Scan(
		&state, &attempt, &maximum, &leaseID, &owner, &leaseExpiresAt, &updatedAt)
	if err == pgx.ErrNoRows {
		return Claim{}, ErrNotFound
	}
	if err != nil {
		return Claim{}, fmt.Errorf("lock producer background job: %w", err)
	}
	heartbeatAt := now.UTC()
	if heartbeatAt.Before(updatedAt) {
		heartbeatAt = updatedAt
	}
	nextExpiry := heartbeatAt.Add(input.LeaseDuration)

	if state == string(StateRunning) {
		if leaseID == nil || owner == nil || *owner != input.WorkerID || leaseExpiresAt == nil || !leaseExpiresAt.After(now) {
			return Claim{}, ErrClaimLost
		}
		if nextExpiry.Before(*leaseExpiresAt) {
			nextExpiry = *leaseExpiresAt
		}
		if _, err := tx.Exec(ctx, `UPDATE background_jobs SET lease_expires_at=$3,claimable_at=$3,updated_at=$4
			WHERE tenant_id=$1 AND id=$2`, input.TenantID, input.JobID, nextExpiry, heartbeatAt); err != nil {
			return Claim{}, fmt.Errorf("heartbeat producer background job: %w", err)
		}
		command, err := tx.Exec(ctx, `UPDATE background_job_attempts SET last_heartbeat_at=$6,lease_expires_at=$7
			WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND lease_id=$4 AND worker_id=$5 AND state='running'`,
			input.TenantID, input.JobID, attempt, *leaseID, input.WorkerID, heartbeatAt, nextExpiry)
		if err != nil || command.RowsAffected() != 1 {
			return Claim{}, ErrClaimLost
		}
		job, err := loadStoredJob(ctx, tx, input.TenantID, input.JobID, false)
		return Claim{Job: job, LeaseID: *leaseID, WorkerID: input.WorkerID, LeaseExpiresAt: nextExpiry}, err
	}
	if state != string(StateQueued) {
		return Claim{}, ErrInvalidTransition
	}
	if attempt >= maximum {
		return Claim{}, ErrRetriesExhausted
	}
	nextAttempt := attempt + 1
	newLeaseID := uuid.New()
	if _, err := tx.Exec(ctx, `WITH counts AS (
		SELECT count(*) FILTER (WHERE state <> 'pending')::integer AS completed,
		       count(*) FILTER (WHERE state='succeeded')::integer AS succeeded,
		       count(*) FILTER (WHERE state='failed')::integer AS failed,
		       count(*) FILTER (WHERE state='cancelled')::integer AS cancelled
		FROM background_job_items WHERE tenant_id=$1 AND job_id=$2)
		UPDATE background_jobs job SET state='running',attempt=$3,started_at=COALESCE(job.started_at,$4),
		updated_at=$4,completed_at=NULL,last_error_code=NULL,lease_id=$5,lease_owner=$6,
		lease_expires_at=$7,claimable_at=$7,completed_count=counts.completed,
		succeeded_count=counts.succeeded,failed_count=counts.failed,cancelled_count=counts.cancelled
		FROM counts WHERE job.tenant_id=$1 AND job.id=$2`, input.TenantID, input.JobID,
		nextAttempt, heartbeatAt, newLeaseID, input.WorkerID, nextExpiry); err != nil {
		return Claim{}, fmt.Errorf("start producer background job: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO background_job_attempts(
		tenant_id,job_id,attempt,lease_id,worker_id,state,started_at,last_heartbeat_at,lease_expires_at)
		VALUES($1,$2,$3,$4,$5,'running',$6,$6,$7)`, input.TenantID, input.JobID,
		nextAttempt, newLeaseID, input.WorkerID, heartbeatAt, nextExpiry); err != nil {
		return Claim{}, fmt.Errorf("record producer background job attempt: %w", err)
	}
	job, err := loadStoredJob(ctx, tx, input.TenantID, input.JobID, false)
	return Claim{Job: job, LeaseID: newLeaseID, WorkerID: input.WorkerID, LeaseExpiresAt: nextExpiry}, err
}

func ReportTx(ctx context.Context, tx pgx.Tx, input ReportInput, now time.Time) (ReportResult, error) {
	if ctx == nil || tx == nil || now.IsZero() || validateStoreReport(input) != nil {
		return ReportResult{}, ErrInvalidReport
	}
	var result ReportResult
	var jobState string
	var currentAttempt, maximumAttempts, total int
	var leaseID *uuid.UUID
	var owner *string
	var leaseExpiresAt *time.Time
	err := tx.QueryRow(ctx, `
			SELECT state, attempt, max_attempts, total_count, lease_id, lease_owner, lease_expires_at
			FROM background_jobs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
		input.TenantID, input.JobID).Scan(
		&jobState, &currentAttempt, &maximumAttempts, &total, &leaseID, &owner, &leaseExpiresAt)
	if err == pgx.ErrNoRows {
		return ReportResult{}, ErrNotFound
	}
	if err != nil {
		return ReportResult{}, fmt.Errorf("lock report background job: %w", err)
	}
	if input.Report.Attempt < uint32(currentAttempt) {
		result.Job, err = loadStoredJob(ctx, tx, input.TenantID, input.JobID, false)
		return result, err
	}
	if input.Report.Attempt > uint32(currentAttempt) || currentAttempt == 0 {
		return ReportResult{}, ErrInvalidReport
	}

	var itemState string
	var itemAttempt int
	var sequence int64
	var errorCode *string
	err = tx.QueryRow(ctx, `
			SELECT state, attempt, sequence, error_code
			FROM background_job_items
			WHERE tenant_id=$1 AND job_id=$2 AND item_id=$3 FOR UPDATE`,
		input.TenantID, input.JobID, input.Report.ItemID).Scan(&itemState, &itemAttempt, &sequence, &errorCode)
	if err == pgx.ErrNoRows {
		return ReportResult{}, ErrInvalidReport
	}
	if err != nil {
		return ReportResult{}, fmt.Errorf("lock background job item: %w", err)
	}
	if ItemState(itemState) != ItemPending {
		if uint32(itemAttempt) == input.Report.Attempt && uint64(sequence) == input.Report.Sequence &&
			(ItemState(itemState) != input.Report.State || stringValue(errorCode) != input.Report.Code) {
			return ReportResult{}, ErrReportConflict
		}
		result.Job, err = loadStoredJob(ctx, tx, input.TenantID, input.JobID, false)
		return result, err
	}
	if State(jobState).Terminal() {
		result.Job, err = loadStoredJob(ctx, tx, input.TenantID, input.JobID, false)
		return result, err
	}
	if jobState == string(StateQueued) && input.Report.Attempt == uint32(currentAttempt) {
		result.Job, err = loadStoredJob(ctx, tx, input.TenantID, input.JobID, false)
		return result, err
	}
	if jobState != string(StateRunning) || leaseID == nil || *leaseID != input.LeaseID ||
		owner == nil || *owner != input.WorkerID || leaseExpiresAt == nil || !leaseExpiresAt.After(now) {
		return ReportResult{}, ErrClaimLost
	}

	var nullableCode any
	if input.Report.Code != "" {
		nullableCode = input.Report.Code
	}
	if _, err := tx.Exec(ctx, `
			INSERT INTO background_job_results (
				id, tenant_id, job_id, item_id, attempt, sequence,
				state, error_code, source, reported_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'worker',$9)`,
		uuid.New(), input.TenantID, input.JobID, input.Report.ItemID,
		input.Report.Attempt, int64(input.Report.Sequence), string(input.Report.State), nullableCode, now); err != nil {
		return ReportResult{}, fmt.Errorf("record background job result: %w", err)
	}
	var completed, succeeded, failed, cancelled int
	if err := tx.QueryRow(ctx, `
			SELECT (count(*) FILTER (WHERE state <> 'pending') + 1)::integer,
			       (count(*) FILTER (WHERE state = 'succeeded') +
			        CASE WHEN $3='succeeded' THEN 1 ELSE 0 END)::integer,
			       (count(*) FILTER (WHERE state = 'failed') +
			        CASE WHEN $3='failed' THEN 1 ELSE 0 END)::integer,
			       (count(*) FILTER (WHERE state = 'cancelled') +
			        CASE WHEN $3='cancelled' THEN 1 ELSE 0 END)::integer
			FROM background_job_items WHERE tenant_id=$1 AND job_id=$2`,
		input.TenantID, input.JobID, string(input.Report.State)).Scan(
		&completed, &succeeded, &failed, &cancelled); err != nil {
		return ReportResult{}, fmt.Errorf("aggregate background job progress: %w", err)
	}
	var finalState State
	var finalCode string
	if completed == total {
		finalState, finalCode = aggregateState(total, succeeded, failed, cancelled)
		var nullableFinalCode any
		if finalCode != "" {
			nullableFinalCode = finalCode
		}
		if _, err := tx.Exec(ctx, `
				UPDATE background_jobs
				SET state=$3, completed_count=$4, succeeded_count=$5, failed_count=$6,
				    cancelled_count=$7, lease_id=NULL, lease_owner=NULL, lease_expires_at=NULL,
				    claimable_at=NULL, last_error_code=$8, completed_at=$9, updated_at=$9
				WHERE tenant_id=$1 AND id=$2`, input.TenantID, input.JobID, string(finalState),
			completed, succeeded, failed, cancelled, nullableFinalCode, now); err != nil {
			return ReportResult{}, fmt.Errorf("complete background job: %w", err)
		}
	} else if _, err := tx.Exec(ctx, `
			UPDATE background_jobs
			SET completed_count=$3, succeeded_count=$4, failed_count=$5,
			    cancelled_count=$6, updated_at=$7
			WHERE tenant_id=$1 AND id=$2`, input.TenantID, input.JobID,
		completed, succeeded, failed, cancelled, now); err != nil {
		return ReportResult{}, fmt.Errorf("update background job progress: %w", err)
	}
	if _, err := tx.Exec(ctx, `
			UPDATE background_job_items
			SET state=$4, attempt=$5, sequence=$6, error_code=$7, completed_at=$8
			WHERE tenant_id=$1 AND job_id=$2 AND item_id=$3`, input.TenantID, input.JobID,
		input.Report.ItemID, string(input.Report.State), input.Report.Attempt,
		int64(input.Report.Sequence), nullableCode, now); err != nil {
		return ReportResult{}, fmt.Errorf("apply background job result: %w", err)
	}
	if completed == total {
		var nullableFinalCode any
		if finalCode != "" {
			nullableFinalCode = finalCode
		}
		command, err := tx.Exec(ctx, `
				UPDATE background_job_attempts
				SET state=$6, completed_at=$7, error_code=$8
				WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND lease_id=$4 AND worker_id=$5`,
			input.TenantID, input.JobID, input.Report.Attempt, input.LeaseID,
			input.WorkerID, string(finalState), now, nullableFinalCode)
		if err != nil {
			return ReportResult{}, fmt.Errorf("complete background job attempt: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ReportResult{}, ErrClaimLost
		}
		if (finalState == StateFailed || finalState == StatePartialFailed) && failed > 0 && currentAttempt >= maximumAttempts {
			if err := insertDeadLetter(ctx, tx, input.TenantID, input.JobID,
				uint32(currentAttempt), finalCode, failed, "worker", now); err != nil {
				return ReportResult{}, err
			}
		}
	}
	result.Applied = true
	result.Job, err = loadStoredJob(ctx, tx, input.TenantID, input.JobID, false)
	return result, err
}
