package cnameallocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// JobCancel names who cancels a CNAME job inside their own transaction and
// how the cancel is recorded (site delete, regenerate superseding a job).
type JobCancel struct {
	ActorScopeID, ActorUserID uuid.UUID
	Platform                  bool   // receipt audience: platform, else tenant
	RequestID                 string // the audit event's request ID
	KeyNamespace, KeyPrefix   string // receipt idempotency key: prefix + digest(namespace, job ID)
	WorkerID                  string // owner of the attempt a retried job is taken over with
}

// CancelJobTx cancels the job (jobstate.CancelTx) and, like every cancel or
// retry of a background job, records the job.cancel audit event and the
// background_job_command_receipts row migration 094/104 requires in the same
// transaction (P9402 otherwise). A queued job that already ran is taken over
// first (takeOverRetriedJob). jobstate.ErrInvalidTransition: the job already
// ended (or has no attempt left); jobstate.ErrNotFound: no such job.
func CancelJobTx(ctx context.Context, tx pgx.Tx, cancel JobCancel, tenantID, jobID uuid.UUID, now time.Time) error {
	if err := takeOverRetriedJob(ctx, tx, tenantID, jobID, cancel.WorkerID, now); err != nil {
		return err
	}
	job, err := jobstate.CancelTx(ctx, tx, tenantID, jobID, now)
	if err != nil {
		return err
	}
	return recordCancelReceipt(ctx, tx, cancel, job, now)
}

// takeOverRetriedJob: a queued job that already ran (its current attempt
// deferred by a voluntary yield, failed or lease_expired, all immutable) can
// only become cancelled through a running attempt of its own (115: a
// cancelled job's current attempt is cancelled). N19: the allocation job
// yielded while its child DNS task was in flight and deleting the site
// failed with "cancelled background job attempt is invalid" (HTTP 500).
// The canceller opens the next attempt in its transaction (jobstate.StartTx)
// and CancelTx ends it cancelled; no worker sees it. A job with no attempt
// left is not taken over (ErrRetriesExhausted): callers skip it like a
// settled job and the claim path finalizes it.
func takeOverRetriedJob(ctx context.Context, tx pgx.Tx, tenantID, jobID uuid.UUID, workerID string, now time.Time) error {
	var state, kind string
	var attempt int
	if err := tx.QueryRow(ctx, `SELECT state,kind,attempt FROM background_jobs
		WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, jobID).Scan(&state, &kind, &attempt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return jobstate.ErrNotFound
		}
		return err
	}
	if state != string(jobstate.StateQueued) || attempt == 0 {
		return nil
	}
	_, err := jobstate.StartTx(ctx, tx, jobstate.StartInput{TenantID: tenantID, JobID: jobID, Kind: kind,
		WorkerID: workerID, LeaseDuration: time.Minute}, now)
	if errors.Is(err, jobstate.ErrRetriesExhausted) {
		return jobstate.ErrInvalidTransition
	}
	return err
}

func recordCancelReceipt(ctx context.Context, tx pgx.Tx, cancel JobCancel, job jobstate.StoredJob, now time.Time) error {
	audience := "tenant"
	if cancel.Platform {
		audience = "platform"
	}
	// A job is cancelled at most once, so the job ID makes the key unique.
	keyDigest := sha256.Sum256([]byte(cancel.KeyNamespace + "\x00" + job.ID.String()))
	receiptKey := cancel.KeyPrefix + hex.EncodeToString(keyDigest[:16])
	requestDigest := sha256.Sum256([]byte(receiptKey))
	optional := func(value time.Time) *time.Time {
		if value.IsZero() {
			return nil
		}
		utc := value.UTC()
		return &utc
	}
	var failureCode *string
	if job.LastErrorCode != "" {
		failureCode = &job.LastErrorCode
	}
	auditID, err := audit.AppendTx(ctx, tx, audit.Event{
		ScopeID: cancel.ActorScopeID, ActorUserID: &cancel.ActorUserID, Action: "job.cancel",
		ResourceType: "background_job", ResourceID: job.ID.String(), RequestID: cancel.RequestID,
		// The canceller's clock: 104 requires occurred_at >= the receipt's
		// created_at (the job's updated_at, set by CancelTx at now).
		Result: "success", OccurredAt: now, Payload: map[string]any{
			"audience": audience, "operation": "cancel", "idempotency_key": receiptKey,
			"request_digest": hex.EncodeToString(requestDigest[:]), "tenant_id": job.TenantID.String(),
			"result_data": map[string]any{
				"task_id": job.ID.String(), "tenant_id": job.TenantID.String(), "kind": job.Kind,
				"subject": job.Subject, "request_id": job.RequestID, "trace_id": job.TraceID,
				"state": string(job.State), "attempt": job.Attempt, "max_attempts": job.MaxAttempts,
				"total_count": job.Progress.Total, "completed_count": job.Progress.Completed,
				"succeeded_count": job.Progress.Succeeded, "failed_count": job.Progress.Failed,
				"cancelled_count": job.Progress.Cancelled, "failure_code": failureCode,
				"created_at": job.CreatedAt.UTC(), "started_at": optional(job.StartedAt),
				"updated_at": job.UpdatedAt.UTC(), "completed_at": optional(job.CompletedAt),
			},
		},
	})
	if err != nil {
		return err
	}
	completedAt := now
	if completedAt.Before(job.UpdatedAt) {
		completedAt = job.UpdatedAt
	}
	_, err = tx.Exec(ctx, `INSERT INTO background_job_command_receipts (
			actor_scope_id,actor_user_id,idempotency_key,request_digest,audience,
			tenant_id,job_id,operation,request_id,audit_event_id,
			result_kind,result_subject,result_request_id,result_trace_id,
			result_state,result_attempt,result_max_attempts,
			result_total_count,result_completed_count,result_succeeded_count,
			result_failed_count,result_cancelled_count,result_failure_code,
			result_created_at,result_started_at,result_updated_at,result_completed_at,
			created_at,completed_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,'cancel',$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`,
		cancel.ActorScopeID, cancel.ActorUserID, receiptKey, requestDigest[:], audience,
		job.TenantID, job.ID, cancel.RequestID, auditID,
		job.Kind, job.Subject, job.RequestID, job.TraceID, string(job.State),
		job.Attempt, job.MaxAttempts, job.Progress.Total, job.Progress.Completed,
		job.Progress.Succeeded, job.Progress.Failed, job.Progress.Cancelled, failureCode,
		job.CreatedAt, optional(job.StartedAt), job.UpdatedAt, optional(job.CompletedAt),
		job.UpdatedAt, completedAt)
	return err
}
