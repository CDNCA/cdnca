package site

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// inFlightCNAMEJobsSQL lists the site's queued or running CNAME jobs: the
// intents written by site saves (dns.cname.intent) and the allocations they
// start (dns.cname.allocation, whose frozen target names the site).
// retest-n1: after a site was deleted these stayed claimable and kept
// calling the DNS provider.
const inFlightCNAMEJobsSQL = `SELECT job.tenant_id, job.id FROM background_jobs job
	WHERE job.state IN ('queued','running') AND (
	  (job.kind='dns.cname.intent' AND EXISTS (SELECT 1 FROM cname_allocation_intents intent
	    WHERE intent.tenant_id=job.tenant_id AND intent.job_id=job.id
	      AND intent.tenant_scope_id=$1 AND intent.site_id=$2)) OR
	  (job.kind='dns.cname.allocation' AND EXISTS (SELECT 1 FROM cname_allocation_targets target
	    WHERE target.tenant_id=job.tenant_id AND target.job_id=job.id
	      AND target.tenant_scope_id=$1 AND target.site_id=$2)))
	ORDER BY job.id FOR UPDATE OF job`

// cnameJobCanceller cancels one background job in the site delete
// transaction (cancelBackgroundJob; replaced in tests).
type cnameJobCanceller func(ctx context.Context, tx pgx.Tx, actor Actor, requestID string,
	tenantID, jobID uuid.UUID, now time.Time) error

// cancelBackgroundJob cancels the job (jobstate.CancelTx) and, like every
// cancel/retry of a background job, records the job.cancel audit event and
// the background_job_command_receipts row migration 094/104 requires in the
// same transaction (P9402 otherwise), attributed to the deleting user.
func cancelBackgroundJob(ctx context.Context, tx pgx.Tx, actor Actor, requestID string,
	tenantID, jobID uuid.UUID, now time.Time) error {
	if err := takeOverRetriedJob(ctx, tx, tenantID, jobID, now); err != nil {
		return err
	}
	job, err := jobstate.CancelTx(ctx, tx, tenantID, jobID, now)
	if err != nil {
		return err
	}
	return recordSiteDeleteCancelReceipt(ctx, tx, actor, requestID, job, now)
}

// siteDeleteWorkerID owns the attempt a site delete opens to cancel a job.
const siteDeleteWorkerID = "site-delete-cancel"

// takeOverRetriedJob: a queued job that already ran (its current attempt
// deferred by a voluntary yield, failed or lease_expired, all immutable) can
// only become cancelled through a running attempt of its own (115: a
// cancelled job's current attempt is cancelled). N19: the allocation job
// yielded while its child DNS task was in flight and deleting the site
// failed with "cancelled background job attempt is invalid" (HTTP 500).
// The delete opens the next attempt in its transaction (jobstate.StartTx)
// and CancelTx ends it cancelled; no worker sees it. A job with no attempt
// left is not taken over (ErrRetriesExhausted): cancelSiteCNAMEJobs skips it
// like a settled job and the claim path finalizes it.
func takeOverRetriedJob(ctx context.Context, tx pgx.Tx, tenantID, jobID uuid.UUID, now time.Time) error {
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
		WorkerID: siteDeleteWorkerID, LeaseDuration: time.Minute}, now)
	if errors.Is(err, jobstate.ErrRetriesExhausted) {
		return jobstate.ErrInvalidTransition
	}
	return err
}

func recordSiteDeleteCancelReceipt(ctx context.Context, tx pgx.Tx, actor Actor, requestID string,
	job jobstate.StoredJob, now time.Time) error {
	audience := "tenant"
	if actor.ScopeKind == "platform" {
		audience = "platform"
	}
	// A job is cancelled at most once, so the job ID makes the key unique.
	keyDigest := sha256.Sum256([]byte("cdnca.site-delete-cname-cancel/v1\x00" + job.ID.String()))
	receiptKey := "site-delete-cancel-" + hex.EncodeToString(keyDigest[:16])
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
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "job.cancel",
		ResourceType: "background_job", ResourceID: job.ID.String(), RequestID: requestID,
		Result: "success", Payload: map[string]any{
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
		actor.ScopeID, actor.UserID, receiptKey, requestDigest[:], audience,
		job.TenantID, job.ID, requestID, auditID,
		job.Kind, job.Subject, job.RequestID, job.TraceID, string(job.State),
		job.Attempt, job.MaxAttempts, job.Progress.Total, job.Progress.Completed,
		job.Progress.Succeeded, job.Progress.Failed, job.Progress.Cancelled, failureCode,
		job.CreatedAt, optional(job.StartedAt), job.UpdatedAt, optional(job.CompletedAt),
		job.UpdatedAt, completedAt)
	return err
}

// cancelSiteCNAMEJobs cancels every in-flight CNAME job of the deleted site
// so no worker claims it again. A job that settled meanwhile is skipped.
func cancelSiteCNAMEJobs(ctx context.Context, tx pgx.Tx, actor Actor, requestID string,
	scopeID, siteID uuid.UUID, now time.Time, cancel cnameJobCanceller) error {
	rows, err := tx.Query(ctx, inFlightCNAMEJobsSQL, scopeID, siteID)
	if err != nil {
		return err
	}
	type job struct{ tenantID, id uuid.UUID }
	jobs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (job, error) {
		var value job
		return value, row.Scan(&value.tenantID, &value.id)
	})
	if err != nil {
		return err
	}
	for _, item := range jobs {
		if err := cancel(ctx, tx, actor, requestID, item.tenantID, item.id, now); err != nil &&
			!errors.Is(err, jobstate.ErrInvalidTransition) && !errors.Is(err, jobstate.ErrNotFound) {
			return err
		}
	}
	// n12b: the site's own CNAME owners were (or may have been) written to
	// the provider; register them for the retirement worker.
	return cnameallocation.RetireSiteOwnersTx(ctx, tx, scopeID, siteID, now)
}
