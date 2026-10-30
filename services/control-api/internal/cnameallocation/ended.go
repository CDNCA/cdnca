package cnameallocation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// jobstate ends a CNAME job without its worker when the
// job runs out of attempts (finalizeExhausted, retries_exhausted) or is
// cancelled (CancelTx: task center, site delete). Only background_jobs
// changed, so the allocation and the site stayed pending ("generating")
// forever. The terminal hooks below fail them in the same transaction, the
// allocation through the worker's own settlement (settleAllocationTx), and
// SweepEndedJobs repairs what ended before the hooks existed.
const (
	FailureAllocationExhausted = "cname_allocation_exhausted"
	FailureAllocationCancelled = "cname_allocation_cancelled"
	intentJobKind              = "dns.cname.intent"
	endedWorkerID              = "jobstate-terminal"
	sweepBatch                 = 100
	sweepMaxBatches            = 10
)

func init() {
	for _, kind := range []string{databaseJobKind, intentJobKind, StreamIntentJobKind} {
		jobstate.RegisterTerminalHook(kind, TerminalHook())
	}
}

// TerminalHook is the jobstate.TerminalHook of both CNAME job kinds.
func TerminalHook() jobstate.TerminalHook {
	return func(ctx context.Context, tx pgx.Tx, tenantID, jobID uuid.UUID, code string, now time.Time) error {
		var kind string
		if err := tx.QueryRow(ctx, `SELECT kind FROM background_jobs WHERE tenant_id=$1 AND id=$2`,
			tenantID, jobID).Scan(&kind); err != nil {
			return err
		}
		if _, err := endedStore(now).failEndedJobTx(ctx, tx, tenantID, jobID, kind, code, "terminal"); err != nil {
			return err
		}
		// Checked inside jobstate's savepoint, not at the outer commit.
		if _, err := tx.Exec(ctx, "SET CONSTRAINTS "+endedConstraints+" IMMEDIATE"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "SET CONSTRAINTS "+endedConstraints+" DEFERRED")
		return err
	}
}

// endedConstraints are the deferred CNAME authority triggers (113, 262) of
// the rows failEndedJobTx writes.
const endedConstraints = "cname_allocations_consistent_113,sites_cname_authority_validate_113," +
	"cname_allocation_requests_validate_113,cname_allocation_requests_platform_authority"

// endedStore settles inside a caller's transaction with the caller's clock.
func endedStore(now time.Time) *Store {
	clock := func() time.Time { return now }
	return &Store{now: clock, auditor: audit.NewWithClock(nil, clock)}
}

// endedFailureCode names why jobstate ended the job (jobstate code).
func endedFailureCode(code string) string {
	if code == jobstate.CodeCancelled {
		return FailureAllocationCancelled
	}
	return FailureAllocationExhausted
}

// failEndedJobTx fails the pending allocation and the live sites of the
// ended CNAME job, returning how many sites it failed. A job already
// settled, superseded or of a deleted site is left alone (0).
func (store *Store) failEndedJobTx(ctx context.Context, tx pgx.Tx, tenantID, jobID uuid.UUID,
	kind, jobCode, source string) (int, error) {
	failure := endedFailureCode(jobCode)
	var sites []uuid.UUID
	var scopeID uuid.UUID
	switch kind {
	case databaseJobKind:
		var req ResultRequest
		var attempt int
		// The target's anchor (migration 507): its live site, or its live stream.
		err := tx.QueryRow(ctx, `SELECT target.tenant_scope_id,COALESCE(target.site_id,target.stream_id),allocation.id,
			allocation.current_revision,job.attempt,
			COALESCE((SELECT lease_id FROM background_job_attempts attempt
			  WHERE attempt.tenant_id=job.tenant_id AND attempt.job_id=job.id
			  ORDER BY attempt.attempt DESC LIMIT 1),job.id)
			FROM cname_allocation_targets target
			JOIN cname_allocations allocation ON allocation.tenant_scope_id=target.tenant_scope_id
			 AND allocation.id=target.allocation_id AND allocation.job_id=target.job_id AND allocation.state='pending'
			LEFT JOIN sites site ON site.scope_id=target.tenant_scope_id AND site.id=target.site_id AND site.deleted_at IS NULL
			LEFT JOIN l4_forwards forward ON forward.scope_id=target.tenant_scope_id AND forward.id=target.stream_id
			 AND forward.deleted_at IS NULL
			JOIN background_jobs job ON job.tenant_id=target.tenant_id AND job.id=target.job_id
			WHERE target.tenant_id=$1 AND target.job_id=$2 AND (site.id IS NOT NULL OR forward.id IS NOT NULL)`,
			tenantID, jobID).Scan(&req.TargetScopeID,
			&req.SiteID, &req.AllocationID, &req.ExpectedRevision, &attempt, &req.LeaseID)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		req.JobID, req.WorkerID, req.Attempt, req.Sequence, req.FailureCode = jobID, endedWorkerID, uint32(max(attempt, 1)), 1, failure
		allocation, actorScopeID, actorUserID, requestID, err := lockSettlement(ctx, tx, req)
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		if _, err := store.settleAllocationTx(ctx, tx, req, StateFailed, resultDigest(req, StateFailed),
			allocation, actorScopeID, actorUserID, requestID); err != nil {
			return 0, err
		}
		if allocation.streamOwnerID != nil {
			// A stream's own allocation (migration 505): no site is projected.
			return 0, nil
		}
		// projectBoundSites failed every site bound to the allocation.
		rows, err := tx.Query(ctx, `SELECT site.id FROM sites site
			WHERE site.scope_id=$1 AND site.cname_task_id=$2 AND site.cname_state='failed' AND site.deleted_at IS NULL
			ORDER BY site.id`, req.TargetScopeID, jobID)
		if err != nil {
			return 0, err
		}
		if sites, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
			return 0, err
		}
		scopeID = req.TargetScopeID
	case intentJobKind:
		// The intent never allocated: its site points at the intent job
		// (412: a failed or, from 479, cancelled intent requires failed).
		rows, err := tx.Query(ctx, `UPDATE sites site SET cname_state='failed',updated_at=$3
			FROM cname_allocation_intents intent
			WHERE intent.tenant_id=$1 AND intent.job_id=$2 AND site.scope_id=intent.tenant_scope_id
			  AND site.id=intent.site_id AND site.cname_task_id=$2 AND site.cname_state='pending'
			  AND site.deleted_at IS NULL
			RETURNING site.scope_id,site.id`, tenantID, jobID, store.timestamp())
		if err != nil {
			return 0, err
		}
		type siteRef struct{ scopeID, siteID uuid.UUID }
		refs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (siteRef, error) {
			var ref siteRef
			return ref, row.Scan(&ref.scopeID, &ref.siteID)
		})
		if err != nil {
			return 0, err
		}
		for _, ref := range refs {
			scopeID = ref.scopeID
			sites = append(sites, ref.siteID)
		}
		if err := publishProjectedSitesTx(ctx, tx, scopeID, sites, jobID); err != nil {
			return 0, err
		}
	case StreamIntentJobKind:
		// The stream list reads the intent job's own state; nothing to project.
		return 0, nil
	default:
		return 0, fmt.Errorf("%w: CNAME job kind %q", ErrInvalidInput, kind)
	}
	for _, siteID := range sites {
		if _, err := audit.AppendTx(ctx, tx, audit.Event{
			ScopeID: scopeID, Action: "dns.cname.job_ended", ResourceType: "site", ResourceID: siteID.String(),
			RequestID: "cname-job-ended/" + jobID.String(), Result: "failure", OccurredAt: store.timestamp(),
			ActorKind: audit.ActorSystem, ActorRef: "job:cname_job_ended",
			Payload: map[string]any{"job_id": jobID.String(), "job_kind": kind, "job_code": jobCode,
				"failure_code": failure, "source": source},
		}); err != nil {
			return 0, err
		}
	}
	return len(sites), nil
}

// SweepEndedJobs fails sites still pending on a CNAME job jobstate already
// ended retries_exhausted or cancelled (before the terminal hooks, e.g. 73's
// cdnca-t1). Bounded (sweepMaxBatches of sweepBatch, one transaction per
// job) and idempotent: a failed site no longer matches. Returns the number of
// sites failed.
func (store *Store) SweepEndedJobs(ctx context.Context) (int, error) {
	if ctx == nil {
		return 0, ErrInvalidInput
	}
	total := 0
	for batch := 0; batch < sweepMaxBatches; batch++ {
		rows, err := store.pool.Query(ctx, `SELECT job.tenant_id,job.id,job.kind,job.last_error_code
			FROM sites site JOIN background_jobs job ON job.id=site.cname_task_id
			WHERE site.cname_state='pending' AND site.deleted_at IS NULL
			  AND job.kind=ANY($1::text[]) AND job.state IN ('failed','partial_failed','cancelled')
			  AND job.last_error_code=ANY($2::text[])
			ORDER BY job.id LIMIT $3`, []string{databaseJobKind, intentJobKind},
			[]string{jobstate.CodeRetriesExhausted, jobstate.CodeCancelled}, sweepBatch)
		if err != nil {
			return total, unavailable(err)
		}
		type endedJob struct {
			tenantID, jobID uuid.UUID
			kind, code      string
		}
		jobs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (endedJob, error) {
			var job endedJob
			return job, row.Scan(&job.tenantID, &job.jobID, &job.kind, &job.code)
		})
		if err != nil {
			return total, unavailable(err)
		}
		progressed := 0
		for _, job := range jobs {
			var failed int
			err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
				var err error
				failed, err = store.failEndedJobTx(ctx, tx, job.tenantID, job.jobID, job.kind, job.code, "sweep")
				return err
			})
			if err != nil {
				if ctx.Err() != nil {
					return total, ctx.Err()
				}
				slog.Warn("CNAME ended job sweep failed", "tenant_id", job.tenantID, "job_id", job.jobID, "error", err)
				continue
			}
			total += failed
			progressed++
		}
		if len(jobs) < sweepBatch || progressed == 0 {
			break
		}
	}
	return total, nil
}
