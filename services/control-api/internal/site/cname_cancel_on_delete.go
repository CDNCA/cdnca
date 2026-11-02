package site

import (
	"context"
	"errors"
	"time"

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

// cancelBackgroundJob cancels the job in the site delete transaction
// (cnameallocation.CancelJobTx: the job.cancel audit event and the 094/104
// receipt), attributed to the deleting user.
func cancelBackgroundJob(ctx context.Context, tx pgx.Tx, actor Actor, requestID string,
	tenantID, jobID uuid.UUID, now time.Time) error {
	return cnameallocation.CancelJobTx(ctx, tx, cnameallocation.JobCancel{
		ActorScopeID: actor.ScopeID, ActorUserID: actor.UserID, Platform: actor.ScopeKind == "platform",
		RequestID: requestID, KeyNamespace: "cdnca.site-delete-cname-cancel/v1", KeyPrefix: "site-delete-cancel-",
		WorkerID: siteDeleteWorkerID,
	}, tenantID, jobID, now)
}

// siteDeleteWorkerID owns the attempt a site delete opens to cancel a job.
const siteDeleteWorkerID = "site-delete-cancel"

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
