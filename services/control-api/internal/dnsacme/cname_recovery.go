package dnsacme

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CNAMERecoverableFailureCodes are the CNAME intent failures caused by DNS
// configuration that was missing when the site was created. allocation_rejected
// is the code intents recorded for these before the reasons were split.
var CNAMERecoverableFailureCodes = []string{
	"dns_provider_not_configured", "cname_zone_not_configured", "cname_zone_provider_mismatch", "allocation_rejected",
	"platform_dns_sync_failed",
}

// cnameRecoveryBatch bounds one recovery pass per tenant scope.
const cnameRecoveryBatch = 500

// RequeueCNAMEConfigFailures re-queues the failed CNAME intents of scopeID
// whose failure was a missing DNS configuration that now resolves: a usable
// provider and a zone named after the intent's CNAME domain (the default zone
// when the intent has none). The same intent job is retried, so attempts stay
// bounded by its max_attempts; a queued intent is not touched again
// (idempotent). Each re-queued site gets a dns.cname.requeue system audit.
func RequeueCNAMEConfigFailures(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, reason string, now time.Time) (int, error) {
	rows, err := tx.Query(ctx, `SELECT site.id,job.tenant_id,job.id,item.error_code,intent.domain,
		       intent.actor_scope_id,intent.actor_user_id,actor_scope.kind
		FROM sites site
		JOIN cname_allocation_intents intent
		  ON intent.tenant_scope_id=site.scope_id AND intent.site_id=site.id AND intent.job_id=site.cname_task_id
		JOIN background_jobs job ON job.tenant_id=intent.tenant_id AND job.id=intent.job_id
		JOIN background_job_items item ON item.tenant_id=job.tenant_id AND item.job_id=job.id
		JOIN access_scopes actor_scope ON actor_scope.id=intent.actor_scope_id
		-- The retry receipt (migration 094) is the intent actor's; skip intents
		-- whose actor left the scope.
		JOIN memberships membership ON membership.scope_id=intent.actor_scope_id
		 AND membership.user_id=intent.actor_user_id AND membership.status='active'
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL AND site.cname_state='failed'
		  AND job.kind='dns.cname.intent' AND job.state='failed' AND job.attempt<job.max_attempts
		  AND item.state='failed' AND item.error_code=ANY($2::text[])
		  -- Mirrors cnameallocation resolveZoneAuthority: a usable zone (not
		  -- failed, its own provider enabled) named after the domain, or for no
		  -- domain the default or a random-allocation zone (fix-cnamerand, 550).
		  AND EXISTS(SELECT 1 FROM dns_zones zone
		      JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
		       AND provider.status<>'disabled'
		      WHERE zone.scope_id=site.scope_id AND zone.status<>'failed'
		        AND ((intent.domain='' AND (zone.is_default OR zone.random_allocation)) OR
		             (intent.domain<>'' AND lower(zone.name)=lower(intent.domain))))
		ORDER BY site.id LIMIT $3
		FOR UPDATE OF site,job`, scopeID, CNAMERecoverableFailureCodes, cnameRecoveryBatch)
	if err != nil {
		return 0, err
	}
	type candidate struct {
		siteID, tenantID, jobID, actorScopeID, actorUserID uuid.UUID
		code, domain, actorScopeKind                       string
	}
	candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (candidate, error) {
		var value candidate
		return value, row.Scan(&value.siteID, &value.tenantID, &value.jobID, &value.code, &value.domain,
			&value.actorScopeID, &value.actorUserID, &value.actorScopeKind)
	})
	if err != nil {
		return 0, err
	}
	for _, item := range candidates {
		job, err := jobstate.RetryTx(ctx, tx, item.tenantID, item.jobID, now)
		if err != nil {
			return 0, err
		}
		requestID := "cname-requeue/" + item.jobID.String()
		if err := recordCNAMERetryReceipt(ctx, tx, item.actorScopeID, item.actorUserID, item.actorScopeKind,
			requestID, job, now); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE sites SET cname_state='pending',updated_at=$4
			WHERE scope_id=$1 AND id=$2 AND cname_task_id=$3 AND cname_state='failed'`,
			scopeID, item.siteID, item.jobID, now); err != nil {
			return 0, err
		}
		// The site write advanced the scope's revision outside any site
		// request (fix-autopub): an automatic scope publishes it.
		if _, err := edgeautopublish.EnqueueUnrequestedSiteRevisionTx(ctx, tx, scopeID, item.siteID, requestID); err != nil {
			return 0, err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.Event{
			ScopeID: scopeID, Action: "dns.cname.requeue", ResourceType: "site", ResourceID: item.siteID.String(),
			RequestID: requestID, Result: "success",
			ActorKind: audit.ActorSystem, ActorRef: "job:cname_config_recovery",
			Payload: map[string]any{"job_id": item.jobID.String(), "previous_failure_code": item.code,
				"cname_domain": item.domain, "reason": reason},
		}); err != nil {
			return 0, err
		}
	}
	return len(candidates), nil
}

// recordCNAMERetryReceipt writes the job.retry audit event and the
// background_job_command_receipts row migration 094 requires for a
// failed -> queued transition, attributed to the intent's actor.
func recordCNAMERetryReceipt(ctx context.Context, tx pgx.Tx, actorScopeID, actorUserID uuid.UUID,
	actorScopeKind, requestID string, job jobstate.StoredJob, now time.Time) error {
	audience := "tenant"
	if actorScopeKind == "platform" {
		audience = "platform"
	}
	keyDigest := sha256.Sum256([]byte("cdnca.cname-requeue/v1\x00" + job.ID.String() + "\x00" +
		strconv.FormatUint(uint64(job.Attempt), 10)))
	receiptKey := "cname-requeue-" + hex.EncodeToString(keyDigest[:16])
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
		ScopeID: actorScopeID, ActorUserID: &actorUserID, Action: "job.retry",
		ActorKind: audit.ActorSystem, ActorRef: "job:cname_config_recovery",
		ResourceType: "background_job", ResourceID: job.ID.String(), RequestID: requestID,
		Result: "success", Payload: map[string]any{
			"audience": audience, "operation": "retry", "idempotency_key": receiptKey,
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
		) VALUES ($1,$2,$3,$4,$5,$6,$7,'retry',$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`,
		actorScopeID, actorUserID, receiptKey, requestDigest[:], audience,
		job.TenantID, job.ID, requestID, auditID,
		job.Kind, job.Subject, job.RequestID, job.TraceID, string(job.State),
		job.Attempt, job.MaxAttempts, job.Progress.Total, job.Progress.Completed,
		job.Progress.Succeeded, job.Progress.Failed, job.Progress.Cancelled, failureCode,
		job.CreatedAt, optional(job.StartedAt), job.UpdatedAt, optional(job.CompletedAt),
		job.UpdatedAt, completedAt)
	return err
}
