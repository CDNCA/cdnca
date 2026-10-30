package cachecontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// recordJobCommandReceipt writes the job.<command> audit event and the
// background_job_command_receipts row that migration 094 requires, in the same
// transaction, for every cancel/retry transition of the unified background job.
func (store *Store) recordJobCommandReceipt(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operationID uuid.UUID,
	command, idempotencyKey, requestID string,
	requestDigest [sha256.Size]byte,
	job jobstate.StoredJob,
	now time.Time,
) error {
	var scopeKind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM access_scopes WHERE id=$1`,
		actor.ActorScopeID).Scan(&scopeKind); err != nil {
		return fmt.Errorf("load cache job command actor scope: %w", err)
	}
	audience := "tenant"
	if scopeKind == "platform" {
		audience = "platform"
	}
	// Receipts are unique per actor and key across all jobs, while cache command
	// keys are only unique per scope, operation and command: derive a bound key.
	keyDigest := sha256.Sum256([]byte(actor.ScopeID.String() + "\x00" + operationID.String() +
		"\x00" + command + "\x00" + idempotencyKey))
	receiptKey := "cache-" + hex.EncodeToString(keyDigest[:])
	var failureCode *string
	if job.LastErrorCode != "" {
		failureCode = &job.LastErrorCode
	}
	optional := func(value time.Time) *time.Time {
		if value.IsZero() {
			return nil
		}
		utc := value.UTC()
		return &utc
	}
	action := "job." + command
	if err := store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ActorScopeID, ActorUserID: &actor.UserID, Action: action, ActorRef: auditActorRef(ctx),
		ResourceType: "background_job", ResourceID: job.ID.String(), RequestID: requestID,
		Result: "success", Payload: map[string]any{
			"audience": audience, "operation": command, "idempotency_key": receiptKey,
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
	}); err != nil {
		return err
	}
	var auditEventID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM audit_events
		WHERE scope_id=$1 AND actor_user_id=$2 AND action=$3 AND resource_type='background_job'
		  AND resource_id=$4 AND request_id=$5 AND result='success'
		  AND payload->>'idempotency_key'=$6
		ORDER BY stream_position DESC LIMIT 1`, actor.ActorScopeID, actor.UserID, action,
		job.ID.String(), requestID, receiptKey).Scan(&auditEventID); err != nil {
		return fmt.Errorf("load cache job command audit fact: %w", err)
	}
	completedAt := now
	if completedAt.Before(job.UpdatedAt) {
		completedAt = job.UpdatedAt
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO background_job_command_receipts (
			actor_scope_id,actor_user_id,idempotency_key,request_digest,audience,
			tenant_id,job_id,operation,request_id,audit_event_id,
			result_kind,result_subject,result_request_id,result_trace_id,
			result_state,result_attempt,result_max_attempts,
			result_total_count,result_completed_count,result_succeeded_count,
			result_failed_count,result_cancelled_count,result_failure_code,
			result_created_at,result_started_at,result_updated_at,result_completed_at,
			created_at,completed_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
			$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29
		)`,
		actor.ActorScopeID, actor.UserID, receiptKey, requestDigest[:], audience,
		job.TenantID, job.ID, command, requestID, auditEventID,
		job.Kind, job.Subject, job.RequestID, job.TraceID, string(job.State),
		job.Attempt, job.MaxAttempts, job.Progress.Total, job.Progress.Completed,
		job.Progress.Succeeded, job.Progress.Failed, job.Progress.Cancelled, failureCode,
		job.CreatedAt, optional(job.StartedAt), job.UpdatedAt, optional(job.CompletedAt),
		job.UpdatedAt, completedAt); err != nil {
		return fmt.Errorf("record cache job command receipt: %w", err)
	}
	return nil
}
