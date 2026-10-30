package dnsreconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	dnsReconcileMaxAttempts = uint32(20)
	maximumLeaseDuration    = time.Hour
)

var dnsReconcileKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type PostgresStore struct {
	pool    *pgxpool.Pool
	jobs    *jobstate.Store
	auditor *audit.Log
	now     func() time.Time
}

type dnsCommandAuditInput struct {
	ScopeID          uuid.UUID
	ActorUserID      uuid.UUID
	TaskID           uuid.UUID
	RequestID        string
	Action           Action
	ExpectedRevision int64
	ProviderRevision int64
	// PlatformActor: the actor is not a member of the tenant scope, a
	// platform administrator acting for the tenant (fix-regen2).
	PlatformActor bool
}

func NewPostgresStore(pool *pgxpool.Pool, jobs *jobstate.Store, now func() time.Time) (*PostgresStore, error) {
	if pool == nil || jobs == nil {
		return nil, ErrUnavailable
	}
	if now == nil {
		now = time.Now
	}
	return &PostgresStore{pool: pool, jobs: jobs, auditor: audit.NewWithClock(pool, now), now: now}, nil
}

func dnsCommandAuditEvent(input dnsCommandAuditInput) (audit.Event, error) {
	if input.ScopeID == uuid.Nil || input.ActorUserID == uuid.Nil || input.TaskID == uuid.Nil ||
		!validSafeText(input.RequestID, 128, false) || input.ExpectedRevision < 1 ||
		input.ProviderRevision < 1 ||
		(input.Action != ActionApply && input.Action != ActionCommit && input.Action != ActionCancel) {
		return audit.Event{}, ErrInvalidInput
	}
	actorID := input.ActorUserID
	payload := map[string]any{
		"action": string(input.Action), "expected_revision": input.ExpectedRevision,
		"provider_revision": input.ProviderRevision,
	}
	if input.PlatformActor {
		payload["actor_scope_kind"], payload["on_behalf_of_tenant"] = "platform", true
	}
	return audit.Event{
		ScopeID: input.ScopeID, ActorUserID: &actorID,
		Action: "dns.reconcile." + string(input.Action), ResourceType: "dns_reconcile_task",
		ResourceID: input.TaskID.String(), RequestID: input.RequestID, Result: "success",
		Payload: payload,
	}, nil
}

func (store *PostgresStore) appendDNSCommandAudit(
	ctx context.Context,
	tx pgx.Tx,
	input dnsCommandAuditInput,
) error {
	if store == nil || store.auditor == nil || tx == nil {
		return ErrUnavailable
	}
	var member bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM memberships
		WHERE scope_id=$1 AND user_id=$2 AND status='active')`, input.ScopeID, input.ActorUserID).Scan(&member); err != nil {
		return err
	}
	input.PlatformActor = !member
	event, err := dnsCommandAuditEvent(input)
	if err != nil {
		return err
	}
	return store.auditor.Append(ctx, tx, event)
}

func dnsReconcileTaskScopeID(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, taskID uuid.UUID,
) (uuid.UUID, error) {
	var scopeID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT tenant_scope_id FROM dns_reconcile_tasks
		WHERE tenant_id=$1 AND job_id=$2`, tenantID, taskID).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	if scopeID == uuid.Nil {
		return uuid.Nil, ErrUnavailable
	}
	return scopeID, nil
}

func (store *PostgresStore) Create(ctx context.Context, request ApplyRequest, prepared dnscheck.PreparedReconcile) (Task, bool, error) {
	if ctx == nil || ctx.Err() != nil || !validCreate(request, prepared) {
		return Task{}, false, ErrInvalidInput
	}
	preparedJSON, err := json.Marshal(storedCanonicalRequest{
		Version: 1, ActorUserID: request.ActorUserID, RequestID: request.RequestID, Prepared: prepared,
	})
	if err != nil {
		return Task{}, false, ErrInvalidInput
	}
	planJSON, err := json.Marshal(prepared.Result.Plan)
	if err != nil {
		return Task{}, false, ErrInvalidInput
	}
	payloadDigest, err := decodeDigest(prepared.Result.PayloadDigest)
	if err != nil {
		return Task{}, false, ErrInvalidInput
	}
	planDigest, err := decodeDigest(prepared.Result.Plan.Digest)
	if err != nil {
		return Task{}, false, ErrInvalidInput
	}
	subject := "dns_reconcile/" + request.SiteID.String()
	jobIdempotencyKey := backgroundJobIdempotencyKey(request.IdempotencyKey)
	jobDigest, err := backgroundJobDigest(subject, preparedJSON)
	if err != nil {
		return Task{}, false, ErrInvalidInput
	}

	now := store.timestamp()
	jobID := uuid.New()
	replayed := false
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		command, err := tx.Exec(ctx, `
			INSERT INTO background_jobs (
				id,tenant_id,kind,subject,idempotency_key,request_digest,
				request_id,trace_id,state,attempt,max_attempts,claimable_at,
				total_count,created_at,updated_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'queued',0,$9,$10,1,$10,$10)
			ON CONFLICT (tenant_id,idempotency_key) DO NOTHING`,
			jobID, request.TenantID, JobKind, subject, jobIdempotencyKey, jobDigest[:],
			request.RequestID, request.Traceparent, dnsReconcileMaxAttempts, now)
		if err != nil {
			return fmt.Errorf("insert DNS reconcile background job: %w", err)
		}
		if command.RowsAffected() == 0 {
			var existingSite, existingJob uuid.UUID
			var existingDigest []byte
			err := tx.QueryRow(ctx, `
				SELECT job_id,COALESCE(site_id,stream_id),payload_digest FROM dns_reconcile_tasks
				WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE`,
				request.TenantID, request.IdempotencyKey).Scan(&existingJob, &existingSite, &existingDigest)
			if err == pgx.ErrNoRows {
				return ErrIdempotencyConflict
			}
			if err != nil {
				return err
			}
			if existingSite != request.SiteID || !bytes.Equal(existingDigest, payloadDigest) {
				return ErrIdempotencyConflict
			}
			jobID = existingJob
			replayed = true
			return nil
		}

		// request.SiteID is the task's anchor (migration 507): a live site, or
		// a live stream whose own CNAME this writes (a stream may have no site).
		var scopeID uuid.UUID
		var siteID, streamID *uuid.UUID
		err = tx.QueryRow(ctx, `
			SELECT anchor.scope_id,anchor.site_id,anchor.stream_id
			FROM (SELECT site.scope_id,site.id AS site_id,NULL::uuid AS stream_id FROM sites site
			      WHERE site.id=$1 AND site.deleted_at IS NULL
			      UNION ALL
			      SELECT forward.scope_id,NULL::uuid,forward.id FROM l4_forwards forward
			      WHERE forward.id=$1 AND forward.deleted_at IS NULL) anchor
			JOIN access_scopes scope ON scope.id=anchor.scope_id
			WHERE scope.kind='tenant' AND scope.tenant_id=$2`,
			request.SiteID, request.TenantID).Scan(&scopeID, &siteID, &streamID)
		if err == pgx.ErrNoRows {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO background_job_items(
			tenant_id,job_id,ordinal,item_id,state
		) VALUES($1,$2,1,$3,'pending')`, request.TenantID, jobID, JobItemID); err != nil {
			return fmt.Errorf("insert DNS reconcile job item: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO dns_reconcile_tasks(
			tenant_id,tenant_scope_id,job_id,site_id,zone_id,idempotency_key,job_idempotency_key,
			payload_digest,job_request_digest,canonical_request,plan_digest,
			deterministic_plan,initial_provider_revision,required_consecutive,created_at,stream_id
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			request.TenantID, scopeID, jobID, siteID, prepared.Request.Provider.ZoneID,
			request.IdempotencyKey, jobIdempotencyKey, payloadDigest, jobDigest[:], preparedJSON, planDigest,
			planJSON, prepared.Result.InitialRevision, request.RequiredConsecutive, now, streamID); err != nil {
			return fmt.Errorf("insert DNS reconcile task: %w", err)
		}
		if err := insertOperationFacts(ctx, tx, request, jobID, prepared.Result, now); err != nil {
			return err
		}
		if err := store.appendDNSCommandAudit(ctx, tx, dnsCommandAuditInput{
			ScopeID: scopeID, ActorUserID: request.ActorUserID, TaskID: jobID,
			RequestID: request.RequestID, Action: ActionApply,
			ExpectedRevision: request.ExpectedRevision, ProviderRevision: prepared.Result.InitialRevision,
		}); err != nil {
			return fmt.Errorf("audit accepted DNS apply: %w", err)
		}
		return nil
	})
	if err != nil {
		return Task{}, false, mapStoreError(err)
	}
	task, err := store.Get(ctx, request.TenantID, jobID)
	if err != nil {
		return Task{}, false, err
	}
	task.Replayed = replayed
	return task, replayed, nil
}

func (store *PostgresStore) Get(ctx context.Context, tenantID, taskID uuid.UUID) (Task, error) {
	if ctx == nil || tenantID == uuid.Nil || taskID == uuid.Nil {
		return Task{}, ErrInvalidInput
	}
	var task Task
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	}, func(tx pgx.Tx) error {
		var err error
		task, err = loadDNSReconcileSnapshot(ctx, tx, tenantID, taskID)
		return err
	})
	if err != nil {
		return Task{}, mapStoreError(err)
	}
	return task, nil
}

func (store *PostgresStore) Claim(ctx context.Context, request ClaimRequest) ([]ApplyLease, error) {
	if ctx == nil || request.TenantID == uuid.Nil || !validWorker(request.WorkerID) || request.Limit < 1 ||
		request.Limit > 100 || !validLeaseDuration(request.LeaseDuration) {
		return nil, ErrInvalidInput
	}
	claims, err := store.jobs.Claim(ctx, jobstate.ClaimInput{
		TenantID: request.TenantID, Kind: JobKind, WorkerID: request.WorkerID,
		Limit: request.Limit, LeaseDuration: request.LeaseDuration,
	})
	if err != nil {
		return nil, mapJobstateError(err)
	}
	result := make([]ApplyLease, 0, len(claims))
	for _, claim := range claims {
		task, err := store.Get(ctx, request.TenantID, claim.Job.ID)
		if err != nil {
			return nil, err
		}
		task.Job = claim.Job
		result = append(result, ApplyLease{
			Task: task, WorkerID: claim.WorkerID, Attempt: claim.Job.Attempt,
			LeaseID: claim.LeaseID, LeaseExpiresAt: claim.LeaseExpiresAt,
		})
	}
	return result, nil
}

func (store *PostgresStore) HeartbeatApply(ctx context.Context, lease ApplyLease, duration time.Duration) (ApplyLease, error) {
	if ctx == nil || !validApplyLease(lease) || !validLeaseDuration(duration) {
		return ApplyLease{}, ErrInvalidInput
	}
	expiresAt, err := store.jobs.Heartbeat(ctx, jobstate.HeartbeatInput{
		TenantID: lease.Task.TenantID, JobID: lease.Task.ID, WorkerID: lease.WorkerID,
		Attempt: lease.Attempt, LeaseID: lease.LeaseID, LeaseDuration: duration,
	})
	if err != nil {
		return ApplyLease{}, mapJobstateError(err)
	}
	lease.LeaseExpiresAt = expiresAt
	task, err := store.Get(ctx, lease.Task.TenantID, lease.Task.ID)
	if err != nil {
		return ApplyLease{}, err
	}
	lease.Task = task
	return lease, nil
}

func (store *PostgresStore) CheckpointApply(ctx context.Context, lease ApplyLease, result dnscheck.ReconcileResult) (Task, error) {
	if ctx == nil || !validApplyLease(lease) || !resultMatchesTask(result, lease.Task) {
		return Task{}, ErrInvalidInput
	}
	task, err := store.appendResult(ctx, lease.Task.TenantID, lease.Task.ID, "worker",
		int(lease.Attempt), lease.LeaseID, lease.WorkerID, result, 0)
	if err != nil {
		return Task{}, err
	}
	return task, nil
}

func (store *PostgresStore) checkpointApplyAfter(
	ctx context.Context,
	lease ApplyLease,
	result dnscheck.ReconcileResult,
	delay time.Duration,
) (Task, error) {
	if ctx == nil || !validApplyLease(lease) || !resultMatchesTask(result, lease.Task) ||
		delay <= 0 || delay > maximumRetryAfterDeferral || result.Status != dnscheck.TaskPropagating {
		return Task{}, ErrInvalidInput
	}
	return store.appendResult(ctx, lease.Task.TenantID, lease.Task.ID, "worker",
		int(lease.Attempt), lease.LeaseID, lease.WorkerID, result, delay)
}

func (store *PostgresStore) FinishApply(ctx context.Context, lease ApplyLease, result dnscheck.ReconcileResult) (Task, error) {
	if result.Status != dnscheck.TaskReadyToCommit && result.Status != dnscheck.TaskCommitted &&
		result.Status != dnscheck.TaskFailed && result.Status != dnscheck.TaskCancelled &&
		result.Status != dnscheck.TaskTimedOut {
		return Task{}, ErrInvalidInput
	}
	checkpointed, err := store.CheckpointApply(ctx, lease, result)
	if err != nil {
		return Task{}, err
	}
	state := jobstate.ItemSucceeded
	code := ""
	if result.Status != dnscheck.TaskReadyToCommit && result.Status != dnscheck.TaskCommitted {
		state = jobstate.ItemFailed
		code = result.ErrorCode
		if code == "" {
			code = "dns_reconcile_failed"
		}
	}
	reported, err := store.jobs.Report(ctx, jobstate.ReportInput{
		TenantID: checkpointed.TenantID, JobID: checkpointed.ID,
		WorkerID: lease.WorkerID, LeaseID: lease.LeaseID,
		Report: jobstate.Report{ItemID: JobItemID, State: state, Code: code,
			Attempt: lease.Attempt, Sequence: uint64(checkpointed.Revision)},
	})
	if err != nil {
		return Task{}, mapJobstateError(err)
	}
	checkpointed.Job = reported.Job
	return checkpointed, nil
}

func (store *PostgresStore) AcquireCommit(
	ctx context.Context,
	request CommitRequest,
	workerID string,
	duration time.Duration,
) (CommitLease, bool, error) {
	if ctx == nil || request.TenantID == uuid.Nil || request.SiteID == uuid.Nil || request.TaskID == uuid.Nil ||
		request.ActorUserID == uuid.Nil ||
		!dnsReconcileKeyPattern.MatchString(request.IdempotencyKey) || request.ExpectedRevision < 1 ||
		!validSafeText(request.RequestID, 128, false) || !validSafeText(request.Traceparent, 512, false) ||
		!validWorker(workerID) || !validLeaseDuration(duration) {
		return CommitLease{}, false, ErrInvalidInput
	}
	commandDigest, err := dnsCommandDigest(ActionCommit, request.TenantID, request.SiteID,
		request.TaskID, request.ExpectedRevision, request.ActorUserID, nil)
	if err != nil {
		return CommitLease{}, false, ErrInvalidInput
	}
	now := store.timestamp()
	var result CommitLease
	replayed := false
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := lockDNSReconcileTask(ctx, tx, request.TenantID, request.TaskID); err != nil {
			return err
		}
		task, err := loadDNSReconcileTask(ctx, tx, request.TenantID, request.TaskID)
		if err != nil {
			return err
		}
		if task.SiteID != request.SiteID {
			return ErrIdempotencyConflict
		}
		canonical, commandFound, err := loadCommitCommand(ctx, tx, request.TenantID, request.IdempotencyKey)
		if err != nil {
			return err
		}
		previous, found, err := loadLatestCommitFact(ctx, tx, request.TenantID, request.TaskID)
		if err != nil {
			return err
		}
		if found && previous.actorUserID != uuid.Nil && previous.actorUserID != request.ActorUserID {
			return ErrIdempotencyConflict
		}
		if commandFound {
			if canonical.actorUserID == uuid.Nil || !found || previous.actorUserID == uuid.Nil {
				return ErrUnavailable
			}
			if canonical.jobID != request.TaskID || canonical.actorUserID != request.ActorUserID ||
				!bytes.Equal(canonical.commandDigest, commandDigest[:]) {
				return ErrIdempotencyConflict
			}
			if previous.eventType == "committed" ||
				(previous.eventType != "failed" && previous.expiresAt.After(now)) {
				result = CommitLease{
					Task: task, WorkerID: previous.workerID, Attempt: uint32(previous.attempt),
					LeaseID: previous.leaseID, LeaseExpiresAt: previous.expiresAt, Command: request,
				}
				replayed = true
				return nil
			}
		} else {
			if found {
				if previous.actorUserID == uuid.Nil {
					return ErrUnavailable
				}
				return ErrIdempotencyConflict
			}
			if task.Revision != request.ExpectedRevision {
				return ErrRevisionConflict
			}
		}
		if task.Result.Status == dnscheck.TaskCommitted {
			return ErrIdempotencyConflict
		}
		if task.Result.Status != dnscheck.TaskReadyToCommit && task.Result.Status != dnscheck.TaskCommitFailed {
			return ErrCommitNotReady
		}
		factSequence := int64(1)
		attempt := 1
		expectedTaskRevision := request.ExpectedRevision
		if found {
			factSequence = previous.sequence + 1
			attempt = previous.attempt + 1
			expectedTaskRevision = previous.expectedTaskRevision
		}
		leaseID := uuid.New()
		expiresAt := now.Add(duration)
		if _, err := tx.Exec(ctx, `INSERT INTO dns_reconcile_commit_facts(
			tenant_id,job_id,actor_user_id,command_idempotency_key,command_digest,request_id,traceparent,
			expected_task_revision,fact_sequence,commit_attempt,lease_id,worker_id,
			lease_expires_at,event_type,expected_provider_revision,compensation_plan,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'claimed',$14,'[]'::jsonb,$15)`,
			request.TenantID, request.TaskID, request.ActorUserID, request.IdempotencyKey, commandDigest[:],
			request.RequestID, request.Traceparent, expectedTaskRevision, factSequence, attempt,
			leaseID, workerID, expiresAt, task.Result.ProviderRevision, now); err != nil {
			return fmt.Errorf("claim DNS commit: %w", err)
		}
		scopeID, err := dnsReconcileTaskScopeID(ctx, tx, request.TenantID, request.TaskID)
		if err != nil {
			return err
		}
		if err := store.appendDNSCommandAudit(ctx, tx, dnsCommandAuditInput{
			ScopeID: scopeID, ActorUserID: request.ActorUserID, TaskID: request.TaskID,
			RequestID: request.RequestID, Action: ActionCommit,
			ExpectedRevision: request.ExpectedRevision, ProviderRevision: task.Result.ProviderRevision,
		}); err != nil {
			return fmt.Errorf("audit accepted DNS commit: %w", err)
		}
		result = CommitLease{
			Task: task, WorkerID: workerID, Attempt: uint32(attempt),
			LeaseID: leaseID, LeaseExpiresAt: expiresAt, Command: request,
		}
		return nil
	})
	if err != nil {
		return CommitLease{}, false, mapStoreError(err)
	}
	if result.Task.ID != uuid.Nil {
		job, err := store.jobs.Get(ctx, result.Task.TenantID, result.Task.ID)
		if err == nil {
			result.Task.Job = job
		}
	}
	return result, replayed, nil
}

func (store *PostgresStore) HeartbeatCommit(ctx context.Context, lease CommitLease, duration time.Duration) (CommitLease, error) {
	if ctx == nil || !validCommitLease(lease) || !validLeaseDuration(duration) {
		return CommitLease{}, ErrInvalidInput
	}
	now := store.timestamp()
	newExpiry := now.Add(duration)
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := lockDNSReconcileTask(ctx, tx, lease.Task.TenantID, lease.Task.ID); err != nil {
			return err
		}
		previous, found, err := loadLatestCommitFact(ctx, tx, lease.Task.TenantID, lease.Task.ID)
		if err != nil {
			return err
		}
		if !found || previous.actorUserID == uuid.Nil {
			return ErrUnavailable
		}
		if !commitFactMatches(previous, lease, now) {
			return ErrClaimLost
		}
		if !newExpiry.After(previous.expiresAt) {
			newExpiry = previous.expiresAt.Add(time.Microsecond)
		}
		_, err = tx.Exec(ctx, `INSERT INTO dns_reconcile_commit_facts(
			tenant_id,job_id,actor_user_id,command_idempotency_key,command_digest,request_id,traceparent,
			expected_task_revision,fact_sequence,commit_attempt,lease_id,worker_id,
			lease_expires_at,event_type,expected_provider_revision,compensation_plan,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'heartbeat',$14,'[]'::jsonb,$15)`,
			lease.Task.TenantID, lease.Task.ID, previous.actorUserID, previous.commandKey, previous.commandDigest,
			previous.requestID, previous.traceparent, previous.expectedTaskRevision,
			previous.sequence+1, lease.Attempt, lease.LeaseID, lease.WorkerID, newExpiry,
			previous.expectedRevision, now)
		return err
	})
	if err != nil {
		return CommitLease{}, mapStoreError(err)
	}
	lease.LeaseExpiresAt = newExpiry
	return lease, nil
}

func (store *PostgresStore) CheckpointCommit(ctx context.Context, lease CommitLease, result dnscheck.ReconcileResult) (Task, error) {
	if ctx == nil || !validCommitLease(lease) || !resultMatchesTask(result, lease.Task) {
		return Task{}, ErrInvalidInput
	}
	now := store.timestamp()
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := lockDNSReconcileTask(ctx, tx, lease.Task.TenantID, lease.Task.ID); err != nil {
			return err
		}
		current, err := loadDNSReconcileTask(ctx, tx, lease.Task.TenantID, lease.Task.ID)
		if err != nil {
			return err
		}
		previousFact, found, err := loadLatestCommitFact(ctx, tx, lease.Task.TenantID, lease.Task.ID)
		if err != nil {
			return err
		}
		if !found || previousFact.actorUserID == uuid.Nil {
			return ErrUnavailable
		}
		if !commitFactMatches(previousFact, lease, now) {
			return ErrClaimLost
		}
		if sameResult(current.Result, result) {
			return nil
		}
		if err := validateResultAdvance(current.Result, result, checkpointPhaseCommit); err != nil {
			return err
		}
		fact := previousFact
		for index := range result.DeferredDeletes {
			priorSequence := uint64(0)
			if index < len(current.Result.DeferredDeletes) {
				priorSequence = current.Result.DeferredDeletes[index].ReportSequence
			}
			operation := result.DeferredDeletes[index]
			// N25: the delete's request ID names the task's own intent (its apply
			// key + phase "commit"), like the 076 operation row written at Create,
			// the 089 claim trigger and dnscheck. The commit command's key differs
			// per caller (retarget, package, HTTP) and must not change the ID.
			expectedRequestID := operationRequestID(current.TenantID, current.Prepared.IdempotencyKey,
				current.Result.PayloadDigest, "commit", operation.SourceSequence)
			if operation.ClientRequestID != "" && operation.ClientRequestID != expectedRequestID {
				return ErrInvalidInput
			}
			if operation.Status != dnscheck.OperationSucceeded || operation.ReportSequence <= priorSequence {
				continue
			}
			fact.sequence++
			if _, err := tx.Exec(ctx, `INSERT INTO dns_reconcile_commit_facts(
				tenant_id,job_id,actor_user_id,command_idempotency_key,command_digest,request_id,traceparent,
				expected_task_revision,fact_sequence,commit_attempt,lease_id,worker_id,
				lease_expires_at,event_type,operation_ordinal,provider_request_id,
				provider_record_id,report_sequence,expected_provider_revision,
				provider_revision,compensation_plan,created_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'delete_succeeded',$14,$15,$16,$17,$18,$19,'[]'::jsonb,$20)`,
				lease.Task.TenantID, lease.Task.ID, fact.actorUserID, fact.commandKey, fact.commandDigest, fact.requestID,
				fact.traceparent, fact.expectedTaskRevision, fact.sequence, lease.Attempt, lease.LeaseID,
				lease.WorkerID, fact.expiresAt, index+1, operation.ProviderRequestID,
				operation.ProviderRecordID, operation.ReportSequence, fact.expectedRevision,
				operation.ProviderRevision, now); err != nil {
				return fmt.Errorf("record DNS commit delete: %w", err)
			}
		}
		terminalFact := ""
		if result.Status == dnscheck.TaskCommitted {
			terminalFact = "committed"
		} else if result.Status == dnscheck.TaskCommitFailed || result.ErrorCode != "" {
			terminalFact = "failed"
		}
		if terminalFact != "" {
			fact.sequence++
			compensation, err := jsonArray(result.CompensationPlan)
			if err != nil {
				return err
			}
			var errorClass, errorCode any
			if terminalFact == "failed" {
				errorClass = string(result.ErrorClass)
				if errorClass == "" {
					errorClass = string(dnscheck.ProviderErrorPermanent)
				}
				errorCode = result.ErrorCode
				if errorCode == "" {
					errorCode = "commit_failed"
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO dns_reconcile_commit_facts(
				tenant_id,job_id,actor_user_id,command_idempotency_key,command_digest,request_id,traceparent,
				expected_task_revision,fact_sequence,commit_attempt,lease_id,worker_id,
				lease_expires_at,event_type,expected_provider_revision,provider_revision,
				compensation_plan,error_class,error_code,created_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,COALESCE($18,''),$19,$20)`,
				lease.Task.TenantID, lease.Task.ID, fact.actorUserID, fact.commandKey, fact.commandDigest, fact.requestID,
				fact.traceparent, fact.expectedTaskRevision, fact.sequence, lease.Attempt, lease.LeaseID,
				lease.WorkerID, fact.expiresAt, terminalFact, fact.expectedRevision,
				nullableRevision(result.ProviderRevision), compensation, errorClass, errorCode, now); err != nil {
				return fmt.Errorf("record DNS commit terminal fact: %w", err)
			}
		}
		if err := insertTaskEvent(ctx, tx, current, "commit", int(lease.Attempt),
			lease.LeaseID, lease.WorkerID, result, now); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return Task{}, mapStoreError(err)
	}
	return store.Get(ctx, lease.Task.TenantID, lease.Task.ID)
}

func (store *PostgresStore) Cancel(ctx context.Context, request CancelRequest) (Task, bool, error) {
	if ctx == nil || request.TenantID == uuid.Nil || request.SiteID == uuid.Nil || request.TaskID == uuid.Nil ||
		request.ActorUserID == uuid.Nil ||
		!dnsReconcileKeyPattern.MatchString(request.IdempotencyKey) || request.ExpectedRevision < 1 ||
		!validSafeText(request.RequestID, 128, false) || !validSafeText(request.Traceparent, 512, false) {
		return Task{}, false, ErrInvalidInput
	}
	commandDigest, err := dnsCommandDigest(ActionCancel, request.TenantID, request.SiteID,
		request.TaskID, request.ExpectedRevision, request.ActorUserID, nil)
	if err != nil {
		return Task{}, false, ErrInvalidInput
	}
	now := store.timestamp()
	replayed := false
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := lockDNSReconcileTask(ctx, tx, request.TenantID, request.TaskID); err != nil {
			return err
		}
		current, err := loadDNSReconcileTask(ctx, tx, request.TenantID, request.TaskID)
		if err != nil {
			return err
		}
		canonicalJobID, canonicalActorUserID, canonicalDigest, found, err := loadCancelCommand(
			ctx, tx, request.TenantID, request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if canonicalActorUserID == uuid.Nil {
				return ErrUnavailable
			}
			if canonicalJobID != request.TaskID || canonicalActorUserID != request.ActorUserID ||
				!bytes.Equal(canonicalDigest, commandDigest[:]) {
				return ErrIdempotencyConflict
			}
			replayed = true
			return nil
		}
		var existingKey string
		var existingActorUserID *uuid.UUID
		err = tx.QueryRow(ctx, `SELECT command_idempotency_key,actor_user_id FROM dns_reconcile_cancel_facts
			WHERE tenant_id=$1 AND job_id=$2`, request.TenantID, request.TaskID).Scan(&existingKey, &existingActorUserID)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if err == nil {
			if existingActorUserID == nil || *existingActorUserID == uuid.Nil {
				return ErrUnavailable
			}
			return ErrIdempotencyConflict
		}
		if current.SiteID != request.SiteID {
			return ErrIdempotencyConflict
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if operationInFlight(current.Result) {
			return ErrOperationInFlight
		}

		var state string
		var attempt int
		err = tx.QueryRow(ctx, `SELECT state,attempt FROM background_jobs
			WHERE tenant_id=$1 AND id=$2 AND kind=$3 FOR UPDATE`,
			request.TenantID, request.TaskID, JobKind).Scan(&state, &attempt)
		if err == pgx.ErrNoRows {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if state != string(jobstate.StateQueued) && state != string(jobstate.StateRunning) {
			return ErrInvalidInput
		}

		result := current.Result
		result.Status = dnscheck.TaskCancelled
		result.ErrorClass = dnscheck.ProviderErrorCancelled
		result.ErrorCode = "cancelled"
		result.CompensationPlan = dnscheck.CompensationForApplied(result.Operations)
		result.UpdatedAt = now
		if err := insertTaskEvent(ctx, tx, current, "control", 0, uuid.Nil, "", result, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO dns_reconcile_cancel_facts(
			tenant_id,job_id,site_id,actor_user_id,command_idempotency_key,command_digest,request_id,
			traceparent,expected_task_revision,event_sequence,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, request.TenantID, request.TaskID,
			request.SiteID, request.ActorUserID, request.IdempotencyKey, commandDigest[:], request.RequestID,
			request.Traceparent, request.ExpectedRevision, current.Revision, now); err != nil {
			return fmt.Errorf("insert DNS cancel fact: %w", err)
		}

		var total, succeeded, failed, cancelled, pending int
		if err := tx.QueryRow(ctx, `SELECT count(*)::integer,
			count(*) FILTER (WHERE state='succeeded')::integer,
			count(*) FILTER (WHERE state='failed')::integer,
			count(*) FILTER (WHERE state='cancelled')::integer,
			count(*) FILTER (WHERE state='pending')::integer
			FROM background_job_items WHERE tenant_id=$1 AND job_id=$2`,
			request.TenantID, request.TaskID).Scan(&total, &succeeded, &failed, &cancelled, &pending); err != nil {
			return fmt.Errorf("aggregate cancelled DNS job: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE background_jobs
			SET state='cancelled',cancel_requested_at=$3,completed_count=$4,
				succeeded_count=$5,failed_count=$6,cancelled_count=$7,
				lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,claimable_at=NULL,
				last_error_code=$8,completed_at=$3,updated_at=$3
			WHERE tenant_id=$1 AND id=$2`, request.TenantID, request.TaskID, now, total,
			succeeded, failed, cancelled+pending, jobstate.CodeCancelled); err != nil {
			return fmt.Errorf("cancel DNS background job: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE background_job_items
			SET state='cancelled',attempt=$3,sequence=0,error_code=$4,completed_at=$5
			WHERE tenant_id=$1 AND job_id=$2 AND state='pending'`, request.TenantID,
			request.TaskID, attempt, jobstate.CodeCancelled, now); err != nil {
			return fmt.Errorf("cancel DNS background job items: %w", err)
		}
		if state == string(jobstate.StateRunning) {
			command, err := tx.Exec(ctx, `UPDATE background_job_attempts
				SET state='cancelled',completed_at=$4,error_code=$5
				WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND state='running'`,
				request.TenantID, request.TaskID, attempt, now, jobstate.CodeCancelled)
			if err != nil {
				return fmt.Errorf("cancel DNS background job attempt: %w", err)
			}
			if command.RowsAffected() != 1 {
				return ErrClaimLost
			}
		}
		scopeID, err := dnsReconcileTaskScopeID(ctx, tx, request.TenantID, request.TaskID)
		if err != nil {
			return err
		}
		if err := store.appendDNSCommandAudit(ctx, tx, dnsCommandAuditInput{
			ScopeID: scopeID, ActorUserID: request.ActorUserID, TaskID: request.TaskID,
			RequestID: request.RequestID, Action: ActionCancel,
			ExpectedRevision: request.ExpectedRevision, ProviderRevision: current.Result.ProviderRevision,
		}); err != nil {
			return fmt.Errorf("audit accepted DNS cancel: %w", err)
		}
		return nil
	})
	if err != nil {
		return Task{}, false, mapStoreError(err)
	}
	cancelled, err := store.Get(ctx, request.TenantID, request.TaskID)
	if err != nil {
		return Task{}, false, err
	}
	cancelled.Replayed = replayed
	return cancelled, replayed, nil
}

func (store *PostgresStore) RecordProviderReport(ctx context.Context, request ProviderReportRequest) (ReportResult, error) {
	if ctx == nil || request.TenantID == uuid.Nil || request.SiteID == uuid.Nil || request.TaskID == uuid.Nil ||
		!validWorker(request.WorkloadID) || request.JobAttempt == 0 || request.LeaseID == uuid.Nil ||
		!dnsReconcileKeyPattern.MatchString(request.IdempotencyKey) || request.ExpectedRevision < 1 ||
		!validSafeText(request.RequestID, 128, false) || !validSafeText(request.Traceparent, 512, false) ||
		!validReportedOperationStatus(request.Report.Status) || request.Report.ClientRequestID == "" || request.Report.Sequence == 0 ||
		(request.Report.ProviderRequestID != "" && !dnscheck.ValidProviderIdentifier(request.Report.ProviderRequestID)) ||
		(request.Report.ProviderRecordID != "" && !dnscheck.ValidProviderIdentifier(request.Report.ProviderRecordID)) {
		return ReportResult{}, ErrInvalidInput
	}
	commandDigest, err := dnsCommandDigest(Action("provider_report"), request.TenantID, request.SiteID,
		request.TaskID, request.ExpectedRevision, uuid.Nil, struct {
			WorkloadID string                  `json:"workload_id"`
			JobAttempt uint32                  `json:"job_attempt"`
			LeaseID    uuid.UUID               `json:"lease_id"`
			Report     dnscheck.ProviderReport `json:"report"`
		}{request.WorkloadID, request.JobAttempt, request.LeaseID, request.Report})
	if err != nil {
		return ReportResult{}, ErrInvalidInput
	}
	now := store.timestamp()
	accepted := false
	replayed := false
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := lockDNSReconcileTask(ctx, tx, request.TenantID, request.TaskID); err != nil {
			return err
		}
		current, err := loadDNSReconcileTask(ctx, tx, request.TenantID, request.TaskID)
		if err != nil {
			return err
		}
		canonicalJobID, canonicalDigest, canonicalAccepted, found, err := loadProviderReportCommand(
			ctx, tx, request.TenantID, request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if canonicalJobID != request.TaskID || !bytes.Equal(canonicalDigest, commandDigest[:]) {
				return ErrIdempotencyConflict
			}
			accepted = canonicalAccepted
			replayed = true
			return nil
		}
		if current.SiteID != request.SiteID {
			return ErrIdempotencyConflict
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		liveAttempt, liveLeaseID, liveWorkerID, err := loadLiveApplyClaim(
			ctx, tx, request.TenantID, request.TaskID, now)
		if err != nil {
			return err
		}
		if request.JobAttempt != uint32(liveAttempt) || request.LeaseID != liveLeaseID ||
			request.WorkloadID != liveWorkerID {
			return ErrClaimLost
		}
		if err := assertLiveApplyClaim(ctx, tx, request.TenantID, request.TaskID,
			liveAttempt, liveLeaseID, liveWorkerID, now); err != nil {
			return err
		}
		phase, ordinal, existing, found := findOperation(current.Result, request.Report.ClientRequestID)
		if !found {
			return ErrInvalidInput
		}
		if request.Report.Status == dnscheck.OperationSucceeded &&
			(!dnscheck.ValidProviderIdentifier(request.Report.ProviderRequestID) ||
				!dnscheck.ValidProviderIdentifier(request.Report.ProviderRecordID) ||
				request.Report.ProviderRevision <= current.Result.ProviderRevision ||
				request.Report.ProviderRevision < existing.ProviderRevision ||
				(existing.Operation.Action != dnscheck.ProviderCreate &&
					request.Report.ProviderRecordID != existing.Operation.RecordID) ||
				request.Report.ErrorClass != dnscheck.ProviderErrorNone || request.Report.ErrorCode != "") {
			return ErrInvalidInput
		}
		merged, applied := dnscheck.MergeProviderReport(existing, request.Report)
		if current.Result.Status != dnscheck.TaskApplying && current.Result.Status != dnscheck.TaskPropagating {
			applied = false
		}
		disposition := reportDisposition(existing, request.Report, applied)
		command := &providerReportCommand{
			key: request.IdempotencyKey, digest: commandDigest[:], requestID: request.RequestID,
			traceparent: request.Traceparent, expectedTaskRevision: request.ExpectedRevision,
		}
		if err := insertRawProviderReport(ctx, tx, request.TenantID, request.TaskID, phase, ordinal,
			"workload", int(request.JobAttempt), request.LeaseID, request.WorkloadID,
			command, request.Report, applied, disposition, now); err != nil {
			return err
		}
		if !applied {
			return nil
		}
		result := current.Result
		if phase == "apply" {
			result.Operations[ordinal-1] = merged
		} else {
			result.DeferredDeletes[ordinal-1] = merged
		}
		if merged.Status == dnscheck.OperationSucceeded {
			result.ProviderRevision = merged.ProviderRevision
		}
		result.UpdatedAt = now
		retryDelay := time.Duration(0)
		if merged.Status == dnscheck.OperationTransientFailed && merged.RetryAfter > 0 &&
			merged.ErrorCode != "dependency_unavailable" {
			result.Status = dnscheck.TaskPropagating
			retryDelay = retryAfterDelay(ApplyLease{
				Task: current, WorkerID: liveWorkerID, Attempt: uint32(liveAttempt), LeaseID: liveLeaseID,
			}, merged.RetryAfter)
			var consumed bool
			result, consumed = consumeRetryAfterHints(result)
			if retryDelay <= 0 || !consumed {
				return ErrInvalidInput
			}
		}
		if err := insertTaskEvent(ctx, tx, current, "workload", 0, uuid.Nil, "", result, now); err != nil {
			return err
		}
		if retryDelay > 0 {
			if err := jobstate.VoluntaryYieldTx(ctx, tx, jobstate.VoluntaryYieldInput{
				TenantID: request.TenantID, JobID: request.TaskID, Kind: JobKind,
				Attempt: uint32(liveAttempt), LeaseID: liveLeaseID, WorkerID: liveWorkerID,
				YieldedAt: now, NotBefore: now.Add(retryDelay),
			}); err != nil {
				return mapJobstateError(err)
			}
		}
		accepted = true
		return nil
	})
	if err != nil {
		return ReportResult{}, mapStoreError(err)
	}
	task, err := store.Get(ctx, request.TenantID, request.TaskID)
	if err != nil {
		return ReportResult{}, err
	}
	task.Replayed = replayed
	return ReportResult{Task: task, Accepted: accepted}, nil
}

func (store *PostgresStore) appendResult(
	ctx context.Context,
	tenantID, taskID uuid.UUID,
	source string,
	attempt int,
	leaseID uuid.UUID,
	workerID string,
	result dnscheck.ReconcileResult,
	retryDelay time.Duration,
) (Task, error) {
	now := store.timestamp()
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := lockDNSReconcileTask(ctx, tx, tenantID, taskID); err != nil {
			return err
		}
		current, err := loadDNSReconcileTask(ctx, tx, tenantID, taskID)
		if err != nil {
			return err
		}
		if err := validateResultAdvance(current.Result, result, checkpointPhaseApply); err != nil {
			return err
		}
		checkpointResult := result
		if retryDelay > 0 {
			var consumed bool
			checkpointResult, consumed = consumeRetryAfterHints(result)
			// N22: once every provider write succeeded, the delay paces the next
			// propagation check (authority_conflict, public_quorum_pending, or
			// healthy but short of RequiredConsecutive). There is no operation
			// RetryAfter left to consume; requiring one rejected every such
			// retry and left the task holding its lease until it expired.
			if !consumed && result.ErrorCode != "dependency_unavailable" && !propagationRetry(result) {
				return ErrInvalidInput
			}
		}
		if source == "worker" {
			if err := assertLiveApplyClaim(ctx, tx, tenantID, taskID, attempt, leaseID, workerID, now); err != nil {
				return err
			}
		}
		if sameResult(current.Result, checkpointResult) && retryDelay == 0 {
			return nil
		}
		if source == "worker" {
			// N22: ready/committed needs every provider write confirmed by the
			// provider lookup (validResultCompletion), not consecutive healthy
			// propagation checks.
			if err := insertApplyCheckpointDetails(ctx, tx, current.Result, result,
				tenantID, taskID, attempt, leaseID, workerID, now); err != nil {
				return err
			}
		}
		if err := insertTaskEvent(ctx, tx, current, source, attempt, leaseID, workerID, checkpointResult, now); err != nil {
			return err
		}
		if retryDelay > 0 {
			err := jobstate.VoluntaryYieldTx(ctx, tx, jobstate.VoluntaryYieldInput{
				TenantID: tenantID, JobID: taskID, Kind: JobKind, Attempt: uint32(attempt),
				LeaseID: leaseID, WorkerID: workerID, YieldedAt: now, NotBefore: now.Add(retryDelay),
			})
			if err != nil {
				return mapJobstateError(err)
			}
		}
		return nil
	})
	if err != nil {
		return Task{}, mapStoreError(err)
	}
	return store.Get(ctx, tenantID, taskID)
}

// propagationRetry reports a propagating result whose provider writes all
// succeeded: its delayed checkpoint schedules the next propagation check.
func propagationRetry(result dnscheck.ReconcileResult) bool {
	if result.Status != dnscheck.TaskPropagating || len(result.Operations) == 0 {
		return false
	}
	for _, operation := range result.Operations {
		if operation.Status != dnscheck.OperationSucceeded {
			return false
		}
	}
	return true
}

func consumeRetryAfterHints(result dnscheck.ReconcileResult) (dnscheck.ReconcileResult, bool) {
	consumed := false
	checkpoint := result
	checkpoint.Operations = append([]dnscheck.OperationResult(nil), result.Operations...)
	checkpoint.DeferredDeletes = append([]dnscheck.OperationResult(nil), result.DeferredDeletes...)
	consume := func(operations []dnscheck.OperationResult) {
		for index := range operations {
			operation := &operations[index]
			if (operation.Status == dnscheck.OperationRunning || operation.Status == dnscheck.OperationTransientFailed) &&
				operation.RetryAfter > 0 &&
				(operation.ErrorClass == dnscheck.ProviderErrorTransient || operation.ErrorClass == dnscheck.ProviderErrorTimeout) {
				operation.RetryAfter = 0
				consumed = true
			}
		}
	}
	consume(checkpoint.Operations)
	consume(checkpoint.DeferredDeletes)
	return checkpoint, consumed
}

func insertOperationFacts(
	ctx context.Context,
	tx pgx.Tx,
	request ApplyRequest,
	jobID uuid.UUID,
	result dnscheck.ReconcileResult,
	createdAt time.Time,
) error {
	insert := func(phase string, ordinal int, operation dnscheck.OperationResult) error {
		clientRequestID := operation.ClientRequestID
		if clientRequestID == "" {
			clientRequestID = operationRequestID(request.TenantID, request.IdempotencyKey,
				result.PayloadDigest, phase, operation.SourceSequence)
		}
		encoded, err := json.Marshal(operation.Operation)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO dns_reconcile_operations(
			tenant_id,job_id,phase,ordinal,source_sequence,action,
			client_request_id,operation,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, request.TenantID, jobID, phase,
			ordinal, operation.SourceSequence, string(operation.Operation.Action), clientRequestID,
			encoded, createdAt)
		return err
	}
	for index, operation := range result.Operations {
		if operation.Operation.Action == dnscheck.ProviderDelete || operation.SourceSequence < 1 {
			return ErrInvalidInput
		}
		if err := insert("apply", index+1, operation); err != nil {
			return fmt.Errorf("insert DNS apply operation: %w", err)
		}
	}
	for index, operation := range result.DeferredDeletes {
		if operation.Operation.Action != dnscheck.ProviderDelete || operation.SourceSequence < 1 {
			return ErrInvalidInput
		}
		if err := insert("commit", index+1, operation); err != nil {
			return fmt.Errorf("insert DNS commit operation: %w", err)
		}
	}
	return nil
}

func insertApplyCheckpointDetails(
	ctx context.Context,
	tx pgx.Tx,
	current, next dnscheck.ReconcileResult,
	tenantID, taskID uuid.UUID,
	attempt int,
	leaseID uuid.UUID,
	workerID string,
	now time.Time,
) error {
	if len(next.Operations) != len(current.Operations) || len(next.DeferredDeletes) != len(current.DeferredDeletes) {
		return ErrInvalidInput
	}
	for index, operation := range next.Operations {
		if operation.ReportSequence <= current.Operations[index].ReportSequence || operation.ReportSequence == 0 {
			continue
		}
		report := dnscheck.ProviderReport{
			ClientRequestID: operation.ClientRequestID, ProviderRequestID: operation.ProviderRequestID,
			ProviderRecordID: operation.ProviderRecordID, ProviderRevision: operation.ProviderRevision,
			Status: operation.Status, ErrorClass: operation.ErrorClass, ErrorCode: operation.ErrorCode,
			Sequence: operation.ReportSequence,
		}
		if err := insertRawProviderReport(ctx, tx, tenantID, taskID, "apply", index+1,
			"worker", attempt, leaseID, workerID, nil, report, true, "accepted", now); err != nil {
			return err
		}
	}
	for index := len(current.Propagation); index < len(next.Propagation); index++ {
		propagation := next.Propagation[index]
		var check any = map[string]any{"status": propagation.Status}
		if next.LastCheck != nil {
			check = next.LastCheck
		}
		checkJSON, err := json.Marshal(check)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO dns_reconcile_propagation_attempts(
			tenant_id,job_id,job_attempt,lease_id,worker_id,attempt_number,
			classification,consecutive_healthy,check_result,checked_at,recorded_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, tenantID, taskID, attempt,
			leaseID, workerID, propagation.Number, string(propagation.Status),
			propagation.ConsecutiveHealthy, checkJSON, propagation.CheckedAt, now); err != nil {
			return fmt.Errorf("insert DNS propagation attempt: %w", err)
		}
	}
	return nil
}

type providerReportCommand struct {
	key                  string
	digest               []byte
	requestID            string
	traceparent          string
	expectedTaskRevision int64
}

func insertRawProviderReport(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, taskID uuid.UUID,
	phase string,
	ordinal int,
	source string,
	attempt int,
	leaseID uuid.UUID,
	workerID string,
	command *providerReportCommand,
	report dnscheck.ProviderReport,
	accepted bool,
	disposition string,
	now time.Time,
) error {
	var providerRequestID, providerRecordID, errorCode any
	if report.ProviderRequestID != "" {
		providerRequestID = report.ProviderRequestID
	}
	if report.ProviderRecordID != "" {
		providerRecordID = report.ProviderRecordID
	}
	if report.ErrorCode != "" {
		errorCode = report.ErrorCode
	}
	var commandKey, commandDigest, requestID, traceparent, expectedTaskRevision any
	var attemptValue, leaseValue, workerValue any
	if source == "worker" {
		attemptValue, leaseValue, workerValue = attempt, leaseID, workerID
	} else if command != nil {
		commandKey, commandDigest, requestID = command.key, command.digest, command.requestID
		traceparent, expectedTaskRevision = command.traceparent, command.expectedTaskRevision
		attemptValue, leaseValue, workerValue = attempt, leaseID, workerID
	}
	_, err := tx.Exec(ctx, `INSERT INTO dns_reconcile_provider_reports(
		id,tenant_id,job_id,phase,operation_ordinal,source,command_idempotency_key,
		command_digest,request_id,traceparent,expected_task_revision,job_attempt,lease_id,worker_id,
		report_sequence,status,provider_request_id,provider_record_id,provider_revision,
		error_class,error_code,accepted,disposition,reported_at,received_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$24)`,
		uuid.New(), tenantID, taskID, phase, ordinal, source, commandKey, commandDigest,
		requestID, traceparent, expectedTaskRevision, attemptValue, leaseValue, workerValue,
		int64(report.Sequence), string(report.Status), providerRequestID, providerRecordID,
		nullableRevision(report.ProviderRevision), string(report.ErrorClass), errorCode,
		accepted, disposition, now)
	if err != nil {
		return fmt.Errorf("insert DNS provider report: %w", err)
	}
	return nil
}

func insertTaskEvent(
	ctx context.Context,
	tx pgx.Tx,
	current Task,
	source string,
	attempt int,
	leaseID uuid.UUID,
	workerID string,
	result dnscheck.ReconcileResult,
	now time.Time,
) error {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return err
	}
	compensation, err := jsonArray(result.CompensationPlan)
	if err != nil {
		return err
	}
	var attemptValue, leaseValue, workerValue, errorCode any
	if source == "worker" || source == "commit" {
		attemptValue, leaseValue, workerValue = attempt, leaseID, workerID
	}
	if result.ErrorCode != "" {
		errorCode = result.ErrorCode
	}
	_, err = tx.Exec(ctx, `INSERT INTO dns_reconcile_task_events(
		tenant_id,job_id,event_sequence,source,job_attempt,lease_id,worker_id,
		status,provider_revision,result_snapshot,compensation_plan,error_class,
		error_code,occurred_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		current.TenantID, current.ID, current.Revision, source, attemptValue, leaseValue,
		workerValue, string(result.Status), nullableRevision(result.ProviderRevision),
		resultJSON, compensation, string(result.ErrorClass), errorCode, now)
	if err != nil {
		return fmt.Errorf("insert DNS task event: %w", err)
	}
	return nil
}

type dnsReconcileQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type dnsReconcileReader interface {
	dnsReconcileQueryer
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func loadDNSReconcileSnapshot(
	ctx context.Context,
	database dnsReconcileReader,
	tenantID, taskID uuid.UUID,
) (Task, error) {
	task, err := loadDNSReconcileTask(ctx, database, tenantID, taskID)
	if err != nil {
		return Task{}, err
	}
	task.Job, err = loadDNSReconcileJob(ctx, database, tenantID, taskID)
	if err != nil {
		return Task{}, err
	}
	return task, nil
}

func loadDNSReconcileJob(
	ctx context.Context,
	database dnsReconcileReader,
	tenantID, taskID uuid.UUID,
) (jobstate.StoredJob, error) {
	var job jobstate.StoredJob
	var digest []byte
	var state string
	var attempt, maximum int
	var cancelRequestedAt, startedAt, completedAt *time.Time
	var lastErrorCode *string
	err := database.QueryRow(ctx, `SELECT id,tenant_id,kind,subject,idempotency_key,request_digest,
		request_id,trace_id,state,attempt,max_attempts,cancel_requested_at,total_count,
		completed_count,succeeded_count,failed_count,cancelled_count,last_error_code,
		created_at,started_at,updated_at,completed_at
		FROM background_jobs WHERE tenant_id=$1 AND id=$2`, tenantID, taskID).Scan(
		&job.ID, &job.TenantID, &job.Kind, &job.Subject, &job.IdempotencyKey, &digest,
		&job.RequestID, &job.TraceID, &state, &attempt, &maximum, &cancelRequestedAt,
		&job.Progress.Total, &job.Progress.Completed, &job.Progress.Succeeded,
		&job.Progress.Failed, &job.Progress.Cancelled, &lastErrorCode,
		&job.CreatedAt, &startedAt, &job.UpdatedAt, &completedAt)
	if err == pgx.ErrNoRows {
		return jobstate.StoredJob{}, ErrNotFound
	}
	if err != nil {
		return jobstate.StoredJob{}, fmt.Errorf("read DNS reconcile background job: %w", err)
	}
	copy(job.RequestDigest[:], digest)
	job.State = jobstate.State(state)
	job.Attempt = uint32(attempt)
	job.MaxAttempts = uint32(maximum)
	job.Progress.Pending = job.Progress.Total - job.Progress.Completed
	job.CancelRequestedAt = optionalTime(cancelRequestedAt)
	job.StartedAt = optionalTime(startedAt)
	job.CompletedAt = optionalTime(completedAt)
	job.LastErrorCode = optionalString(lastErrorCode)

	rows, err := database.Query(ctx, `SELECT item_id,node_id,state,attempt,sequence,error_code,completed_at
		FROM background_job_items WHERE tenant_id=$1 AND job_id=$2 ORDER BY ordinal`, tenantID, taskID)
	if err != nil {
		return jobstate.StoredJob{}, fmt.Errorf("read DNS reconcile background job items: %w", err)
	}
	defer rows.Close()
	job.Items = make([]jobstate.StoredItem, 0, job.Progress.Total)
	for rows.Next() {
		var item jobstate.StoredItem
		var nodeID *uuid.UUID
		var itemState string
		var itemAttempt int
		var sequence int64
		var errorCode *string
		var itemCompletedAt *time.Time
		if err := rows.Scan(&item.ItemID, &nodeID, &itemState, &itemAttempt, &sequence,
			&errorCode, &itemCompletedAt); err != nil {
			return jobstate.StoredJob{}, fmt.Errorf("scan DNS reconcile background job item: %w", err)
		}
		if nodeID != nil {
			cloned := *nodeID
			item.NodeID = &cloned
		}
		item.State = jobstate.ItemState(itemState)
		item.Attempt = uint32(itemAttempt)
		item.Sequence = uint64(sequence)
		item.ErrorCode = optionalString(errorCode)
		item.CompletedAt = optionalTime(itemCompletedAt)
		job.Items = append(job.Items, item)
	}
	if err := rows.Err(); err != nil {
		return jobstate.StoredJob{}, fmt.Errorf("iterate DNS reconcile background job items: %w", err)
	}
	return job, nil
}

func optionalTime(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}

func optionalUUID(value *uuid.UUID) uuid.UUID {
	if value == nil {
		return uuid.Nil
	}
	return *value
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func loadDNSReconcileTask(ctx context.Context, database dnsReconcileQueryer, tenantID, taskID uuid.UUID) (Task, error) {
	var task Task
	var preparedJSON, resultJSON []byte
	var eventSequence *int64
	var eventAt *time.Time
	err := database.QueryRow(ctx, `
		SELECT task.job_id,task.tenant_id,COALESCE(task.site_id,task.stream_id),task.required_consecutive,
		       task.canonical_request,task.created_at,
		       event.event_sequence,event.result_snapshot,event.occurred_at
		FROM dns_reconcile_tasks task
		LEFT JOIN LATERAL (
			SELECT event_sequence,result_snapshot,occurred_at
			FROM dns_reconcile_task_events
			WHERE tenant_id=task.tenant_id AND job_id=task.job_id
			ORDER BY event_sequence DESC LIMIT 1
		) event ON true
		WHERE task.tenant_id=$1 AND task.job_id=$2`, tenantID, taskID).Scan(
		&task.ID, &task.TenantID, &task.SiteID, &task.RequiredConsecutive, &preparedJSON, &task.CreatedAt,
		&eventSequence, &resultJSON, &eventAt)
	if err == pgx.ErrNoRows {
		return Task{}, ErrNotFound
	}
	if err != nil {
		return Task{}, err
	}
	var canonical storedCanonicalRequest
	if err := json.Unmarshal(preparedJSON, &canonical); err != nil {
		return Task{}, fmt.Errorf("decode DNS prepared request: %w", err)
	}
	if canonical.Version != 1 || canonical.ActorUserID == uuid.Nil ||
		!validSafeText(canonical.RequestID, 128, false) {
		return Task{}, fmt.Errorf("decode DNS prepared request: %w", ErrUnavailable)
	}
	task.Prepared = canonical.Prepared
	task.ActorUserID = canonical.ActorUserID
	task.RequestID = canonical.RequestID
	task.Result = task.Prepared.Result
	task.Revision = 1
	task.UpdatedAt = task.CreatedAt
	if eventSequence != nil {
		// N25: decode into a fresh value. Unmarshalling into task.Result reused
		// the slices it shares with task.Prepared.Result, so the prepared
		// deferred deletes took the snapshot's request IDs and every commit
		// after one that recorded a delete intent was refused.
		var snapshot dnscheck.ReconcileResult
		if err := json.Unmarshal(resultJSON, &snapshot); err != nil {
			return Task{}, fmt.Errorf("decode DNS result snapshot: %w", err)
		}
		task.Result = snapshot
		task.Revision = *eventSequence + 1
		task.UpdatedAt = *eventAt
	}
	return task, nil
}

func lockDNSReconcileTask(ctx context.Context, tx pgx.Tx, tenantID, taskID uuid.UUID) error {
	var found uuid.UUID
	err := tx.QueryRow(ctx, `SELECT job_id FROM dns_reconcile_tasks
		WHERE tenant_id=$1 AND job_id=$2 FOR UPDATE`, tenantID, taskID).Scan(&found)
	if err == pgx.ErrNoRows {
		return ErrNotFound
	}
	return err
}

func assertLiveApplyClaim(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, taskID uuid.UUID,
	attempt int,
	leaseID uuid.UUID,
	workerID string,
	now time.Time,
) error {
	var live bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM background_jobs job
		JOIN background_job_attempts claimed
		  ON claimed.tenant_id=job.tenant_id AND claimed.job_id=job.id AND claimed.attempt=job.attempt
		WHERE job.tenant_id=$1 AND job.id=$2 AND job.kind=$3 AND job.state='running'
		  AND job.attempt=$4 AND job.lease_id=$5 AND job.lease_owner=$6
		  AND job.lease_expires_at > $7 AND claimed.state='running'
		  AND claimed.lease_id=$5 AND claimed.worker_id=$6
		  AND claimed.lease_expires_at=job.lease_expires_at
	)`, tenantID, taskID, JobKind, attempt, leaseID, workerID, now).Scan(&live)
	if err != nil {
		return err
	}
	if !live {
		return ErrClaimLost
	}
	return nil
}

func loadLiveApplyClaim(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, taskID uuid.UUID,
	now time.Time,
) (int, uuid.UUID, string, error) {
	var attempt int
	var leaseID uuid.UUID
	var workerID string
	err := tx.QueryRow(ctx, `SELECT attempt,lease_id,lease_owner FROM background_jobs
		WHERE tenant_id=$1 AND id=$2 AND kind=$3 AND state='running'
		  AND lease_expires_at > $4 FOR UPDATE`, tenantID, taskID, JobKind, now).Scan(
		&attempt, &leaseID, &workerID)
	if err == pgx.ErrNoRows {
		return 0, uuid.Nil, "", ErrClaimLost
	}
	return attempt, leaseID, workerID, err
}

type commitFact struct {
	jobID                uuid.UUID
	actorUserID          uuid.UUID
	commandKey           string
	commandDigest        []byte
	requestID            string
	traceparent          string
	expectedTaskRevision int64
	sequence             int64
	attempt              int
	leaseID              uuid.UUID
	workerID             string
	expiresAt            time.Time
	eventType            string
	expectedRevision     int64
}

func loadCommitCommand(
	ctx context.Context,
	tx pgx.Tx,
	tenantID uuid.UUID,
	key string,
) (commitFact, bool, error) {
	var fact commitFact
	var actorUserID *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT job_id,command_idempotency_key,command_digest,request_id,
		traceparent,expected_task_revision,fact_sequence,commit_attempt,lease_id,worker_id,
		actor_user_id,
		lease_expires_at,event_type,expected_provider_revision
		FROM dns_reconcile_commit_facts
		WHERE tenant_id=$1 AND command_idempotency_key=$2 AND fact_sequence=1`, tenantID, key).Scan(
		&fact.jobID, &fact.commandKey, &fact.commandDigest, &fact.requestID, &fact.traceparent,
		&fact.expectedTaskRevision, &fact.sequence, &fact.attempt, &fact.leaseID, &fact.workerID,
		&actorUserID, &fact.expiresAt, &fact.eventType, &fact.expectedRevision)
	if err == pgx.ErrNoRows {
		return commitFact{}, false, nil
	}
	fact.actorUserID = optionalUUID(actorUserID)
	return fact, err == nil, err
}

func loadLatestCommitFact(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, taskID uuid.UUID,
) (commitFact, bool, error) {
	var fact commitFact
	var actorUserID *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT job_id,command_idempotency_key,command_digest,request_id,
		traceparent,expected_task_revision,fact_sequence,commit_attempt,lease_id,worker_id,
		actor_user_id,
		lease_expires_at,event_type,expected_provider_revision
		FROM dns_reconcile_commit_facts WHERE tenant_id=$1 AND job_id=$2
		ORDER BY fact_sequence DESC LIMIT 1`, tenantID, taskID).Scan(
		&fact.jobID, &fact.commandKey, &fact.commandDigest, &fact.requestID, &fact.traceparent,
		&fact.expectedTaskRevision, &fact.sequence, &fact.attempt, &fact.leaseID, &fact.workerID,
		&actorUserID, &fact.expiresAt, &fact.eventType, &fact.expectedRevision)
	if err == pgx.ErrNoRows {
		return commitFact{}, false, nil
	}
	fact.actorUserID = optionalUUID(actorUserID)
	return fact, err == nil, err
}

func loadProviderReportCommand(
	ctx context.Context,
	tx pgx.Tx,
	tenantID uuid.UUID,
	key string,
) (uuid.UUID, []byte, bool, bool, error) {
	var jobID uuid.UUID
	var digest []byte
	var accepted bool
	err := tx.QueryRow(ctx, `SELECT job_id,command_digest,accepted
		FROM dns_reconcile_provider_reports
		WHERE tenant_id=$1 AND source='workload' AND command_idempotency_key=$2`,
		tenantID, key).Scan(&jobID, &digest, &accepted)
	if err == pgx.ErrNoRows {
		return uuid.Nil, nil, false, false, nil
	}
	return jobID, digest, accepted, err == nil, err
}

func loadCancelCommand(
	ctx context.Context,
	tx pgx.Tx,
	tenantID uuid.UUID,
	key string,
) (uuid.UUID, uuid.UUID, []byte, bool, error) {
	var jobID uuid.UUID
	var digest []byte
	var actorUserID *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT job_id,actor_user_id,command_digest
		FROM dns_reconcile_cancel_facts
		WHERE tenant_id=$1 AND command_idempotency_key=$2`, tenantID, key).Scan(&jobID, &actorUserID, &digest)
	if err == pgx.ErrNoRows {
		return uuid.Nil, uuid.Nil, nil, false, nil
	}
	return jobID, optionalUUID(actorUserID), digest, err == nil, err
}

func commitFactMatches(fact commitFact, lease CommitLease, now time.Time) bool {
	return fact.eventType != "failed" && fact.eventType != "committed" && fact.attempt == int(lease.Attempt) &&
		fact.leaseID == lease.LeaseID && fact.workerID == lease.WorkerID &&
		fact.actorUserID != uuid.Nil && fact.actorUserID == lease.Command.ActorUserID && fact.expiresAt.After(now)
}

func findOperation(result dnscheck.ReconcileResult, clientRequestID string) (string, int, dnscheck.OperationResult, bool) {
	for index, operation := range result.Operations {
		if operation.ClientRequestID == clientRequestID {
			return "apply", index + 1, operation, true
		}
	}
	for index, operation := range result.DeferredDeletes {
		if operation.ClientRequestID == clientRequestID && clientRequestID != "" {
			return "commit", index + 1, operation, true
		}
	}
	return "", 0, dnscheck.OperationResult{}, false
}

func operationInFlight(result dnscheck.ReconcileResult) bool {
	for _, operation := range result.Operations {
		if operation.Status == dnscheck.OperationRunning {
			return true
		}
	}
	for _, operation := range result.DeferredDeletes {
		if operation.Status == dnscheck.OperationRunning {
			return true
		}
	}
	return false
}

func reportDisposition(current dnscheck.OperationResult, report dnscheck.ProviderReport, accepted bool) string {
	if accepted {
		return "accepted"
	}
	if report.Sequence < current.ReportSequence {
		return "stale_sequence"
	}
	if report.Sequence == current.ReportSequence {
		if current.Status == report.Status && current.ProviderRequestID == report.ProviderRequestID &&
			current.ProviderRecordID == report.ProviderRecordID && current.ProviderRevision == report.ProviderRevision {
			return "duplicate"
		}
		return "conflict"
	}
	return "status_regression"
}

func validCreate(request ApplyRequest, prepared dnscheck.PreparedReconcile) bool {
	if request.TenantID == uuid.Nil || request.SiteID == uuid.Nil || request.ActorUserID == uuid.Nil ||
		!dnsReconcileKeyPattern.MatchString(request.IdempotencyKey) ||
		!validSafeText(request.RequestID, 128, false) || !validSafeText(request.Traceparent, 512, true) ||
		request.ExpectedRevision < 1 || prepared.IdempotencyKey != request.IdempotencyKey ||
		prepared.Request.TenantID != request.TenantID || prepared.Request.SiteID != request.SiteID ||
		prepared.Request.Provider.ZoneID == uuid.Nil || prepared.Result.TenantID != request.TenantID ||
		prepared.Result.SiteID != request.SiteID || prepared.Result.ZoneID != prepared.Request.Provider.ZoneID ||
		prepared.Result.InitialRevision != request.ExpectedRevision ||
		prepared.Result.InitialRevision != prepared.Request.Provider.Revision ||
		prepared.Result.Status != dnscheck.TaskDryRun || request.RequiredConsecutive < 1 ||
		request.RequiredConsecutive > 5 {
		return false
	}
	return request.Check.TenantID == request.TenantID && request.Check.SiteID == request.SiteID &&
		request.Check.Provider.TenantID == request.TenantID && request.Check.Provider.SiteID == request.SiteID &&
		request.Check.Provider.ZoneID == prepared.Request.Provider.ZoneID &&
		request.Check.Provider.Revision == request.ExpectedRevision
}

type storedCanonicalRequest struct {
	Version     uint8                      `json:"version"`
	ActorUserID uuid.UUID                  `json:"actor_user_id"`
	RequestID   string                     `json:"request_id"`
	Prepared    dnscheck.PreparedReconcile `json:"prepared"`
}

func validApplyLease(lease ApplyLease) bool {
	return lease.Task.ID != uuid.Nil && lease.Task.TenantID != uuid.Nil && lease.Task.SiteID != uuid.Nil &&
		validWorker(lease.WorkerID) && lease.Attempt > 0 && lease.LeaseID != uuid.Nil &&
		!lease.LeaseExpiresAt.IsZero()
}

func validCommitLease(lease CommitLease) bool {
	return lease.Task.ID != uuid.Nil && lease.Task.TenantID != uuid.Nil && validWorker(lease.WorkerID) &&
		lease.Attempt > 0 && lease.LeaseID != uuid.Nil && !lease.LeaseExpiresAt.IsZero() &&
		lease.Command.ActorUserID != uuid.Nil
}

func validWorker(value string) bool {
	return validSafeText(value, 128, false)
}

func validSafeText(value string, maximum int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > maximum || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}

func validLeaseDuration(duration time.Duration) bool {
	return duration >= time.Second && duration <= maximumLeaseDuration
}

func validReportedOperationStatus(status dnscheck.OperationStatus) bool {
	return status == dnscheck.OperationRunning || status == dnscheck.OperationSucceeded ||
		status == dnscheck.OperationTransientFailed || status == dnscheck.OperationPermanentFailed ||
		status == dnscheck.OperationRevisionConflict || status == dnscheck.OperationCancelled
}

func resultMatchesTask(result dnscheck.ReconcileResult, task Task) bool {
	return result.TenantID == task.TenantID && result.SiteID == task.SiteID &&
		result.ZoneID == task.Prepared.Request.Provider.ZoneID &&
		result.PayloadDigest == task.Prepared.Result.PayloadDigest &&
		result.Plan.Digest == task.Prepared.Result.Plan.Digest
}

type checkpointPhase string

const (
	checkpointPhaseApply  checkpointPhase = "apply"
	checkpointPhaseCommit checkpointPhase = "commit"
)

func validateResultAdvance(current, next dnscheck.ReconcileResult, phase checkpointPhase) error {
	if (phase != checkpointPhaseApply && phase != checkpointPhaseCommit) ||
		current.TenantID != next.TenantID || current.SiteID != next.SiteID || current.ZoneID != next.ZoneID ||
		current.PayloadDigest != next.PayloadDigest || current.Plan.Digest != next.Plan.Digest ||
		len(current.Operations) != len(next.Operations) ||
		len(current.DeferredDeletes) != len(next.DeferredDeletes) ||
		len(next.Propagation) < len(current.Propagation) ||
		phase == checkpointPhaseCommit && len(next.Propagation) != len(current.Propagation) ||
		!validResultCompletion(next) {
		return ErrInvalidInput
	}
	for index := range current.Propagation {
		if !sameJSON(current.Propagation[index], next.Propagation[index]) {
			return ErrInvalidInput
		}
	}
	if phase == checkpointPhaseApply {
		if !sameOperationResults(current.DeferredDeletes, next.DeferredDeletes) {
			return ErrInvalidInput
		}
		for index := range current.Operations {
			if !validOperationResultAdvance(current.Operations[index], next.Operations[index], false) {
				return ErrInvalidInput
			}
		}
	} else {
		if !sameOperationResults(current.Operations, next.Operations) {
			return ErrInvalidInput
		}
		for index := range current.DeferredDeletes {
			if !validOperationResultAdvance(current.DeferredDeletes[index], next.DeferredDeletes[index], true) {
				return ErrInvalidInput
			}
		}
	}
	return nil
}

func sameOperationResults(current, next []dnscheck.OperationResult) bool {
	if len(current) != len(next) {
		return false
	}
	for index := range current {
		if !sameJSON(current[index], next[index]) {
			return false
		}
	}
	return true
}

func validResultCompletion(result dnscheck.ReconcileResult) bool {
	if result.Status != dnscheck.TaskReadyToCommit && result.Status != dnscheck.TaskCommitted {
		return true
	}
	for _, operation := range result.Operations {
		if operation.Status != dnscheck.OperationSucceeded {
			return false
		}
	}
	if result.Status == dnscheck.TaskReadyToCommit {
		return true
	}
	for _, operation := range result.DeferredDeletes {
		if operation.Status != dnscheck.OperationSucceeded {
			return false
		}
	}
	return true
}

func validOperationResultAdvance(current, next dnscheck.OperationResult, allowClientRequestIDFill bool) bool {
	if next.ReportSequence < current.ReportSequence || next.SourceSequence != current.SourceSequence ||
		!sameJSON(next.Operation, current.Operation) {
		return false
	}
	if next.ClientRequestID != current.ClientRequestID &&
		(!allowClientRequestIDFill || current.ClientRequestID != "" || next.ReportSequence <= current.ReportSequence) {
		return false
	}
	if next.ReportSequence > current.ReportSequence || sameJSON(next, current) {
		return true
	}
	if current.Status != dnscheck.OperationPlanned && current.Status != dnscheck.OperationDeferred {
		return false
	}
	expected := current
	expected.Status = dnscheck.OperationSkipped
	expected.ErrorCode = "prior_operation_failed"
	return sameJSON(next, expected)
}

func sameResult(left, right dnscheck.ReconcileResult) bool {
	return sameJSON(left, right)
}

func sameJSON(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func decodeDigest(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return nil, ErrInvalidInput
	}
	return decoded, nil
}

func dnsCommandDigest(
	action Action,
	tenantID, siteID, taskID uuid.UUID,
	expectedRevision int64,
	actorUserID uuid.UUID,
	payload any,
) ([sha256.Size]byte, error) {
	var actor *uuid.UUID
	if actorUserID != uuid.Nil {
		actor = &actorUserID
	}
	encoded, err := json.Marshal(struct {
		Version          uint8      `json:"version"`
		Action           Action     `json:"action"`
		TenantID         uuid.UUID  `json:"tenant_id"`
		SiteID           uuid.UUID  `json:"site_id"`
		TaskID           uuid.UUID  `json:"task_id"`
		ExpectedRevision int64      `json:"expected_revision"`
		ActorUserID      *uuid.UUID `json:"actor_user_id,omitempty"`
		Payload          any        `json:"payload"`
	}{
		Version: 1, Action: action, TenantID: tenantID, SiteID: siteID,
		TaskID: taskID, ExpectedRevision: expectedRevision, ActorUserID: actor, Payload: payload,
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func backgroundJobDigest(subject string, payload []byte) ([sha256.Size]byte, error) {
	type digestItem struct {
		ItemID string `json:"item_id"`
		NodeID string `json:"node_id,omitempty"`
	}
	encoded, err := json.Marshal(struct {
		Version     uint8        `json:"version"`
		Kind        string       `json:"kind"`
		Subject     string       `json:"subject"`
		Payload     []byte       `json:"payload"`
		Items       []digestItem `json:"items"`
		MaxAttempts uint32       `json:"max_attempts"`
	}{
		Version: 1, Kind: JobKind, Subject: subject, Payload: payload,
		Items: []digestItem{{ItemID: JobItemID}}, MaxAttempts: dnsReconcileMaxAttempts,
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func operationRequestID(tenantID uuid.UUID, key, digest, phase string, sequence int) string {
	input := tenantID.String() + "\x00" + key + "\x00" + digest + "\x00" + phase + "\x00" + fmt.Sprint(sequence)
	sum := sha256.Sum256([]byte(input))
	return "dns-" + hex.EncodeToString(sum[:16])
}

func backgroundJobIdempotencyKey(key string) string {
	digest := sha256.Sum256([]byte(key))
	return "dnsr-" + hex.EncodeToString(digest[:])
}

func jsonArray(value any) ([]byte, error) {
	if value == nil {
		return []byte("[]"), nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(encoded, []byte("null")) {
		return []byte("[]"), nil
	}
	return encoded, nil
}

func nullableRevision(revision int64) any {
	if revision < 1 {
		return nil
	}
	return revision
}

func (store *PostgresStore) timestamp() time.Time {
	return store.now().UTC().Truncate(time.Microsecond)
}

func mapJobstateError(err error) error {
	switch {
	case errors.Is(err, jobstate.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, jobstate.ErrClaimLost):
		return ErrClaimLost
	case errors.Is(err, jobstate.ErrIdempotencyConflict):
		return ErrIdempotencyConflict
	case errors.Is(err, jobstate.ErrInvalidRequest), errors.Is(err, jobstate.ErrInvalidReport):
		return ErrInvalidInput
	default:
		return fmt.Errorf("DNS reconcile jobstate: %w", err)
	}
}

func mapStoreError(err error) error {
	for _, sentinel := range []error{
		ErrInvalidInput, ErrNotFound, ErrIdempotencyConflict, ErrRevisionConflict,
		ErrCommitNotReady, ErrClaimLost, ErrOperationInFlight,
	} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		if postgresError.Code == "55000" {
			return ErrClaimLost
		}
		if postgresError.Code == "23505" {
			return ErrIdempotencyConflict
		}
	}
	return fmt.Errorf("persist DNS reconcile facts: %w", err)
}
