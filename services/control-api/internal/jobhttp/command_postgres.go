package jobhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type commandAuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type commandActorFacts struct {
	tenantID *uuid.UUID
}

type commandJobSnapshot struct {
	tenantID     uuid.UUID
	tupleVersion string
	state        string
	attempt      int
	kind         string
}

// producerOwnedCommandKinds: kinds whose producer keeps its own projection
// of the job (CACHE-ADD-05: a cache operation's cache_operations/node rows,
// cancel outbox and retry scheduling). Service.Command routes their
// cancel/retry to the registered ProducerCommandRouter (fix-cacheflow2); the
// generic cancel/retry only moves background_jobs, so when no router is
// registered (cache control disabled) and for replay it is refused here.
var producerOwnedCommandKinds = map[string]bool{"cache.operation": true}

func genericCommandSupported(kind string, _ CommandOperation) bool {
	return !producerOwnedCommandKinds[kind]
}

var errCommandConcurrentStateChanged = errors.New("job command state changed while waiting for lock")

type storedCommandReceipt struct {
	digest           []byte
	audience         string
	tenantID         uuid.UUID
	jobID            uuid.UUID
	operation        string
	requestID        string
	result           Job
	createdAt        time.Time
	completedAt      time.Time
	auditScopeID     uuid.UUID
	auditActorUserID *uuid.UUID
	auditAction      string
	auditResource    string
	auditRequestID   string
	auditResult      string
	auditPayload     []byte
}

type storedDeniedCommandAudit struct {
	resourceType string
	resourceID   string
	payload      []byte
}

func newCommandAuditor(pool *pgxpool.Pool, clock func() time.Time) commandAuditAppender {
	return audit.NewWithClock(pool, clock)
}

func (reader *PostgresReader) Execute(ctx context.Context, input CommandInput) (CommandResult, error) {
	if ctx == nil || reader == nil || reader.pool == nil || reader.auditor == nil || reader.now == nil ||
		input.Principal.UserID == uuid.Nil || input.Principal.ScopeID == uuid.Nil ||
		input.TaskID == uuid.Nil || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		!requestIDPattern.MatchString(input.RequestID) ||
		(input.ExpectedRevision != "" && !jobRevisionPattern.MatchString(input.ExpectedRevision)) ||
		(input.Operation != CommandCancel && input.Operation != CommandRetry && input.Operation != CommandReplay) {
		return CommandResult{}, ErrInvalidRequest
	}
	tx, err := reader.pool.Begin(ctx)
	if err != nil {
		return CommandResult{}, postgresError(ctx, "begin job command")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	// API-JOBS-02：IAM 全局锁须是事务内第一个有效锁，所以先于 authorizeLiveCommand 的行锁复核密钥。
	if err := authorizeCommandAPIKey(ctx, tx, reader.apiKeys, input); err != nil {
		if errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrScopeForbidden) {
			reason := "permission_denied"
			if errors.Is(err, ErrScopeForbidden) {
				reason = "scope_forbidden"
			}
			return reader.denyCommand(ctx, tx, input, reason, err)
		}
		return CommandResult{}, mapCommandPostgresError(ctx, err)
	}
	actor, err := authorizeLiveCommand(ctx, tx, input)
	if err != nil {
		if actor != nil && (errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrScopeForbidden)) {
			reason := "permission_denied"
			if errors.Is(err, ErrScopeForbidden) {
				reason = "scope_forbidden"
			}
			return reader.denyCommand(ctx, tx, input, reason, err)
		}
		return CommandResult{}, mapCommandPostgresError(ctx, err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", commandReceiptLockKey(input)); err != nil {
		return CommandResult{}, postgresError(ctx, "lock job command receipt")
	}

	receipt, found, err := readCommandReceipt(ctx, tx, input)
	if err != nil {
		return CommandResult{}, postgresError(ctx, "read job command receipt")
	}
	if found {
		if !validCommandReceipt(receipt, input) {
			return reader.denyCommand(ctx, tx, input, "idempotency_conflict", ErrIdempotencyConflict)
		}
		if input.Audience == AudienceTenant && (actor.tenantID == nil || *actor.tenantID != receipt.tenantID) {
			return CommandResult{}, ErrInvalidStoreResponse
		}
		if err := tx.Commit(ctx); err != nil {
			return CommandResult{}, postgresError(ctx, "commit job command replay")
		}
		return CommandResult{Data: receipt.result, Replayed: true}, nil
	}

	initialJob, err := readCommandJobSnapshot(ctx, tx, input, actor)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return reader.denyCommand(ctx, tx, input, "not_found", ErrNotFound)
		}
		return CommandResult{}, mapCommandPostgresError(ctx, err)
	}
	lockedJob, err := lockCommandJobSnapshot(ctx, tx, input.TaskID, initialJob)
	if err != nil {
		if errors.Is(err, errCommandConcurrentStateChanged) {
			return reader.denyCommand(ctx, tx, input, "concurrent_state_changed", ErrInvalidTransition)
		}
		return CommandResult{}, mapCommandPostgresError(ctx, err)
	}
	currentJob, err := scanJob(tx.QueryRow(ctx, platformGetSQL, input.TaskID))
	if err != nil {
		return CommandResult{}, mapCommandPostgresError(ctx, err)
	}
	if input.ExpectedRevision != "" && currentJob.Revision != input.ExpectedRevision {
		return reader.denyCommand(ctx, tx, input, "revision_conflict", ErrRevisionConflict)
	}
	if !genericCommandSupported(lockedJob.kind, input.Operation) {
		return reader.denyCommand(ctx, tx, input, "producer_command", ErrProducerCommand)
	}
	tenantID := lockedJob.tenantID
	now := reader.now().UTC().Truncate(time.Microsecond)
	var stored jobstate.StoredJob
	switch input.Operation {
	case CommandCancel:
		stored, err = jobstate.CancelTx(ctx, tx, tenantID, input.TaskID, now)
	case CommandRetry:
		stored, err = jobstate.RetryTx(ctx, tx, tenantID, input.TaskID, now)
	case CommandReplay:
		stored, err = jobstate.ReplayTx(ctx, tx, jobstate.ReplayInput{
			TenantID: tenantID, JobID: input.TaskID,
			ActorScopeID: input.Principal.ScopeID, ActorUserID: input.Principal.UserID,
			IdempotencyKey: input.IdempotencyKey, RequestDigest: input.Digest[:],
			RequestID: input.RequestID,
		}, now)
	}
	if err != nil {
		switch {
		case errors.Is(err, jobstate.ErrInvalidTransition):
			return reader.denyCommand(ctx, tx, input, "invalid_transition", ErrInvalidTransition)
		case errors.Is(err, jobstate.ErrRetriesExhausted):
			return reader.denyCommand(ctx, tx, input, "retries_exhausted", ErrRetriesExhausted)
		case errors.Is(err, jobstate.ErrNotFound):
			return reader.denyCommand(ctx, tx, input, "not_found", ErrNotFound)
		default:
			return CommandResult{}, postgresError(ctx, "transition job command")
		}
	}
	job := commandJobFromStored(stored)
	if job.TenantID != tenantID || validateCommandResult(job, input.Operation) != nil {
		return CommandResult{}, ErrInvalidStoreResponse
	}
	if err := reader.appendCommandAudit(ctx, tx, input, "success", "", tenantID, &job); err != nil {
		return CommandResult{}, postgresError(ctx, "audit job command")
	}
	auditID, err := commandAuditID(ctx, tx, input)
	if err != nil {
		return CommandResult{}, postgresError(ctx, "bind job command audit")
	}
	commandCompletedAt := reader.now().UTC().Truncate(time.Microsecond)
	if commandCompletedAt.Before(now) {
		commandCompletedAt = now
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
		input.Principal.ScopeID, input.Principal.UserID, input.IdempotencyKey, input.Digest[:],
		input.Audience, tenantID, input.TaskID, input.Operation, input.RequestID, auditID,
		job.Kind, job.RelatedResource.Reference, job.RequestID, job.TraceID, job.Status,
		job.Attempt, job.MaxAttempts, job.Progress.Total, job.Progress.Completed,
		job.Progress.Succeeded, job.Progress.Failed, job.Progress.Cancelled,
		nullableString(job.FailureCode), job.CreatedAt, job.StartedAt, job.UpdatedAt,
		job.CompletedAt, now, commandCompletedAt); err != nil {
		return CommandResult{}, postgresError(ctx, "record job command receipt")
	}
	if err := tx.Commit(ctx); err != nil {
		return CommandResult{}, postgresError(ctx, "commit job command")
	}
	return CommandResult{Data: job}, nil
}

func authorizeLiveCommand(ctx context.Context, tx pgx.Tx, input CommandInput) (*commandActorFacts, error) {
	var scopeKind, userStatus string
	var tenantID *uuid.UUID
	err := tx.QueryRow(ctx, `
			SELECT scope.kind,scope.tenant_id,actor.status
			FROM users actor
			CROSS JOIN access_scopes scope
			WHERE actor.id=$1 AND scope.id=$2
			FOR SHARE OF actor,scope`, input.Principal.UserID, input.Principal.ScopeID).Scan(
		&scopeKind, &tenantID, &userStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPermissionDenied
	}
	if err != nil {
		return nil, err
	}
	facts := &commandActorFacts{tenantID: tenantID}
	if userStatus != "active" || scopeKind != string(input.Principal.ScopeKind) {
		return facts, ErrPermissionDenied
	}
	var membershipStatus string
	err = tx.QueryRow(ctx, `SELECT status FROM memberships
		WHERE user_id=$1 AND scope_id=$2 FOR SHARE`, input.Principal.UserID, input.Principal.ScopeID).Scan(&membershipStatus)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && membershipStatus != "active" {
		return facts, ErrPermissionDenied
	}
	if err != nil {
		return facts, err
	}
	permissions := []string{PermissionManage}
	if input.Audience == AudiencePlatform {
		if scopeKind != string(ScopePlatform) || tenantID != nil {
			return facts, ErrScopeForbidden
		}
		permissions = []string{PermissionManageAll, PermissionAdmin}
	} else if input.Audience == AudienceTenant {
		if scopeKind != string(ScopeTenant) || tenantID == nil {
			return facts, ErrScopeForbidden
		}
		if input.Operation == CommandReplay {
			return facts, ErrScopeForbidden
		}
	} else {
		return facts, ErrInvalidRequest
	}
	var permission string
	err = tx.QueryRow(ctx, `
		SELECT role_permission.permission_name
		FROM role_assignments assignment
		JOIN roles role ON role.scope_id=assignment.scope_id AND role.id=assignment.role_id
		JOIN role_permissions role_permission ON role_permission.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2
		  AND role_permission.permission_name=ANY($3::text[])
		ORDER BY role_permission.permission_name
		LIMIT 1
		FOR SHARE OF assignment,role,role_permission`,
		input.Principal.ScopeID, input.Principal.UserID, permissions).Scan(&permission)
	if errors.Is(err, pgx.ErrNoRows) {
		return facts, ErrPermissionDenied
	}
	if err != nil {
		return facts, err
	}
	return facts, nil
}

func readCommandReceipt(
	ctx context.Context,
	tx pgx.Tx,
	input CommandInput,
) (storedCommandReceipt, bool, error) {
	var receipt storedCommandReceipt
	var resultState string
	var resultAttempt, resultMaxAttempts int
	var resultFailureCode *string
	var resultStartedAt, resultCompletedAt *time.Time
	err := tx.QueryRow(ctx, `
			SELECT receipt.request_digest,receipt.audience,receipt.tenant_id,receipt.job_id,
			       receipt.operation,receipt.request_id,
			       receipt.result_kind,receipt.result_subject,receipt.result_request_id,
			       receipt.result_trace_id,receipt.result_state,receipt.result_attempt,
			       receipt.result_max_attempts,receipt.result_total_count,
			       receipt.result_completed_count,receipt.result_succeeded_count,
			       receipt.result_failed_count,receipt.result_cancelled_count,
			       receipt.result_failure_code,receipt.result_created_at,
			       receipt.result_started_at,receipt.result_updated_at,receipt.result_completed_at,
			       receipt.created_at,receipt.completed_at,
			       audit.scope_id,audit.actor_user_id,
			       audit.action,audit.resource_id,audit.request_id,audit.result,
			       audit.payload
			FROM background_job_command_receipts receipt
			JOIN audit_events audit ON audit.id=receipt.audit_event_id
			WHERE receipt.actor_scope_id=$1 AND receipt.actor_user_id=$2 AND receipt.idempotency_key=$3
			FOR UPDATE OF receipt`, input.Principal.ScopeID, input.Principal.UserID, input.IdempotencyKey).Scan(
		&receipt.digest, &receipt.audience, &receipt.tenantID, &receipt.jobID,
		&receipt.operation, &receipt.requestID,
		&receipt.result.Kind, &receipt.result.RelatedResource.Reference,
		&receipt.result.RequestID, &receipt.result.TraceID, &resultState,
		&resultAttempt, &resultMaxAttempts, &receipt.result.Progress.Total,
		&receipt.result.Progress.Completed, &receipt.result.Progress.Succeeded,
		&receipt.result.Progress.Failed, &receipt.result.Progress.Cancelled,
		&resultFailureCode, &receipt.result.CreatedAt, &resultStartedAt,
		&receipt.result.UpdatedAt, &resultCompletedAt, &receipt.createdAt, &receipt.completedAt,
		&receipt.auditScopeID, &receipt.auditActorUserID,
		&receipt.auditAction, &receipt.auditResource, &receipt.auditRequestID, &receipt.auditResult,
		&receipt.auditPayload)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedCommandReceipt{}, false, nil
	}
	if err == nil {
		receipt.result.TaskID = receipt.jobID
		receipt.result.TenantID = receipt.tenantID
		receipt.result.Status = State(resultState)
		receipt.result.Attempt = uint32(resultAttempt)
		receipt.result.MaxAttempts = uint32(resultMaxAttempts)
		receipt.result.Progress.Pending = receipt.result.Progress.Total - receipt.result.Progress.Completed
		receipt.result.FailureCode = pointerString(resultFailureCode)
		receipt.result.CreatedAt = receipt.result.CreatedAt.UTC()
		receipt.result.StartedAt = utcTimePointer(resultStartedAt)
		receipt.result.UpdatedAt = receipt.result.UpdatedAt.UTC()
		receipt.result.CompletedAt = utcTimePointer(resultCompletedAt)
		receipt.result.Revision = revisionForJob(receipt.result)
		receipt.createdAt = receipt.createdAt.UTC()
		receipt.completedAt = receipt.completedAt.UTC()
	}
	return receipt, err == nil, err
}

func validCommandReceipt(receipt storedCommandReceipt, input CommandInput) bool {
	return bytes.Equal(receipt.digest, input.Digest[:]) && receipt.audience == string(input.Audience) &&
		receipt.jobID == input.TaskID && receipt.operation == string(input.Operation) &&
		requestIDPattern.MatchString(receipt.requestID) && receipt.auditScopeID == input.Principal.ScopeID &&
		receipt.auditActorUserID != nil && *receipt.auditActorUserID == input.Principal.UserID &&
		receipt.auditAction == commandAuditAction(input.Operation) &&
		receipt.auditResource == input.TaskID.String() && receipt.auditRequestID == receipt.requestID &&
		receipt.auditResult == "success" &&
		validateCommandResult(receipt.result, input.Operation) == nil &&
		!receipt.createdAt.IsZero() && !receipt.completedAt.Before(receipt.createdAt) &&
		validCommandAuditPayload(receipt.auditPayload, input, receipt.tenantID, receipt.result)
}

func commandJobFromStored(stored jobstate.StoredJob) Job {
	job := Job{
		TaskID: stored.ID, TenantID: stored.TenantID, Kind: stored.Kind,
		RelatedResource: RelatedResource{Reference: stored.Subject},
		RequestID:       stored.RequestID, TraceID: stored.TraceID, Status: State(stored.State),
		Attempt: stored.Attempt, MaxAttempts: stored.MaxAttempts,
		Progress: Progress{
			Total: stored.Progress.Total, Completed: stored.Progress.Completed,
			Succeeded: stored.Progress.Succeeded, Failed: stored.Progress.Failed,
			Cancelled: stored.Progress.Cancelled, Pending: stored.Progress.Pending,
		},
		FailureCode: stored.LastErrorCode, CreatedAt: stored.CreatedAt.UTC(),
		StartedAt: optionalCommandTime(stored.StartedAt), UpdatedAt: stored.UpdatedAt.UTC(),
		CompletedAt: optionalCommandTime(stored.CompletedAt),
	}
	job.Revision = revisionForJob(job)
	return job
}

func revisionForJob(job Job) string {
	job.Revision = ""
	encoded, _ := json.Marshal(job)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func optionalCommandTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func validateCommandResult(job Job, operation CommandOperation) error {
	if validateJob(job) != nil {
		return ErrInvalidStoreResponse
	}
	switch operation {
	case CommandCancel:
		if job.Status != StateCancelled {
			return ErrInvalidStoreResponse
		}
	case CommandRetry, CommandReplay:
		if job.Status != StateQueued {
			return ErrInvalidStoreResponse
		}
	default:
		return ErrInvalidStoreResponse
	}
	return nil
}

func commandAuditPayload(
	input CommandInput,
	reason string,
	tenantID uuid.UUID,
	job *Job,
) map[string]any {
	payload := map[string]any{
		"audience": input.Audience, "operation": input.Operation,
		"idempotency_key": input.IdempotencyKey,
		"request_digest":  hex.EncodeToString(input.Digest[:]),
	}
	if tenantID != uuid.Nil {
		payload["tenant_id"] = tenantID.String()
	}
	if reason != "" {
		payload["reason"] = reason
	}
	if job != nil {
		payload["result_data"] = map[string]any{
			"task_id": job.TaskID.String(), "tenant_id": job.TenantID.String(),
			"kind": job.Kind, "subject": job.RelatedResource.Reference,
			"request_id": job.RequestID, "trace_id": job.TraceID, "state": job.Status,
			"attempt": job.Attempt, "max_attempts": job.MaxAttempts,
			"total_count": job.Progress.Total, "completed_count": job.Progress.Completed,
			"succeeded_count": job.Progress.Succeeded, "failed_count": job.Progress.Failed,
			"cancelled_count": job.Progress.Cancelled, "failure_code": job.FailureCode,
			"created_at": job.CreatedAt, "started_at": job.StartedAt,
			"updated_at": job.UpdatedAt, "completed_at": job.CompletedAt,
		}
	}
	return payload
}

func validCommandAuditPayload(payload []byte, input CommandInput, tenantID uuid.UUID, job Job) bool {
	want, err := json.Marshal(commandAuditPayload(input, "", tenantID, &job))
	if err != nil {
		return false
	}
	var actual any
	if err := json.Unmarshal(payload, &actual); err != nil {
		return false
	}
	canonical, err := json.Marshal(actual)
	return err == nil && bytes.Equal(canonical, want)
}

func readCommandJobSnapshot(
	ctx context.Context,
	tx pgx.Tx,
	input CommandInput,
	actor *commandActorFacts,
) (commandJobSnapshot, error) {
	var row pgx.Row
	if input.Audience == AudienceTenant {
		if actor.tenantID == nil {
			return commandJobSnapshot{}, ErrScopeForbidden
		}
		row = tx.QueryRow(ctx, `SELECT job.tenant_id,job.xmin::text,job.state,job.attempt,job.kind
			FROM background_jobs job WHERE job.id=$1 AND job.tenant_id=$2`, input.TaskID, *actor.tenantID)
	} else {
		row = tx.QueryRow(ctx, `SELECT job.tenant_id,job.xmin::text,job.state,job.attempt,job.kind
			FROM background_jobs job WHERE job.id=$1`, input.TaskID)
	}
	return scanCommandJobSnapshot(row)
}

func lockCommandJobSnapshot(
	ctx context.Context,
	tx pgx.Tx,
	jobID uuid.UUID,
	initial commandJobSnapshot,
) (commandJobSnapshot, error) {
	locked, err := scanCommandJobSnapshot(tx.QueryRow(ctx, `
		SELECT job.tenant_id,job.xmin::text,job.state,job.attempt,job.kind
		FROM background_jobs job
		WHERE job.id=$1 AND job.tenant_id=$2
		FOR UPDATE`, jobID, initial.tenantID))
	if errors.Is(err, ErrNotFound) {
		return commandJobSnapshot{}, errCommandConcurrentStateChanged
	}
	if err != nil {
		return commandJobSnapshot{}, err
	}
	if !sameCommandJobSnapshot(initial, locked) {
		return commandJobSnapshot{}, errCommandConcurrentStateChanged
	}
	return locked, nil
}

func scanCommandJobSnapshot(row pgx.Row) (commandJobSnapshot, error) {
	var snapshot commandJobSnapshot
	err := row.Scan(&snapshot.tenantID, &snapshot.tupleVersion, &snapshot.state, &snapshot.attempt, &snapshot.kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return commandJobSnapshot{}, ErrNotFound
	}
	return snapshot, err
}

func sameCommandJobSnapshot(initial, locked commandJobSnapshot) bool {
	return initial == locked
}

func (reader *PostgresReader) denyCommand(
	ctx context.Context,
	tx pgx.Tx,
	input CommandInput,
	reason string,
	public error,
) (CommandResult, error) {
	denialError := commandDenialPublicError(reason)
	if errors.Is(denialError, ErrInvalidStoreResponse) || !errors.Is(public, denialError) {
		return CommandResult{}, ErrInvalidStoreResponse
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", commandAuditStreamLockKey(input.Principal.ScopeID)); err != nil {
		return CommandResult{}, postgresError(ctx, "lock denied job command audit")
	}
	stored, found, err := readDeniedCommandAudit(ctx, tx, input)
	if err != nil {
		if errors.Is(err, ErrInvalidStoreResponse) {
			return CommandResult{}, ErrInvalidStoreResponse
		}
		return CommandResult{}, postgresError(ctx, "read denied job command audit")
	}
	if found {
		if !validDeniedCommandAudit(stored, input, reason) {
			return CommandResult{}, ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return CommandResult{}, postgresError(ctx, "commit denied job command replay")
		}
		return CommandResult{}, denialError
	}
	if err := reader.appendCommandAudit(ctx, tx, input, "denied", reason, uuid.Nil, nil); err != nil {
		return CommandResult{}, postgresError(ctx, "audit denied job command")
	}
	if err := tx.Commit(ctx); err != nil {
		return CommandResult{}, postgresError(ctx, "commit denied job command")
	}
	return CommandResult{}, denialError
}

func readDeniedCommandAudit(
	ctx context.Context,
	tx pgx.Tx,
	input CommandInput,
) (storedDeniedCommandAudit, bool, error) {
	rows, err := tx.Query(ctx, `
		SELECT resource_type,resource_id,payload
		FROM audit_events
		WHERE scope_id=$1 AND actor_user_id=$2 AND action=$3
		  AND request_id=$4 AND result='denied'
		ORDER BY stream_position`, input.Principal.ScopeID, input.Principal.UserID,
		commandAuditAction(input.Operation), input.RequestID)
	if err != nil {
		return storedDeniedCommandAudit{}, false, err
	}
	defer rows.Close()
	var stored storedDeniedCommandAudit
	found := false
	for rows.Next() {
		if found {
			return storedDeniedCommandAudit{}, false, ErrInvalidStoreResponse
		}
		if err := rows.Scan(&stored.resourceType, &stored.resourceID, &stored.payload); err != nil {
			return storedDeniedCommandAudit{}, false, err
		}
		found = true
	}
	if err := rows.Err(); err != nil {
		return storedDeniedCommandAudit{}, false, err
	}
	return stored, found, nil
}

func validDeniedCommandAudit(
	stored storedDeniedCommandAudit,
	input CommandInput,
	reason string,
) bool {
	if stored.resourceType != "background_job" || stored.resourceID != input.TaskID.String() {
		return false
	}
	want, err := json.Marshal(commandAuditPayload(input, reason, uuid.Nil, nil))
	if err != nil {
		return false
	}
	var actual any
	if err := json.Unmarshal(stored.payload, &actual); err != nil {
		return false
	}
	canonical, err := json.Marshal(actual)
	return err == nil && bytes.Equal(canonical, want)
}

func commandDenialPublicError(reason string) error {
	switch reason {
	case "permission_denied":
		return ErrPermissionDenied
	case "scope_forbidden":
		return ErrScopeForbidden
	case "not_found":
		return ErrNotFound
	case "idempotency_conflict":
		return ErrIdempotencyConflict
	case "invalid_transition", "concurrent_state_changed":
		return ErrInvalidTransition
	case "retries_exhausted":
		return ErrRetriesExhausted
	case "revision_conflict":
		return ErrRevisionConflict
	case "producer_command":
		return ErrProducerCommand
	default:
		return ErrInvalidStoreResponse
	}
}

func (reader *PostgresReader) appendCommandAudit(
	ctx context.Context,
	tx pgx.Tx,
	input CommandInput,
	result, reason string,
	tenantID uuid.UUID,
	job *Job,
) error {
	actorID := input.Principal.UserID
	return reader.auditor.Append(ctx, tx, audit.Event{
		ScopeID: input.Principal.ScopeID, ActorUserID: &actorID,
		Action: commandAuditAction(input.Operation), ResourceType: "background_job",
		ResourceID: input.TaskID.String(), RequestID: input.RequestID,
		Result: result, Payload: commandAuditPayload(input, reason, tenantID, job),
	})
}

func commandAuditID(ctx context.Context, tx pgx.Tx, input CommandInput) (uuid.UUID, error) {
	var auditID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT id FROM audit_events
		WHERE scope_id=$1 AND actor_user_id=$2 AND action=$3 AND resource_type='background_job'
		  AND resource_id=$4 AND request_id=$5 AND result='success'
		  AND payload->>'idempotency_key'=$6 AND payload->>'request_digest'=$7
		ORDER BY stream_position DESC LIMIT 1`,
		input.Principal.ScopeID, input.Principal.UserID, commandAuditAction(input.Operation),
		input.TaskID.String(), input.RequestID, input.IdempotencyKey, hex.EncodeToString(input.Digest[:])).Scan(&auditID)
	return auditID, err
}

func commandAuditAction(operation CommandOperation) string {
	return "job." + string(operation)
}

func commandReceiptLockKey(input CommandInput) int64 {
	digest := sha256.Sum256([]byte(input.Principal.ScopeID.String() + "\x00" +
		input.Principal.UserID.String() + "\x00" + input.IdempotencyKey))
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func commandAuditStreamLockKey(scopeID uuid.UUID) int64 {
	digest := sha256.Sum256(scopeID[:])
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func mapCommandPostgresError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrPermissionDenied),
		errors.Is(err, ErrScopeForbidden), errors.Is(err, ErrNotFound),
		errors.Is(err, ErrInvalidStoreResponse):
		return err
	default:
		return fmt.Errorf("%w", ErrStoreUnavailable)
	}
}

var _ CommandStore = (*PostgresReader)(nil)
