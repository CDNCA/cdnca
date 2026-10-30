package analyticslog

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	exportMaxRows       = 100000
	exportMaxBytes      = 8 << 20
	exportArtifactTTL   = time.Hour
	exportGrantTTL      = 5 * time.Minute
	exportWorkerLease   = time.Minute
	exportWorkerTimeout = 45 * time.Second
)

var exportIdempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{16,128}$`)

type ExportStatus string

const (
	ExportPending   ExportStatus = "pending"
	ExportRunning   ExportStatus = "running"
	ExportCompleted ExportStatus = "completed"
	ExportFailed    ExportStatus = "failed"
)

type AccessExport struct {
	ID           string       `json:"id"`
	Status       ExportStatus `json:"status"`
	Reason       string       `json:"reason"`
	SnapshotAt   *time.Time   `json:"snapshot_at"`
	RowCount     *int         `json:"row_count"`
	ByteCount    *int         `json:"byte_count"`
	SHA256       string       `json:"sha256,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	ExpiresAt    *time.Time   `json:"expires_at"`
	Downloadable bool         `json:"downloadable"`
	// Filter 是申请时冻结的原查询条件（LOG-02）；文档版本不认识时为 null。
	Filter *exportFilterBody `json:"filter"`
}

type AccessExportGrant struct {
	ExportID  string    `json:"export_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AccessExportDownload struct {
	Content  []byte
	SHA256   string
	Filename string
}

type ExportManager struct {
	pool   *pgxpool.Pool
	source Store
	audit  *audit.Log
	now    func() time.Time

	workerMu          sync.Mutex
	workerRunning     bool
	workerWakePending bool
}

func NewExportManager(pool *pgxpool.Pool, source Store, now func() time.Time) (*ExportManager, error) {
	if !configuredPGXPool(pool) || source == nil {
		return nil, ErrInvalidConfiguration
	}
	if now == nil {
		now = time.Now
	}
	return &ExportManager{pool: pool, source: source, audit: audit.NewWithClock(pool, now), now: now}, nil
}

func (manager *ExportManager) Create(
	ctx context.Context,
	actor Actor,
	request QueryRequest,
	idempotencyKey string,
) (AccessExport, bool, error) {
	queryScope, filter, err := authorizeQuery(actor, request)
	if err != nil {
		return AccessExport{}, false, err
	}
	if queryScope.platform() {
		// Exports are tenant-owned artifacts; the platform must pick a tenant.
		return AccessExport{}, false, ErrInvalidInput
	}
	identity, err := exportIdentityFromActor(actor)
	if err != nil {
		return AccessExport{}, false, err
	}
	if !exportIdempotencyPattern.MatchString(idempotencyKey) {
		return AccessExport{}, false, ErrInvalidInput
	}
	key, err := exportScopeDigest(queryScope.tenantID, filter)
	if err != nil {
		return AccessExport{}, false, err
	}
	digest := key.digest
	now := manager.now().UTC().Truncate(time.Microsecond)
	targetScopeID, err := manager.targetScope(ctx, queryScope.tenantID)
	if err != nil {
		return AccessExport{}, false, err
	}
	tenantUUID, err := uuid.Parse(queryScope.tenantID)
	if err != nil || tenantUUID == uuid.Nil {
		return AccessExport{}, false, ErrInvalidInput
	}
	tx, err := manager.pool.Begin(ctx)
	if err != nil {
		return AccessExport{}, false, ErrStorageUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	// LOG-01：同一账号的申请串行判定（幂等键与"同范围复用"都按账号，不按会话）。
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
		'analytics_log_export:' || $1::text || ':' || $2::text, 0))`, identity.scopeID, identity.actorID); err != nil {
		return AccessExport{}, false, ErrStorageUnavailable
	}
	var keyedID uuid.UUID
	var keyedScope uuid.UUID
	var keyedDigest []byte
	err = tx.QueryRow(ctx, `SELECT id,scope_id,request_digest FROM analytics_log_exports_v1
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3`,
		identity.scopeID, identity.actorID, idempotencyKey).Scan(&keyedID, &keyedScope, &keyedDigest)
	keyed := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return AccessExport{}, false, ErrStorageUnavailable
	}
	if keyed && (keyedScope != targetScopeID || len(keyedDigest) != sha256.Size ||
		subtle.ConstantTimeCompare(keyedDigest, digest[:]) != 1) {
		return AccessExport{}, false, ErrConflict
	}
	latest, err := latestExportForScope(ctx, tx, identity, targetScopeID, digest[:])
	if err != nil {
		return AccessExport{}, false, err
	}
	var exportID uuid.UUID
	created := false
	switch decision := decideExportScope(latest, now); {
	case decision == exportScopeReuse:
		exportID = latest.ID
	case decision == exportScopeRetry:
		exportID = latest.ID
		created = true
		if err := manager.retryFailedExport(ctx, tx, tenantUUID, latest.ID, identity, now); err != nil {
			return AccessExport{}, false, err
		}
	case keyed:
		// 原幂等键对应的申请已过期或重试用尽：同一键只回放原结果，新一代须换键。
		exportID = keyedID
	default:
		generation := 1
		if latest != nil {
			generation = latest.Generation + 1
		}
		if exportID, err = manager.insertExport(ctx, tx, insertExportInput{
			targetScopeID: targetScopeID, tenantID: tenantUUID, identity: identity, idempotencyKey: idempotencyKey,
			key: key, generation: generation,
		}, now); err != nil {
			return AccessExport{}, false, err
		}
		created = true
	}
	job, err := queryExport(ctx, tx, exportID, targetScopeID, identity, now)
	if err != nil {
		return AccessExport{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AccessExport{}, false, ErrStorageUnavailable
	}
	manager.kick()
	return job, !created, nil
}

type insertExportInput struct {
	targetScopeID  uuid.UUID
	tenantID       uuid.UUID
	identity       exportIdentity
	idempotencyKey string
	key            exportScopeKey
	generation     int
}

func (manager *ExportManager) insertExport(ctx context.Context, tx pgx.Tx, input insertExportInput, now time.Time) (uuid.UUID, error) {
	exportID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, ErrStorageUnavailable
	}
	if _, err := tx.Exec(ctx, `INSERT INTO analytics_log_exports_v1(
		id,scope_id,tenant_id,actor_scope_id,actor_user_id,credential_kind,credential_id,
		idempotency_key,request_digest,filter,scope_generation,created_at)
		VALUES($1,$2,$3,$4,$5,'session',$6,$7,$8,$9,$10,$11)`,
		exportID, input.targetScopeID, input.tenantID, input.identity.scopeID, input.identity.actorID,
		input.identity.credentialID, input.idempotencyKey, input.key.digest[:], input.key.encoded,
		input.generation, now); err != nil {
		return uuid.Nil, ErrStorageUnavailable
	}
	if _, err := tx.Exec(ctx, `INSERT INTO analytics_log_export_events_v1(
		export_id,sequence,state,reason,occurred_at) VALUES($1,1,'pending','created',$2)`, exportID, now); err != nil {
		return uuid.Nil, ErrStorageUnavailable
	}
	if err := manager.audit.Append(ctx, tx, audit.Event{
		ScopeID: input.identity.scopeID, ActorUserID: &input.identity.actorID, Action: "analytics_log.export.create",
		ResourceType: "analytics_log_export", ResourceID: exportID.String(), RequestID: RequestIDFromContext(ctx),
		Result: "success", Payload: map[string]any{
			"target_scope_id": input.targetScopeID.String(), "tenant_id": input.tenantID.String(),
			"request_digest": hex.EncodeToString(input.key.digest[:]), "scope_generation": input.generation,
		},
	}); err != nil {
		return uuid.Nil, ErrStorageUnavailable
	}
	requestID := RequestIDFromContext(ctx)
	if requestID == "" {
		requestID = exportID.String()
	}
	if _, err := jobstate.CreateTx(ctx, tx, jobstate.CreateInput{
		JobID: exportID, TenantID: input.tenantID, Kind: "analytics.log_export",
		Subject: exportID.String(), IdempotencyKey: "analytics.log_export." + exportID.String(),
		Payload: input.key.encoded, Items: []jobstate.CreateItem{{ItemID: exportID.String()}}, MaxAttempts: 10,
		RequestID: requestID, TraceID: traceIDFromContext(ctx),
	}, now); err != nil {
		return uuid.Nil, ErrStorageUnavailable
	}
	return exportID, nil
}

// retryFailedExport 在原申请上重试（同一导出编号与幂等键）：统一任务回到排队，
// 导出事件追加 pending/retried，worker 重新认领。
func (manager *ExportManager) retryFailedExport(
	ctx context.Context, tx pgx.Tx, tenantID, exportID uuid.UUID, identity exportIdentity, now time.Time,
) error {
	job, err := jobstate.RetryTx(ctx, tx, tenantID, exportID, now)
	if err != nil {
		return ErrStorageUnavailable
	}
	// merge-p22: failed -> queued is a job command; migration 094 requires its
	// job.retry audit fact and one background_job_command_receipts row in the
	// same transaction (as dnsacme recordCNAMERetryReceipt does).
	if err := manager.recordRetryReceipt(ctx, tx, identity, job, now); err != nil {
		return ErrStorageUnavailable
	}
	if _, err := tx.Exec(ctx, `INSERT INTO analytics_log_export_events_v1(export_id,sequence,state,reason,occurred_at)
		SELECT $1,COALESCE(max(sequence),0)+1,'pending','retried',$2 FROM analytics_log_export_events_v1 WHERE export_id=$1`,
		exportID, now); err != nil {
		return ErrStorageUnavailable
	}
	return manager.appendAudit(ctx, tx, identity.scopeID, identity.actorID, exportID,
		"analytics_log.export.retry", "success", "retried")
}

// recordRetryReceipt writes the job.retry audit event and the command receipt
// for an in-place export retry, attributed to the requesting account; the key
// is bound to the export and the attempt it starts.
func (manager *ExportManager) recordRetryReceipt(
	ctx context.Context, tx pgx.Tx, identity exportIdentity, job jobstate.StoredJob, now time.Time,
) error {
	keyDigest := sha256.Sum256([]byte("cdnca.analytics-log-export-retry/v1\x00" + job.ID.String() + "\x00" +
		strconv.FormatUint(uint64(job.Attempt), 10)))
	receiptKey := "export-retry-" + hex.EncodeToString(keyDigest[:16])
	requestDigest := sha256.Sum256([]byte(receiptKey))
	requestID := RequestIDFromContext(ctx)
	if requestID == "" {
		requestID = "export-retry/" + job.ID.String()
	}
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
	if err := manager.audit.Append(ctx, tx, audit.Event{
		ScopeID: identity.scopeID, ActorUserID: &identity.actorID, Action: "job.retry",
		ResourceType: "background_job", ResourceID: job.ID.String(), RequestID: requestID,
		Result: "success", Payload: map[string]any{
			"audience": "tenant", "operation": "retry", "idempotency_key": receiptKey,
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
		WHERE scope_id=$1 AND actor_user_id=$2 AND action='job.retry' AND resource_type='background_job'
		  AND resource_id=$3 AND request_id=$4 AND result='success' AND payload->>'idempotency_key'=$5
		ORDER BY stream_position DESC LIMIT 1`, identity.scopeID, identity.actorID, job.ID.String(),
		requestID, receiptKey).Scan(&auditEventID); err != nil {
		return err
	}
	completedAt := now
	if completedAt.Before(job.UpdatedAt) {
		completedAt = job.UpdatedAt
	}
	_, err := tx.Exec(ctx, `INSERT INTO background_job_command_receipts (
			actor_scope_id,actor_user_id,idempotency_key,request_digest,audience,
			tenant_id,job_id,operation,request_id,audit_event_id,
			result_kind,result_subject,result_request_id,result_trace_id,
			result_state,result_attempt,result_max_attempts,
			result_total_count,result_completed_count,result_succeeded_count,
			result_failed_count,result_cancelled_count,result_failure_code,
			result_created_at,result_started_at,result_updated_at,result_completed_at,
			created_at,completed_at
		) VALUES ($1,$2,$3,$4,'tenant',$5,$6,'retry',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)`,
		identity.scopeID, identity.actorID, receiptKey, requestDigest[:],
		job.TenantID, job.ID, requestID, auditEventID,
		job.Kind, job.Subject, job.RequestID, job.TraceID, string(job.State),
		job.Attempt, job.MaxAttempts, job.Progress.Total, job.Progress.Completed,
		job.Progress.Succeeded, job.Progress.Failed, job.Progress.Cancelled, failureCode,
		job.CreatedAt, optional(job.StartedAt), job.UpdatedAt, optional(job.CompletedAt),
		job.UpdatedAt, completedAt)
	return err
}

// FindByScope 返回当前账号在该查询范围上的最新一代申请（0 或 1 条），供日志
// 视图在重新登录或换页后找回原申请。
func (manager *ExportManager) FindByScope(ctx context.Context, actor Actor, request QueryRequest) ([]AccessExport, error) {
	request.Limit = 1
	queryScope, filter, err := authorizeQuery(actor, request)
	if err != nil {
		return nil, err
	}
	if queryScope.platform() {
		return nil, ErrInvalidInput
	}
	identity, err := exportIdentityFromActor(actor)
	if err != nil {
		return nil, err
	}
	key, err := exportScopeDigest(queryScope.tenantID, filter)
	if err != nil {
		return nil, err
	}
	targetScopeID, err := manager.targetScope(ctx, queryScope.tenantID)
	if err != nil {
		return nil, err
	}
	manager.kick()
	latest, err := latestExportForScope(ctx, manager.pool, identity, targetScopeID, key.digest[:])
	if err != nil || latest == nil {
		return []AccessExport{}, err
	}
	job, err := queryExport(ctx, manager.pool, latest.ID, targetScopeID, identity, manager.now().UTC())
	if err != nil {
		return nil, err
	}
	return []AccessExport{job}, nil
}

type exportScopeKey struct {
	encoded []byte
	digest  [sha256.Size]byte
}

// exportScopeDigest 是"查询范围"：租户 + 规范化后的筛选条件。创建与按范围
// 找回必须用同一函数，否则重新登录后对不上原申请。
func exportScopeDigest(tenantID string, filter Filter) (exportScopeKey, error) {
	encoded, err := json.Marshal(struct {
		Version  int    `json:"version"`
		TenantID string `json:"tenant_id"`
		Filter   Filter `json:"filter"`
	}{Version: 1, TenantID: tenantID, Filter: normalizeFilter(filter)})
	if err != nil || len(encoded) > 16384 {
		return exportScopeKey{}, ErrInvalidInput
	}
	return exportScopeKey{encoded: encoded, digest: sha256.Sum256(encoded)}, nil
}

type exportScopeAction int

const (
	exportScopeCreate exportScopeAction = iota
	exportScopeReuse
	exportScopeRetry
)

type exportScopeLatest struct {
	ID                uuid.UUID
	Generation        int
	Status            ExportStatus
	ArtifactExpiresAt *time.Time
	JobState          string
	Attempt           int
	MaxAttempts       int
}

func decideExportScope(latest *exportScopeLatest, now time.Time) exportScopeAction {
	if latest == nil {
		return exportScopeCreate
	}
	switch latest.Status {
	case ExportPending, ExportRunning:
		return exportScopeReuse
	case ExportCompleted:
		if latest.ArtifactExpiresAt != nil && latest.ArtifactExpiresAt.After(now) {
			return exportScopeReuse
		}
	case ExportFailed:
		if latest.JobState == string(jobstate.StateFailed) && latest.Attempt < latest.MaxAttempts {
			return exportScopeRetry
		}
	}
	return exportScopeCreate
}

func latestExportForScope(ctx context.Context, querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, identity exportIdentity, targetScopeID uuid.UUID, digest []byte) (*exportScopeLatest, error) {
	var latest exportScopeLatest
	err := querier.QueryRow(ctx, `SELECT request.id,request.scope_generation,latest.state,
		artifact.artifact_expires_at,job.state,job.attempt,job.max_attempts
		FROM analytics_log_exports_v1 request
		JOIN LATERAL (SELECT state FROM analytics_log_export_events_v1 event WHERE event.export_id=request.id
			ORDER BY sequence DESC LIMIT 1) latest ON true
		JOIN background_jobs job ON job.id=request.id AND job.tenant_id=request.tenant_id
		LEFT JOIN analytics_log_export_artifacts_v1 artifact ON artifact.export_id=request.id
		WHERE request.actor_scope_id=$1 AND request.actor_user_id=$2 AND request.scope_id=$3 AND request.request_digest=$4
		ORDER BY request.scope_generation DESC LIMIT 1`, identity.scopeID, identity.actorID, targetScopeID, digest).Scan(
		&latest.ID, &latest.Generation, &latest.Status, &latest.ArtifactExpiresAt,
		&latest.JobState, &latest.Attempt, &latest.MaxAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrStorageUnavailable
	}
	return &latest, nil
}

func (manager *ExportManager) List(ctx context.Context, actor Actor, audience Audience, tenantID string) ([]AccessExport, error) {
	queryScope, err := authorizeExportScope(actor, audience, tenantID)
	if err != nil {
		return nil, err
	}
	identity, err := exportIdentityFromActor(actor)
	if err != nil {
		return nil, err
	}
	targetScopeID, err := manager.targetScope(ctx, queryScope.tenantID)
	if err != nil {
		return nil, err
	}
	manager.kick()
	now := manager.now().UTC()
	rows, err := manager.pool.Query(ctx, exportSelectSQL+`
		WHERE request.scope_id=$1 AND request.actor_scope_id=$2 AND request.actor_user_id=$3
		ORDER BY request.created_at DESC,request.id DESC LIMIT 50`,
		targetScopeID, identity.scopeID, identity.actorID)
	if err != nil {
		return nil, ErrStorageUnavailable
	}
	defer rows.Close()
	jobs := make([]AccessExport, 0)
	for rows.Next() {
		job, err := scanExport(rows, now)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	if rows.Err() != nil {
		return nil, ErrStorageUnavailable
	}
	return jobs, nil
}

func (manager *ExportManager) Get(ctx context.Context, actor Actor, audience Audience, tenantID, exportID string) (AccessExport, error) {
	_, identity, targetScopeID, id, err := manager.exportAccess(ctx, actor, audience, tenantID, exportID)
	if err != nil {
		return AccessExport{}, err
	}
	manager.kick()
	return queryExport(ctx, manager.pool, id, targetScopeID, identity, manager.now().UTC())
}

func (manager *ExportManager) Grant(ctx context.Context, actor Actor, audience Audience, tenantID, exportID string) (AccessExportGrant, error) {
	_, identity, targetScopeID, id, err := manager.exportAccess(ctx, actor, audience, tenantID, exportID)
	if err != nil {
		return AccessExportGrant{}, err
	}
	now := manager.now().UTC().Truncate(time.Microsecond)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return AccessExportGrant{}, ErrStorageUnavailable
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	grantID, err := uuid.NewV7()
	if err != nil {
		return AccessExportGrant{}, ErrStorageUnavailable
	}
	tx, err := manager.pool.Begin(ctx)
	if err != nil {
		return AccessExportGrant{}, ErrStorageUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	command, err := tx.Exec(ctx, `INSERT INTO analytics_log_export_grants_v1(
		id,export_id,scope_id,actor_user_id,session_id,token_sha256,created_at,expires_at)
		SELECT $1,request.id,request.scope_id,request.actor_user_id,$9,$2,$3,$4
		FROM analytics_log_exports_v1 request
		JOIN LATERAL (SELECT state FROM analytics_log_export_events_v1 event WHERE event.export_id=request.id
			ORDER BY sequence DESC LIMIT 1) latest ON true
		JOIN analytics_log_export_artifacts_v1 artifact ON artifact.export_id=request.id
		WHERE request.id=$5 AND request.scope_id=$6 AND request.actor_scope_id=$7 AND request.actor_user_id=$8
		  AND latest.state='completed' AND artifact.artifact_expires_at>$3`,
		grantID, digest[:], now, now.Add(exportGrantTTL), id, targetScopeID, identity.scopeID, identity.actorID, identity.credentialID)
	if err != nil {
		return AccessExportGrant{}, ErrStorageUnavailable
	}
	if command.RowsAffected() != 1 {
		return AccessExportGrant{}, ErrNotFound
	}
	if err := manager.appendAudit(ctx, tx, identity.scopeID, identity.actorID, id,
		"analytics_log.export.grant", "success", "grant_issued"); err != nil {
		return AccessExportGrant{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AccessExportGrant{}, ErrStorageUnavailable
	}
	return AccessExportGrant{ExportID: id.String(), Token: token, ExpiresAt: now.Add(exportGrantTTL)}, nil
}

func (manager *ExportManager) Consume(
	ctx context.Context,
	actor Actor,
	audience Audience,
	tenantID, exportID, token string,
) (AccessExportDownload, error) {
	_, identity, targetScopeID, id, err := manager.exportAccess(ctx, actor, audience, tenantID, exportID)
	if err != nil {
		return AccessExportDownload{}, err
	}
	raw, decodeErr := base64.RawURLEncoding.DecodeString(token)
	if decodeErr != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return AccessExportDownload{}, manager.auditReject(ctx, identity.scopeID, identity.actorID, id, "invalid_token")
	}
	digest := sha256.Sum256([]byte(token))
	now := manager.now().UTC().Truncate(time.Microsecond)
	tx, err := manager.pool.Begin(ctx)
	if err != nil {
		return AccessExportDownload{}, ErrStorageUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var content, artifactDigest []byte
	err = tx.QueryRow(ctx, `WITH consumed AS (
		UPDATE analytics_log_export_grants_v1 g SET consumed_at=$1
		FROM analytics_log_exports_v1 request
		WHERE g.export_id=request.id AND g.export_id=$2 AND g.scope_id=$3
		  AND g.actor_user_id=$4 AND g.session_id=$5 AND g.token_sha256=$6
		  AND request.actor_scope_id=$7 AND g.consumed_at IS NULL AND g.expires_at>$1
		RETURNING g.export_id)
		SELECT artifact.content,artifact.content_sha256 FROM consumed
		JOIN analytics_log_export_artifacts_v1 artifact ON artifact.export_id=consumed.export_id
		WHERE artifact.artifact_expires_at>$1`, now, id, targetScopeID, identity.actorID, identity.credentialID,
		digest[:], identity.scopeID).Scan(&content, &artifactDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		if auditErr := manager.appendAudit(ctx, tx, identity.scopeID, identity.actorID, id,
			"analytics_log.export.reject", "denied", "grant_rejected"); auditErr != nil {
			return AccessExportDownload{}, auditErr
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return AccessExportDownload{}, ErrStorageUnavailable
		}
		return AccessExportDownload{}, ErrExpired
	}
	if err != nil || len(artifactDigest) != sha256.Size {
		return AccessExportDownload{}, ErrStorageUnavailable
	}
	calculatedDigest := sha256.Sum256(content)
	if subtle.ConstantTimeCompare(artifactDigest, calculatedDigest[:]) != 1 {
		return AccessExportDownload{}, ErrInvalidResponse
	}
	if err := manager.appendAudit(ctx, tx, identity.scopeID, identity.actorID, id, "analytics_log.export.download", "success", "grant_consumed"); err != nil {
		return AccessExportDownload{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AccessExportDownload{}, ErrStorageUnavailable
	}
	return AccessExportDownload{Content: content, SHA256: hex.EncodeToString(artifactDigest), Filename: "analytics-access-" + id.String() + ".csv"}, nil
}

func (manager *ExportManager) kick() {
	manager.workerMu.Lock()
	if manager.workerRunning {
		manager.workerWakePending = true
		manager.workerMu.Unlock()
		return
	}
	manager.workerRunning = true
	manager.workerMu.Unlock()
	go manager.runWorker()
}

func (manager *ExportManager) runWorker() {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), exportWorkerTimeout)
		progressed, cleanStop := false, false
		for {
			processed, err := manager.processOne(ctx)
			if err != nil {
				break
			}
			if !processed {
				cleanStop = true
				break
			}
			progressed = true
		}
		if ctx.Err() == nil {
			_ = manager.Cleanup(ctx)
		}
		timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
		cancel()

		manager.workerMu.Lock()
		rerun := (cleanStop && manager.workerWakePending) || (timedOut && progressed)
		manager.workerWakePending = false
		if !rerun {
			manager.workerRunning = false
		}
		manager.workerMu.Unlock()
		if !rerun {
			return
		}
	}
}

func (manager *ExportManager) ProcessOne(ctx context.Context) error {
	_, err := manager.processOne(ctx)
	return err
}

func (manager *ExportManager) processOne(ctx context.Context) (bool, error) {
	workerID := uuid.New()
	now := manager.now().UTC().Truncate(time.Microsecond)
	tx, err := manager.pool.Begin(ctx)
	if err != nil {
		return false, ErrStorageUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var exportID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT claim_analytics_log_export_132($1,$2,$3)`, workerID, now, exportWorkerLease).Scan(&exportID); err != nil {
		return false, ErrStorageUnavailable
	}
	if exportID == nil {
		return false, tx.Commit(ctx)
	}
	var actorScopeID, actorID uuid.UUID
	var tenantID, storedRequestID, storedTraceID string
	var encoded []byte
	err = tx.QueryRow(ctx, `SELECT request.actor_scope_id,request.actor_user_id,request.tenant_id::text,request.filter,
		job.request_id,job.trace_id
		FROM analytics_log_exports_v1 request
		JOIN background_jobs job ON job.id=request.id AND job.tenant_id=request.tenant_id
		WHERE request.id=$1`, *exportID).Scan(&actorScopeID, &actorID, &tenantID, &encoded,
		&storedRequestID, &storedTraceID)
	if err != nil {
		return false, ErrStorageUnavailable
	}
	// 后台 worker 的 ctx 来自 context.Background()，没有请求编号；审计表要求
	// request_id 非空。每个任务用创建时持久化在统一任务里的请求/追踪编号单独
	// 建上下文，不复用上一条任务的编号。
	ctx = exportJobContext(ctx, storedRequestID, storedTraceID, *exportID)
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil || tenantUUID == uuid.Nil {
		return false, ErrStorageUnavailable
	}
	if _, err := jobstate.StartTx(ctx, tx, jobstate.StartInput{
		TenantID: tenantUUID, JobID: *exportID, Kind: "analytics.log_export",
		WorkerID: "analytics.log_export." + exportID.String(), LeaseDuration: time.Hour,
	}, now); err != nil {
		return false, ErrStorageUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return false, ErrStorageUnavailable
	}
	var request struct {
		Version  int    `json:"version"`
		TenantID string `json:"tenant_id"`
		Filter   Filter `json:"filter"`
	}
	if json.Unmarshal(encoded, &request) != nil || request.Version != 1 || request.TenantID != tenantID ||
		validateFilter(request.Filter) != nil {
		return true, manager.failClaim(ctx, *exportID, workerID, actorScopeID, actorID, "invalid_filter")
	}
	artifact, err := buildAccessExportCSV(ctx, manager.source, scope{tenantID: tenantID}, request.Filter,
		ExportLimits{MaxRows: exportMaxRows, MaxBytes: exportMaxBytes, PageSize: MaxLimit}, manager.now)
	if err != nil {
		if errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrInvalidResponse) || errors.Is(err, ErrResponseTooLarge) ||
			errors.Is(err, ErrCapabilityUnsupported) {
			return true, manager.failClaim(ctx, *exportID, workerID, actorScopeID, actorID, "export_rejected")
		}
		return true, err
	}
	return true, manager.completeClaim(ctx, *exportID, workerID, actorScopeID, actorID, artifact)
}

// exportJobContext 为单个导出任务建立执行上下文：请求编号取统一任务里持久化
// 的值（Create 时写入，缺失时 Create 已用导出编号兜底），仍不合法则用导出编号，
// 与 Create 的兜底规则一致。
func exportJobContext(parent context.Context, requestID, traceID string, exportID uuid.UUID) context.Context {
	ctx := WithRequestID(parent, requestID)
	if requestID == "" || RequestIDFromContext(ctx) != requestID {
		ctx = WithRequestID(parent, exportID.String())
	}
	return withTraceID(ctx, traceID)
}

func (manager *ExportManager) completeClaim(ctx context.Context, exportID, workerID, scopeID, actorID uuid.UUID, artifact AccessExportArtifact) error {
	now := manager.now().UTC().Truncate(time.Microsecond)
	digest, err := hex.DecodeString(artifact.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return ErrInvalidResponse
	}
	calculatedDigest := sha256.Sum256(artifact.Bytes)
	if subtle.ConstantTimeCompare(digest, calculatedDigest[:]) != 1 {
		return ErrInvalidResponse
	}
	tx, err := manager.pool.Begin(ctx)
	if err != nil {
		return ErrStorageUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	command, err := tx.Exec(ctx, `DELETE FROM analytics_log_export_leases_v1
		WHERE export_id=$1 AND worker_id=$2 AND lease_expires_at>$3`, exportID, workerID, now)
	if err != nil || command.RowsAffected() != 1 {
		return ErrConflict
	}
	if _, err := tx.Exec(ctx, `INSERT INTO analytics_log_export_artifacts_v1(
		export_id,content,content_sha256,row_count,artifact_expires_at,created_at)
		VALUES($1,$2,$3,$4,$5,$6)`, exportID, artifact.Bytes, digest, artifact.RowCount,
		now.Add(exportArtifactTTL), now); err != nil {
		return ErrStorageUnavailable
	}
	if _, err := tx.Exec(ctx, `INSERT INTO analytics_log_export_events_v1(
		export_id,sequence,state,reason,snapshot_at,row_count,byte_count,artifact_sha256,occurred_at)
		SELECT $1,COALESCE(max(sequence),0)+1,'completed','completed',$2,$3,$4,$5,$6
		FROM analytics_log_export_events_v1 WHERE export_id=$1`, exportID, artifact.SnapshotAt,
		artifact.RowCount, len(artifact.Bytes), digest, now); err != nil {
		return ErrStorageUnavailable
	}
	if err := manager.appendAudit(ctx, tx, scopeID, actorID, exportID, "analytics_log.export.complete", "success", "completed"); err != nil {
		return err
	}
	if err := reportExportJobTx(ctx, tx, exportID, jobstate.ItemSucceeded, "", now); err != nil {
		return ErrStorageUnavailable
	}
	return tx.Commit(ctx)
}

func (manager *ExportManager) failClaim(ctx context.Context, exportID, workerID, scopeID, actorID uuid.UUID, reason string) error {
	now := manager.now().UTC().Truncate(time.Microsecond)
	tx, err := manager.pool.Begin(ctx)
	if err != nil {
		return ErrStorageUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	command, err := tx.Exec(ctx, `DELETE FROM analytics_log_export_leases_v1
		WHERE export_id=$1 AND worker_id=$2 AND lease_expires_at>$3`, exportID, workerID, now)
	if err != nil || command.RowsAffected() != 1 {
		return ErrConflict
	}
	if _, err := tx.Exec(ctx, `INSERT INTO analytics_log_export_events_v1(export_id,sequence,state,reason,occurred_at)
		SELECT $1,COALESCE(max(sequence),0)+1,'failed',$2,$3 FROM analytics_log_export_events_v1 WHERE export_id=$1`,
		exportID, reason, now); err != nil {
		return ErrStorageUnavailable
	}
	if err := manager.appendAudit(ctx, tx, scopeID, actorID, exportID, "analytics_log.export.reject", "failure", reason); err != nil {
		return err
	}
	if err := reportExportJobTx(ctx, tx, exportID, jobstate.ItemFailed, reason, now); err != nil {
		return ErrStorageUnavailable
	}
	return tx.Commit(ctx)
}

func reportExportJobTx(
	ctx context.Context,
	tx pgx.Tx,
	exportID uuid.UUID,
	state jobstate.ItemState,
	code string,
	now time.Time,
) error {
	var tenantID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT tenant_id FROM analytics_log_exports_v1 WHERE id=$1`, exportID).Scan(&tenantID); err != nil {
		return err
	}
	claim, err := jobstate.StartTx(ctx, tx, jobstate.StartInput{
		TenantID: tenantID, JobID: exportID, Kind: "analytics.log_export",
		WorkerID: "analytics.log_export." + exportID.String(), LeaseDuration: time.Hour,
	}, now)
	if err != nil {
		return err
	}
	_, err = jobstate.ReportTx(ctx, tx, jobstate.ReportInput{
		TenantID: tenantID, JobID: exportID, WorkerID: claim.WorkerID, LeaseID: claim.LeaseID,
		Report: jobstate.Report{
			ItemID: exportID.String(), State: state, Code: code,
			Attempt: claim.Job.Attempt, Sequence: 1,
		},
	}, now)
	return err
}

func (manager *ExportManager) Cleanup(ctx context.Context) error {
	now := manager.now().UTC().Truncate(time.Microsecond)
	for _, query := range []string{
		`DELETE FROM analytics_log_export_grants_v1 WHERE ctid IN (SELECT ctid FROM analytics_log_export_grants_v1
		 WHERE expires_at<=$1 OR consumed_at<=$1-INTERVAL '1 hour' ORDER BY expires_at FOR UPDATE SKIP LOCKED LIMIT 100)`,
		`DELETE FROM analytics_log_export_artifacts_v1 WHERE ctid IN (SELECT ctid FROM analytics_log_export_artifacts_v1
		 WHERE artifact_expires_at<=$1 ORDER BY artifact_expires_at FOR UPDATE SKIP LOCKED LIMIT 100)`,
		`DELETE FROM analytics_log_export_leases_v1 WHERE ctid IN (SELECT ctid FROM analytics_log_export_leases_v1
		 WHERE lease_expires_at<=$1 ORDER BY lease_expires_at FOR UPDATE SKIP LOCKED LIMIT 100)`,
	} {
		if _, err := manager.pool.Exec(ctx, query, now); err != nil {
			return ErrStorageUnavailable
		}
	}
	return nil
}

type exportIdentity struct {
	actorID, scopeID, credentialID uuid.UUID
}

func exportIdentityFromActor(actor Actor) (exportIdentity, error) {
	actorID, actorErr := uuid.Parse(actor.ActorID)
	scopeID, scopeErr := uuid.Parse(actor.ScopeID)
	credentialID, credentialErr := uuid.Parse(actor.SessionID)
	if actorErr != nil || scopeErr != nil || credentialErr != nil || actorID == uuid.Nil || scopeID == uuid.Nil || credentialID == uuid.Nil {
		return exportIdentity{}, ErrScopeForbidden
	}
	return exportIdentity{actorID: actorID, scopeID: scopeID, credentialID: credentialID}, nil
}

func (manager *ExportManager) targetScope(ctx context.Context, tenantID string) (uuid.UUID, error) {
	var scopeID uuid.UUID
	err := manager.pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='tenant' AND tenant_id=$1`, tenantID).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrScopeForbidden
	}
	if err != nil || scopeID == uuid.Nil {
		return uuid.Nil, ErrStorageUnavailable
	}
	return scopeID, nil
}

func (manager *ExportManager) exportAccess(ctx context.Context, actor Actor, audience Audience, tenantID, rawID string) (scope, exportIdentity, uuid.UUID, uuid.UUID, error) {
	queryScope, err := authorizeExportScope(actor, audience, tenantID)
	if err != nil {
		return scope{}, exportIdentity{}, uuid.Nil, uuid.Nil, err
	}
	identity, err := exportIdentityFromActor(actor)
	if err != nil {
		return scope{}, exportIdentity{}, uuid.Nil, uuid.Nil, err
	}
	id, err := uuid.Parse(rawID)
	if err != nil || id == uuid.Nil || id.String() != rawID {
		return scope{}, exportIdentity{}, uuid.Nil, uuid.Nil, ErrInvalidInput
	}
	targetScopeID, err := manager.targetScope(ctx, queryScope.tenantID)
	return queryScope, identity, targetScopeID, id, err
}

const exportSelectSQL = `SELECT request.id,latest.state,latest.reason,latest.snapshot_at,latest.row_count,
	latest.byte_count,latest.artifact_sha256,request.created_at,artifact.artifact_expires_at,request.filter
	FROM analytics_log_exports_v1 request
	JOIN LATERAL (SELECT state,reason,snapshot_at,row_count,byte_count,artifact_sha256
		FROM analytics_log_export_events_v1 event WHERE event.export_id=request.id
		ORDER BY sequence DESC LIMIT 1) latest ON true
	LEFT JOIN analytics_log_export_artifacts_v1 artifact ON artifact.export_id=request.id `

type rowScanner interface{ Scan(...any) error }

func queryExport(ctx context.Context, querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id, targetScopeID uuid.UUID, identity exportIdentity, now time.Time) (AccessExport, error) {
	return scanExport(querier.QueryRow(ctx, exportSelectSQL+`
		WHERE request.id=$1 AND request.scope_id=$2 AND request.actor_scope_id=$3 AND request.actor_user_id=$4`,
		id, targetScopeID, identity.scopeID, identity.actorID), now)
}

func scanExport(row rowScanner, now time.Time) (AccessExport, error) {
	var id uuid.UUID
	var job AccessExport
	var digest, filter []byte
	if err := row.Scan(&id, &job.Status, &job.Reason, &job.SnapshotAt, &job.RowCount, &job.ByteCount,
		&digest, &job.CreatedAt, &job.ExpiresAt, &filter); errors.Is(err, pgx.ErrNoRows) {
		return AccessExport{}, ErrNotFound
	} else if err != nil {
		return AccessExport{}, ErrStorageUnavailable
	}
	job.ID = id.String()
	if digest != nil {
		if len(digest) != sha256.Size {
			return AccessExport{}, ErrInvalidResponse
		}
		job.SHA256 = hex.EncodeToString(digest)
	}
	job.Downloadable = job.Status == ExportCompleted && job.ExpiresAt != nil && job.ExpiresAt.After(now)
	if summary, ok := exportFilterSummary(filter); ok {
		job.Filter = &summary
	}
	return job, nil
}

func (manager *ExportManager) appendAudit(ctx context.Context, tx pgx.Tx, scopeID, actorID, exportID uuid.UUID, action, result, reason string) error {
	var targetScopeID uuid.UUID
	var tenantID string
	if err := tx.QueryRow(ctx, `SELECT scope_id,tenant_id::text FROM analytics_log_exports_v1 WHERE id=$1`, exportID).
		Scan(&targetScopeID, &tenantID); err != nil {
		return ErrStorageUnavailable
	}
	err := manager.audit.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorUserID: &actorID, Action: action, ResourceType: "analytics_log_export",
		ResourceID: exportID.String(), RequestID: RequestIDFromContext(ctx), Result: result,
		Payload: map[string]any{"reason": reason, "target_scope_id": targetScopeID.String(), "tenant_id": tenantID},
	})
	if err != nil {
		return ErrStorageUnavailable
	}
	return nil
}

func (manager *ExportManager) auditReject(ctx context.Context, scopeID, actorID, exportID uuid.UUID, reason string) error {
	tx, err := manager.pool.Begin(ctx)
	if err != nil {
		return ErrStorageUnavailable
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := manager.appendAudit(ctx, tx, scopeID, actorID, exportID, "analytics_log.export.reject", "denied", reason); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrStorageUnavailable
	}
	return ErrExpired
}

// authorizeExportScope is authorizeScope for tenant-owned export artifacts:
// the platform audience must name a tenant.
func authorizeExportScope(actor Actor, audience Audience, tenantID string) (scope, error) {
	queryScope, err := authorizeScope(actor, audience, tenantID)
	if err == nil && queryScope.platform() {
		return scope{}, ErrInvalidInput
	}
	return queryScope, err
}
