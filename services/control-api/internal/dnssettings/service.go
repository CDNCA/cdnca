package dnssettings

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	settingsOperation = "dns_settings.update"
	repairJobKind     = "dns.repair.v1"
	cleanupJobKind    = "dns.cleanup.v1"
)

type Service struct {
	pool  *pgxpool.Pool
	jobs  *jobstate.Store
	audit *audit.Log
	now   func() time.Time
}

func NewService(pool *pgxpool.Pool, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	var jobs *jobstate.Store
	if pool != nil {
		jobs, _ = jobstate.NewStore(pool, now)
	}
	return &Service{pool: pool, jobs: jobs, audit: audit.NewWithClock(pool, now), now: now}
}

func (s *Service) Get(ctx context.Context, actor Actor) (Settings, error) {
	if ctx == nil || !actor.validForRead() || s == nil || s.pool == nil {
		return Settings{}, ErrUnavailable
	}
	var result Settings
	result.ScopeID = actor.ScopeID
	err := s.pool.QueryRow(ctx, `
		SELECT ttl, revision, updated_at
		FROM dns_legacy_settings
		WHERE scope_id=$1`, actor.ScopeID).Scan(&result.TTL, &result.Revision, &result.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		result.TTL = DefaultTTL
		result.Revision = 1
		return result, nil
	}
	if err != nil {
		return Settings{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (Settings, error) {
	if ctx == nil || !actor.valid() || s == nil || s.pool == nil ||
		request.TTL < MinTTL || request.TTL > MaxTTL || request.ExpectedRevision < 1 ||
		!validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) {
		return Settings{}, ErrInvalidInput
	}
	digest := sha256.Sum256(mustJSON(struct {
		ScopeID uuid.UUID `json:"scope_id"`
		TTL     int       `json:"ttl"`
		Version int64     `json:"version"`
	}{actor.ScopeID, request.TTL, request.ExpectedRevision}))
	var result Settings
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var existingDigest []byte
		var existingBody []byte
		err := tx.QueryRow(ctx, `
			SELECT request_digest, response_body
			FROM dns_legacy_settings_write_requests
			WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3
			FOR UPDATE`, actor.UserID, settingsOperation, request.IdempotencyKey).
			Scan(&existingDigest, &existingBody)
		if err == nil {
			if !bytes.Equal(existingDigest, digest[:]) {
				return ErrIdempotencyConflict
			}
			return json.Unmarshal(existingBody, &result)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return ErrUnavailable
		}
		command, err := tx.Exec(ctx, `
			INSERT INTO dns_legacy_settings_write_requests(
				id, actor_user_id, actor_scope_id, target_scope_id, operation,
				idempotency_key, request_digest, created_at
			) VALUES($1,$2,$3,$3,$4,$5,$6,$7)
			ON CONFLICT(actor_user_id, operation, idempotency_key) DO NOTHING`, uuid.New(), actor.UserID,
			actor.ScopeID, settingsOperation, request.IdempotencyKey, digest[:], s.now().UTC())
		if err != nil {
			return ErrUnavailable
		}
		if command.RowsAffected() == 0 {
			if err := tx.QueryRow(ctx, `
				SELECT request_digest, response_body
				FROM dns_legacy_settings_write_requests
				WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3
				FOR UPDATE`, actor.UserID, settingsOperation, request.IdempotencyKey).
				Scan(&existingDigest, &existingBody); err != nil || !bytes.Equal(existingDigest, digest[:]) {
				return ErrIdempotencyConflict
			}
			if len(existingBody) > 0 {
				return json.Unmarshal(existingBody, &result)
			}
			return ErrUnavailable
		}

		var currentTTL int
		var currentRevision int64
		var currentUpdated time.Time
		err = tx.QueryRow(ctx, `
			SELECT ttl, revision, updated_at
			FROM dns_legacy_settings
			WHERE scope_id=$1
			FOR UPDATE`, actor.ScopeID).Scan(&currentTTL, &currentRevision, &currentUpdated)
		if errors.Is(err, pgx.ErrNoRows) {
			currentTTL, currentRevision = DefaultTTL, 1
		} else if err != nil {
			return ErrUnavailable
		}
		if currentRevision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		result = Settings{ScopeID: actor.ScopeID, TTL: request.TTL, Revision: currentRevision + 1, UpdatedAt: &now}
		_, err = tx.Exec(ctx, `
			INSERT INTO dns_legacy_settings(scope_id, tenant_id, ttl, revision, updated_by_user_id, updated_at)
			VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT(scope_id) DO UPDATE SET ttl=EXCLUDED.ttl, revision=EXCLUDED.revision,
				updated_by_user_id=EXCLUDED.updated_by_user_id, updated_at=EXCLUDED.updated_at`,
			actor.ScopeID, actor.TenantID, result.TTL, result.Revision, actor.UserID, now)
		if err != nil {
			return ErrUnavailable
		}
		if s.audit == nil || s.audit.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: settingsOperation,
			ResourceType: "dns_legacy_settings", ResourceID: actor.ScopeID.String(),
			RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"ttl": result.TTL, "version": result.Revision},
		}) != nil {
			return ErrUnavailable
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return ErrUnavailable
		}
		_, err = tx.Exec(ctx, `
			UPDATE dns_legacy_settings_write_requests
			SET response_body=$4, completed_at=$5
			WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`,
			actor.UserID, settingsOperation, request.IdempotencyKey, encoded, now)
		return err
	})
	if err != nil {
		return Settings{}, err
	}
	return result, nil
}

func (s *Service) StartOperation(ctx context.Context, actor Actor, request OperationRequest) (Operation, bool, error) {
	if ctx == nil || !actor.valid() || s == nil || s.jobs == nil ||
		(request.Kind != OperationRepair && request.Kind != OperationCleanup) ||
		!validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) ||
		len(request.TraceID) > 128 {
		return Operation{}, false, ErrInvalidInput
	}
	kind := repairJobKind
	if request.Kind == OperationCleanup {
		kind = cleanupJobKind
	}
	payload, err := json.Marshal(struct {
		Schema  string `json:"schema"`
		ScopeID string `json:"scope_id"`
		Action  string `json:"action"`
	}{"dns-operation/v1", actor.ScopeID.String(), request.Kind})
	if err != nil {
		return Operation{}, false, ErrUnavailable
	}
	result, err := s.jobs.Create(ctx, jobstate.CreateInput{
		TenantID: actor.TenantID, Kind: kind,
		Subject:        "dns " + request.Kind,
		IdempotencyKey: request.IdempotencyKey, Payload: payload,
		Items:       []jobstate.CreateItem{{ItemID: "scope:" + actor.ScopeID.String()}},
		MaxAttempts: 3, RequestID: request.RequestID, TraceID: request.TraceID,
	})
	if err != nil {
		if errors.Is(err, jobstate.ErrIdempotencyConflict) {
			return Operation{}, false, ErrIdempotencyConflict
		}
		return Operation{}, false, ErrUnavailable
	}
	if !result.Replayed && s.audit != nil {
		if err := s.appendOperationAudit(ctx, actor, result.Job.ID, request); err != nil {
			return Operation{}, false, ErrUnavailable
		}
	}
	return operationFromJob(result.Job), result.Replayed, nil
}

// PlatformTarget is a tenant scope holding a copy of the platform DNS
// configuration.
type PlatformTarget struct {
	TenantID uuid.UUID
	ScopeID  uuid.UUID
	// Items are the job's result lines (one CNAME owner or provider record
	// each, see dnsmaintenance); at least one.
	Items []string
}

// StartPlatformOperation starts 记录修复 / 清除CDN无关解析 from the platform
// DNS configuration: one tenant-scoped background job per target scope, all
// replayable under the caller's idempotency key.
func (s *Service) StartPlatformOperation(ctx context.Context, actorUserID, platformScopeID uuid.UUID,
	targets []PlatformTarget, request OperationRequest) ([]Operation, bool, error) {
	if ctx == nil || s == nil || s.jobs == nil || actorUserID == uuid.Nil || platformScopeID == uuid.Nil ||
		(request.Kind != OperationRepair && request.Kind != OperationCleanup) ||
		!validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) || len(request.TraceID) > 128 {
		return nil, false, ErrInvalidInput
	}
	kind := repairJobKind
	if request.Kind == OperationCleanup {
		kind = cleanupJobKind
	}
	operations := make([]Operation, 0, len(targets))
	replayed := len(targets) > 0
	for _, target := range targets {
		if len(target.Items) == 0 {
			return nil, false, ErrInvalidInput
		}
		items := make([]jobstate.CreateItem, len(target.Items))
		for index, item := range target.Items {
			items[index] = jobstate.CreateItem{ItemID: item}
		}
		payload, err := json.Marshal(struct {
			Schema  string `json:"schema"`
			ScopeID string `json:"scope_id"`
			Action  string `json:"action"`
		}{"dns-operation/v1", target.ScopeID.String(), request.Kind})
		if err != nil {
			return nil, false, ErrUnavailable
		}
		key := sha256.Sum256([]byte(request.IdempotencyKey + "/" + target.ScopeID.String()))
		result, err := s.jobs.Create(ctx, jobstate.CreateInput{
			TenantID: target.TenantID, Kind: kind, Subject: operationSubject(request.Kind),
			IdempotencyKey: "dns-platform-" + hex.EncodeToString(key[:24]), Payload: payload,
			Items:       items,
			MaxAttempts: 1, RequestID: request.RequestID, TraceID: request.TraceID,
		})
		if errors.Is(err, jobstate.ErrIdempotencyConflict) {
			return nil, false, ErrIdempotencyConflict
		}
		if err != nil {
			return nil, false, ErrUnavailable
		}
		replayed = replayed && result.Replayed
		operations = append(operations, operationFromJob(result.Job))
	}
	if !replayed && s.audit != nil {
		if err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			return s.audit.Append(ctx, tx, audit.Event{
				ScopeID: platformScopeID, ActorUserID: &actorUserID,
				Action: "dns_operation.enqueue", ResourceType: "dns_platform_config", ResourceID: platformScopeID.String(),
				RequestID: request.RequestID, Result: "success",
				Payload: map[string]any{"kind": request.Kind, "jobs": len(operations)},
			})
		}); err != nil {
			return nil, false, ErrUnavailable
		}
	}
	return operations, replayed, nil
}

func (s *Service) GetOperation(ctx context.Context, actor Actor, id uuid.UUID) (Operation, error) {
	if ctx == nil || !actor.valid() || s == nil || s.jobs == nil || id == uuid.Nil {
		return Operation{}, ErrInvalidInput
	}
	job, err := s.jobs.Get(ctx, actor.TenantID, id)
	if errors.Is(err, jobstate.ErrNotFound) {
		return Operation{}, ErrNotFound
	}
	if err != nil {
		return Operation{}, ErrUnavailable
	}
	if job.Kind != repairJobKind && job.Kind != cleanupJobKind {
		return Operation{}, ErrNotFound
	}
	return operationFromJob(job), nil
}

func (s *Service) appendOperationAudit(ctx context.Context, actor Actor, jobID uuid.UUID, request OperationRequest) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return s.audit.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: "dns_operation.enqueue", ResourceType: "background_job",
			ResourceID: jobID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"kind": request.Kind, "job_id": jobID.String()},
		})
	})
}

func operationFromJob(job jobstate.StoredJob) Operation {
	result := Operation{
		ID: job.ID, Kind: job.Kind, Subject: job.Subject, State: string(job.State),
		Attempt: job.Attempt, MaxAttempts: job.MaxAttempts,
		Progress: Progress{Total: job.Progress.Total, Completed: job.Progress.Completed,
			Succeeded: job.Progress.Succeeded, Failed: job.Progress.Failed,
			Cancelled: job.Progress.Cancelled, Pending: job.Progress.Pending},
		LastError: job.LastErrorCode, CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt,
	}
	if !job.StartedAt.IsZero() {
		value := job.StartedAt
		result.StartedAt = &value
	}
	if !job.CompletedAt.IsZero() {
		value := job.CompletedAt
		result.CompletedAt = &value
	}
	return result
}

func validMetadata(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if !(character >= 'A' && character <= 'Z') && !(character >= 'a' && character <= 'z') &&
			!(character >= '0' && character <= '9') && !strings.ContainsRune("._:-", character) {
			return false
		}
	}
	return true
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

// operationSubject is the task name under 系统管理 > 后台任务.
func operationSubject(kind string) string {
	if kind == OperationCleanup {
		return "清除CDN无关解析"
	}
	return "DNS记录修复"
}
