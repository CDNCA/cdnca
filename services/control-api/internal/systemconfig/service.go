package systemconfig

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	operationCreateDraft = "system_configuration.create_draft"
	operationPreflight   = "system_configuration.preflight"
	operationActivate    = "system_configuration.activate"
	operationRollback    = "system_configuration.rollback"
	permissionRead       = "system_configuration.read"
	permissionManage     = "system_configuration.manage"
	maxRevision          = int64(1<<63 - 2)
	preflightTTL         = 15 * time.Minute
)

type Service struct {
	pool      *pgxpool.Pool
	auditor   AuditAppender
	publisher ActivationPublisher
	now       Clock
	clockMu   sync.Mutex
	lastNow   time.Time
}

func NewService(pool *pgxpool.Pool) (*Service, error) {
	if pool == nil {
		return nil, ErrInvalidStore
	}
	return NewServiceWithDependencies(pool, audit.New(pool), time.Now)
}

func NewServiceWithDependencies(pool *pgxpool.Pool, auditor AuditAppender, now Clock) (*Service, error) {
	return newServiceWithDependencies(pool, auditor, now, nil)
}

func NewServiceWithPublisher(pool *pgxpool.Pool, auditor AuditAppender, now Clock, publisher ActivationPublisher) (*Service, error) {
	if publisher == nil {
		return nil, ErrInvalidStore
	}
	return newServiceWithDependencies(pool, auditor, now, publisher)
}

func newServiceWithDependencies(pool *pgxpool.Pool, auditor AuditAppender, now Clock, publisher ActivationPublisher) (*Service, error) {
	if pool == nil || auditor == nil || now == nil {
		return nil, ErrInvalidStore
	}
	return &Service{pool: pool, auditor: auditor, publisher: publisher, now: now}, nil
}

func (s *Service) CreateDraft(ctx context.Context, actor Actor, request CreateDraftRequest) (Revision, error) {
	if err := authorizeActorShape(actor); err != nil {
		return Revision{}, err
	}
	if request.ExpectedHeadRevision < 0 || request.ExpectedHeadRevision >= maxRevision ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return Revision{}, ErrInvalidInput
	}
	normalized, snapshot, snapshotHash, err := CanonicalSnapshot(request.Configuration)
	if err != nil {
		return Revision{}, err
	}
	request.Configuration = normalized
	digest, err := digestRequest(struct {
		ExpectedHeadRevision int64  `json:"expected_head_revision"`
		SnapshotSHA256       string `json:"snapshot_sha256"`
	}{request.ExpectedHeadRevision, snapshotHash})
	if err != nil {
		return Revision{}, err
	}
	return s.createDraft(ctx, actor, request, snapshot, snapshotHash, digest)
}

func (s *Service) RecordPreflight(ctx context.Context, actor Actor, request RecordPreflightRequest) (Revision, error) {
	if err := authorizeActorShape(actor); err != nil {
		return Revision{}, err
	}
	checks, passed, err := normalizeChecks(request.Checks)
	if err != nil || request.Revision < 1 || request.Revision > maxRevision ||
		(request.ExpectedStatus != StatusDraft && request.ExpectedStatus != StatusValidated) ||
		(request.ExpectedStatus == StatusValidated && !passed) ||
		!hexSHA256Pattern.MatchString(request.SnapshotSHA256) ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return Revision{}, ErrInvalidInput
	}
	request.Checks = checks
	digest, err := digestRequest(struct {
		Revision       int64            `json:"revision"`
		ExpectedStatus string           `json:"expected_status"`
		SnapshotSHA256 string           `json:"snapshot_sha256"`
		Checks         []PreflightCheck `json:"checks"`
	}{request.Revision, request.ExpectedStatus, request.SnapshotSHA256, checks})
	if err != nil {
		return Revision{}, err
	}
	return s.recordPreflight(ctx, actor, request, passed, digest)
}

func (s *Service) Activate(ctx context.Context, actor Actor, request ActivateRequest) (Revision, error) {
	if err := authorizeActorShape(actor); err != nil {
		return Revision{}, err
	}
	if request.Revision < 1 || request.Revision > maxRevision ||
		request.ExpectedActiveRevision < 0 || request.ExpectedActiveRevision > maxRevision ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) ||
		!validPendingCategories(request.ExpectedPendingCategories) {
		return Revision{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		Revision                  int64     `json:"revision"`
		ExpectedActiveRevision    int64     `json:"expected_active_revision"`
		ExpectedPendingCategories *[]string `json:"expected_pending_categories,omitempty"`
	}{request.Revision, request.ExpectedActiveRevision, request.ExpectedPendingCategories})
	if err != nil {
		return Revision{}, err
	}
	return s.activate(ctx, actor, request, digest)
}

func (s *Service) Rollback(ctx context.Context, actor Actor, request RollbackRequest) (Revision, error) {
	if err := authorizeActorShape(actor); err != nil {
		return Revision{}, err
	}
	if request.TargetRevision < 1 || request.TargetRevision > maxRevision ||
		request.ExpectedHeadRevision < 1 || request.ExpectedHeadRevision >= maxRevision ||
		request.ExpectedActiveRevision < 1 || request.ExpectedActiveRevision > maxRevision ||
		request.TargetRevision > request.ExpectedHeadRevision ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return Revision{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		TargetRevision         int64 `json:"target_revision"`
		ExpectedHeadRevision   int64 `json:"expected_head_revision"`
		ExpectedActiveRevision int64 `json:"expected_active_revision"`
	}{request.TargetRevision, request.ExpectedHeadRevision, request.ExpectedActiveRevision})
	if err != nil {
		return Revision{}, err
	}
	return s.rollback(ctx, actor, request, digest)
}

func (s *Service) GetRevision(ctx context.Context, actor Actor, revision int64) (Revision, error) {
	if err := authorizeActorShape(actor); err != nil {
		return Revision{}, err
	}
	if revision < 1 || revision > maxRevision {
		return Revision{}, ErrInvalidInput
	}
	return s.getRevision(ctx, actor, revision)
}

func (s *Service) GetActive(ctx context.Context, actor Actor) (Revision, error) {
	if err := authorizeActorShape(actor); err != nil {
		return Revision{}, err
	}
	return s.getActive(ctx, actor)
}

func authorizeActorShape(actor Actor) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil ||
		(actor.ScopeKind != "platform" && actor.ScopeKind != "tenant") {
		return ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return ErrPermissionDenied
	}
	return nil
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, fmt.Errorf("encode system configuration request: %w", err)
	}
	return sha256.Sum256(encoded), nil
}

func (s *Service) currentTime() (time.Time, error) {
	now, err := checkedStoreTime(s.now())
	if err != nil {
		return time.Time{}, err
	}
	s.clockMu.Lock()
	defer s.clockMu.Unlock()
	if !s.lastNow.IsZero() && now.Before(s.lastNow) {
		return time.Time{}, ErrClockRollback
	}
	if now.After(s.lastNow) {
		s.lastNow = now
	}
	return now, nil
}

func checkedStoreTime(value time.Time) (time.Time, error) {
	value = value.UTC().Truncate(time.Microsecond)
	if value.Year() < 1 || value.Year() > 9999 {
		return time.Time{}, ErrInvalidInput
	}
	return value, nil
}

func checkedPreflightExpiry(now time.Time) (time.Time, error) {
	now, err := checkedStoreTime(now)
	if err != nil {
		return time.Time{}, err
	}
	expiresAt := now.Add(preflightTTL)
	if expiresAt.Year() > 9999 || !expiresAt.After(now) {
		return time.Time{}, ErrInvalidInput
	}
	return expiresAt, nil
}
