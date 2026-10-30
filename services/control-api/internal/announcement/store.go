package announcement

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool       *pgxpool.Pool
	auditor    AuditAppender
	outbox     PublicationOutbox
	now        Clock
	authorizer TxAuthorizer
	cursorKeys CursorKeyring
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, ErrInvalidStore
	}
	return NewStoreWithDependencies(pool, audit.New(pool), NoopPublicationOutbox{}, time.Now, CursorKeyring{})
}

func NewStoreWithDependencies(pool *pgxpool.Pool, auditor AuditAppender, outbox PublicationOutbox, now Clock, keyring CursorKeyring, authorizers ...TxAuthorizer) (*Store, error) {
	if pool == nil || auditor == nil || outbox == nil || now == nil {
		return nil, ErrInvalidStore
	}
	cursorKeys, ok := validatedCursorKeyring(keyring)
	if !ok {
		return nil, ErrInvalidStore
	}
	authorizer := TxAuthorizer(denyAuthorizer{})
	if len(authorizers) > 1 {
		return nil, ErrInvalidStore
	}
	if len(authorizers) == 1 {
		if authorizers[0] == nil {
			return nil, ErrInvalidStore
		}
		authorizer = authorizers[0]
	}
	return &Store{pool: pool, auditor: auditor, outbox: outbox, now: now,
		authorizer: authorizer, cursorKeys: cursorKeys}, nil
}

func (s *Store) ListAnnouncements(ctx context.Context, actor Actor, request AnnouncementListRequest) (AnnouncementPage, error) {
	if request.Limit == 0 {
		request.Limit = DefaultPageSize
	}
	if request.Limit < 1 || request.Limit > MaxPageSize {
		return AnnouncementPage{}, ErrInvalidInput
	}
	if request.Status != "" && request.Status != StatusDraft && request.Status != StatusScheduled &&
		request.Status != StatusPublished && request.Status != StatusWithdrawn && request.Status != StatusArchived {
		return AnnouncementPage{}, ErrInvalidInput
	}
	var cursor *announcementCursor
	if request.Cursor != "" {
		decoded, err := decodeAnnouncementCursor(s.cursorKeys, request.Cursor)
		if err != nil {
			return AnnouncementPage{}, err
		}
		if decoded.ScopeID != actor.ScopeID || decoded.UserID != actor.UserID || decoded.Filter != normalizeStatusFilter(request.Status) {
			return AnnouncementPage{}, ErrInvalidCursor
		}
		cursor = &decoded
	}
	var result AnnouncementPage
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if err := s.authorizeManage(ctx, tx, actor); err != nil {
			return err
		}
		watermark := int64(0)
		if cursor != nil {
			watermark = cursor.Watermark
		} else {
			var err error
			watermark, err = announcementStateWatermark(ctx, tx, actor.ScopeID)
			if err != nil {
				return err
			}
		}
		var err error
		result, err = s.listAnnouncementSnapshot(ctx, tx, actor, request, cursor, watermark)
		return err
	})
	if err != nil {
		return AnnouncementPage{}, fmt.Errorf("list announcements: %w", err)
	}
	return result, nil
}

func (s *Store) GetAnnouncement(ctx context.Context, actor Actor, id uuid.UUID) (Announcement, error) {
	if id == uuid.Nil {
		return Announcement{}, ErrInvalidInput
	}
	var result Announcement
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeManage(ctx, tx, actor); err != nil {
			return err
		}
		root, err := lockRoot(ctx, tx, actor.ScopeID, id)
		if err != nil {
			return err
		}
		result, err = loadAnnouncement(ctx, tx, actor.ScopeID, id, root.HeadVersion, false)
		return err
	})
	if err != nil {
		return Announcement{}, fmt.Errorf("get announcement: %w", err)
	}
	return result, nil
}

func (s *Store) CreateDraft(ctx context.Context, actor Actor, request CreateDraftRequest) (Announcement, error) {
	request.Presentation = NormalizePresentation(request.Presentation)
	if err := validateDraftInput(request.Content, request.Presentation, request.Audience, request.WithdrawalVisibility, request.IdempotencyKey, request.RequestID); err != nil {
		return Announcement{}, err
	}
	request.Audience = canonicalAudience(request.Audience)
	digest, err := requestDigest(request)
	if err != nil {
		return Announcement{}, err
	}
	var result Announcement
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeManage(ctx, tx, actor); err != nil {
			return err
		}
		replay, found, err := s.claimWrite(ctx, tx, actor, operationCreate, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			return decodeReplay(replay, &result)
		}
		now := storeTime(s.now())
		announcementID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO announcements(
			id,tenant_scope_id,head_version,created_by_user_id,created_at,updated_at
		) VALUES($1,$2,1,$3,$4,$4)`, announcementID, actor.ScopeID, actor.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO announcement_versions(
			tenant_scope_id,announcement_id,version,revision,status,title,body,audience_mode,
			withdrawal_visibility,content_format,link_url,sort_order,is_visible,is_popup,style_red,style_bold,
			created_by_user_id,created_at,state_changed_at
		) VALUES($1,$2,1,1,'draft',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)`, actor.ScopeID, announcementID,
			request.Title, request.Body, audienceMode(request.Audience), request.WithdrawalVisibility,
			request.Format, nullableLinkURL(request.LinkURL), request.SortOrder, request.Visible, request.Popup,
			request.Red, request.Bold, actor.UserID, now); err != nil {
			return err
		}
		if err := insertAudience(ctx, tx, actor.ScopeID, announcementID, 1, request.Audience); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO announcement_archive_254(
			tenant_scope_id,announcement_id,changed_at,changed_by_user_id
		) VALUES($1,$2,$3,$4)`, actor.ScopeID, announcementID, now, actor.UserID); err != nil {
			return err
		}
		factID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO announcement_lifecycle_facts_254(
			id,tenant_scope_id,announcement_id,revision,state,actor_user_id,occurred_at,request_id
		) VALUES($1,$2,$3,1,'active',$4,$5,$6)`, factID, actor.ScopeID, announcementID,
			actor.UserID, now, request.RequestID); err != nil {
			return err
		}
		result, err = loadAnnouncement(ctx, tx, actor.ScopeID, announcementID, 1, false)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, &actor.UserID, result, request.RequestID, operationCreate, nil); err != nil {
			return fmt.Errorf("audit announcement create: %w", err)
		}
		return s.completeWrite(ctx, tx, actor, operationCreate, request.IdempotencyKey, result)
	})
	if err != nil {
		return Announcement{}, fmt.Errorf("create announcement draft: %w", err)
	}
	return result, nil
}

func (s *Store) UpdateDraft(ctx context.Context, actor Actor, request UpdateDraftRequest) (Announcement, error) {
	if request.AnnouncementID == uuid.Nil || request.Version < 1 || request.ExpectedRevision < 1 {
		return Announcement{}, ErrInvalidInput
	}
	request.Presentation = NormalizePresentation(request.Presentation)
	if err := validateDraftInput(request.Content, request.Presentation, request.Audience, request.WithdrawalVisibility, request.IdempotencyKey, request.RequestID); err != nil {
		return Announcement{}, err
	}
	request.Audience = canonicalAudience(request.Audience)
	digest, err := requestDigest(request)
	if err != nil {
		return Announcement{}, err
	}
	var result Announcement
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeManage(ctx, tx, actor); err != nil {
			return err
		}
		replay, found, err := s.claimWrite(ctx, tx, actor, operationUpdate, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			return decodeReplay(replay, &result)
		}
		root, err := lockRoot(ctx, tx, actor.ScopeID, request.AnnouncementID)
		if err != nil {
			return err
		}
		current, err := loadAnnouncement(ctx, tx, actor.ScopeID, request.AnnouncementID, request.Version, true)
		if err != nil {
			return err
		}
		if root.HeadVersion != request.Version || current.Status != StatusDraft || current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if _, err := tx.Exec(ctx, `DELETE FROM announcement_audience_users
			WHERE tenant_scope_id=$1 AND announcement_id=$2 AND announcement_version=$3`, actor.ScopeID, request.AnnouncementID, request.Version); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM announcement_audience_groups
			WHERE tenant_scope_id=$1 AND announcement_id=$2 AND announcement_version=$3`, actor.ScopeID, request.AnnouncementID, request.Version); err != nil {
			return err
		}
		if err := insertAudience(ctx, tx, actor.ScopeID, request.AnnouncementID, request.Version, request.Audience); err != nil {
			return err
		}
		now := storeTime(s.now())
		command, err := tx.Exec(ctx, `UPDATE announcement_versions SET
			title=$4,body=$5,audience_mode=$6,withdrawal_visibility=$7,content_format=$8,link_url=$9,
			sort_order=$10,is_visible=$11,is_popup=$12,style_red=$13,style_bold=$14,
			revision=revision+1,state_changed_at=$15
			WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=$3
			  AND status='draft' AND revision=$16`, actor.ScopeID, request.AnnouncementID, request.Version,
			request.Title, request.Body, audienceMode(request.Audience), request.WithdrawalVisibility,
			request.Format, nullableLinkURL(request.LinkURL), request.SortOrder, request.Visible, request.Popup,
			request.Red, request.Bold, now, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result, err = loadAnnouncement(ctx, tx, actor.ScopeID, request.AnnouncementID, request.Version, false)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, &actor.UserID, result, request.RequestID, operationUpdate, map[string]any{"expected_revision": request.ExpectedRevision}); err != nil {
			return fmt.Errorf("audit announcement update: %w", err)
		}
		return s.completeWrite(ctx, tx, actor, operationUpdate, request.IdempotencyKey, result)
	})
	if err != nil {
		return Announcement{}, fmt.Errorf("update announcement draft: %w", err)
	}
	return result, nil
}

func (s *Store) Schedule(ctx context.Context, actor Actor, request ScheduleRequest) (Announcement, error) {
	now := storeTime(s.now())
	request.PublishAt = storeTime(request.PublishAt)
	if request.AnnouncementID == uuid.Nil || request.Version < 1 || request.ExpectedRevision < 1 ||
		request.PublishAt.Before(now) || !validMeta(request.IdempotencyKey, request.RequestID) {
		return Announcement{}, ErrInvalidInput
	}
	digest, err := requestDigest(request)
	if err != nil {
		return Announcement{}, err
	}
	var result Announcement
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeManage(ctx, tx, actor); err != nil {
			return err
		}
		replay, found, err := s.claimWrite(ctx, tx, actor, operationSchedule, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			return decodeReplay(replay, &result)
		}
		if _, err := lockRoot(ctx, tx, actor.ScopeID, request.AnnouncementID); err != nil {
			return err
		}
		current, err := loadAnnouncement(ctx, tx, actor.ScopeID, request.AnnouncementID, request.Version, true)
		if err != nil {
			return err
		}
		if current.Status != StatusDraft || current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		command, err := tx.Exec(ctx, `UPDATE announcement_versions SET
			status='scheduled',scheduled_at=$4,sealed_at=$5,revision=revision+1,state_changed_at=$5
			WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=$3
			  AND status='draft' AND revision=$6`, actor.ScopeID, request.AnnouncementID, request.Version,
			request.PublishAt, now, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result, err = loadAnnouncement(ctx, tx, actor.ScopeID, request.AnnouncementID, request.Version, false)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, &actor.UserID, result, request.RequestID, operationSchedule, map[string]any{"publish_at": request.PublishAt}); err != nil {
			return fmt.Errorf("audit announcement schedule: %w", err)
		}
		return s.completeWrite(ctx, tx, actor, operationSchedule, request.IdempotencyKey, result)
	})
	if err != nil {
		return Announcement{}, fmt.Errorf("schedule announcement: %w", err)
	}
	return result, nil
}

func (s *Store) Publish(ctx context.Context, actor Actor, request PublishRequest) (Announcement, error) {
	if request.AnnouncementID == uuid.Nil || request.Version < 1 || request.ExpectedRevision < 1 ||
		!validMeta(request.IdempotencyKey, request.RequestID) {
		return Announcement{}, ErrInvalidInput
	}
	digest, err := requestDigest(request)
	if err != nil {
		return Announcement{}, err
	}
	var result Announcement
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeManage(ctx, tx, actor); err != nil {
			return err
		}
		replay, found, err := s.claimWrite(ctx, tx, actor, operationPublish, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			return decodeReplay(replay, &result)
		}
		root, err := lockRoot(ctx, tx, actor.ScopeID, request.AnnouncementID)
		if err != nil {
			return err
		}
		current, err := loadAnnouncement(ctx, tx, actor.ScopeID, request.AnnouncementID, request.Version, true)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		result, err = s.publishLocked(ctx, tx, root, current, &actor.UserID, request.RequestID)
		if err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operationPublish, request.IdempotencyKey, result)
	})
	if err != nil {
		return Announcement{}, fmt.Errorf("publish announcement: %w", err)
	}
	return result, nil
}

func (s *Store) PublishDue(ctx context.Context, limit int) ([]Announcement, error) {
	if limit < 1 || limit > 1000 {
		return nil, ErrInvalidInput
	}
	results := make([]Announcement, 0, limit)
	for len(results) < limit {
		var result Announcement
		published := false
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			now := storeTime(s.now())
			var scopeID, announcementID uuid.UUID
			var version int64
			err := tx.QueryRow(ctx, `SELECT tenant_scope_id,announcement_id,version
				FROM announcement_versions WHERE status='scheduled' AND scheduled_at <= $1
				ORDER BY scheduled_at,tenant_scope_id,announcement_id,version LIMIT 1`, now).
				Scan(&scopeID, &announcementID, &version)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			root, err := lockRoot(ctx, tx, scopeID, announcementID)
			if err != nil {
				return err
			}
			current, err := loadAnnouncement(ctx, tx, scopeID, announcementID, version, true)
			if err != nil {
				return err
			}
			if current.Status != StatusScheduled || current.ScheduledAt == nil || current.ScheduledAt.After(now) {
				return nil
			}
			result, err = s.publishLocked(ctx, tx, root, current, nil,
				fmt.Sprintf("announcement-scheduler:%s:%d", announcementID, version))
			if err != nil {
				return err
			}
			published = true
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("publish scheduled announcement: %w", err)
		}
		if !published {
			break
		}
		results = append(results, result)
	}
	return results, nil
}

func (s *Store) Revise(ctx context.Context, actor Actor, request ReviseRequest) (Announcement, error) {
	if request.AnnouncementID == uuid.Nil || request.ExpectedHeadVersion < 1 {
		return Announcement{}, ErrInvalidInput
	}
	request.Presentation = NormalizePresentation(request.Presentation)
	if err := validateDraftInput(request.Content, request.Presentation, request.Audience, request.WithdrawalVisibility, request.IdempotencyKey, request.RequestID); err != nil {
		return Announcement{}, err
	}
	request.Audience = canonicalAudience(request.Audience)
	digest, err := requestDigest(request)
	if err != nil {
		return Announcement{}, err
	}
	var result Announcement
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeManage(ctx, tx, actor); err != nil {
			return err
		}
		replay, found, err := s.claimWrite(ctx, tx, actor, operationRevise, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			return decodeReplay(replay, &result)
		}
		root, err := lockRoot(ctx, tx, actor.ScopeID, request.AnnouncementID)
		if err != nil {
			return err
		}
		if root.HeadVersion != request.ExpectedHeadVersion {
			return ErrRevisionConflict
		}
		source, err := loadAnnouncement(ctx, tx, actor.ScopeID, request.AnnouncementID, root.HeadVersion, true)
		if err != nil {
			return err
		}
		if source.Status != StatusPublished && source.Status != StatusWithdrawn {
			return ErrInvalidTransition
		}
		version := root.HeadVersion + 1
		now := storeTime(s.now())
		if _, err := tx.Exec(ctx, `INSERT INTO announcement_versions(
			tenant_scope_id,announcement_id,version,revision,status,title,body,audience_mode,
			withdrawal_visibility,content_format,link_url,sort_order,is_visible,is_popup,style_red,style_bold,
			created_by_user_id,created_at,state_changed_at
		) VALUES($1,$2,$3,1,'draft',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$16)`, actor.ScopeID, request.AnnouncementID,
			version, request.Title, request.Body, audienceMode(request.Audience), request.WithdrawalVisibility,
			request.Format, nullableLinkURL(request.LinkURL), request.SortOrder, request.Visible, request.Popup,
			request.Red, request.Bold, actor.UserID, now); err != nil {
			return err
		}
		if err := insertAudience(ctx, tx, actor.ScopeID, request.AnnouncementID, version, request.Audience); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE announcements SET head_version=$3,updated_at=$4
			WHERE tenant_scope_id=$1 AND id=$2 AND head_version=$5`, actor.ScopeID, request.AnnouncementID, version, now, request.ExpectedHeadVersion)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result, err = loadAnnouncement(ctx, tx, actor.ScopeID, request.AnnouncementID, version, false)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, &actor.UserID, result, request.RequestID, operationRevise, map[string]any{"source_version": source.Version}); err != nil {
			return fmt.Errorf("audit announcement revise: %w", err)
		}
		return s.completeWrite(ctx, tx, actor, operationRevise, request.IdempotencyKey, result)
	})
	if err != nil {
		return Announcement{}, fmt.Errorf("revise announcement: %w", err)
	}
	return result, nil
}

func (s *Store) Withdraw(ctx context.Context, actor Actor, request WithdrawRequest) (Announcement, error) {
	if request.AnnouncementID == uuid.Nil || request.Version < 1 || request.ExpectedRevision < 1 ||
		!validMeta(request.IdempotencyKey, request.RequestID) {
		return Announcement{}, ErrInvalidInput
	}
	digest, err := requestDigest(request)
	if err != nil {
		return Announcement{}, err
	}
	var result Announcement
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeManage(ctx, tx, actor); err != nil {
			return err
		}
		replay, found, err := s.claimWrite(ctx, tx, actor, operationWithdraw, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			return decodeReplay(replay, &result)
		}
		root, err := lockRoot(ctx, tx, actor.ScopeID, request.AnnouncementID)
		if err != nil {
			return err
		}
		current, err := loadAnnouncement(ctx, tx, actor.ScopeID, request.AnnouncementID, request.Version, true)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if current.Status != StatusPublished && current.Status != StatusScheduled {
			return ErrInvalidTransition
		}
		now := storeTime(s.now())
		command, err := tx.Exec(ctx, `UPDATE announcement_versions SET
			status='withdrawn',withdrawn_at=$4,revision=revision+1,state_changed_at=$4
			WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=$3
			  AND status IN ('scheduled','published') AND revision=$5`, actor.ScopeID, request.AnnouncementID, request.Version, now, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		var fallback *int64
		if err := tx.QueryRow(ctx, `SELECT max(version) FROM announcement_versions
			WHERE tenant_scope_id=$1 AND announcement_id=$2 AND status='published'`,
			actor.ScopeID, request.AnnouncementID).Scan(&fallback); err != nil {
			return err
		}
		pointerChanged := root.CurrentPublishedVersion == nil && fallback != nil ||
			root.CurrentPublishedVersion != nil && (fallback == nil || *root.CurrentPublishedVersion != *fallback)
		if pointerChanged {
			if _, err := tx.Exec(ctx, `UPDATE announcements
				SET current_published_version=$3,updated_at=$4
				WHERE tenant_scope_id=$1 AND id=$2`, actor.ScopeID, request.AnnouncementID, fallback, now); err != nil {
				return err
			}
		}
		result, err = loadAnnouncement(ctx, tx, actor.ScopeID, request.AnnouncementID, request.Version, false)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, &actor.UserID, result, request.RequestID, operationWithdraw, map[string]any{"visibility": result.WithdrawalVisibility}); err != nil {
			return fmt.Errorf("audit announcement withdraw: %w", err)
		}
		return s.completeWrite(ctx, tx, actor, operationWithdraw, request.IdempotencyKey, result)
	})
	if err != nil {
		return Announcement{}, fmt.Errorf("withdraw announcement: %w", err)
	}
	return result, nil
}

func (s *Store) Archive(ctx context.Context, actor Actor, request ArchiveRequest) (Announcement, error) {
	return s.transitionArchive(ctx, actor, request.AnnouncementID, request.ExpectedLifecycleRevision,
		request.IdempotencyKey, request.RequestID, true)
}

func (s *Store) Restore(ctx context.Context, actor Actor, request RestoreRequest) (Announcement, error) {
	return s.transitionArchive(ctx, actor, request.AnnouncementID, request.ExpectedLifecycleRevision,
		request.IdempotencyKey, request.RequestID, false)
}

func (s *Store) transitionArchive(ctx context.Context, actor Actor, announcementID uuid.UUID, expectedRevision int64,
	idempotencyKey, requestID string, archive bool) (Announcement, error) {
	if announcementID == uuid.Nil || expectedRevision < 1 || !validMeta(idempotencyKey, requestID) {
		return Announcement{}, ErrInvalidInput
	}
	request := struct {
		AnnouncementID            uuid.UUID `json:"announcement_id"`
		ExpectedLifecycleRevision int64     `json:"expected_lifecycle_revision"`
	}{announcementID, expectedRevision}
	digest, err := requestDigest(request)
	if err != nil {
		return Announcement{}, err
	}
	operation := operationRestore
	action := operationRestore
	if archive {
		operation, action = operationArchive, operationArchive
	}
	var result Announcement
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeManage(ctx, tx, actor); err != nil {
			return err
		}
		replay, found, err := s.claimWrite(ctx, tx, actor, operation, idempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			return decodeReplay(replay, &result)
		}
		root, err := lockRoot(ctx, tx, actor.ScopeID, announcementID)
		if err != nil {
			return err
		}
		var current bool
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT archived,revision FROM announcement_archive_254
			WHERE tenant_scope_id=$1 AND announcement_id=$2 FOR UPDATE`, actor.ScopeID, announcementID).
			Scan(&current, &revision); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if revision != expectedRevision || current == archive {
			if revision != expectedRevision {
				return ErrRevisionConflict
			}
			return ErrInvalidTransition
		}
		now := storeTime(s.now())
		var archivedAt any
		var archivedBy any
		if archive {
			archivedAt, archivedBy = now, actor.UserID
		}
		command, err := tx.Exec(ctx, `UPDATE announcement_archive_254 SET archived=$3,revision=revision+1,
			archived_at=$4,archived_by_user_id=$5,changed_at=$6,changed_by_user_id=$7
			WHERE tenant_scope_id=$1 AND announcement_id=$2 AND revision=$8`, actor.ScopeID, announcementID,
			archive, archivedAt, archivedBy, now, actor.UserID, expectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		factID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		state := "active"
		if archive {
			state = "archived"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO announcement_lifecycle_facts_254(
			id,tenant_scope_id,announcement_id,revision,state,actor_user_id,occurred_at,request_id
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, factID, actor.ScopeID, announcementID, expectedRevision+1,
			state, actor.UserID, now, requestID); err != nil {
			return err
		}
		result, err = loadAnnouncement(ctx, tx, actor.ScopeID, announcementID, root.HeadVersion, false)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, &actor.UserID, result, requestID, action, map[string]any{
			"lifecycle_revision": result.LifecycleRevision, "archived": result.Archived,
		}); err != nil {
			return fmt.Errorf("audit announcement %s: %w", action, err)
		}
		return s.completeWrite(ctx, tx, actor, operation, idempotencyKey, result)
	})
	if err != nil {
		return Announcement{}, fmt.Errorf("%s announcement: %w", action, err)
	}
	return result, nil
}

func (s *Store) publishLocked(
	ctx context.Context,
	tx pgx.Tx,
	root rootState,
	current Announcement,
	actorID *uuid.UUID,
	requestID string,
) (Announcement, error) {
	if current.Status != StatusDraft && current.Status != StatusScheduled {
		return Announcement{}, ErrInvalidTransition
	}
	now := storeTime(s.now())
	if current.Status == StatusScheduled && (current.ScheduledAt == nil || current.ScheduledAt.After(now)) {
		return Announcement{}, ErrInvalidTransition
	}
	if root.CurrentPublishedVersion != nil && current.Version <= *root.CurrentPublishedVersion {
		return Announcement{}, ErrInvalidTransition
	}
	command, err := tx.Exec(ctx, `INSERT INTO announcement_recipient_snapshots(
		tenant_scope_id,announcement_id,announcement_version,user_id,resolved_at
	)
	SELECT $1,$2,$3,recipient.user_id,$5 FROM (`+tenantRecipientsSQL+`) recipient
	ON CONFLICT DO NOTHING`, current.ScopeID, current.ID, current.Version, audienceMode(current.Audience), now)
	if err != nil {
		return Announcement{}, err
	}
	if command.RowsAffected() == 0 {
		return Announcement{}, ErrEmptyAudience
	}
	rows, err := tx.Query(ctx, `SELECT user_id FROM announcement_recipient_snapshots
		WHERE tenant_scope_id=$1 AND announcement_id=$2 AND announcement_version=$3 ORDER BY user_id`,
		current.ScopeID, current.ID, current.Version)
	if err != nil {
		return Announcement{}, err
	}
	var recipients []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return Announcement{}, err
		}
		recipients = append(recipients, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Announcement{}, err
	}
	rows.Close()
	eventIDs := make([]uuid.UUID, 0, len(recipients))
	for _, recipientID := range recipients {
		eventID, err := uuid.NewV7()
		if err != nil {
			return Announcement{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO announcement_inbox_events(
			id,tenant_scope_id,announcement_id,announcement_version,recipient_user_id,
			title,body,published_at,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8)`, eventID, current.ScopeID, current.ID,
			current.Version, recipientID, current.Title, current.Body, now); err != nil {
			return Announcement{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO announcement_inbox_states(
			tenant_scope_id,event_id,user_id,revision,updated_at
		) VALUES($1,$2,$3,1,$4)`, current.ScopeID, eventID, recipientID, now); err != nil {
			return Announcement{}, err
		}
		eventIDs = append(eventIDs, eventID)
	}
	if err := s.outbox.EnqueuePublication(ctx, tx, PublicationNotice{
		ScopeID: current.ScopeID, AnnouncementID: current.ID, Version: current.Version,
		Title: current.Title, Body: current.Body, PublishedAt: now,
		RecipientIDs: recipients, InboxEventIDs: eventIDs,
	}); err != nil {
		return Announcement{}, fmt.Errorf("enqueue announcement publication: %w", err)
	}
	command, err = tx.Exec(ctx, `UPDATE announcement_versions SET
		status='published',sealed_at=COALESCE(sealed_at,$4),published_at=$4,
		revision=revision+1,state_changed_at=$4
		WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=$3
		  AND status IN ('draft','scheduled') AND revision=$5`, current.ScopeID, current.ID, current.Version, now, current.Revision)
	if err != nil {
		return Announcement{}, err
	}
	if command.RowsAffected() != 1 {
		return Announcement{}, ErrRevisionConflict
	}
	command, err = tx.Exec(ctx, `UPDATE announcements SET current_published_version=$3,updated_at=$4
		WHERE tenant_scope_id=$1 AND id=$2 AND head_version >= $3
		  AND (current_published_version IS NULL OR current_published_version < $3)`, current.ScopeID, current.ID, current.Version, now)
	if err != nil {
		return Announcement{}, err
	}
	if command.RowsAffected() != 1 {
		return Announcement{}, ErrRevisionConflict
	}
	result, err := loadAnnouncement(ctx, tx, current.ScopeID, current.ID, current.Version, false)
	if err != nil {
		return Announcement{}, err
	}
	if err := s.appendAudit(ctx, tx, actorID, result, requestID, operationPublish, map[string]any{"recipient_count": len(recipients)}); err != nil {
		return Announcement{}, fmt.Errorf("audit announcement publish: %w", err)
	}
	return result, nil
}

func validateDraftInput(content Content, presentation Presentation, audience Audience, visibility, key, requestID string) error {
	if err := ValidatePresentation(presentation, content); err != nil {
		return err
	}
	if err := ValidateAudience(audience); err != nil {
		return err
	}
	if visibility != VisibilityRetain && visibility != VisibilityHide {
		return fielderr.New(ErrInvalidInput, "withdrawal_visibility", fielderr.Invalid)
	}
	if !validMeta(key, requestID) {
		return ErrInvalidInput
	}
	return nil
}

func insertAudience(ctx context.Context, tx pgx.Tx, scopeID, announcementID uuid.UUID, version int64, audience Audience) error {
	if audience.All {
		return nil
	}
	if len(audience.UserIDs) > 0 {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM memberships
			WHERE scope_id=$1 AND status='active' AND user_id=ANY($2)`, scopeID, audience.UserIDs).Scan(&count); err != nil {
			return err
		}
		if count != len(audience.UserIDs) {
			return ErrAudienceScopeDenied
		}
		for _, userID := range audience.UserIDs {
			if _, err := tx.Exec(ctx, `INSERT INTO announcement_audience_users(
				tenant_scope_id,announcement_id,announcement_version,user_id
			) VALUES($1,$2,$3,$4)`, scopeID, announcementID, version, userID); err != nil {
				return err
			}
		}
	}
	if len(audience.GroupIDs) > 0 {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM roles role
			LEFT JOIN custom_roles custom_role ON custom_role.id=role.id
			 AND custom_role.tenant_scope_id=role.scope_id
			WHERE role.scope_id=$1 AND role.id=ANY($2)
			  AND (custom_role.id IS NULL OR custom_role.deactivated_at IS NULL)`, scopeID, audience.GroupIDs).Scan(&count); err != nil {
			return err
		}
		if count != len(audience.GroupIDs) {
			return ErrAudienceScopeDenied
		}
		for _, groupID := range audience.GroupIDs {
			if _, err := tx.Exec(ctx, `INSERT INTO announcement_audience_groups(
				tenant_scope_id,announcement_id,announcement_version,group_role_id
			) VALUES($1,$2,$3,$4)`, scopeID, announcementID, version, groupID); err != nil {
				return err
			}
		}
	}
	return nil
}

func audienceMode(audience Audience) string {
	if audience.All {
		return "all"
	}
	return "selected"
}

func nullableLinkURL(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

type rootState struct {
	HeadVersion             int64
	CurrentPublishedVersion *int64
}

func lockRoot(ctx context.Context, tx pgx.Tx, scopeID, announcementID uuid.UUID) (rootState, error) {
	var result rootState
	err := tx.QueryRow(ctx, `SELECT head_version,current_published_version FROM announcements
		WHERE tenant_scope_id=$1 AND id=$2 FOR UPDATE`, scopeID, announcementID).
		Scan(&result.HeadVersion, &result.CurrentPublishedVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return rootState{}, ErrNotFound
	}
	return result, err
}

func loadAnnouncement(ctx context.Context, tx pgx.Tx, scopeID, announcementID uuid.UUID, version int64, lock bool) (Announcement, error) {
	query := `SELECT root.id,root.tenant_scope_id,revision_row.version,root.head_version,
		revision_row.revision,revision_row.status,revision_row.title,revision_row.body,
		revision_row.content_format,revision_row.link_url,revision_row.sort_order,
		revision_row.is_visible,revision_row.is_popup,revision_row.style_red,revision_row.style_bold,
		revision_row.audience_mode,revision_row.withdrawal_visibility,revision_row.scheduled_at,
		revision_row.published_at,revision_row.withdrawn_at,revision_row.created_at,revision_row.state_changed_at,
		archive.archived,archive.revision,archive.archived_at
		FROM announcements root JOIN announcement_versions revision_row
		  ON revision_row.tenant_scope_id=root.tenant_scope_id AND revision_row.announcement_id=root.id
		JOIN announcement_archive_254 archive
		  ON archive.tenant_scope_id=root.tenant_scope_id AND archive.announcement_id=root.id
		WHERE root.tenant_scope_id=$1 AND root.id=$2 AND revision_row.version=$3`
	if lock {
		query += ` FOR UPDATE OF revision_row`
	}
	var result Announcement
	var mode string
	var linkURL *string
	err := tx.QueryRow(ctx, query, scopeID, announcementID, version).Scan(
		&result.ID, &result.ScopeID, &result.Version, &result.HeadVersion, &result.Revision,
		&result.Status, &result.Title, &result.Body, &result.Format, &linkURL, &result.SortOrder,
		&result.Visible, &result.Popup, &result.Red, &result.Bold, &mode, &result.WithdrawalVisibility,
		&result.ScheduledAt, &result.PublishedAt, &result.WithdrawnAt, &result.CreatedAt, &result.StateChangedAt,
		&result.Archived, &result.LifecycleRevision, &result.ArchivedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Announcement{}, ErrNotFound
	}
	if err != nil {
		return Announcement{}, err
	}
	if linkURL != nil {
		result.LinkURL = *linkURL
	}
	result.Audience, err = loadAudience(ctx, tx, scopeID, announcementID, version, mode)
	return result, err
}

func loadAudience(ctx context.Context, tx pgx.Tx, scopeID, announcementID uuid.UUID, version int64, mode string) (Audience, error) {
	if mode == "all" {
		return Audience{All: true}, nil
	}
	result := Audience{}
	userRows, err := tx.Query(ctx, `SELECT user_id FROM announcement_audience_users
		WHERE tenant_scope_id=$1 AND announcement_id=$2 AND announcement_version=$3 ORDER BY user_id`, scopeID, announcementID, version)
	if err != nil {
		return Audience{}, err
	}
	for userRows.Next() {
		var id uuid.UUID
		if err := userRows.Scan(&id); err != nil {
			userRows.Close()
			return Audience{}, err
		}
		result.UserIDs = append(result.UserIDs, id)
	}
	if err := userRows.Err(); err != nil {
		userRows.Close()
		return Audience{}, err
	}
	userRows.Close()
	groupRows, err := tx.Query(ctx, `SELECT group_role_id FROM announcement_audience_groups
		WHERE tenant_scope_id=$1 AND announcement_id=$2 AND announcement_version=$3 ORDER BY group_role_id`, scopeID, announcementID, version)
	if err != nil {
		return Audience{}, err
	}
	defer groupRows.Close()
	for groupRows.Next() {
		var id uuid.UUID
		if err := groupRows.Scan(&id); err != nil {
			return Audience{}, err
		}
		result.GroupIDs = append(result.GroupIDs, id)
	}
	return result, groupRows.Err()
}

func (s *Store) authorizeManage(ctx context.Context, tx pgx.Tx, actor Actor) error {
	if actor.ScopeID == uuid.Nil || actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil {
		return ErrPermissionDenied
	}
	return s.authorizer.Authorize(ctx, tx, actor, permissionManage)
}

func (s *Store) authorizeSelf(ctx context.Context, tx pgx.Tx, actor Actor) error {
	if actor.ScopeID == uuid.Nil || actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil {
		return ErrPermissionDenied
	}
	return s.authorizer.Authorize(ctx, tx, actor, permissionRead)
}

func (s *Store) appendAudit(ctx context.Context, tx pgx.Tx, actorID *uuid.UUID, item Announcement, requestID, action string, extra map[string]any) error {
	payload := map[string]any{"version": item.Version, "revision": item.Revision, "status": item.Status}
	for key, value := range extra {
		payload[key] = value
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: item.ScopeID, ActorUserID: actorID, Action: action,
		ResourceType: "announcement", ResourceID: fmt.Sprintf("%s:%d", item.ID, item.Version),
		RequestID: requestID, Result: "success", Payload: payload,
	})
}

func requestDigest(request any) ([32]byte, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return [32]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func (s *Store) claimWrite(ctx context.Context, tx pgx.Tx, actor Actor, operation, key string, digest [32]byte) ([]byte, bool, error) {
	if response, found, err := findWrite(ctx, tx, actor, operation, key, digest); err != nil || found {
		return response, found, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, false, err
	}
	command, err := tx.Exec(ctx, `INSERT INTO announcement_write_requests(
		id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)
	ON CONFLICT(tenant_scope_id,actor_user_id,operation,idempotency_key) DO NOTHING`, id,
		actor.ScopeID, actor.UserID, operation, key, digest[:], storeTime(s.now()))
	if err != nil {
		return nil, false, err
	}
	if command.RowsAffected() == 1 {
		return nil, false, nil
	}
	response, found, err := findWrite(ctx, tx, actor, operation, key, digest)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, ErrIdempotencyConflict
	}
	return response, true, nil
}

func findWrite(ctx context.Context, tx pgx.Tx, actor Actor, operation, key string, digest [32]byte) ([]byte, bool, error) {
	var storedDigest, response []byte
	var completedAt *time.Time
	err := tx.QueryRow(ctx, `SELECT request_digest,response_body,completed_at
		FROM announcement_write_requests WHERE tenant_scope_id=$1 AND actor_user_id=$2
		  AND operation=$3 AND idempotency_key=$4`, actor.ScopeID, actor.UserID, operation, key).
		Scan(&storedDigest, &response, &completedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(storedDigest, digest[:]) || completedAt == nil || len(response) == 0 {
		return nil, false, ErrIdempotencyConflict
	}
	return response, true, nil
}

func (s *Store) completeWrite(ctx context.Context, tx pgx.Tx, actor Actor, operation, key string, result any) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE announcement_write_requests
		SET response_body=$5,completed_at=$6
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND operation=$3
		  AND idempotency_key=$4 AND completed_at IS NULL`, actor.ScopeID, actor.UserID,
		operation, key, encoded, storeTime(s.now()))
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func decodeReplay(encoded []byte, target any) error {
	if err := json.Unmarshal(encoded, target); err != nil {
		return err
	}
	switch result := target.(type) {
	case *Announcement:
		result.Replayed = true
	case *GlobalAnnouncement:
		result.Replayed = true
	case *InboxState:
		result.Replayed = true
	}
	return nil
}

func storeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}
