package sitetrafficlimit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Audit actions (catalog_site.go).
const (
	AuditUpdate   = "site.traffic_limit.update"
	AuditExceeded = "site.traffic_limit.exceeded"
	AuditRestored = "site.traffic_limit.restored"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, auditor: audit.New(pool), now: now}
}

type row struct {
	setting        Setting
	totalSince     *time.Time
	exceededPeriod *string
	exceededAt     *time.Time
	evaluatedAt    *time.Time
	updatedAt      time.Time
}

func (s *Store) Get(ctx context.Context, actor Actor, siteID uuid.UUID) (State, error) {
	var result State
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		query := `SELECT scope_id,revision FROM sites WHERE id=$1 AND deleted_at IS NULL`
		args := []any{siteID}
		if actor.ScopeKind == "tenant" {
			query += ` AND scope_id=$2`
			args = append(args, actor.ScopeID)
		}
		var scopeID uuid.UUID
		var revision int64
		if err := tx.QueryRow(ctx, query, args...).Scan(&scopeID, &revision); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		stored, found, err := readRow(ctx, tx, siteID, false)
		if err != nil {
			return err
		}
		result = newState(siteID, revision, stored, found)
		return nil
	})
	if err != nil {
		return State{}, fmt.Errorf("get site traffic limit: %w", err)
	}
	return result, nil
}

func (s *Store) Update(ctx context.Context, actor Actor, request UpdateRequest, digest [32]byte) (State, error) {
	var result State
	var auditScopeID uuid.UUID
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID, err := targetScope(ctx, tx, actor, request.SiteID)
		if err != nil {
			return err
		}
		auditScopeID = scopeID
		// Publication lock order: configuration scope before the site row.
		if err := lockEdgeConfigurationScope(ctx, tx, scopeID); err != nil {
			return err
		}
		var deletedAt, lockedAt *time.Time
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT deleted_at,locked_at,revision FROM sites
			WHERE id=$1 AND scope_id=$2 FOR UPDATE`, request.SiteID, scopeID).Scan(&deletedAt, &lockedAt, &revision); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if replayed, err := s.replay(ctx, tx, actor, request, digest, &result); err != nil || replayed {
			return err
		}
		if deletedAt != nil {
			return ErrNotFound
		}
		if lockedAt != nil && actor.ScopeKind == "tenant" {
			return ErrLocked
		}
		if revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		previous, found, err := readRow(ctx, tx, request.SiteID, true)
		if err != nil {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		next := row{setting: request.Setting, updatedAt: now}
		// The total cap counts from when it was set; changing it restarts it.
		if request.Setting.TotalBytes != nil {
			if found && previous.setting.TotalBytes != nil && *previous.setting.TotalBytes == *request.Setting.TotalBytes &&
				previous.totalSince != nil {
				next.totalSince = previous.totalSince
			} else {
				next.totalSince = &now
			}
		}
		// The decision stands only while the caps it was made on stand (a
		// notice page or zone edit keeps it); changed caps are decided again
		// on the next evaluation, and a disabled limit stops serving the page
		// with this very release.
		keep := request.Setting.Enabled && found && previous.exceededPeriod != nil && previous.setting.Enabled &&
			sameLimit(previous.setting.DailyBytes, request.Setting.DailyBytes) &&
			sameLimit(previous.setting.MonthlyBytes, request.Setting.MonthlyBytes) &&
			sameLimit(previous.setting.TotalBytes, request.Setting.TotalBytes) && previous.setting.TimeZone == request.Setting.TimeZone
		if keep {
			next.exceededPeriod, next.exceededAt = previous.exceededPeriod, previous.exceededAt
		}
		if err := writeRow(ctx, tx, scopeID, request.SiteID, actor.UserID, next, keep); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE sites SET revision=revision+1,updated_by_user_id=$2,updated_at=$3
			WHERE id=$1 AND revision=$4 AND deleted_at IS NULL`, request.SiteID, actor.UserID, now, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		automatic, err := edgeautopublish.EnqueueSiteSettingTx(ctx, tx, scopeID, request.SiteID, request.RequestID)
		if err != nil {
			return err
		}
		result = newState(request.SiteID, request.ExpectedRevision+1, next, true)
		before := map[string]any{}
		if found {
			before = summary(previous.setting)
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &actor.UserID, Action: AuditUpdate,
			ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{
				"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "site_id": request.SiteID.String(),
				"from_version": request.ExpectedRevision, "to_version": result.Version,
				"changes": changes(before, summary(request.Setting)), "automatic_publication": automatic,
			},
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, scopeID, request, digest, result, now)
	})
	if err != nil {
		if reason := deniedReason(err); reason != "" && auditScopeID != uuid.Nil {
			if auditErr := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
				return s.auditor.Append(ctx, tx, audit.Event{
					ScopeID: auditScopeID, ActorUserID: &actor.UserID, Action: AuditUpdate,
					ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "denied",
					Payload: map[string]any{
						"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "site_id": request.SiteID.String(),
						"reason_code": reason, "expected_version": request.ExpectedRevision,
						"requested": summary(request.Setting),
					},
				})
			}); auditErr != nil {
				return State{}, fmt.Errorf("update site traffic limit: %w (audit denied write: %v)", err, auditErr)
			}
		}
		return State{}, fmt.Errorf("update site traffic limit: %w", err)
	}
	return result, nil
}

func deniedReason(err error) string {
	switch {
	case errors.Is(err, ErrLocked):
		return "site_locked"
	case errors.Is(err, ErrRevisionConflict):
		return "revision_conflict"
	case errors.Is(err, ErrIdempotencyConflict):
		return "idempotency_conflict"
	}
	return ""
}

// summary is the audit form of a setting (the page by size only).
func summary(setting Setting) map[string]any {
	limit := func(value *int64) any {
		if value == nil {
			return "none"
		}
		return *value
	}
	return map[string]any{
		"enabled": setting.Enabled, "daily_bytes": limit(setting.DailyBytes), "monthly_bytes": limit(setting.MonthlyBytes),
		"total_bytes": limit(setting.TotalBytes), "time_zone": setting.TimeZone, "notice_html_bytes": len(setting.NoticeHTML),
	}
}

func changes(before, after map[string]any) map[string]any {
	result := map[string]any{}
	for key, to := range after {
		from, exists := before[key]
		fromJSON, _ := json.Marshal(from)
		toJSON, _ := json.Marshal(to)
		if !exists || !bytes.Equal(fromJSON, toJSON) {
			result[key] = map[string]any{"from": from, "to": to}
		}
	}
	return result
}

func newState(siteID uuid.UUID, revision int64, stored row, found bool) State {
	state := State{SiteID: siteID, Version: revision, Setting: Setting{TimeZone: "Asia/Shanghai"}}
	if !found {
		return state
	}
	state.Setting = stored.setting
	state.TotalSince, state.ExceededAt, state.EvaluatedAt = stored.totalSince, stored.exceededAt, stored.evaluatedAt
	if stored.exceededPeriod != nil {
		state.ExceededPeriod = *stored.exceededPeriod
	}
	updatedAt := stored.updatedAt
	state.UpdatedAt = &updatedAt
	return state
}

func targetScope(ctx context.Context, tx pgx.Tx, actor Actor, siteID uuid.UUID) (uuid.UUID, error) {
	if actor.ScopeKind == "tenant" {
		return actor.ScopeID, nil
	}
	var scopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1`, siteID).Scan(&scopeID); errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	} else if err != nil {
		return uuid.Nil, err
	}
	return scopeID, nil
}

func lockEdgeConfigurationScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
		VALUES($1,1,clock_timestamp()) ON CONFLICT(scope_id) DO NOTHING`, scopeID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT 1 FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`, scopeID)
	return err
}

func readRow(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, lock bool) (row, bool, error) {
	query := `SELECT enabled,daily_bytes,monthly_bytes,total_bytes,total_since,time_zone,notice_html,
		exceeded_period,exceeded_at,evaluated_at,updated_at FROM site_traffic_limits WHERE site_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	var stored row
	err := tx.QueryRow(ctx, query, siteID).Scan(&stored.setting.Enabled, &stored.setting.DailyBytes, &stored.setting.MonthlyBytes,
		&stored.setting.TotalBytes, &stored.totalSince, &stored.setting.TimeZone, &stored.setting.NoticeHTML,
		&stored.exceededPeriod, &stored.exceededAt, &stored.evaluatedAt, &stored.updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return row{}, false, nil
	}
	return stored, err == nil, err
}

// writeRow upserts the setting. keepExceeded keeps the recorded exceeded
// period (start included); otherwise it is cleared and the next evaluation
// decides again.
func writeRow(ctx context.Context, tx pgx.Tx, scopeID, siteID, userID uuid.UUID, next row, keepExceeded bool) error {
	_, err := tx.Exec(ctx, `INSERT INTO site_traffic_limits(scope_id,site_id,enabled,daily_bytes,monthly_bytes,total_bytes,
		total_since,time_zone,notice_html,updated_by_user_id,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT(site_id) DO UPDATE SET enabled=EXCLUDED.enabled,daily_bytes=EXCLUDED.daily_bytes,
			monthly_bytes=EXCLUDED.monthly_bytes,total_bytes=EXCLUDED.total_bytes,total_since=EXCLUDED.total_since,
			time_zone=EXCLUDED.time_zone,notice_html=EXCLUDED.notice_html,updated_by_user_id=EXCLUDED.updated_by_user_id,
			updated_at=EXCLUDED.updated_at,evaluated_at=NULL,
			exceeded_period=CASE WHEN $12 THEN site_traffic_limits.exceeded_period END,
			exceeded_at=CASE WHEN $12 THEN site_traffic_limits.exceeded_at END,
			exceeded_period_start=CASE WHEN $12 THEN site_traffic_limits.exceeded_period_start END`,
		scopeID, siteID, next.setting.Enabled, next.setting.DailyBytes, next.setting.MonthlyBytes, next.setting.TotalBytes,
		next.totalSince, next.setting.TimeZone, next.setting.NoticeHTML, userID, next.updatedAt, keepExceeded)
	return err
}

func (s *Store) replay(ctx context.Context, tx pgx.Tx, actor Actor, request UpdateRequest, digest [32]byte, result *State) (bool, error) {
	var storedSiteID uuid.UUID
	var storedDigest, body []byte
	err := tx.QueryRow(ctx, `SELECT site_id,request_digest,response_body FROM site_traffic_limit_write_requests
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3`,
		actor.ScopeID, actor.UserID, request.IdempotencyKey).Scan(&storedSiteID, &storedDigest, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if storedSiteID != request.SiteID || !bytes.Equal(storedDigest, digest[:]) {
		return false, ErrIdempotencyConflict
	}
	if err := json.Unmarshal(body, result); err != nil {
		return false, fmt.Errorf("decode stored site traffic limit response: %w", err)
	}
	return true, nil
}

func (s *Store) completeWrite(ctx context.Context, tx pgx.Tx, actor Actor, scopeID uuid.UUID, request UpdateRequest,
	digest [32]byte, result State, now time.Time) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `INSERT INTO site_traffic_limit_write_requests(
		id,actor_scope_id,actor_user_id,target_scope_id,site_id,idempotency_key,request_digest,response_body,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
	ON CONFLICT(actor_scope_id,actor_user_id,idempotency_key) DO NOTHING`,
		id, actor.ScopeID, actor.UserID, scopeID, request.SiteID, request.IdempotencyKey, digest[:], string(body), now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func sameLimit(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
