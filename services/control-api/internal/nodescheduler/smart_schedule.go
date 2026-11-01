package nodescheduler

import (
	"context"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SmartScheduleSettings is a line group's smart schedule configuration
// (migration 609; selection lives in internal/smartsched).
type SmartScheduleSettings struct {
	Enabled              bool   `json:"enabled"`
	TopN                 int    `json:"top_n"`
	Granularity          string `json:"granularity"`
	LatencyWindowMinutes int    `json:"latency_window_minutes"`
	MaxLoadPercent       int    `json:"max_load_percent"`
	Fallback             string `json:"fallback"`
}

// DefaultSmartScheduleSettings: off, top 3, carrier lines, 15 minutes, 85 %.
func DefaultSmartScheduleSettings() SmartScheduleSettings {
	return SmartScheduleSettings{TopN: 3, Granularity: "carrier", LatencyWindowMinutes: 15, MaxLoadPercent: 85,
		Fallback: "carrier_then_default"}
}

func (settings SmartScheduleSettings) valid() bool {
	return settings.TopN >= 1 && settings.TopN <= 20 &&
		(settings.Granularity == "carrier" || settings.Granularity == "province_carrier") &&
		settings.LatencyWindowMinutes >= 5 && settings.LatencyWindowMinutes <= 60 &&
		settings.MaxLoadPercent >= 1 && settings.MaxLoadPercent <= 100 && settings.Fallback == "carrier_then_default"
}

// SmartScheduleReader reads the line group's selections and latency inside
// the authorized transaction (smartsched.Reader).
type SmartScheduleReader interface {
	Lines(ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID, revision int64) (any, error)
	ProbeSource(ctx context.Context, tx pgx.Tx) (any, error)
	Matrix(ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID, window int) (any, error)
	ProvinceLines(ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID) (bool, error)
}

// SmartSchedule is the GET view.
type SmartSchedule struct {
	SmartScheduleSettings
	// ProvinceLinesSupported is false when the zone's DNS provider of a site
	// on this line group cannot write province lines (carrier lines only).
	ProvinceLinesSupported bool  `json:"province_lines_supported"`
	Lines                  any   `json:"lines"`
	ProbeSource            any   `json:"probe_source"`
	Revision               int64 `json:"revision"`
}

// GetSmartSchedule reads the configuration (defaults when never written)
// and the current selections of a line group (node_scheduling.read).
func (s *Service) GetSmartSchedule(ctx context.Context, actor Actor, groupID uuid.UUID, reader SmartScheduleReader) (SmartSchedule, error) {
	if ctx == nil || actor.UserID == uuid.Nil || groupID == uuid.Nil || reader == nil {
		return SmartSchedule{}, ErrInvalidInput
	}
	var result SmartSchedule
	err := s.readTx(ctx, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		revision, err := smartGroupRevision(ctx, tx, actor.ResourceScopeID(), groupID, false)
		if err != nil {
			return err
		}
		result.SmartScheduleSettings, result.Revision, err = loadSmartSettings(ctx, tx, actor.ResourceScopeID(), groupID)
		if err != nil {
			return err
		}
		if result.Lines, err = reader.Lines(ctx, tx, actor.ResourceScopeID(), groupID, revision); err != nil {
			return err
		}
		if result.ProbeSource, err = reader.ProbeSource(ctx, tx); err != nil {
			return err
		}
		result.ProvinceLinesSupported, err = reader.ProvinceLines(ctx, tx, actor.ResourceScopeID(), groupID)
		return err
	})
	return result, err
}

// LatencyMatrix reads the windowed latency matrix (node_scheduling.read).
func (s *Service) LatencyMatrix(ctx context.Context, actor Actor, groupID uuid.UUID, window int, reader SmartScheduleReader) (any, error) {
	if ctx == nil || actor.UserID == uuid.Nil || groupID == uuid.Nil || reader == nil || window < 1 || window > 60 {
		return nil, ErrInvalidInput
	}
	var rows any
	err := s.readTx(ctx, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		if _, err := smartGroupRevision(ctx, tx, actor.ResourceScopeID(), groupID, false); err != nil {
			return err
		}
		var err error
		rows, err = reader.Matrix(ctx, tx, actor.ResourceScopeID(), groupID, window)
		return err
	})
	return rows, err
}

// PutSmartSchedule replaces the configuration (node_scheduling.manage) and
// audits the change. Turning it off drops the selections at once so the DNS
// writer returns to the static lines on its next tick.
func (s *Service) PutSmartSchedule(ctx context.Context, actor Actor, groupID uuid.UUID, settings SmartScheduleSettings,
	requestID string) (SmartScheduleSettings, int64, error) {
	if ctx == nil || actor.UserID == uuid.Nil || groupID == uuid.Nil || !writeMetadataPattern.MatchString(requestID) {
		return SmartScheduleSettings{}, 0, ErrInvalidInput
	}
	settings.Fallback = "carrier_then_default"
	if !settings.valid() {
		return SmartScheduleSettings{}, 0, ErrInvalidInput
	}
	if actor.ScopeKind == "platform" && actor.ResourceScopeID() != actor.ScopeID {
		return SmartScheduleSettings{}, 0, ErrPlatformWriteDenied
	}
	var revision int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionManage, true); err != nil {
			return err
		}
		scopeID := actor.ResourceScopeID()
		if _, err := smartGroupRevision(ctx, tx, scopeID, groupID, true); err != nil {
			return err
		}
		before, current, err := loadSmartSettings(ctx, tx, scopeID, groupID)
		if err != nil {
			return err
		}
		revision = current
		if before == settings && current > 0 {
			return nil
		}
		revision = current + 1
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_group_smart_schedules(tenant_scope_id,line_group_id,enabled,top_n,
				granularity,latency_window_minutes,max_load_percent,fallback,revision,updated_by_user_id,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (tenant_scope_id,line_group_id) DO UPDATE SET enabled=EXCLUDED.enabled,top_n=EXCLUDED.top_n,
				granularity=EXCLUDED.granularity,latency_window_minutes=EXCLUDED.latency_window_minutes,
				max_load_percent=EXCLUDED.max_load_percent,fallback=EXCLUDED.fallback,revision=EXCLUDED.revision,
				updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
			scopeID, groupID, settings.Enabled, settings.TopN, settings.Granularity, settings.LatencyWindowMinutes,
			settings.MaxLoadPercent, settings.Fallback, revision, actor.UserID, s.now().UTC()); err != nil {
			return fmt.Errorf("write smart schedule: %w", err)
		}
		if !settings.Enabled {
			if _, err := tx.Exec(ctx, `DELETE FROM node_line_smart_selections WHERE tenant_scope_id=$1 AND line_group_id=$2`,
				scopeID, groupID); err != nil {
				return fmt.Errorf("clear smart selections: %w", err)
			}
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &actor.UserID, Action: "node_scheduling.group.smart_schedule",
			ResourceType: "node_line_group", ResourceID: groupID.String(), RequestID: requestID, Result: "success",
			Payload: map[string]any{"changes": map[string]any{"before": before, "after": settings}, "revision": revision},
		})
	})
	return settings, revision, err
}

// readTx is not READ ONLY: authorizeTx (iamlock) takes FOR SHARE / FOR KEY
// SHARE row locks, which PostgreSQL rejects in a read-only transaction.
func (s *Service) readTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func smartGroupRevision(ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID, lock bool) (int64, error) {
	query := `SELECT current_revision FROM node_line_groups WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL`
	if lock {
		query += ` FOR UPDATE`
	}
	var revision int64
	err := tx.QueryRow(ctx, query, scopeID, groupID).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("load node line group: %w", err)
	}
	return revision, nil
}

func loadSmartSettings(ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID) (SmartScheduleSettings, int64, error) {
	settings := DefaultSmartScheduleSettings()
	var topN, window, maxLoad int16
	var revision int64
	err := tx.QueryRow(ctx, `SELECT enabled,top_n,granularity,latency_window_minutes,max_load_percent,fallback,revision
		FROM node_line_group_smart_schedules WHERE tenant_scope_id=$1 AND line_group_id=$2`, scopeID, groupID).Scan(
		&settings.Enabled, &topN, &settings.Granularity, &window, &maxLoad, &settings.Fallback, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return settings, 0, nil
	}
	if err != nil {
		return SmartScheduleSettings{}, 0, fmt.Errorf("load smart schedule: %w", err)
	}
	settings.TopN, settings.LatencyWindowMinutes, settings.MaxLoadPercent = int(topN), int(window), int(maxLoad)
	return settings, revision, nil
}
