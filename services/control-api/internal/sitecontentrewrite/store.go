package sitecontentrewrite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/contentrewrite"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditAction is the audit event of a write.
const AuditAction = "site.content_rewrite.update"

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

func (s *Store) Get(ctx context.Context, actor Actor, siteID uuid.UUID) (State, error) {
	query := `SELECT s.revision,s.content_rewrite,` + site.ActiveDomainsSQL("s") + ` FROM sites s WHERE s.id=$1 AND s.deleted_at IS NULL`
	args := []any{siteID}
	if actor.ScopeKind == "tenant" {
		query += ` AND s.scope_id=$2`
		args = append(args, actor.ScopeID)
	}
	var revision int64
	var raw []byte
	var domains []string
	if err := s.pool.QueryRow(ctx, query, args...).Scan(&revision, &raw, &domains); errors.Is(err, pgx.ErrNoRows) {
		return State{}, ErrNotFound
	} else if err != nil {
		return State{}, fmt.Errorf("get site content rewrite: %w", err)
	}
	settings, err := decode(raw)
	if err != nil {
		return State{}, err
	}
	return State{SiteID: siteID, Version: revision, Settings: settings, Domains: domains}, nil
}

func decode(raw []byte) (contentrewrite.Settings, error) {
	if raw == nil {
		return defaults(), nil
	}
	var settings contentrewrite.Settings
	if err := json.Unmarshal(raw, &settings); err != nil {
		return contentrewrite.Settings{}, fmt.Errorf("decode site content rewrite: %w", err)
	}
	if settings.Rules == nil {
		settings.Rules = []contentrewrite.Rule{}
	}
	return settings, nil
}

func (s *Store) Update(ctx context.Context, actor Actor, request UpdateRequest) (State, error) {
	var result State
	var auditScopeID uuid.UUID
	var previous contentrewrite.Settings
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID := actor.ScopeID
		if actor.ScopeKind != "tenant" {
			if err := tx.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1`, request.SiteID).Scan(&scopeID); errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			} else if err != nil {
				return err
			}
		}
		auditScopeID = scopeID
		// Publication lock order: configuration scope before the site row.
		if _, err := tx.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
			VALUES($1,1,clock_timestamp()) ON CONFLICT(scope_id) DO NOTHING`, scopeID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`, scopeID); err != nil {
			return err
		}
		var lockedAt *time.Time
		var revision int64
		var raw []byte
		var domains []string
		if err := tx.QueryRow(ctx, `SELECT s.locked_at,s.revision,s.content_rewrite,`+site.ActiveDomainsSQL("s")+` FROM sites s
			WHERE s.id=$1 AND s.scope_id=$2 AND s.deleted_at IS NULL FOR UPDATE`, request.SiteID, scopeID).Scan(&lockedAt, &revision, &raw, &domains); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if lockedAt != nil && actor.ScopeKind == "tenant" {
			return ErrLocked
		}
		if revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		var err error
		if previous, err = decode(raw); err != nil {
			return err
		}
		var stored any
		if !request.Settings.Empty() {
			encoded, err := json.Marshal(request.Settings)
			if err != nil {
				return err
			}
			stored = string(encoded)
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		command, err := tx.Exec(ctx, `UPDATE sites SET content_rewrite=$2::jsonb,revision=revision+1,updated_by_user_id=$3,updated_at=$4
			WHERE id=$1 AND revision=$5 AND deleted_at IS NULL`, request.SiteID, stored, actor.UserID, now, request.ExpectedRevision)
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
		result = State{SiteID: request.SiteID, Version: request.ExpectedRevision + 1, Settings: request.Settings, Domains: domains}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &actor.UserID, Action: AuditAction,
			ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{
				"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "site_id": request.SiteID.String(),
				"from_version": request.ExpectedRevision, "to_version": result.Version,
				"changes": changes(previous, request.Settings), "automatic_publication": automatic,
			},
		})
	})
	if err != nil {
		if reason := deniedReason(err); reason != "" && auditScopeID != uuid.Nil {
			// The refused write rolled back; its audit event is its own transaction.
			if auditErr := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
				return s.auditor.Append(ctx, tx, audit.Event{
					ScopeID: auditScopeID, ActorUserID: &actor.UserID, Action: AuditAction,
					ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "denied",
					Payload: map[string]any{
						"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "site_id": request.SiteID.String(),
						"reason_code": reason, "expected_version": request.ExpectedRevision,
						"requested": summary(request.Settings),
					},
				})
			}); auditErr != nil {
				return State{}, fmt.Errorf("update site content rewrite: %w (audit denied write: %v)", err, auditErr)
			}
		}
		return State{}, fmt.Errorf("update site content rewrite: %w", err)
	}
	return result, nil
}

func deniedReason(err error) string {
	switch {
	case errors.Is(err, ErrLocked):
		return "site_locked"
	case errors.Is(err, ErrRevisionConflict):
		return "revision_conflict"
	}
	return ""
}

// summary is the audit form: counts, not the rule text.
func summary(settings contentrewrite.Settings) map[string]any {
	enabled := 0
	for _, rule := range settings.Rules {
		if rule.Enabled {
			enabled++
		}
	}
	return map[string]any{"rules": len(settings.Rules), "enabled": enabled, "max_bytes": settings.MaxBytes}
}

func changes(previous, next contentrewrite.Settings) map[string]any {
	before, after := summary(previous), summary(next)
	out := map[string]any{}
	for key, value := range after {
		if before[key] != value {
			out[key] = map[string]any{"from": before[key], "to": value}
		}
	}
	return out
}
