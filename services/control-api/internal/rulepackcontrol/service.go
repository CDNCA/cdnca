package rulepackcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewService(pool *pgxpool.Pool, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{pool: pool, now: func() time.Time { return now().UTC() }}
}

type querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type packRow struct {
	packID         string
	layer          string
	ownerScopeID   *uuid.UUID
	currentVersion *string
	updatePolicy   string
	updatedAt      time.Time
	compiled       *rulepack.CompiledPack
}

// loadPacks returns every usable pack (optionally only packID) with its current
// version compiled from the stored canonical bytes.
func loadPacks(ctx context.Context, q querier, packID string) ([]packRow, error) {
	rows, err := q.Query(ctx, `SELECT pack.pack_id, pack.layer, pack.owner_scope_id, pack.current_version,
		pack.update_policy, pack.updated_at, artifact.sha256, artifact.content
		FROM rule_packs pack
		LEFT JOIN rule_pack_artifacts artifact ON artifact.pack_id=pack.pack_id AND artifact.version=pack.current_version
		WHERE ($1::text='' OR pack.pack_id=$1) AND NOT EXISTS (
			-- A market pack whose plugin authorization this installation lost
			-- (ADR 0007 §9) is withdrawn: its bytes stay, it is neither listed
			-- nor enabled nor mounted, so sites using it become "待重新发布".
			SELECT 1 FROM market_data_pack_sources source
			WHERE source.kind='market_rule_pack' AND source.local_name=pack.pack_id AND source.status='withdrawn')
		ORDER BY pack.pack_id`, packID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []packRow{}
	for rows.Next() {
		var row packRow
		var sha *string
		var content []byte
		if err := rows.Scan(&row.packID, &row.layer, &row.ownerScopeID, &row.currentVersion, &row.updatePolicy,
			&row.updatedAt, &sha, &content); err != nil {
			return nil, err
		}
		if sha != nil && content != nil {
			// A sealed (encrypted, PA-14) pack is read by its public manifest
			// only: the control plane never has its rules.
			load := rulepack.Load
			if rulepack.IsSealed(content) {
				load = rulepack.OpenManifest
			}
			compiled, err := load(content, *sha)
			if err != nil {
				return nil, fmt.Errorf("stored rule pack %s does not compile: %w", row.packID, err)
			}
			row.compiled = compiled
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func loadOverrides(ctx context.Context, q querier, subject rulepack.Subject, packID string) ([]Override, error) {
	rows, err := q.Query(ctx, `SELECT level, level_object_id, pack_id, coalesce(rule_id,''), state, allow_lower,
		priority, params, updated_by_user_id, updated_at
		FROM rule_pack_enablements
		WHERE ($3::text='' OR pack_id=$3) AND (level='platform' OR
		      level='tenant' AND level_object_id=$1::uuid OR level='site' AND level_object_id=$2::uuid)
		ORDER BY pack_id, level, rule_id NULLS FIRST`, nullUUID(subject.TenantScopeID), nullUUID(subject.SiteID), packID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Override{}
	for rows.Next() {
		var row Override
		var params []byte
		if err := rows.Scan(&row.Level, &row.LevelObjectID, &row.PackID, &row.RuleID, &row.State, &row.AllowLower,
			&row.Priority, &params, &row.UpdatedBy, &row.UpdatedAt); err != nil {
			return nil, err
		}
		if params != nil {
			if err := json.Unmarshal(params, &row.Params); err != nil {
				return nil, err
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func nullUUID(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func toLibOverrides(rows []Override) []rulepack.Override {
	out := make([]rulepack.Override, 0, len(rows))
	for _, row := range rows {
		objectID := ""
		if row.LevelObjectID != nil {
			objectID = row.LevelObjectID.String()
		}
		out = append(out, rulepack.Override{Level: row.Level, ObjectID: objectID, PackID: row.PackID, RuleID: row.RuleID,
			State: row.State, AllowLower: row.AllowLower, Priority: row.Priority, Params: row.Params})
	}
	return out
}

func compiledPacks(rows []packRow) []*rulepack.CompiledPack {
	out := []*rulepack.CompiledPack{}
	for _, row := range rows {
		if row.compiled != nil {
			out = append(out, row.compiled)
		}
	}
	return out
}

// subjectFor checks that actor may see the level and returns the
// inheritance subject of it. A site's subject is its tenant scope + site.
func subjectFor(ctx context.Context, q querier, actor Actor, ref LevelInput) (rulepack.Subject, rulepack.LevelRef, error) {
	if !actor.system && (actor.UserID == uuid.Nil || actor.ScopeKind != "platform" && actor.ScopeKind != "tenant") {
		return rulepack.Subject{}, rulepack.LevelRef{}, ErrPermissionDenied
	}
	switch ref.Level {
	case rulepack.LevelPlatform:
		if ref.ObjectID != nil {
			return rulepack.Subject{}, rulepack.LevelRef{}, ErrInvalidInput
		}
		if !actor.platform() {
			return rulepack.Subject{}, rulepack.LevelRef{}, ErrPermissionDenied
		}
		return rulepack.Subject{}, rulepack.LevelRef{Level: rulepack.LevelPlatform}, nil
	case rulepack.LevelTenant:
		if ref.ObjectID == nil {
			return rulepack.Subject{}, rulepack.LevelRef{}, ErrInvalidInput
		}
		var exists bool
		if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM access_scopes WHERE id=$1 AND kind='tenant')`,
			*ref.ObjectID).Scan(&exists); err != nil {
			return rulepack.Subject{}, rulepack.LevelRef{}, err
		}
		if !exists {
			return rulepack.Subject{}, rulepack.LevelRef{}, ErrNotFound
		}
		if !actor.platform() && actor.ScopeID != *ref.ObjectID {
			return rulepack.Subject{}, rulepack.LevelRef{}, ErrPermissionDenied
		}
		return rulepack.Subject{TenantScopeID: ref.ObjectID.String()},
			rulepack.LevelRef{Level: rulepack.LevelTenant, ObjectID: ref.ObjectID.String()}, nil
	case rulepack.LevelSite:
		if ref.ObjectID == nil {
			return rulepack.Subject{}, rulepack.LevelRef{}, ErrInvalidInput
		}
		var scopeID uuid.UUID
		err := q.QueryRow(ctx, `SELECT site.scope_id FROM sites site
			JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
			WHERE site.id=$1 AND site.deleted_at IS NULL`, *ref.ObjectID).Scan(&scopeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return rulepack.Subject{}, rulepack.LevelRef{}, ErrNotFound
		}
		if err != nil {
			return rulepack.Subject{}, rulepack.LevelRef{}, err
		}
		if !actor.platform() && actor.ScopeID != scopeID {
			// Do not reveal another tenant's site.
			return rulepack.Subject{}, rulepack.LevelRef{}, ErrNotFound
		}
		return rulepack.Subject{TenantScopeID: scopeID.String(), SiteID: ref.ObjectID.String()},
			rulepack.LevelRef{Level: rulepack.LevelSite, ObjectID: ref.ObjectID.String()}, nil
	}
	return rulepack.Subject{}, rulepack.LevelRef{}, ErrInvalidInput
}

// LevelInput names a level object.
type LevelInput struct {
	Level    rulepack.Level
	ObjectID *uuid.UUID
}

// mayManagePack: platform operators manage system / developer packs; a
// tenant manages its own user packs.
func mayManagePack(actor Actor, layer string, owner *uuid.UUID) bool {
	if layer == string(rulepack.LayerUser) {
		return owner != nil && !actor.platform() && actor.ScopeID == *owner
	}
	return actor.platform()
}

func isUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}
