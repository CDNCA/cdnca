package siteschedule302

import (
	"bytes"
	"context"
	"crypto/rand"
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

// AuditAction is the audit event of a write (success, or denied with a
// reason code); changes name the settings whose value changed.
const AuditAction = "site.schedule302.update"

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
	var result State
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		query := `SELECT scope_id,revision,cardinality(http_ports)>0 FROM sites WHERE id=$1 AND deleted_at IS NULL`
		args := []any{siteID}
		if actor.ScopeKind == "tenant" {
			query += ` AND scope_id=$2`
			args = append(args, actor.ScopeID)
		}
		var scopeID uuid.UUID
		var revision int64
		var plain bool
		if err := tx.QueryRow(ctx, query, args...).Scan(&scopeID, &revision, &plain); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		settings, updatedAt, err := readSettings(ctx, tx, scopeID, siteID, false)
		if err != nil {
			return err
		}
		result = State{SiteID: siteID, Version: revision, Settings: settings, PlainHTTP: plain, UpdatedAt: updatedAt}
		return nil
	})
	if err != nil {
		return State{}, fmt.Errorf("get site schedule302: %w", err)
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
		var plain bool
		if err := tx.QueryRow(ctx, `SELECT deleted_at,locked_at,revision,cardinality(http_ports)>0 FROM sites
			WHERE id=$1 AND scope_id=$2 FOR UPDATE`, request.SiteID, scopeID).Scan(&deletedAt, &lockedAt, &revision, &plain); errors.Is(err, pgx.ErrNoRows) {
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
		if request.Settings.Enabled && !plain {
			return ErrNoPlainListener
		}
		previous, _, err := readSettings(ctx, tx, scopeID, request.SiteID, true)
		if err != nil {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		if err := writeSettings(ctx, tx, scopeID, request.SiteID, actor.UserID, request.Settings, now); err != nil {
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
		var updatedAt *time.Time
		if request.Settings.Enabled {
			updatedAt = &now
		}
		result = State{SiteID: request.SiteID, Version: request.ExpectedRevision + 1, Settings: request.Settings,
			PlainHTTP: plain, UpdatedAt: updatedAt}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &actor.UserID, Action: AuditAction,
			ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{
				"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "site_id": request.SiteID.String(),
				"from_version": request.ExpectedRevision, "to_version": result.Version,
				"changes": settingsChanges(previous, request.Settings), "enabled": request.Settings.Enabled,
				"automatic_publication": automatic,
			},
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, scopeID, request, digest, result, now)
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
				return State{}, fmt.Errorf("update site schedule302: %w (audit denied write: %v)", err, auditErr)
			}
		}
		return State{}, fmt.Errorf("update site schedule302: %w", err)
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
	case errors.Is(err, ErrNoPlainListener):
		return "schedule302_no_plain_http"
	}
	return ""
}

// summary is the audit form of settings ("off" when disabled).
func summary(settings Settings) map[string]any {
	if !settings.Enabled {
		return map[string]any{"enabled": false}
	}
	return map[string]any{
		"enabled": true, "target": settings.Target, "keep_path": settings.KeepPath, "keep_query": settings.KeepQuery,
		"signature_ttl_seconds": settings.SignatureTTLSeconds, "https_to_http": settings.HTTPSToHTTP,
		"extensions": settings.Extensions, "path_prefixes": settings.PathPrefixes, "min_size_bytes": settings.MinSizeBytes,
	}
}

// settingsChanges is the audit change summary: each changed item {"from","to"}.
func settingsChanges(previous, next Settings) map[string]any {
	before, after := summary(previous), summary(next)
	changes := map[string]any{}
	keys := map[string]bool{}
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	for key := range keys {
		fromJSON, _ := json.Marshal(before[key])
		toJSON, _ := json.Marshal(after[key])
		if !bytes.Equal(fromJSON, toJSON) {
			changes[key] = map[string]any{"from": before[key], "to": after[key]}
		}
	}
	return changes
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

func readSettings(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, lock bool) (Settings, *time.Time, error) {
	query := `SELECT target,keep_path,keep_query,signature_ttl_seconds,https_to_http,extensions,path_prefixes,
		min_size_bytes,updated_at FROM site_schedule302_settings WHERE scope_id=$1 AND site_id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	settings := Settings{Enabled: true}
	var updatedAt time.Time
	err := tx.QueryRow(ctx, query, scopeID, siteID).Scan(&settings.Target, &settings.KeepPath, &settings.KeepQuery,
		&settings.SignatureTTLSeconds, &settings.HTTPSToHTTP, &settings.Extensions, &settings.PathPrefixes,
		&settings.MinSizeBytes, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultSettings(), nil, nil
	}
	if err != nil {
		return Settings{}, nil, err
	}
	return settings, &updatedAt, nil
}

// writeSettings stores enabled settings (the signing key is generated once
// and kept while the site stays scheduled) or deletes them.
func writeSettings(ctx context.Context, tx pgx.Tx, scopeID, siteID, userID uuid.UUID, settings Settings, now time.Time) error {
	if !settings.Enabled {
		_, err := tx.Exec(ctx, `DELETE FROM site_schedule302_settings WHERE scope_id=$1 AND site_id=$2`, scopeID, siteID)
		return err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO site_schedule302_settings(scope_id,site_id,target,keep_path,keep_query,
			signature_ttl_seconds,https_to_http,extensions,path_prefixes,min_size_bytes,sign_key,updated_by_user_id,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT(site_id) DO UPDATE SET target=EXCLUDED.target,keep_path=EXCLUDED.keep_path,
			keep_query=EXCLUDED.keep_query,signature_ttl_seconds=EXCLUDED.signature_ttl_seconds,
			https_to_http=EXCLUDED.https_to_http,extensions=EXCLUDED.extensions,path_prefixes=EXCLUDED.path_prefixes,
			min_size_bytes=EXCLUDED.min_size_bytes,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
		scopeID, siteID, settings.Target, settings.KeepPath, settings.KeepQuery, settings.SignatureTTLSeconds,
		settings.HTTPSToHTTP, settings.Extensions, settings.PathPrefixes, settings.MinSizeBytes, key, userID, now)
	return err
}

func (s *Store) replay(ctx context.Context, tx pgx.Tx, actor Actor, request UpdateRequest, digest [32]byte, result *State) (bool, error) {
	var storedSiteID uuid.UUID
	var storedDigest, body []byte
	err := tx.QueryRow(ctx, `SELECT site_id,request_digest,response_body FROM site_schedule302_write_requests
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
		return false, fmt.Errorf("decode stored site schedule302 response: %w", err)
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
	command, err := tx.Exec(ctx, `INSERT INTO site_schedule302_write_requests(
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
