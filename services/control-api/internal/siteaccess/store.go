package siteaccess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type Service struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
}

func NewService(pool *pgxpool.Pool, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{pool: pool, auditor: audit.New(pool), now: now}
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && (actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

func decodePublished(raw []byte) (edgeconfig.SiteAccess, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value edgeconfig.SiteAccess
	if err := decoder.Decode(&value); err != nil || value.Empty() {
		return edgeconfig.SiteAccess{}, fmt.Errorf("decode site access settings: %v", err)
	}
	return value, nil
}

func (s *Service) Get(ctx context.Context, actor Actor, siteID uuid.UUID) (State, error) {
	if !validActor(actor) || siteID == uuid.Nil {
		return State{}, ErrInvalidInput
	}
	var result State
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		scopeID, err := targetScope(ctx, tx, actor, siteID)
		if err != nil {
			return err
		}
		site, revision, err := readSite(ctx, tx, scopeID, siteID, false)
		if err != nil {
			return err
		}
		published, updatedAt, err := readSettings(ctx, tx, scopeID, siteID, false)
		if err != nil {
			return err
		}
		result = state(siteID, revision, site, readable(published, site.status, site.exclude), updatedAt)
		if published.BasicAuth != nil {
			result.BasicAuthUsers = append([]edgeconfig.BasicAuthUser(nil), published.BasicAuth.Users...)
		}
		return nil
	})
	if err != nil {
		return State{}, fmt.Errorf("get site access: %w", err)
	}
	return result, nil
}

type siteRow struct {
	siteFacts
	locked  bool
	deleted bool
	status  int
	exclude []string
}

func state(siteID uuid.UUID, revision int64, site siteRow, settings Settings, updatedAt *time.Time) State {
	return State{SiteID: siteID, Version: revision, Settings: settings, HTTPS: site.https, ForceHTTPS: site.forceHTTPS,
		Domains: append([]string{}, site.domains...), UpdatedAt: updatedAt}
}

func readSite(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, lock bool) (siteRow, int64, error) {
	query := `SELECT site.revision,site.locked_at IS NOT NULL,site.deleted_at IS NOT NULL,
		site.https_enabled AND cardinality(site.https_ports)>0,site.force_https,
		site.https_redirect_status,site.https_redirect_exclude_hosts,
		COALESCE((SELECT array_agg(current_domain.canonical_domain ORDER BY current_domain.canonical_domain)
			FROM (SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain,fact.action
				FROM site_domain_facts fact WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
				ORDER BY fact.canonical_domain,fact.global_sequence DESC) current_domain
			WHERE current_domain.action='activate'),ARRAY[site.domain]::text[])
		FROM sites site WHERE site.id=$1 AND site.scope_id=$2`
	if lock {
		query += ` FOR UPDATE OF site`
	}
	var row siteRow
	var revision int64
	if err := tx.QueryRow(ctx, query, siteID, scopeID).Scan(&revision, &row.locked, &row.deleted, &row.https,
		&row.forceHTTPS, &row.status, &row.exclude, &row.domains); errors.Is(err, pgx.ErrNoRows) {
		return siteRow{}, 0, ErrNotFound
	} else if err != nil {
		return siteRow{}, 0, err
	}
	if row.deleted {
		return siteRow{}, 0, ErrNotFound
	}
	return row, revision, nil
}

func readSettings(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, lock bool) (edgeconfig.SiteAccess, *time.Time, error) {
	query := `SELECT settings,updated_at FROM site_access_settings WHERE scope_id=$1 AND site_id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	var raw []byte
	var updatedAt time.Time
	if err := tx.QueryRow(ctx, query, scopeID, siteID).Scan(&raw, &updatedAt); errors.Is(err, pgx.ErrNoRows) {
		return edgeconfig.SiteAccess{}, nil, nil
	} else if err != nil {
		return edgeconfig.SiteAccess{}, nil, err
	}
	value, err := decodePublished(raw)
	if err != nil {
		return edgeconfig.SiteAccess{}, nil, err
	}
	return value, &updatedAt, nil
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

// Update replaces the site's access settings; every setting off deletes the
// row. Passwords are hashed here and never stored.
func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (State, error) {
	if !validActor(actor) || request.SiteID == uuid.Nil || request.ExpectedRevision < 1 ||
		!idempotencyPattern.MatchString(request.IdempotencyKey) || strings.TrimSpace(request.RequestID) == "" {
		return State{}, ErrInvalidInput
	}
	encoded, err := json.Marshal(struct {
		SiteID   uuid.UUID                  `json:"site_id"`
		Version  int64                      `json:"expected_version"`
		Settings Settings                   `json:"settings"`
		Hashed   []edgeconfig.BasicAuthUser `json:"hashed_users,omitempty"`
	}{request.SiteID, request.ExpectedRevision, request.Settings, request.HashedUsers})
	if err != nil {
		return State{}, err
	}
	digest := sha256.Sum256(encoded)
	var result State
	var auditScopeID uuid.UUID
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID, err := targetScope(ctx, tx, actor, request.SiteID)
		if err != nil {
			return err
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
		site, revision, err := readSite(ctx, tx, scopeID, request.SiteID, true)
		if err != nil {
			return err
		}
		if replayed, err := s.replay(ctx, tx, actor, request, digest, &result); err != nil || replayed {
			return err
		}
		if site.locked && actor.ScopeKind == "tenant" {
			return ErrLocked
		}
		if revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		previous, _, err := readSettings(ctx, tx, scopeID, request.SiteID, true)
		if err != nil {
			return err
		}
		stored := map[string]edgeconfig.BasicAuthUser{}
		if previous.BasicAuth != nil {
			for _, user := range previous.BasicAuth.Users {
				stored[user.Username] = user
			}
		}
		published, settings, err := normalizeHashed(request.Settings, site.siteFacts, stored, request.HashedUsers)
		if err != nil {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		if published.Empty() {
			if _, err := tx.Exec(ctx, `DELETE FROM site_access_settings WHERE scope_id=$1 AND site_id=$2`, scopeID, request.SiteID); err != nil {
				return err
			}
		} else {
			document, err := json.Marshal(published)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_access_settings(scope_id,site_id,settings,updated_by_user_id,updated_at)
				VALUES($1,$2,$3,$4,$5) ON CONFLICT(site_id) DO UPDATE SET settings=EXCLUDED.settings,
				updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
				scopeID, request.SiteID, string(document), actor.UserID, now); err != nil {
				return err
			}
		}
		command, err := tx.Exec(ctx, `UPDATE sites SET revision=revision+1,updated_by_user_id=$2,updated_at=$3,
			https_redirect_status=$5,https_redirect_exclude_hosts=$6
			WHERE id=$1 AND revision=$4 AND deleted_at IS NULL`, request.SiteID, actor.UserID, now, request.ExpectedRevision,
			settings.ForceHTTPS.Status, settings.ForceHTTPS.ExcludeHosts)
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
		if !published.Empty() {
			updatedAt = &now
		}
		result = state(request.SiteID, request.ExpectedRevision+1, site, settings, updatedAt)
		before := summary(readable(previous, site.status, site.exclude))
		after := summary(settings)
		changes := map[string]any{}
		for key, to := range after {
			if fmt.Sprint(before[key]) != fmt.Sprint(to) {
				changes[key] = map[string]any{"from": before[key], "to": to}
			}
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &actor.UserID, Action: AuditAction,
			ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{
				"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "site_id": request.SiteID.String(),
				"site_domain": site.domains[0], "from_version": request.ExpectedRevision, "to_version": result.Version,
				"changes": changes, "automatic_publication": automatic,
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
					ScopeID: auditScopeID, ActorUserID: &actor.UserID, Action: AuditAction,
					ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "denied",
					Payload: map[string]any{"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind,
						"site_id": request.SiteID.String(), "reason_code": reason, "expected_version": request.ExpectedRevision},
				})
			}); auditErr != nil {
				return State{}, fmt.Errorf("update site access: %w (audit denied write: %v)", err, auditErr)
			}
		}
		return State{}, fmt.Errorf("update site access: %w", err)
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
	case errors.Is(err, ErrNeedsHTTPS):
		return "https_required"
	case errors.Is(err, ErrInvalidInput):
		return "invalid_settings"
	}
	return ""
}

func (s *Service) replay(ctx context.Context, tx pgx.Tx, actor Actor, request UpdateRequest, digest [32]byte, result *State) (bool, error) {
	var storedSiteID uuid.UUID
	var storedDigest, body []byte
	err := tx.QueryRow(ctx, `SELECT site_id,request_digest,response_body FROM site_access_write_requests
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
		return false, fmt.Errorf("decode stored site access response: %w", err)
	}
	return true, nil
}

func (s *Service) completeWrite(ctx context.Context, tx pgx.Tx, actor Actor, scopeID uuid.UUID, request UpdateRequest,
	digest [32]byte, result State, now time.Time) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `INSERT INTO site_access_write_requests(
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
