// Package domainblocklist is the platform domain blocklist (v6.1.0 #11):
// administrators maintain root patterns (the domain and every subdomain) and
// exact patterns, site writes refuse hits (domaintrust.CheckSiteDomainsTx),
// and existing sites that a pattern covers are listed for one-click disable
// through the regular site batch action.
package domainblocklist

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidInput        = domaintrust.ErrInvalidInput
	ErrNotFound            = domaintrust.ErrNotFound
	ErrConflict            = domaintrust.ErrConflict
	ErrRevisionConflict    = domaintrust.ErrRevisionConflict
	ErrIdempotencyConflict = domaintrust.ErrIdempotencyConflict
	ErrPermissionDenied    = domaintrust.ErrPermissionDenied
)

const (
	MatchRoot      = "root"
	MatchExact     = "exact"
	maxImportItems = 5000
	maxListLimit   = 500
	maxHits        = 1000
	maxReasonRunes = 512
)

type Actor struct {
	UserID, ScopeID uuid.UUID
	ScopeKind       string
}

type Entry struct {
	ID        uuid.UUID `json:"id"`
	Pattern   string    `json:"pattern"`
	MatchType string    `json:"match_type"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Revision  int64     `json:"revision"`
}

type Input struct {
	Pattern   string `json:"pattern"`
	MatchType string `json:"match_type"`
	Reason    string `json:"reason"`
}

// Hit is an existing site a blocklist entry covers.
type Hit struct {
	SiteID      uuid.UUID `json:"site_id"`
	ScopeID     uuid.UUID `json:"scope_id"`
	DisplayID   int64     `json:"display_id"`
	Domain      string    `json:"domain"`
	Pattern     string    `json:"pattern"`
	Enabled     bool      `json:"enabled"`
	Revision    int64     `json:"revision"`
	OwnerUserID uuid.UUID `json:"owner_user_id"`
}

type ImportResult struct {
	Created  int  `json:"created"`
	Updated  int  `json:"updated"`
	Replayed bool `json:"-"`
}

type Service struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
}

func NewService(pool *pgxpool.Pool, now func() time.Time) (*Service, error) {
	if pool == nil {
		return nil, ErrInvalidInput
	}
	if now == nil {
		now = time.Now
	}
	return &Service{pool: pool, auditor: audit.New(pool), now: now}, nil
}

func (s *Service) clock() time.Time { return s.now().UTC().Truncate(time.Microsecond) }

func normalizeInput(input Input) (Input, error) {
	input.MatchType = strings.TrimSpace(input.MatchType)
	if input.MatchType == "" {
		input.MatchType = MatchRoot
	}
	pattern, err := domaintrust.Normalize(input.Pattern, false)
	if err != nil || input.MatchType != MatchRoot && input.MatchType != MatchExact {
		return Input{}, ErrInvalidInput
	}
	input.Pattern = pattern
	input.Reason = strings.TrimSpace(input.Reason)
	if !utf8.ValidString(input.Reason) || utf8.RuneCountInString(input.Reason) > maxReasonRunes ||
		strings.ContainsFunc(input.Reason, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return Input{}, ErrInvalidInput
	}
	return input, nil
}

func authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != "platform" {
		return ErrPermissionDenied
	}
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM access_scopes scope
			JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=$2
			JOIN users account ON account.id=membership.user_id
			WHERE scope.id=$1 AND scope.kind='platform' AND scope.tenant_id IS NULL AND
			      membership.status='active' AND account.status='active'
		) AND EXISTS(
			SELECT 1 FROM role_assignments assignment
			JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
			JOIN role_permissions grant_row ON grant_row.role_id=role.id
			WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND
			      grant_row.permission_name IN ($3,'platform.admin'))`,
		actor.ScopeID, actor.UserID, permission).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

const entryColumns = `id,pattern,match_type,reason,created_at,updated_at,revision`

func scanEntry(row pgx.Row) (Entry, error) {
	var item Entry
	err := row.Scan(&item.ID, &item.Pattern, &item.MatchType, &item.Reason, &item.CreatedAt, &item.UpdatedAt, &item.Revision)
	return item, err
}

// List returns entries matching the optional search, newest first.
func (s *Service) List(ctx context.Context, actor Actor, search string, limit int) ([]Entry, error) {
	if limit < 1 || limit > maxListLimit {
		limit = maxListLimit
	}
	search = strings.ToLower(strings.TrimSpace(search))
	if len(search) > 253 {
		return nil, ErrInvalidInput
	}
	items := make([]Entry, 0)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, domainSecurityPermission); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+entryColumns+` FROM platform_domain_blocklist
			WHERE $1='' OR strpos(pattern,$1)>0 ORDER BY created_at DESC, id DESC LIMIT $2`, search, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanEntry(rows)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list domain blocklist: %w", err)
	}
	return items, nil
}

const domainSecurityPermission = "domains.security.manage"

func (s *Service) write(ctx context.Context, actor Actor, operation, key, requestID string, digestInput any,
	replay any, run func(pgx.Tx, time.Time) (any, error)) (bool, error) {
	if !domaintrust.ValidMetadata(key) || !domaintrust.ValidMetadata(requestID) {
		return false, ErrInvalidInput
	}
	digest, err := domaintrust.Digest(digestInput)
	if err != nil {
		return false, err
	}
	write := domaintrust.Write{ActorUserID: actor.UserID, ActorScopeID: actor.ScopeID,
		Operation: operation, Key: key, Digest: digest}
	replayed := false
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, domainSecurityPermission); err != nil {
			return err
		}
		now := s.clock()
		found, err := domaintrust.ClaimWrite(ctx, tx, write, now, replay)
		if err != nil || found {
			replayed = found
			return err
		}
		response, err := run(tx, now)
		if err != nil {
			return err
		}
		return domaintrust.CompleteWrite(ctx, tx, write, 200, response, now)
	})
	return replayed, err
}

func (s *Service) audit(ctx context.Context, tx pgx.Tx, actor Actor, action, resourceID, requestID string, payload map[string]any) error {
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: action, ResourceType: "platform_domain_blocklist",
		ResourceID: resourceID, RequestID: requestID, Result: "success", Payload: payload,
	})
}

func uniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (s *Service) Create(ctx context.Context, actor Actor, input Input, key, requestID string) (Entry, error) {
	input, err := normalizeInput(input)
	if err != nil {
		return Entry{}, err
	}
	var result Entry
	_, err = s.write(ctx, actor, "domain_blocklist.create", key, requestID, input, &result,
		func(tx pgx.Tx, now time.Time) (any, error) {
			item, err := scanEntry(tx.QueryRow(ctx, `INSERT INTO platform_domain_blocklist(
				id,pattern,match_type,reason,created_by_user_id,updated_by_user_id,created_at,updated_at
			) VALUES($1,$2,$3,$4,$5,$5,$6,$6) RETURNING `+entryColumns,
				uuid.New(), input.Pattern, input.MatchType, input.Reason, actor.UserID, now))
			if uniqueViolation(err) {
				return nil, ErrConflict
			}
			if err != nil {
				return nil, err
			}
			result = item
			return item, s.audit(ctx, tx, actor, "domain_blocklist.create", item.ID.String(), requestID,
				map[string]any{"pattern": item.Pattern, "match_type": item.MatchType})
		})
	if err != nil {
		return Entry{}, fmt.Errorf("create domain blocklist entry: %w", err)
	}
	return result, nil
}

func (s *Service) Update(ctx context.Context, actor Actor, id uuid.UUID, expectedRevision int64, input Input, key, requestID string) (Entry, error) {
	input, err := normalizeInput(input)
	if err != nil || id == uuid.Nil || expectedRevision < 1 {
		return Entry{}, ErrInvalidInput
	}
	var result Entry
	_, err = s.write(ctx, actor, "domain_blocklist.update", key, requestID, struct {
		ID       uuid.UUID `json:"id"`
		Revision int64     `json:"expected_revision"`
		Input    Input     `json:"input"`
	}{id, expectedRevision, input}, &result, func(tx pgx.Tx, now time.Time) (any, error) {
		item, err := scanEntry(tx.QueryRow(ctx, `UPDATE platform_domain_blocklist SET pattern=$3,match_type=$4,
			reason=$5,updated_by_user_id=$6,updated_at=$7,revision=revision+1 WHERE id=$1 AND revision=$2
			RETURNING `+entryColumns, id, expectedRevision, input.Pattern, input.MatchType, input.Reason, actor.UserID, now))
		if errors.Is(err, pgx.ErrNoRows) {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform_domain_blocklist WHERE id=$1)`, id).Scan(&exists); err != nil {
				return nil, err
			}
			if exists {
				return nil, ErrRevisionConflict
			}
			return nil, ErrNotFound
		}
		if uniqueViolation(err) {
			return nil, ErrConflict
		}
		if err != nil {
			return nil, err
		}
		result = item
		return item, s.audit(ctx, tx, actor, "domain_blocklist.update", id.String(), requestID,
			map[string]any{"pattern": item.Pattern, "match_type": item.MatchType, "version": item.Revision})
	})
	if err != nil {
		return Entry{}, fmt.Errorf("update domain blocklist entry: %w", err)
	}
	return result, nil
}

func (s *Service) Delete(ctx context.Context, actor Actor, id uuid.UUID, expectedRevision int64, key, requestID string) error {
	if id == uuid.Nil || expectedRevision < 1 {
		return ErrInvalidInput
	}
	var replay struct {
		Deleted bool `json:"deleted"`
	}
	_, err := s.write(ctx, actor, "domain_blocklist.delete", key, requestID, struct {
		ID       uuid.UUID `json:"id"`
		Revision int64     `json:"expected_revision"`
	}{id, expectedRevision}, &replay, func(tx pgx.Tx, now time.Time) (any, error) {
		var pattern string
		err := tx.QueryRow(ctx, `DELETE FROM platform_domain_blocklist WHERE id=$1 AND revision=$2 RETURNING pattern`,
			id, expectedRevision).Scan(&pattern)
		if errors.Is(err, pgx.ErrNoRows) {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform_domain_blocklist WHERE id=$1)`, id).Scan(&exists); err != nil {
				return nil, err
			}
			if exists {
				return nil, ErrRevisionConflict
			}
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		return map[string]bool{"deleted": true}, s.audit(ctx, tx, actor, "domain_blocklist.delete", id.String(),
			requestID, map[string]any{"pattern": pattern})
	})
	if err != nil {
		return fmt.Errorf("delete domain blocklist entry: %w", err)
	}
	return nil
}

// Import upserts many entries at once (pattern is the key).
func (s *Service) Import(ctx context.Context, actor Actor, inputs []Input, key, requestID string) (ImportResult, error) {
	if len(inputs) < 1 || len(inputs) > maxImportItems {
		return ImportResult{}, ErrInvalidInput
	}
	normalized := make([]Input, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		item, err := normalizeInput(input)
		if err != nil {
			return ImportResult{}, err
		}
		if _, duplicate := seen[item.Pattern]; duplicate {
			continue
		}
		seen[item.Pattern] = struct{}{}
		normalized = append(normalized, item)
	}
	var result ImportResult
	replayed, err := s.write(ctx, actor, "domain_blocklist.import", key, requestID, normalized, &result,
		func(tx pgx.Tx, now time.Time) (any, error) {
			for _, input := range normalized {
				var inserted bool
				if err := tx.QueryRow(ctx, `INSERT INTO platform_domain_blocklist(
					id,pattern,match_type,reason,created_by_user_id,updated_by_user_id,created_at,updated_at
				) VALUES($1,$2,$3,$4,$5,$5,$6,$6)
				ON CONFLICT (pattern) DO UPDATE SET match_type=EXCLUDED.match_type,reason=EXCLUDED.reason,
					updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at,
					revision=platform_domain_blocklist.revision+1
				RETURNING (xmax=0)`, uuid.New(), input.Pattern, input.MatchType, input.Reason, actor.UserID, now).
					Scan(&inserted); err != nil {
					return nil, err
				}
				if inserted {
					result.Created++
				} else {
					result.Updated++
				}
			}
			return result, s.audit(ctx, tx, actor, "domain_blocklist.import", actor.ScopeID.String(), requestID,
				map[string]any{"created": result.Created, "updated": result.Updated})
		})
	if err != nil {
		return ImportResult{}, fmt.Errorf("import domain blocklist: %w", err)
	}
	result.Replayed = replayed
	return result, nil
}

// Hits lists existing sites (enabled or not, not deleted) that the entry, or
// every entry when id is nil, covers.
func (s *Service) Hits(ctx context.Context, actor Actor, id uuid.UUID) ([]Hit, error) {
	hits := make([]Hit, 0)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, domainSecurityPermission); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT ON (site.id) site.id, site.scope_id, site.display_id, active.canonical_domain,
			       entry.pattern, site.enabled, site.revision, site.owner_user_id
			FROM platform_domain_blocklist entry
			JOIN site_domain_active active ON
			     (entry.match_type='exact' AND active.canonical_domain=entry.pattern) OR
			     (entry.match_type='root' AND (
			         regexp_replace(active.canonical_domain,'^\*\.','')=entry.pattern OR
			         regexp_replace(active.canonical_domain,'^\*\.','') LIKE '%.' || entry.pattern))
			JOIN sites site ON site.scope_id=active.scope_id AND site.id=active.site_id AND site.deleted_at IS NULL
			WHERE $1::uuid IS NULL OR entry.id=$1
			ORDER BY site.id, active.canonical_domain LIMIT $2`, nullableUUID(id), maxHits)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var hit Hit
			if err := rows.Scan(&hit.SiteID, &hit.ScopeID, &hit.DisplayID, &hit.Domain, &hit.Pattern,
				&hit.Enabled, &hit.Revision, &hit.OwnerUserID); err != nil {
				return err
			}
			hits = append(hits, hit)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list domain blocklist hits: %w", err)
	}
	return hits, nil
}

func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}
