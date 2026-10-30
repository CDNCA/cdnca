package securityban

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
	// changed is called after a committed write (the distributor's Wake).
	changed func()
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, auditor: audit.New(pool), now: now}
}

// OnChange registers a callback run after every committed ban list change.
func (s *Store) OnChange(callback func()) { s.changed = callback }

func (s *Store) notify() {
	if s.changed != nil {
		s.changed()
	}
}

const entryColumns = `entry.id,entry.tenant_scope_id,entry.site_id,site.domain,entry.client_ip,entry.source,entry.rule_id,
	entry.reason,entry.banned_at,entry.banned_until,entry.created_by,entry.released_at,entry.released_by`

func scanEntry(row pgx.Row, now time.Time) (Entry, error) {
	var entry Entry
	var client netip.Prefix
	if err := row.Scan(&entry.ID, &entry.TenantScopeID, &entry.SiteID, &entry.SiteDomain, &client, &entry.Source,
		&entry.RuleID, &entry.Reason, &entry.BannedAt, &entry.BannedUntil, &entry.CreatedBy, &entry.ReleasedAt,
		&entry.ReleasedBy); err != nil {
		return Entry{}, err
	}
	entry.ClientIP = clientText(client)
	entry.BannedAt, entry.BannedUntil = entry.BannedAt.UTC(), entry.BannedUntil.UTC()
	if entry.ReleasedAt != nil {
		released := entry.ReleasedAt.UTC()
		entry.ReleasedAt = &released
	}
	entry.State = entryState(entry, now)
	return entry, nil
}

// List returns bans newest first; a tenant actor sees only its scope.
func (s *Store) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	now := s.now().UTC()
	where := `site.deleted_at IS NULL AND $1::timestamptz IS NOT NULL`
	args := []any{now}
	add := func(clause string, value any) {
		args = append(args, value)
		where += fmt.Sprintf(" AND "+clause, len(args))
	}
	if actor.ScopeKind == "tenant" {
		add("entry.tenant_scope_id=$%d", actor.ScopeID)
	}
	if filter.SiteID != nil {
		add("entry.site_id=$%d", *filter.SiteID)
	}
	if filter.ClientIP != "" {
		client, ok := canonicalClient(filter.ClientIP)
		if !ok {
			return ListResult{}, ErrInvalidInput
		}
		add("entry.client_ip=$%d", client)
	}
	switch filter.State {
	case "":
	case StateActive:
		where += ` AND entry.released_at IS NULL AND entry.banned_until > $1`
	case StateReleased:
		where += ` AND entry.released_at IS NOT NULL`
	case StateExpired:
		where += ` AND entry.released_at IS NULL AND entry.banned_until <= $1`
	default:
		return ListResult{}, ErrInvalidInput
	}
	result := ListResult{Items: []Entry{}, Page: filter.Page, Limit: filter.Limit}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if filter.SiteID != nil {
			if _, _, err := siteScope(ctx, tx, actor, *filter.SiteID, false); err != nil {
				return err
			}
		}
		from := ` FROM security_ban_entries entry JOIN sites site ON site.id=entry.site_id WHERE ` + where
		if err := tx.QueryRow(ctx, `SELECT count(*) `+from, args...).Scan(&result.Total); err != nil {
			return err
		}
		pageArgs := append(append([]any{}, args...), filter.Limit, (filter.Page-1)*filter.Limit)
		rows, err := tx.Query(ctx, `SELECT `+entryColumns+from+fmt.Sprintf(` ORDER BY entry.banned_at DESC, entry.id LIMIT $%d OFFSET $%d`,
			len(args)+1, len(args)+2), pageArgs...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			entry, err := scanEntry(rows, now)
			if err != nil {
				return err
			}
			result.Items = append(result.Items, entry)
		}
		return rows.Err()
	})
	if err != nil {
		return ListResult{}, fmt.Errorf("list security bans: %w", err)
	}
	return result, nil
}

// siteScope resolves the live site the actor reaches: its tenant scope and
// domain. A tenant actor never sees another scope's site (not found).
func siteScope(ctx context.Context, tx pgx.Tx, actor Actor, siteID uuid.UUID, lock bool) (uuid.UUID, string, error) {
	query := `SELECT site.scope_id,site.domain FROM sites site JOIN access_scopes scope ON scope.id=site.scope_id
		WHERE site.id=$1 AND site.deleted_at IS NULL AND scope.kind='tenant'`
	args := []any{siteID}
	if actor.ScopeKind == "tenant" {
		query += ` AND site.scope_id=$2`
		args = append(args, actor.ScopeID)
	}
	if lock {
		query += ` FOR SHARE OF site`
	}
	var scopeID uuid.UUID
	var domain string
	if err := tx.QueryRow(ctx, query, args...).Scan(&scopeID, &domain); errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", ErrSiteNotFound
	} else if err != nil {
		return uuid.Nil, "", err
	}
	return scopeID, domain, nil
}

// lockClient serializes writers of one (site, client): at most one active
// row exists per pair.
func lockClient(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, client netip.Prefix) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-ban/'||$1::text||'/'||$2::text, 0))`,
		siteID, client.String())
	return err
}

func activeEntryID(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, client netip.Prefix, now time.Time) (uuid.UUID, time.Time, bool, error) {
	var id uuid.UUID
	var until time.Time
	err := tx.QueryRow(ctx, `SELECT id,banned_until FROM security_ban_entries
		WHERE site_id=$1 AND client_ip=$2 AND released_at IS NULL AND banned_until > $3
		ORDER BY banned_at DESC LIMIT 1 FOR UPDATE`, siteID, client, now).Scan(&id, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, time.Time{}, false, nil
	}
	return id, until, err == nil, err
}

func (s *Store) audit(ctx context.Context, tx pgx.Tx, event audit.Event) error {
	return s.auditor.Append(ctx, tx, event)
}

// auditDenied writes a refused write's audit event in its own transaction
// (the write rolled back).
func (s *Store) auditDenied(ctx context.Context, event audit.Event) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return s.auditor.Append(ctx, tx, event) })
}

// Create adds a manual ban. A client already banned on the site is refused
// (ErrAlreadyBanned): the operator releases or waits, never silently extends.
func (s *Store) Create(ctx context.Context, actor Actor, request CreateRequest, prefix netip.Prefix) (Entry, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	client := clientText(prefix)
	var result Entry
	var scopeID uuid.UUID
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var domain string
		var err error
		if scopeID, domain, err = siteScope(ctx, tx, actor, request.SiteID, true); err != nil {
			return err
		}
		if err := lockClient(ctx, tx, request.SiteID, prefix); err != nil {
			return err
		}
		if replayed, err := s.replayCreate(ctx, tx, actor, request, prefix, now, &result); err != nil || replayed {
			return err
		}
		if _, _, active, err := activeEntryID(ctx, tx, request.SiteID, prefix, now); err != nil {
			return err
		} else if active {
			return ErrAlreadyBanned
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_ban_entries WHERE site_id=$1 AND released_at IS NULL
			AND banned_until > $2`, request.SiteID, now).Scan(&count); err != nil {
			return err
		}
		if count >= MaxActivePerSite {
			return ErrLimitExceeded
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		until := now.Add(time.Duration(request.DurationSecond) * time.Second)
		if _, err := tx.Exec(ctx, `INSERT INTO security_ban_entries(id,tenant_scope_id,site_id,client_ip,source,reason,
			banned_at,banned_until,created_by) VALUES($1,$2,$3,$4,'manual',$5,$6,$7,$8)`,
			id, scopeID, request.SiteID, prefix, request.Reason, now, until, actor.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_ban_write_requests(actor_scope_id,actor_user_id,idempotency_key,entry_id,created_at)
			VALUES($1,$2,$3,$4,$5)`, actor.ScopeID, actor.UserID, request.IdempotencyKey, id, now); err != nil {
			return err
		}
		createdBy := actor.UserID
		result = Entry{ID: id, TenantScopeID: scopeID, SiteID: request.SiteID, SiteDomain: domain, ClientIP: client,
			Source: SourceManual, Reason: request.Reason, BannedAt: now, BannedUntil: until, CreatedBy: &createdBy, State: StateActive}
		return s.audit(ctx, tx, audit.Event{ScopeID: scopeID, ActorUserID: &actor.UserID, Action: AuditCreate,
			ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "entry_id": id.String(),
				"site_id": request.SiteID.String(), "client_ip": client, "source": SourceManual,
				"duration_seconds": request.DurationSecond, "banned_until": until.Format(time.RFC3339), "reason": request.Reason}})
	})
	if err != nil {
		if reason := deniedReason(err); reason != "" && scopeID != uuid.Nil {
			if auditErr := s.auditDenied(ctx, audit.Event{ScopeID: scopeID, ActorUserID: &actor.UserID, Action: AuditCreate,
				ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "denied",
				Payload: map[string]any{"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "site_id": request.SiteID.String(),
					"client_ip": client, "reason_code": reason}}); auditErr != nil {
				return Entry{}, fmt.Errorf("create security ban: %w (audit denied write: %v)", err, auditErr)
			}
		}
		return Entry{}, fmt.Errorf("create security ban: %w", err)
	}
	s.notify()
	return result, nil
}

// replayCreate answers a repeated create with the same key: the stored
// entry when it is the same ban, ErrIdempotencyKey otherwise.
func (s *Store) replayCreate(ctx context.Context, tx pgx.Tx, actor Actor, request CreateRequest, client netip.Prefix,
	now time.Time, result *Entry) (bool, error) {
	var entryID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT entry_id FROM security_ban_write_requests
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3`, actor.ScopeID, actor.UserID,
		request.IdempotencyKey).Scan(&entryID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	entry, err := scanEntry(tx.QueryRow(ctx, `SELECT `+entryColumns+` FROM security_ban_entries entry
		JOIN sites site ON site.id=entry.site_id WHERE entry.id=$1`, entryID), now)
	if err != nil {
		return false, err
	}
	if entry.SiteID != request.SiteID || entry.ClientIP != clientText(client) || entry.Reason != request.Reason ||
		entry.BannedUntil.Sub(entry.BannedAt) != time.Duration(request.DurationSecond)*time.Second {
		return false, ErrIdempotencyKey
	}
	*result = entry
	return true, nil
}

// Release lifts an active ban (manual or automatic). Releasing a ban that is
// released or expired is ErrNotActive.
func (s *Store) Release(ctx context.Context, actor Actor, request ReleaseRequest) (Entry, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	var result Entry
	var scopeID, siteID uuid.UUID
	var client string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		query := `SELECT ` + entryColumns + ` FROM security_ban_entries entry JOIN sites site ON site.id=entry.site_id
			WHERE entry.id=$2 AND site.deleted_at IS NULL AND $1::timestamptz IS NOT NULL`
		args := []any{now, request.EntryID}
		if actor.ScopeKind == "tenant" {
			query += ` AND entry.tenant_scope_id=$3`
			args = append(args, actor.ScopeID)
		}
		entry, err := scanEntry(tx.QueryRow(ctx, query, args...), now)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		scopeID, siteID, client = entry.TenantScopeID, entry.SiteID, entry.ClientIP
		prefix, _ := clientPrefix(entry.ClientIP)
		if err := lockClient(ctx, tx, entry.SiteID, prefix); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE security_ban_entries SET released_at=$2,released_by=$3
			WHERE id=$1 AND released_at IS NULL AND banned_until > $2`, entry.ID, now, actor.UserID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrNotActive
		}
		released, by := now, actor.UserID
		entry.ReleasedAt, entry.ReleasedBy, entry.State = &released, &by, StateReleased
		result = entry
		return s.audit(ctx, tx, audit.Event{ScopeID: scopeID, ActorUserID: &actor.UserID, Action: AuditRelease,
			ResourceType: "site", ResourceID: entry.SiteID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "entry_id": entry.ID.String(),
				"site_id": entry.SiteID.String(), "client_ip": entry.ClientIP, "source": entry.Source,
				"banned_until": entry.BannedUntil.Format(time.RFC3339)}})
	})
	if err != nil {
		if errors.Is(err, ErrNotActive) && scopeID != uuid.Nil {
			if auditErr := s.auditDenied(ctx, audit.Event{ScopeID: scopeID, ActorUserID: &actor.UserID, Action: AuditRelease,
				ResourceType: "site", ResourceID: siteID.String(), RequestID: request.RequestID, Result: "denied",
				Payload: map[string]any{"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "entry_id": request.EntryID.String(),
					"site_id": siteID.String(), "client_ip": client, "reason_code": "not_active"}}); auditErr != nil {
				return Entry{}, fmt.Errorf("release security ban: %w (audit denied write: %v)", err, auditErr)
			}
		}
		return Entry{}, fmt.Errorf("release security ban: %w", err)
	}
	s.notify()
	return result, nil
}

func deniedReason(err error) string {
	switch {
	case errors.Is(err, ErrAlreadyBanned):
		return "already_banned"
	case errors.Is(err, ErrLimitExceeded):
		return "limit_exceeded"
	case errors.Is(err, ErrIdempotencyKey):
		return "idempotency_conflict"
	}
	return ""
}
