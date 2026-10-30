package marketsubscribehttp

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the BuyerStore and AdvisorySync storage over migration 296.
type PostgresStore struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool, now: func() time.Time { return time.Now().UTC() }}
}

// Advisories lists published advisories, newest first, with this scope's
// acknowledgement (nil when not yet acknowledged).
func (s *PostgresStore) Advisories(ctx context.Context, scope uuid.UUID, pluginID string) ([]Advisory, error) {
	rows, err := s.pool.Query(ctx, `SELECT a.id, a.plugin_id, a.affected_versions, a.fixed_version, a.severity, a.action,
			a.title, a.body, a.published_at, k.disposition, k.note, k.acknowledged_by, k.acknowledged_at
		FROM plugin_security_advisories a
		LEFT JOIN plugin_security_advisory_acks k ON k.advisory_id = a.id AND k.scope_id = $1
		WHERE a.status = 'published' AND ($2 = '' OR a.plugin_id = $2)
		ORDER BY a.published_at DESC, a.id LIMIT 200`, scope, pluginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Advisory{}
	for rows.Next() {
		var a Advisory
		var disposition, note *string
		var by *uuid.UUID
		var at *time.Time
		if err := rows.Scan(&a.ID, &a.PluginID, &a.AffectedVersions, &a.FixedVersion, &a.Severity, &a.Action,
			&a.Title, &a.Body, &a.PublishedAt, &disposition, &note, &by, &at); err != nil {
			return nil, err
		}
		if disposition != nil {
			a.Acknowledgement = &Acknowledgement{Disposition: *disposition, Note: *note, AcknowledgedBy: *by, AcknowledgedAt: *at}
		}
		items = append(items, a)
	}
	return items, rows.Err()
}

// Acknowledge records the scope's acknowledgement once; a repeat returns the
// first one unchanged.
func (s *PostgresStore) Acknowledge(ctx context.Context, scope, advisory, user uuid.UUID, disposition, note string) (Acknowledgement, error) {
	var published bool
	err := s.pool.QueryRow(ctx, `SELECT status = 'published' FROM plugin_security_advisories WHERE id = $1`, advisory).Scan(&published)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !published {
		return Acknowledgement{}, ErrStoreNotFound
	}
	if err != nil {
		return Acknowledgement{}, err
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO plugin_security_advisory_acks(advisory_id, scope_id, acknowledged_by, disposition, note, acknowledged_at)
		VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (advisory_id, scope_id) DO NOTHING`,
		advisory, scope, user, disposition, note, s.now()); err != nil {
		return Acknowledgement{}, mapPG(err)
	}
	var ack Acknowledgement
	err = s.pool.QueryRow(ctx, `SELECT disposition, note, acknowledged_by, acknowledged_at FROM plugin_security_advisory_acks
		WHERE advisory_id = $1 AND scope_id = $2`, advisory, scope).Scan(&ack.Disposition, &ack.Note, &ack.AcknowledgedBy, &ack.AcknowledgedAt)
	return ack, err
}

// ReplaceDelivered makes the published set exactly what the license service
// delivered: delivered advisories are upserted as published, published ones
// it no longer delivers become withdrawn (their acknowledgements stay).
func (s *PostgresStore) ReplaceDelivered(ctx context.Context, delivered []Advisory) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := s.now()
	ids := make([]uuid.UUID, 0, len(delivered))
	for _, a := range delivered {
		ids = append(ids, a.ID)
		if _, err := tx.Exec(ctx, `INSERT INTO plugin_security_advisories(id, plugin_id, affected_versions, fixed_version, severity,
				action, title, body, status, published_at, received_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'published', $9, $10, $10)
			ON CONFLICT (id) DO UPDATE SET plugin_id = EXCLUDED.plugin_id, affected_versions = EXCLUDED.affected_versions,
				fixed_version = EXCLUDED.fixed_version, severity = EXCLUDED.severity, action = EXCLUDED.action,
				title = EXCLUDED.title, body = EXCLUDED.body, status = 'published', published_at = EXCLUDED.published_at,
				updated_at = GREATEST(plugin_security_advisories.updated_at, EXCLUDED.updated_at)`,
			a.ID, a.PluginID, a.AffectedVersions, a.FixedVersion, a.Severity, a.Action, a.Title, a.Body, a.PublishedAt, now); err != nil {
			return mapPG(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE plugin_security_advisories SET status = 'withdrawn', updated_at = GREATEST(updated_at, $2)
		WHERE status = 'published' AND NOT (id = ANY($1))`, ids, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UnreportedPlatformAcks lists platform-scope acknowledgements not yet sent
// to the license service (the installation acknowledges as a whole).
func (s *PostgresStore) UnreportedPlatformAcks(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `SELECT k.advisory_id FROM plugin_security_advisory_acks k
		JOIN access_scopes scope ON scope.id = k.scope_id AND scope.kind = 'platform'
		WHERE k.reported_at IS NULL ORDER BY k.acknowledged_at, k.advisory_id LIMIT 100`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

func (s *PostgresStore) MarkReported(ctx context.Context, advisory uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE plugin_security_advisory_acks k SET reported_at = GREATEST($2, k.acknowledged_at)
		FROM access_scopes scope WHERE scope.id = k.scope_id AND scope.kind = 'platform'
		AND k.advisory_id = $1 AND k.reported_at IS NULL`, advisory, s.now())
	return err
}

func mapPG(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23514" || pgErr.Code == "23503" || pgErr.Code == "22P02") {
		return ErrStoreInvalid
	}
	return err
}

// Library is the per-plugin local state across tenants (migrations 145, 372,
// 386, 397): installation heads, and artifacts the platform withdrew. Only heads
// of the installation the current verified catalog was signed for count: a head
// kept from an earlier installation (migration/restore) is neither installed nor
// enabled here; with no applied catalog no head counts.
func (s *PostgresStore) Library(ctx context.Context) ([]LibraryItem, error) {
	target, err := artifactsync.VerifiedCatalogInstallation(ctx, s.pool)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `WITH artifacts AS (
			SELECT plugin_id, status FROM market_data_pack_sources
			UNION ALL SELECT plugin_id, status FROM plugin_ui_pages
			UNION ALL SELECT plugin_id, status FROM plugin_providers),
		heads AS (SELECT plugin_id, bool_or(status = 'enabled') AS enabled FROM plugin_installation_heads
			WHERE status <> 'uninstalled' AND installation_id = $1::uuid GROUP BY plugin_id)
		SELECT p.plugin_id, h.plugin_id IS NOT NULL, COALESCE(h.enabled, false),
			COALESCE((SELECT bool_or(a.status = 'withdrawn') AND NOT bool_or(a.status = 'active') FROM artifacts a
				WHERE a.plugin_id = p.plugin_id), false)
		FROM (SELECT plugin_id FROM heads UNION SELECT plugin_id FROM artifacts) p
		LEFT JOIN heads h ON h.plugin_id = p.plugin_id
		ORDER BY p.plugin_id LIMIT 1000`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []LibraryItem{}
	for rows.Next() {
		var item LibraryItem
		if err := rows.Scan(&item.PluginID, &item.Installed, &item.Enabled, &item.Withdrawn); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
