package edgeautopublish

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PackageExpirySourceID is the source resource of package_expiry
// republications without a subscription of their own.
var PackageExpirySourceID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("cdnca.edge.package-expiry"))

// PackageExpiryWatcher republishes (trigger package_expiry) the tenant scope
// of every package whose term ended, so its sites go out marked package
// expired, and again when a renewal (fulfillment moved ends_at) or the
// expiry_close setting changes that (errpage-4 S3). A renewal is not left
// to the interval: its fulfillment writes package_order.fulfilled to
// package_commerce_outbox in the same transaction, and the next poll that
// sees a newer such event sweeps at once (defer-small), so the renewed
// scope's republication is queued within one runtime poll. The interval
// sweep stays as the fallback (an admin edit of ends_at, a toggled
// expiry_close, an event committed behind the cursor).
// package_expiry_republication_marks keeps what it acted on;
// a scope is republished only when its sites' served state changes: expired
// with 套餐到期后关闭网站 (expiry_close) on, or not.
type PackageExpiryWatcher struct {
	pool     *pgxpool.Pool
	interval time.Duration
	now      func() time.Time
	last     time.Time
	// fulfilled is the newest package_order.fulfilled outbox event seen
	// (UUIDv7: id order is creation order); primed once it is read.
	fulfilled uuid.UUID
	primed    bool
}

// fulfillmentEventType is what packagecommerce writes for every fulfilled
// order (purchase, renewal, change) to package_commerce_outbox.
const fulfillmentEventType = "package_order.fulfilled"

// newFulfillment reports whether a package_order.fulfilled event newer than
// the cursor exists, and moves the cursor to the newest one. The first call
// only primes the cursor: the first sweep runs regardless.
func (watcher *PackageExpiryWatcher) newFulfillment(ctx context.Context) (bool, error) {
	var newest *uuid.UUID
	// the primary key range after the cursor holds only the new events
	// PostgreSQL 没有 max(uuid)：按主键倒序取一条
	err := watcher.pool.QueryRow(ctx, `SELECT id FROM package_commerce_outbox
		WHERE id>$1 AND aggregate_type='package_order' AND event_type=$2
		ORDER BY id DESC LIMIT 1`, watcher.fulfilled, fulfillmentEventType).Scan(&newest)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	found := newest != nil && watcher.primed
	if newest != nil {
		watcher.fulfilled = *newest
	}
	watcher.primed = true
	return found, nil
}

func NewPackageExpiryWatcher(pool *pgxpool.Pool, interval time.Duration) (*PackageExpiryWatcher, error) {
	if pool == nil || interval < 0 || interval > time.Hour {
		return nil, ErrInvalidInput
	}
	return &PackageExpiryWatcher{pool: pool, interval: interval, now: time.Now}, nil
}

// RunOnce sweeps at once after a fulfillment event, otherwise at most once
// per interval (the runtime polls faster).
func (watcher *PackageExpiryWatcher) RunOnce(ctx context.Context) (bool, error) {
	if watcher == nil || ctx == nil {
		return false, ErrInvalidInput
	}
	fulfilled, err := watcher.newFulfillment(ctx)
	if err != nil {
		return false, err
	}
	now := watcher.now()
	if !fulfilled && !watcher.last.IsZero() && now.Sub(watcher.last) < watcher.interval {
		return false, nil
	}
	watcher.last = now
	scopes, err := watcher.SweepOnce(ctx)
	return len(scopes) > 0, err
}

// SweepOnce returns the scopes it queued, in scope order.
func (watcher *PackageExpiryWatcher) SweepOnce(ctx context.Context) ([]uuid.UUID, error) {
	var queued []uuid.UUID
	err := pgx.BeginFunc(ctx, watcher.pool, func(tx pgx.Tx) error {
		queued = nil
		// Expired: active, enabled, not deleted, term over (database clock).
		// A mark differing from it (renewed, setting toggled, cancelled) is
		// brought up to date. One watcher runs (runtime coordinator); the
		// upsert keeps a concurrent sweep harmless.
		rows, err := tx.Query(ctx, `WITH setting AS (
			SELECT COALESCE(bool_or((settings->>'expiry_close')::boolean),false) AS close FROM platform_system_settings),
		current AS (
			SELECT subscription.id,subscription.tenant_scope_id,subscription.ends_at,
			  subscription.lifecycle_status='active' AND subscription.admin_enabled AND subscription.deleted_at IS NULL
			  AND subscription.ends_at<=clock_timestamp() AS expired
			FROM package_subscriptions subscription)
		SELECT current.id,current.tenant_scope_id,current.ends_at,current.expired,setting.close,
		  mark.subscription_id IS NOT NULL AND mark.expiry_close AS was_closed
		FROM current CROSS JOIN setting
		LEFT JOIN package_expiry_republication_marks mark ON mark.subscription_id=current.id
		WHERE (current.expired AND (mark.subscription_id IS NULL OR mark.ends_at<>current.ends_at OR mark.expiry_close<>setting.close))
		   OR (NOT current.expired AND mark.subscription_id IS NOT NULL)
		ORDER BY current.id`)
		if err != nil {
			return err
		}
		type change struct {
			subscriptionID, scopeID uuid.UUID
			endsAt                  time.Time
			expired, close, was     bool
		}
		changes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (change, error) {
			var item change
			err := row.Scan(&item.subscriptionID, &item.scopeID, &item.endsAt, &item.expired, &item.close, &item.was)
			return item, err
		})
		if err != nil {
			return err
		}
		var scopes []uuid.UUID
		for _, item := range changes {
			if item.expired {
				if _, err := tx.Exec(ctx, `INSERT INTO package_expiry_republication_marks(
					subscription_id,tenant_scope_id,ends_at,expiry_close,observed_at)
					VALUES($1,$2,$3,$4,clock_timestamp())
					ON CONFLICT (subscription_id) DO UPDATE SET ends_at=EXCLUDED.ends_at,
					  expiry_close=EXCLUDED.expiry_close,observed_at=EXCLUDED.observed_at`,
					item.subscriptionID, item.scopeID, item.endsAt, item.close); err != nil {
					return err
				}
			} else if _, err := tx.Exec(ctx, `DELETE FROM package_expiry_republication_marks WHERE subscription_id=$1`,
				item.subscriptionID); err != nil {
				return err
			}
			if item.was != (item.expired && item.close) {
				scopes = append(scopes, item.scopeID)
			}
		}
		slices.SortFunc(scopes, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
		scopes = slices.Compact(scopes)
		for _, scopeID := range scopes {
			if err := requestPackageExpiryRepublicationTx(ctx, tx, scopeID, PackageExpirySourceID,
				"package-expiry."+scopeID.String()+"."+watcher.now().UTC().Format("20060102T150405"), "site.batch.disable"); err != nil {
				return err
			}
		}
		queued = scopes
		return nil
	})
	return queued, err
}

// requestPackageExpiryRepublicationTx advances the scope's revision (no
// site row changed: an automatic scope needs a revision of its own, a manual
// one gets it attributed to package_expiry) and queues the republication.
func requestPackageExpiryRepublicationTx(ctx context.Context, tx pgx.Tx, scopeID, sourceID uuid.UUID,
	requestID, operation string) error {
	var current int64
	err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
		scopeID).Scan(&current)
	if err == pgx.ErrNoRows {
		return nil // never configured: nothing published to change
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, scopeID); err != nil {
		return err
	}
	_, err = RequestRepublicationTx(ctx, tx, RepublishRequest{
		ScopeID: scopeID, Trigger: edgepublish.SystemTriggerPackageExpiry, SourceResourceID: sourceID,
		Operation: operation, SourceRequestID: requestID, FromRevision: current, Immediate: true,
	})
	return err
}
