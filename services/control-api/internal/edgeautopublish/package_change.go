package edgeautopublish

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// A package upgrade or downgrade
// adds an entitlement version; publication compiles every site against its
// subscription's entitlement in effect (migration 691), so no site row changes
// and the scope needs a publication of its own. package_entitlement_republication_marks
// keeps the entitlement revision last published per subscription: the change's
// fulfillment publishes an immediate change and marks it, the package expiry
// watcher's sweep publishes a change that took effect later (next_cycle) or
// one no publication covered, once.

// RequestPackageChangeRepublicationTx runs in the fulfillment transaction of
// an upgrade or downgrade that added entitlementRevision. effective is whether
// that entitlement is in effect now (an immediate change); a later one is left
// to the sweep. A suspended subscription is marked but not published: its
// sites are out of every publication, and unsuspending republishes them
// against the current entitlement. The caller locked the configuration scope
// before the subscription (publication lock order).
func RequestPackageChangeRepublicationTx(ctx context.Context, tx pgx.Tx, scopeID, subscriptionID uuid.UUID,
	entitlementRevision int64, effective bool, requestID string,
) (bool, error) {
	if ctx == nil || tx == nil || scopeID == uuid.Nil || subscriptionID == uuid.Nil || entitlementRevision < 1 ||
		strings.TrimSpace(requestID) == "" {
		return false, ErrInvalidInput
	}
	if !effective {
		return false, nil
	}
	advanced, err := markPackageEntitlementTx(ctx, tx, scopeID, subscriptionID, entitlementRevision)
	if err != nil || !advanced {
		return false, err
	}
	var suspended bool
	if err := tx.QueryRow(ctx, `SELECT suspended_at IS NOT NULL FROM package_subscriptions
		WHERE tenant_scope_id=$1 AND id=$2`, scopeID, subscriptionID).Scan(&suspended); err != nil {
		return false, err
	}
	if suspended {
		return false, nil
	}
	return publishPackageChangeTx(ctx, tx, scopeID, "package-change:"+subscriptionID.String()+":"+requestID)
}

// markPackageEntitlementTx records that the subscription's sites are published
// at entitlementRevision; false when the mark already covers it.
func markPackageEntitlementTx(ctx context.Context, tx pgx.Tx, scopeID, subscriptionID uuid.UUID, entitlementRevision int64) (bool, error) {
	var marked int64
	err := tx.QueryRow(ctx, `INSERT INTO package_entitlement_republication_marks(
		subscription_id,tenant_scope_id,entitlement_revision,observed_at)
		VALUES($1,$2,$3,clock_timestamp())
		ON CONFLICT (subscription_id) DO UPDATE SET entitlement_revision=EXCLUDED.entitlement_revision,
		  observed_at=EXCLUDED.observed_at
		WHERE package_entitlement_republication_marks.entitlement_revision<EXCLUDED.entitlement_revision
		RETURNING entitlement_revision`, subscriptionID, scopeID, entitlementRevision).Scan(&marked)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// markCurrentPackageEntitlementTx marks the entitlement in effect now (an
// unsuspend republishes against it).
func markCurrentPackageEntitlementTx(ctx context.Context, tx pgx.Tx, scopeID, subscriptionID uuid.UUID) error {
	var revision *int64
	if err := tx.QueryRow(ctx, `SELECT package_subscription_effective_entitlement_revision($1,clock_timestamp())`,
		subscriptionID).Scan(&revision); err != nil || revision == nil {
		return err
	}
	_, err := markPackageEntitlementTx(ctx, tx, scopeID, subscriptionID, *revision)
	return err
}

// publishPackageChangeTx gives an automatic scope a new source revision and
// queues it as its policy actor's site.batch.enable (as a package suspension
// change is). A scope never configured, or a manual one, is left to its next
// publication, which compiles the current entitlement. In a savepoint: a
// policy actor the request table refuses (P8602, a suspended account) leaves
// the change unpublished instead of failing the order's fulfillment.
func publishPackageChangeTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, requestID string) (bool, error) {
	var current int64
	err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
		scopeID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	actor, automatic, err := automaticPolicyActor(ctx, tx, scopeID)
	if err != nil || !automatic {
		return false, err
	}
	if len(requestID) > 128 {
		requestID = requestID[:128]
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return false, err
	}
	if _, err := savepoint.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, scopeID); err != nil {
		_ = savepoint.Rollback(ctx)
		return false, err
	}
	result, err := EnqueueTx(ctx, savepoint, EnqueueInput{
		Actor: actor, TargetScopeID: scopeID, SourceKind: SourceSite, Operation: "site.batch.enable",
		Reason: ReasonResourceMutation, Permission: PermissionSitesManage, SourceRequestID: requestID,
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "P8602" {
		return false, savepoint.Rollback(ctx)
	}
	if err != nil {
		_ = savepoint.Rollback(ctx)
		return false, err
	}
	return result.Enqueued && !result.Replayed, savepoint.Commit(ctx)
}

// SweepPackageChangesOnce publishes, once per scope, the live unsuspended
// subscriptions whose entitlement in effect is past their mark with an
// upgrade or downgrade in between: a change that took effect after its
// fulfillment, or one made before migration 691 (its sites still ran the
// purchased product). Other entitlement versions (renewals, admin edits,
// published by their own writers) only move the mark when a change does.
// It returns the scopes it queued, in scope order.
func (watcher *PackageExpiryWatcher) SweepPackageChangesOnce(ctx context.Context) ([]uuid.UUID, error) {
	if watcher == nil || ctx == nil {
		return nil, ErrInvalidInput
	}
	var queued []uuid.UUID
	err := pgx.BeginFunc(ctx, watcher.pool, func(tx pgx.Tx) error {
		queued = nil
		rows, err := tx.Query(ctx, `SELECT subscription.id,subscription.tenant_scope_id,effective.revision
			FROM package_subscriptions subscription
			CROSS JOIN LATERAL (SELECT package_subscription_effective_entitlement_revision(subscription.id,clock_timestamp()) AS revision) effective
			LEFT JOIN package_entitlement_republication_marks mark ON mark.subscription_id=subscription.id
			WHERE subscription.lifecycle_status='active' AND subscription.admin_enabled AND subscription.deleted_at IS NULL
			  AND subscription.suspended_at IS NULL AND subscription.ends_at>clock_timestamp()
			  AND effective.revision>COALESCE(mark.entitlement_revision,0)
			  AND EXISTS(SELECT 1 FROM package_subscription_entitlement_versions change
			    WHERE change.subscription_id=subscription.id AND change.tenant_scope_id=subscription.tenant_scope_id
			      AND change.operation IN ('upgrade','downgrade')
			      AND change.revision>COALESCE(mark.entitlement_revision,0) AND change.revision<=effective.revision)
			ORDER BY subscription.tenant_scope_id,subscription.id`)
		if err != nil {
			return err
		}
		type change struct {
			subscriptionID, scopeID uuid.UUID
			revision                int64
		}
		changes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (change, error) {
			var item change
			return item, row.Scan(&item.subscriptionID, &item.scopeID, &item.revision)
		})
		if err != nil {
			return err
		}
		var scopes []uuid.UUID
		for _, item := range changes {
			// Scope first (publication lock order); the mark, re-read under
			// it, drops a change a concurrent fulfillment already published.
			if _, err := tx.Exec(ctx, `SELECT 1 FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
				item.scopeID); err != nil {
				return err
			}
			advanced, err := markPackageEntitlementTx(ctx, tx, item.scopeID, item.subscriptionID, item.revision)
			if err != nil {
				return err
			}
			if advanced {
				scopes = append(scopes, item.scopeID)
			}
		}
		slices.SortFunc(scopes, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
		scopes = slices.Compact(scopes)
		for _, scopeID := range scopes {
			published, err := publishPackageChangeTx(ctx, tx, scopeID,
				"package-change."+scopeID.String()+"."+watcher.now().UTC().Format("20060102T150405"))
			if err != nil {
				return err
			}
			if published {
				queued = append(queued, scopeID)
			}
		}
		return nil
	})
	return queued, err
}
