package edgepublish

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// checkPackageRuntime runs under the configuration scope lock. NOWAIT is
// essential: resource writers acquire subscription before scope. A concurrent
// writer must cause a retry, never a reversed-lock wait or a stale publication.
func checkPackageRuntime(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, at time.Time, override *securityBindingFact) error {
	rows, err := tx.Query(ctx, `SELECT s.id FROM package_subscriptions s
		WHERE s.tenant_scope_id=$1 AND (
		 EXISTS(SELECT 1 FROM sites r WHERE r.scope_id=$1 AND r.package_subscription_id=s.id
		  AND r.deleted_at IS NULL AND r.enabled)
		 OR EXISTS(SELECT 1 FROM l4_forwards r WHERE r.scope_id=$1 AND r.package_subscription_id=s.id
		  AND r.deleted_at IS NULL AND r.enabled))
		ORDER BY s.id FOR UPDATE OF s NOWAIT`, scopeID)
	if err != nil {
		return packagePublicationLockError(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return packagePublicationLockError(err)
	}
	for _, id := range ids {
		// Exclude suspended sites unless a recovery job will include them. Locking
		// all enabled subscriptions above still serializes recovery with mutation.
		var included bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sites r
		 WHERE r.scope_id=$1 AND r.package_subscription_id=$2 AND r.deleted_at IS NULL AND r.enabled
		 AND (r.status NOT IN ('package_expired','traffic_exceeded') OR EXISTS(
		  SELECT 1 FROM background_jobs j JOIN background_job_items i ON i.job_id=j.id AND i.tenant_id=j.tenant_id
		  WHERE j.kind='site.status_recovery' AND j.state IN ('queued','running') AND i.state='pending' AND i.item_id=r.id::text)))
		 OR EXISTS(SELECT 1 FROM l4_forwards r WHERE r.scope_id=$1 AND r.package_subscription_id=$2
		  AND r.deleted_at IS NULL AND r.enabled)`, scopeID, id).Scan(&included); err != nil {
			return err
		}
		if !included {
			continue
		}
		// An ended package's sites publish marked package expired
		// (package_expiry.go): no limits to check, and its inactive
		// entitlement must not fail the whole scope (errpage-4 S3).
		if ended, err := packageEnded(ctx, tx, id, at); err != nil {
			return err
		} else if ended {
			continue
		}
		limits, err := packageaddon.LockRuntimeLimits(ctx, tx, scopeID, id, at)
		if err != nil {
			return err
		}
		usage, err := packageaddon.SiteUsage(ctx, tx, scopeID, id)
		if err != nil {
			return err
		}
		var streams int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(COALESCE(l.port_end, l.port)-l.port+1),0) FROM l4_forward_listeners l
		 JOIN l4_forwards f ON f.id=l.stream_id WHERE f.scope_id=$1 AND f.package_subscription_id=$2
		 AND f.deleted_at IS NULL AND l.retired_at IS NULL`, scopeID, id).Scan(&streams); err != nil {
			return err
		}
		for _, count := range [][2]int64{{usage.Domains, limits.Domains}, {usage.RootDomains, limits.RootDomains}, {usage.HTTPPorts, limits.HTTPPorts}, {streams, limits.StreamPorts}} {
			if count[1] != -1 && count[0] > count[1] {
				return packageaddon.ErrQuotaExceeded
			}
		}
		var invalidOwner, cc, waf bool
		if err := tx.QueryRow(ctx, `SELECT
		 EXISTS(SELECT 1 FROM sites WHERE scope_id=$1 AND package_subscription_id=$2 AND deleted_at IS NULL AND owner_user_id<>$3)
		 OR EXISTS(SELECT 1 FROM l4_forwards WHERE scope_id=$1 AND package_subscription_id=$2 AND deleted_at IS NULL AND owner_user_id<>$3),
		 EXISTS(SELECT 1 FROM security_policy_site_bindings b JOIN sites s ON s.id=b.site_id
		 JOIN security_policy_versions v ON v.policy_id=b.policy_id AND v.revision=b.active_policy_version
		 WHERE s.scope_id=$1 AND s.package_subscription_id=$2 AND s.enabled AND s.deleted_at IS NULL
		 AND b.policy_kind='cc' AND (v.document->>'enabled')::boolean AND NOT(s.id=$4 AND b.policy_kind=$5)),
		 EXISTS(SELECT 1 FROM security_policy_site_bindings b JOIN sites s ON s.id=b.site_id
		 JOIN security_policy_versions v ON v.policy_id=b.policy_id AND v.revision=b.active_policy_version
		 WHERE s.scope_id=$1 AND s.package_subscription_id=$2 AND s.enabled AND s.deleted_at IS NULL
		 AND b.policy_kind='waf' AND (v.document->>'enabled')::boolean AND NOT(s.id=$4 AND b.policy_kind=$5))`,
			scopeID, id, limits.OwnerUserID, packageOverrideSite(override), packageOverrideKind(override)).Scan(&invalidOwner, &cc, &waf); err != nil {
			return err
		}
		if invalidOwner || cc && !limits.CustomCC || waf && !limits.WAF {
			return packageaddon.ErrFeatureDenied
		}
	}
	return nil
}

func packageOverrideSite(override *securityBindingFact) uuid.UUID {
	if override != nil {
		return override.siteID
	}
	return uuid.Nil
}

func packageOverrideKind(override *securityBindingFact) string {
	if override != nil {
		return override.policy.Kind
	}
	return ""
}

func packagePublicationLockError(err error) error {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && databaseError.Code == "55P03" {
		return ErrRevisionConflict
	}
	return err
}
