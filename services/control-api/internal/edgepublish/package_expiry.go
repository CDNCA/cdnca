package edgepublish

import (
	"context"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Package expiry (errpage-4 S3, competitor semantics): a site whose package
// ended stays in the publication marked package_expired; the node answers the
// package_expired page and never reaches the origin. The other sites of the
// scope publish as usual. Only with the platform's 套餐到期后关闭网站
// (expiry_close) on: with it off an expired site keeps serving. A site whose
// stored status is package_expired (set explicitly) is marked either way,
// unless a renewal status recovery is restoring it.
const packageExpiredSitesQuery = `SELECT site.id FROM sites site
	LEFT JOIN package_subscriptions subscription
	  ON subscription.tenant_scope_id=site.scope_id AND subscription.id=site.package_subscription_id
	WHERE site.scope_id=$1 AND site.id=ANY($2::uuid[]) AND (
	  (site.status='package_expired' AND NOT site.id=ANY(COALESCE($3::uuid[],'{}'::uuid[])))
	  OR (subscription.lifecycle_status='active' AND subscription.ends_at<=$4 AND
	      (SELECT COALESCE(bool_or((settings->>'expiry_close')::boolean),false) FROM platform_system_settings)))
	ORDER BY site.id`

// markSiteRuntimeV2PackageExpiry sets every document site's PackageExpired
// from the current rows (a renewed site loses the mark) and requires
// error_page_slots when one is set.
func markSiteRuntimeV2PackageExpiry(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID,
	document *siteRuntimeV2Document, recovering []uuid.UUID, now time.Time) error {
	if len(document.Sites) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(document.Sites))
	for _, site := range document.Sites {
		ids = append(ids, uuid.MustParse(site.ID))
	}
	rows, err := tx.Query(ctx, packageExpiredSitesQuery, scopeID, ids, recovering, now)
	if err != nil {
		return fmt.Errorf("%w: read package expired sites", ErrPersistence)
	}
	expiredIDs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return fmt.Errorf("%w: scan package expired sites", ErrPersistence)
	}
	expired := make(map[string]bool, len(expiredIDs))
	for _, id := range expiredIDs {
		expired[id.String()] = true
	}
	for index := range document.Sites {
		document.Sites[index].PackageExpired = expired[document.Sites[index].ID]
	}
	if len(expired) != 0 {
		requireSiteRuntimeV2Capability(document, siteobject.ErrorPageSlotsCapability, siteobject.ErrorPageSlotsAPIVersion)
	}
	return nil
}

// packageEnded: the subscription is active but its term is over at at. Its
// sites publish marked package expired (or keep serving with expiry_close
// off); its limits are no longer checked.
func packageEnded(ctx context.Context, tx pgx.Tx, subscriptionID uuid.UUID, at time.Time) (bool, error) {
	var ended bool
	err := tx.QueryRow(ctx, `SELECT lifecycle_status='active' AND ends_at<=$2 FROM package_subscriptions WHERE id=$1`,
		subscriptionID, at).Scan(&ended)
	return ended, err
}
