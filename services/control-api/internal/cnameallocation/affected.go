package cnameallocation

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Kinds of cname_label_settings rows.
const (
	KindLineGroup = "line_group"
)

// AffectedSite is a site whose generated CNAME would change if its allocation
// were regenerated under the current prefix settings.
type AffectedSite struct {
	ScopeID, SiteID uuid.UUID
	// SubscriptionID is set for package mode sites; they share one allocation.
	SubscriptionID *uuid.UUID
}

// PrefixAffectedSites lists the sites that take their label prefix from the
// line group: not the ones named by themselves. It follows the generation order
// of effectiveLabel.
func PrefixAffectedSites(ctx context.Context, tx pgx.Tx, kind string, subjectID uuid.UUID) ([]AffectedSite, error) {
	if kind != KindLineGroup {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT s.scope_id, s.id, sub.id
		FROM sites s
		LEFT JOIN package_subscriptions sub ON sub.tenant_scope_id=s.scope_id AND sub.id=s.package_subscription_id
		WHERE s.deleted_at IS NULL AND s.cname_mode IS NOT NULL
		  AND COALESCE(s.node_group_id, NULLIF(sub.product_snapshot->'spec'->>'node_group_id','')::uuid,
		    (SELECT g.id FROM node_line_groups g WHERE g.is_platform_default AND g.deleted_at IS NULL LIMIT 1))=$1
		  AND (s.cname_mode='package' OR s.cname_custom_label IS NULL)
		  AND COALESCE(sub.product_snapshot->'spec'->'cname'->>'hostname','')=''
		ORDER BY s.scope_id, s.id`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []AffectedSite
	for rows.Next() {
		var item AffectedSite
		if err := rows.Scan(&item.ScopeID, &item.SiteID, &item.SubscriptionID); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
