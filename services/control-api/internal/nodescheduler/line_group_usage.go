package nodescheduler

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// lineGroupUsageSQL counts, in one pass, the live sites and L4 forwards that
// route to each of $2 (line group IDs as text). A site resolves its line group
// as CNAME allocation does (insertFrozenTarget / checkSettledLineGroup): its
// own node_group_id, else its package snapshot's, else (no package) the
// platform default; with no own group the package's backup group also counts.
// A forward counts by its own primary/backup group, else (no own primary) its
// package's primary/backup; a forward without a package (community edition,
// migration 597) still counts by its own groups. Snapshot values are compared
// as text so a malformed stored value matches nothing instead of failing.
// {{scope}} is replaced by the owner filter: a platform scope's groups may be
// referenced by sites and forwards of every scope in this installation; any
// other scope's only by its own.
const lineGroupUsageSQL = `
WITH platform_default AS (
	SELECT line_group.id::text AS id FROM node_line_groups line_group
	WHERE line_group.is_platform_default AND line_group.deleted_at IS NULL LIMIT 1
), usage AS (
	SELECT 'site' AS kind, site.id AS item_id, line.id AS line_group_id
	FROM sites site
	LEFT JOIN package_subscriptions subscription
	  ON subscription.tenant_scope_id=site.scope_id
	 AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
	LEFT JOIN LATERAL (SELECT package_subscription_current_product_snapshot(subscription.id,now()) AS product_snapshot) subscription_current ON true
	CROSS JOIN LATERAL (VALUES
		(CASE WHEN site.node_group_id IS NOT NULL THEN site.node_group_id::text
		      WHEN site.package_subscription_id IS NOT NULL THEN subscription_current.product_snapshot#>>'{spec,node_group_id}'
		      ELSE (SELECT id FROM platform_default) END),
		(CASE WHEN site.node_group_id IS NULL THEN subscription_current.product_snapshot#>>'{spec,backup_node_group_id}' END)
	) line(id)
	WHERE site.deleted_at IS NULL {{scope:site.scope_id}}
	UNION ALL
	SELECT 'forward', forward_rule.id, line.id
	FROM l4_forwards forward_rule
	LEFT JOIN package_subscriptions subscription
	  ON subscription.tenant_scope_id=forward_rule.scope_id
	 AND subscription.id=forward_rule.package_subscription_id
	LEFT JOIN LATERAL (SELECT package_subscription_current_product_snapshot(subscription.id,now()) AS product_snapshot) subscription_current ON true
	CROSS JOIN LATERAL (VALUES
		(forward_rule.node_group_id::text),
		(forward_rule.backup_node_group_id::text),
		(CASE WHEN forward_rule.node_group_id IS NULL THEN subscription_current.product_snapshot#>>'{spec,node_group_id}' END),
		(CASE WHEN forward_rule.node_group_id IS NULL THEN subscription_current.product_snapshot#>>'{spec,backup_node_group_id}' END)
	) line(id)
	WHERE forward_rule.deleted_at IS NULL {{scope:forward_rule.scope_id}}
)
SELECT kind, line_group_id::uuid, count(DISTINCT item_id)
FROM usage
WHERE line_group_id=ANY($2::text[])
GROUP BY kind, line_group_id`

// lineGroupUsage returns the site and forward counts of the scope's line
// groups groupIDs (see lineGroupUsageSQL); NodeCount is left zero.
func lineGroupUsage(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, groupIDs []string) (map[uuid.UUID]LineGroupStatistics, error) {
	result := make(map[uuid.UUID]LineGroupStatistics, len(groupIDs))
	if len(groupIDs) == 0 {
		return result, nil
	}
	var platform bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM access_scopes WHERE id=$1 AND kind='platform')`,
		scopeID).Scan(&platform); err != nil {
		return nil, fmt.Errorf("load node line group owner scope: %w", err)
	}
	query := lineGroupUsageSQL
	for _, column := range []string{"site.scope_id", "forward_rule.scope_id"} {
		filter := "AND " + column + "=$1"
		if platform {
			// $1 stays referenced so both variants take the same arguments.
			filter = "AND $1::uuid IS NOT NULL"
		}
		query = strings.Replace(query, "{{scope:"+column+"}}", filter, 1)
	}
	rows, err := tx.Query(ctx, query, scopeID, groupIDs)
	if err != nil {
		return nil, fmt.Errorf("count node line group usage: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var groupID uuid.UUID
		var count int64
		if err := rows.Scan(&kind, &groupID, &count); err != nil {
			return nil, fmt.Errorf("scan node line group usage: %w", err)
		}
		statistics := result[groupID]
		if kind == "site" {
			statistics.SiteCount = count
		} else {
			statistics.ForwardCount = count
		}
		result[groupID] = statistics
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node line group usage: %w", err)
	}
	return result, nil
}
