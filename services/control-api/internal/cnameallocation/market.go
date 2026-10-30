package cnameallocation

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type rowsQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// SupplyTarget is one usable supply of a site, from site_supply_bindings:
// what the site CNAME can point at on a line (ADR 0008 §6.1). Market
// subscriptions and third-party CDNs resolve the same way; local node
// groups keep their A/AAAA path (Retarget).
type SupplyTarget struct {
	SupplyID  uuid.UUID
	Kind      string // market_subscription or third_party_cdn
	Target    string
	Role      string // primary or backup
	Priority  int
	LineScope string // "" is the default line
}

// SupplyPausedWithoutPackageSQL is the single rule
// of a supply that stops carrying a site without a valid package
// (unbound, or its package disabled/deleted; the edgepublish rule): the
// controller's own (platform scope) third-party CDNs and market subscriptions
// pause; a supply of the site owner's own scope keeps carrying it. supply and
// site are the aliases of a site_supplies and a sites row.
func SupplyPausedWithoutPackageSQL(supply, site string) string {
	return "(" + supply + ".kind IN ('third_party_cdn','market_subscription') AND " + supply + ".platform_scope_id<>" + site + ".scope_id" +
		" AND NOT EXISTS(SELECT 1 FROM package_subscriptions valid_package" +
		" WHERE valid_package.tenant_scope_id=" + site + ".scope_id AND valid_package.id=" + site + ".package_subscription_id" +
		" AND valid_package.admin_enabled AND valid_package.deleted_at IS NULL))"
}

// SupplyTargets lists a site's active supplies that have a target, ordered
// by line, primary before backup, then priority (lowest first) and id. A
// supply paused for lack of a valid package is left out (its binding stays),
// so DNS returns to the site's own line group until the package is valid.
// Health and switching are the scheduler's (ADR 0008 §6.3); this is only
// the preference order.
func SupplyTargets(ctx context.Context, database rowsQuerier, scopeID, siteID uuid.UUID) ([]SupplyTarget, error) {
	rows, err := database.Query(ctx, `SELECT supply.id,supply.kind,supply.target,binding.role,binding.priority,binding.line_scope
		FROM site_supply_bindings binding
		JOIN sites site ON site.id=binding.site_id AND site.scope_id=$1 AND site.deleted_at IS NULL
		JOIN site_supplies supply ON supply.id=binding.supply_id
		WHERE binding.site_id=$2 AND supply.status='active' AND supply.target<>''
		  AND NOT `+SupplyPausedWithoutPackageSQL("supply", "site")+`
		ORDER BY binding.line_scope, binding.role<>'primary', binding.priority, supply.id`, scopeID, siteID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var targets []SupplyTarget
	for rows.Next() {
		var target SupplyTarget
		if err := rows.Scan(&target.SupplyID, &target.Kind, &target.Target, &target.Role, &target.Priority,
			&target.LineScope); err != nil {
			return nil, mapError(err)
		}
		target.Target = strings.ToLower(strings.TrimSuffix(target.Target, "."))
		targets = append(targets, target)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return targets, nil
}

// DefaultLineTarget returns the CNAME a site's hostname must point at on the
// DNS default line, or "" for the site's own node group (A/AAAA). A site
// scheduled by the aggregated edge (aggregated_edge_line_targets, migration
// 366) follows the scheduler's choice, kept as is while the edge is frozen;
// any other site keeps MarketTarget.
func DefaultLineTarget(ctx context.Context, database rowsQuerier, scopeID, siteID uuid.UUID) (string, error) {
	rows, err := database.Query(ctx, `SELECT line.target FROM aggregated_edge_line_targets line
		JOIN sites site ON site.id=line.site_id AND site.scope_id=$1 AND site.deleted_at IS NULL
		WHERE line.site_id=$2 AND line.line_scope=''`, scopeID, siteID)
	if err != nil {
		return "", mapError(err)
	}
	scheduled, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", mapError(err)
	}
	if len(scheduled) == 1 {
		return strings.ToLower(strings.TrimSuffix(scheduled[0], ".")), nil
	}
	return MarketTarget(ctx, database, scopeID, siteID)
}

// MarketTarget returns the supply name a site's CNAME hostname must point at
// when the site's primary supply is a node market subscription, or "" when it
// is served by a local node group as before. Lowest priority wins. Only the
// default line's primary market supply counts: per-line and backup targets
// (and third-party CDNs) need the scheduler (ADR 0008 P1-b).
func MarketTarget(ctx context.Context, database rowsQuerier, scopeID, siteID uuid.UUID) (string, error) {
	targets, err := SupplyTargets(ctx, database, scopeID, siteID)
	if err != nil {
		return "", err
	}
	for _, target := range targets {
		if target.Kind == "market_subscription" && target.Role == "primary" && target.LineScope == "" {
			return target.Target, nil
		}
	}
	return "", nil
}
