package edgepublish

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SiteCacheStatusHeader is the published 响应头显示缓存状态 of a site
// (sites.cache_status_header, migration 472): the site's
// switch, off while attack escalation holds the site at level B or above by
// its target, applied or locked level. Levels are escalate_site_states'
// ("" without a row or lock: A). The escalation worker and the lock /
// unlock / reset writers republish the scope (SystemTriggerAttackEscalation)
// whenever the result can change, so the node never needs the level itself.
func SiteCacheStatusHeader(enabled bool, level, appliedLevel, lockedLevel string) bool {
	escalated := func(value string) bool { return value != "" && value != "A" }
	return enabled && !escalated(level) && !escalated(appliedLevel) && !escalated(lockedLevel)
}

// loadSiteCacheStatusHeaders fills facts[site].CacheStatusHeader for every
// live site of the scope (facts is never nil here: loadSiteRuleMounts made it).
func loadSiteCacheStatusHeaders(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, facts map[string]siteObjectV2Facts) error {
	rows, err := tx.Query(ctx, `SELECT site.id::text,site.cache_status_header,COALESCE(state.level,''),
			COALESCE(state.applied_level,''),COALESCE(state.locked_level,'')
		FROM sites site LEFT JOIN escalate_site_states state ON state.tenant_scope_id=site.scope_id AND state.site_id=site.id
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL`, scopeID)
	if err != nil {
		return fmt.Errorf("%w: load site cache status headers", ErrPersistence)
	}
	defer rows.Close()
	for rows.Next() {
		var siteID, level, applied, locked string
		var enabled bool
		if err := rows.Scan(&siteID, &enabled, &level, &applied, &locked); err != nil {
			return fmt.Errorf("%w: scan site cache status headers", ErrPersistence)
		}
		value := facts[siteID]
		value.CacheStatusHeader = SiteCacheStatusHeader(enabled, level, applied, locked)
		facts[siteID] = value
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: iterate site cache status headers", ErrPersistence)
	}
	return nil
}
