package edgepublish

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
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

// loadSiteCacheStatusHeaders fills facts[site].CacheStatusHeader and
// facts[site].ServerTiming (Server-Timing 响应头, migration 651;
// the same escalation rule) for every live site of the scope (facts is never
// nil here: loadSiteRuleMounts made it).
func loadSiteCacheStatusHeaders(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, facts map[string]siteObjectV2Facts) error {
	rows, err := tx.Query(ctx, `SELECT site.id::text,site.cache_status_header,site.server_timing,COALESCE(state.level,''),
			COALESCE(state.applied_level,''),COALESCE(state.locked_level,'')
		FROM sites site LEFT JOIN escalate_site_states state ON state.tenant_scope_id=site.scope_id AND state.site_id=site.id
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL`, scopeID)
	if err != nil {
		return fmt.Errorf("%w: load site cache status headers", ErrPersistence)
	}
	defer rows.Close()
	for rows.Next() {
		var siteID, level, applied, locked string
		var enabled, serverTiming bool
		if err := rows.Scan(&siteID, &enabled, &serverTiming, &level, &applied, &locked); err != nil {
			return fmt.Errorf("%w: scan site cache status headers", ErrPersistence)
		}
		value := facts[siteID]
		value.CacheStatusHeader = SiteCacheStatusHeader(enabled, level, applied, locked)
		value.ServerTiming = SiteCacheStatusHeader(serverTiming, level, applied, locked)
		facts[siteID] = value
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: iterate site cache status headers", ErrPersistence)
	}
	return nil
}

// requireServerTimingCapability (a release whose sites
// include one that publishes Server-Timing (switch on, not escalated to B or
// above: the same rule as loadSiteCacheStatusHeaders) requires
// SITE_SERVER_TIMING v1, so a target node without it is refused and named
// (TargetCapabilityError). Like ErrorPageSlots, both the compiled document and
// the system overlay call it; a scope with every switch off is unchanged.
func requireServerTimingCapability(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, document *siteRuntimeV2Document) error {
	ids := make([]string, len(document.Sites))
	for index, site := range document.Sites {
		ids[index] = site.ID
	}
	var required bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sites site
		LEFT JOIN escalate_site_states state ON state.tenant_scope_id=site.scope_id AND state.site_id=site.id
		WHERE site.scope_id=$1 AND site.id::text=ANY($2::text[]) AND site.deleted_at IS NULL AND site.server_timing
		  AND COALESCE(state.level,'A')='A' AND COALESCE(state.applied_level,'A')='A' AND COALESCE(state.locked_level,'A')='A')`,
		scopeID, ids).Scan(&required); err != nil {
		return fmt.Errorf("%w: load site server timing", ErrPersistence)
	}
	if required {
		requireSiteRuntimeV2Capability(document, siteobject.ServerTimingCapability, siteobject.ServerTimingAPIVersion)
	}
	return nil
}

// withoutServerTimingCapability drops the ServerTiming fact unless the
// release root requires SITE_SERVER_TIMING (the targets were gated on that
// list): a node that never declared it decodes site objects strictly and
// would refuse the field, so it is never delivered past the gate.
func withoutServerTimingCapability(source siteObjectsV2Source, facts map[string]siteObjectV2Facts) {
	for _, capability := range source.Capabilities {
		if capability.Name == siteobject.ServerTimingCapability && capability.APIVersion >= siteobject.ServerTimingAPIVersion {
			return
		}
	}
	for siteID, value := range facts {
		if value.ServerTiming {
			value.ServerTiming = false
			facts[siteID] = value
		}
	}
}
