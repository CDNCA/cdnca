package edgepublish

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// loadSiteQuickBlockOverrides is the scope's per-site quick block overrides
// (migration 355); a site without a row inherits its
// WAF library's quick block.
func loadSiteQuickBlockOverrides(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (map[uuid.UUID]securitypolicy.QuickBlockOverride, error) {
	rows, err := tx.Query(ctx, `SELECT site_id,override FROM site_quick_block_overrides WHERE scope_id=$1`, scopeID)
	if err != nil {
		return nil, fmt.Errorf("%w: read site quick block overrides", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]securitypolicy.QuickBlockOverride)
	for rows.Next() {
		var siteID uuid.UUID
		var raw []byte
		if err := rows.Scan(&siteID, &raw); err != nil {
			return nil, fmt.Errorf("%w: scan site quick block override", ErrPersistence)
		}
		override, err := securitypolicy.DecodeQuickBlockOverride(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: decode site quick block override", ErrPersistence)
		}
		result[siteID] = override
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("%w: iterate site quick block overrides", ErrPersistence)
	}
	return result, nil
}

// applySiteQuickBlockOverrides attaches each site's override to its WAF
// binding (compileSecurityPoliciesFor applies it), for site runtime v2 and
// config-source v1 releases alike. A site with an override
// and no WAF binding has nothing to carry it: the override waits for one.
func applySiteQuickBlockOverrides(bindings map[uuid.UUID][]securityBindingFact, overrides map[uuid.UUID]securitypolicy.QuickBlockOverride) {
	for siteID, override := range overrides {
		for index := range bindings[siteID] {
			if bindings[siteID][index].policy.Kind == securitypolicy.KindWAF {
				value := override
				bindings[siteID][index].quickBlock = &value
			}
		}
	}
}
