package edgepublish

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// attachSiteCRS gives every WAF binding whose policy runs a managed WAF the
// CRS inputs (rule text, downloaded CRS profile packs) and the site's own
// CRS override (site_crs_overrides, PA-12); securitypublication applies the
// override and selects the profile. Nothing is read when no binding needs it.
func attachSiteCRS(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, bindings map[uuid.UUID][]securityBindingFact) error {
	needed := false
	for _, siteBindings := range bindings {
		for _, binding := range siteBindings {
			needed = needed || securitypolicy.PolicyManagedWAF(binding.policy) != nil
		}
	}
	if !needed {
		return nil
	}
	inputs, err := loadCRSInputs(ctx, tx)
	if err != nil {
		return err
	}
	overrides, err := loadSiteCRSOverrides(ctx, tx, scopeID)
	if err != nil {
		return err
	}
	for siteID := range bindings {
		for index := range bindings[siteID] {
			binding := &bindings[siteID][index]
			if securitypolicy.PolicyManagedWAF(binding.policy) == nil {
				continue
			}
			value := *inputs
			value.Override = overrides[siteID]
			binding.crs = &value
		}
	}
	return nil
}

// loadSiteCRSOverrides is the scope's per-site CRS overrides; a site
// without a row inherits its WAF library's profile and exclusions.
func loadSiteCRSOverrides(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (map[uuid.UUID]securitypolicy.CRSOverride, error) {
	rows, err := tx.Query(ctx, `SELECT site_id,override FROM site_crs_overrides WHERE scope_id=$1`, scopeID)
	if err != nil {
		return nil, fmt.Errorf("%w: read site CRS overrides", ErrPersistence)
	}
	defer rows.Close()
	result := map[uuid.UUID]securitypolicy.CRSOverride{}
	for rows.Next() {
		var siteID uuid.UUID
		var raw []byte
		if err := rows.Scan(&siteID, &raw); err != nil {
			return nil, fmt.Errorf("%w: scan site CRS override", ErrPersistence)
		}
		override, err := securitypolicy.DecodeCRSOverride(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: decode site CRS override", ErrPersistence)
		}
		result[siteID] = override
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("%w: iterate site CRS overrides", ErrPersistence)
	}
	return result, nil
}
