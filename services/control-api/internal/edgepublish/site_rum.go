package edgepublish

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// loadSiteRUM fills facts[site].RUM (真实用户体验上报, migration
// 664) for every live site of the scope with the switch on.
func loadSiteRUM(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, facts map[string]siteObjectV2Facts) error {
	rows, err := tx.Query(ctx, `SELECT id::text,rum_sample_percent FROM sites
		WHERE scope_id=$1 AND deleted_at IS NULL AND rum_sample_percent IS NOT NULL`, scopeID)
	if err != nil {
		return fmt.Errorf("%w: load site rum", ErrPersistence)
	}
	defer rows.Close()
	for rows.Next() {
		var siteID string
		var percent int
		if err := rows.Scan(&siteID, &percent); err != nil {
			return fmt.Errorf("%w: scan site rum", ErrPersistence)
		}
		if value, ok := facts[siteID]; ok {
			value.RUM = &edgeconfig.SiteRUM{SamplePercent: percent}
			facts[siteID] = value
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: iterate site rum", ErrPersistence)
	}
	return nil
}

// requireRUMCapability: a release whose sites include one with
// rum on requires SITE_RUM v1, so a target node without it is refused and
// named (TargetCapabilityError). Both the compiled document and the system
// overlay call it; a scope with every switch off is unchanged.
func requireRUMCapability(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, document *siteRuntimeV2Document) error {
	ids := make([]string, len(document.Sites))
	for index, site := range document.Sites {
		ids[index] = site.ID
	}
	var required bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sites WHERE scope_id=$1 AND id::text=ANY($2::text[])
		AND deleted_at IS NULL AND rum_sample_percent IS NOT NULL)`, scopeID, ids).Scan(&required); err != nil {
		return fmt.Errorf("%w: load site rum", ErrPersistence)
	}
	if required {
		requireSiteRuntimeV2Capability(document, siteobject.RUMCapability, siteobject.RUMAPIVersion)
	}
	return nil
}

// withoutRUMCapability drops the RUM facts unless the release root requires
// SITE_RUM (the targets were gated on that list): a node that never
// declared it decodes site objects strictly and would refuse the field.
func withoutRUMCapability(source siteObjectsV2Source, facts map[string]siteObjectV2Facts) {
	for _, capability := range source.Capabilities {
		if capability.Name == siteobject.RUMCapability && capability.APIVersion >= siteobject.RUMAPIVersion {
			return
		}
	}
	for siteID, value := range facts {
		if value.RUM != nil {
			value.RUM = nil
			facts[siteID] = value
		}
	}
}
