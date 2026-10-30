package edgepublish

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// renewSiteRuntimeV2CertificateReferences points a stop overlay's TLS
// listeners at their certificate's current version (fix-dnscert3 卡 2-B):
// an overlay redelivers the last publication, whose certificate_version_id
// may name a version the asset no longer serves (an automatic renewal, or
// the tenant's activation, switched the site's binding since). The reference
// moves only when the site is still bound to the same certificate and that
// binding names the asset's active version; anything else is left for
// validateSiteRuntimeV2CertificateReferences to refuse.
func renewSiteRuntimeV2CertificateReferences(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID,
	document *siteRuntimeV2Document) error {
	for siteIndex, site := range document.Sites {
		siteID, err := uuid.Parse(site.ID)
		if err != nil {
			return ErrTLSMaterialUnavailable
		}
		renewed := map[string]string{}
		for _, listener := range site.Listeners {
			if listener.TLS == nil {
				continue
			}
			current := listener.TLS.CertificateVersionID
			if _, seen := renewed[current]; seen {
				continue
			}
			versionID, err := uuid.Parse(current)
			if err != nil {
				return ErrTLSMaterialUnavailable
			}
			var next uuid.UUID
			err = tx.QueryRow(ctx, `SELECT binding.version_id FROM certificate_asset_versions referenced
				JOIN LATERAL (
					SELECT action,asset_id,version_id FROM certificate_site_binding_facts
					WHERE tenant_scope_id=$1 AND site_id=$3 ORDER BY sequence DESC LIMIT 1
				) binding ON binding.action='bind' AND binding.asset_id=referenced.asset_id
				WHERE referenced.tenant_scope_id=$1 AND referenced.id=$2 AND binding.version_id<>referenced.id
				  AND binding.version_id=(SELECT activation.version_id FROM certificate_asset_activation_facts activation
				    WHERE activation.tenant_scope_id=$1 AND activation.asset_id=referenced.asset_id
				    ORDER BY activation.sequence DESC LIMIT 1)`, scopeID, versionID, siteID).Scan(&next)
			if errors.Is(err, pgx.ErrNoRows) {
				renewed[current] = current
				continue
			}
			if err != nil {
				return fmt.Errorf("%w: read renewed certificate reference", ErrPersistence)
			}
			renewed[current] = next.String()
		}
		changed := false
		for from, to := range renewed {
			changed = changed || from != to
		}
		if !changed {
			continue
		}
		// The base publication's listeners are shared: copy before rewriting.
		listeners := slices.Clone(site.Listeners)
		for index, listener := range listeners {
			if listener.TLS == nil {
				continue
			}
			tls := *listener.TLS
			tls.CertificateVersionID = renewed[tls.CertificateVersionID]
			listeners[index].TLS = &tls
		}
		document.Sites[siteIndex].Listeners = listeners
	}
	return nil
}
