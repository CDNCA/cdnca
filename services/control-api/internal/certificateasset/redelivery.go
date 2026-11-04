package certificateasset

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RedeliverySite is a site whose current binding (its latest binding fact,
// sequence BindingRevision, naming the asset's active version) a node lacks.
type RedeliverySite struct {
	SiteID          uuid.UUID
	AssetID         uuid.UUID
	VersionID       uuid.UUID
	BindingRevision int64
}

// UseRedeliveryMaterialsInTx gives consumer the key material of each site's
// current binding, re-read under row locks (a node that
// joined, was reinstalled or recovered after the binding was published). A
// site whose binding moved since, or whose version can no longer be served
// (revoked, outside its validity, not covering the site, key unavailable), is
// left out and returned in skipped; consumer is not called when none remain.
func (s *Store) UseRedeliveryMaterialsInTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID,
	sites []RedeliverySite, resolver OpaquePublicationResolver, consumer PublicationConsumer,
) (skipped []uuid.UUID, err error) {
	if s == nil || s.enveloper == nil || s.now == nil || ctx == nil || tx == nil || consumer == nil ||
		scopeID == uuid.Nil || len(sites) == 0 {
		return nil, ErrInvalidInput
	}
	now := storeTime(s.now())
	materials := make([]PublicationMaterial, 0, len(sites))
	defer func() {
		for index := range materials {
			zeroBytes(materials[index].PrivateKeyPEM)
			materials[index].PrivateKeyPEM, materials[index].CertificatePEM = nil, nil
		}
	}()
	for _, site := range sites {
		if site.SiteID == uuid.Nil || site.AssetID == uuid.Nil || site.VersionID == uuid.Nil || site.BindingRevision < 1 {
			return nil, ErrInvalidInput
		}
		var locked struct {
			tenantID uuid.UUID
			domains  []string
		}
		var current bool
		err := tx.QueryRow(ctx, `SELECT scope.tenant_id,COALESCE((
				SELECT array_agg(current_domain.canonical_domain ORDER BY current_domain.canonical_domain)
				FROM (
					SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain,fact.action
					FROM site_domain_facts fact
					WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
					ORDER BY fact.canonical_domain,fact.global_sequence DESC
				) current_domain WHERE current_domain.action='activate'
			),ARRAY[site.domain]::text[]),
			EXISTS(SELECT 1 FROM (SELECT sequence,action,asset_id,version_id FROM certificate_site_binding_facts
			    WHERE tenant_scope_id=site.scope_id AND site_id=site.id ORDER BY sequence DESC LIMIT 1) binding
			  WHERE binding.sequence=$3 AND binding.action='bind' AND binding.asset_id=$4 AND binding.version_id=$5
			    AND binding.version_id=(SELECT version_id FROM certificate_asset_activation_facts
			      WHERE tenant_scope_id=site.scope_id AND asset_id=binding.asset_id ORDER BY sequence DESC LIMIT 1))
			FROM sites site
			JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
			WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL
			FOR SHARE OF site`, scopeID, site.SiteID, site.BindingRevision, site.AssetID, site.VersionID).
			Scan(&locked.tenantID, &locked.domains, &current)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !current {
			skipped = append(skipped, site.SiteID)
			continue
		}
		if err != nil {
			return nil, err
		}
		material, err := s.loadPublicationMaterial(ctx, tx, now, scopeID, locked, Binding{
			TenantScopeID: scopeID, SiteID: site.SiteID, AssetID: site.AssetID, VersionID: site.VersionID,
			Revision: site.BindingRevision, Bound: true,
		}, resolver)
		if redeliveryMaterialUnavailable(err) {
			skipped = append(skipped, site.SiteID)
			continue
		}
		if err != nil {
			return nil, err
		}
		materials = append(materials, material)
	}
	if len(materials) == 0 {
		return skipped, nil
	}
	return skipped, consumer(materials)
}

// redeliveryMaterialUnavailable: loadPublicationMaterial's refusals of the
// version itself (not a database failure).
func redeliveryMaterialUnavailable(err error) bool {
	return errors.Is(err, ErrEnvelopeUnavailable) || errors.Is(err, ErrInvalidTransition) ||
		errors.Is(err, ErrCertificateNotYetValid) || errors.Is(err, ErrCertificateExpired) ||
		errors.Is(err, ErrDomainNotCovered)
}
