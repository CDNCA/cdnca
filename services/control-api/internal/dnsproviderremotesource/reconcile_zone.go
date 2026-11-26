package dnsproviderremotesource

import (
	"context"
	"errors"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SiteReconcileZones finds the zone 修复域名解析 repairs a site domain in
// the site's own DNS
// account (site_auto_dns_tasks: verified, unrevoked, entered by the tenant —
// never the platform copy) and the longest domain of that account's listing
// (tenant_dns_domains, filled by DNS 域名 refresh through the account) that
// is the name or a parent of it. The reconcile pipeline keys a zone by
// dns_zones (id, revision); a listed domain without such a row gets one here,
// outside CNAME allocation (not the scope default, not random). The snapshot
// carries the name's current provider records.
type SiteReconcileZones struct {
	source   *Source
	snapshot *OwnerSnapshot
	auditor  HubAuditor
}

func NewSiteReconcileZones(source *Source, snapshot *OwnerSnapshot, auditor HubAuditor) (*SiteReconcileZones, error) {
	if source == nil || source.pool == nil || snapshot == nil || auditor == nil {
		return nil, ErrUnavailable
	}
	return &SiteReconcileZones{source: source, snapshot: snapshot, auditor: auditor}, nil
}

// ResolveSiteZone returns the provider snapshot of name for the site. A name
// that is not an active domain of the site is dnsreconcile.ErrPermissionDenied;
// no listed domain of the site's account covering it is
// dnsreconcile.ErrZoneNotHosted.
func (zones *SiteReconcileZones) ResolveSiteZone(ctx context.Context, tenantID, siteID, actorUserID uuid.UUID,
	requestID, name string) (dnscheck.ProviderSnapshot, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if zones == nil || ctx == nil || tenantID == uuid.Nil || siteID == uuid.Nil || actorUserID == uuid.Nil ||
		requestID == "" || !validDNSName(strings.TrimPrefix(name, "*.")) {
		return dnscheck.ProviderSnapshot{}, dnsreconcile.ErrInvalidInput
	}
	var (
		zoneID   uuid.UUID
		revision int64
	)
	err := pgx.BeginFunc(ctx, zones.source.pool, func(tx pgx.Tx) error {
		var (
			scopeID    uuid.UUID
			providerID *uuid.UUID
			siteDomain bool
		)
		err := tx.QueryRow(ctx, `SELECT site.scope_id,
				(SELECT provider.id FROM site_auto_dns_tasks task
				 JOIN dns_providers provider ON provider.scope_id=task.scope_id AND provider.id=task.provider_id
				 WHERE task.site_id=site.id AND task.scope_id=site.scope_id AND provider.status='verified'
				   AND NOT provider.credential_revoked AND provider.managed_by='tenant'),
				site.domain=$3 OR EXISTS (SELECT 1 FROM (
					SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain, fact.action
					FROM site_domain_facts fact WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
					ORDER BY fact.canonical_domain, fact.global_sequence DESC) current
					WHERE current.action='activate' AND current.canonical_domain=$3)
			FROM sites site
			JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
			JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
			WHERE site.id=$1 AND scope.tenant_id=$2 AND site.deleted_at IS NULL`,
			siteID, tenantID, name).Scan(&scopeID, &providerID, &siteDomain)
		if errors.Is(err, pgx.ErrNoRows) {
			return dnsreconcile.ErrPermissionDenied
		}
		if err != nil {
			return err
		}
		if !siteDomain {
			return dnsreconcile.ErrPermissionDenied
		}
		if providerID == nil || *providerID == dnsacme.PlatformProviderCopyID(scopeID) {
			return dnsreconcile.ErrZoneNotHosted
		}
		// The longest listed domain equal to the name (a wildcard by its base)
		// or a parent of it.
		base := strings.TrimPrefix(name, "*.")
		var apex string
		err = tx.QueryRow(ctx, `SELECT apex FROM tenant_dns_domains
			WHERE scope_id=$1 AND provider_id=$2 AND ($3=apex OR right($3, char_length(apex)+1)='.'||apex)
			ORDER BY char_length(apex) DESC LIMIT 1`, scopeID, *providerID, base).Scan(&apex)
		if errors.Is(err, pgx.ErrNoRows) {
			return dnsreconcile.ErrZoneNotHosted
		}
		if err != nil {
			return err
		}
		newID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		created, err := tx.Exec(ctx, `INSERT INTO dns_zones(id,scope_id,provider_id,name,created_by_user_id,
				updated_by_user_id,is_default,provider_zone_apex)
			VALUES($1,$2,$3,$4,$5,$5,false,$4) ON CONFLICT (scope_id,name) DO NOTHING`,
			newID, scopeID, *providerID, apex, actorUserID)
		if err != nil {
			return err
		}
		var zoneProvider uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id,provider_id,revision FROM dns_zones WHERE scope_id=$1 AND name=$2
			FOR SHARE`, scopeID, apex).Scan(&zoneID, &zoneProvider, &revision); err != nil {
			return err
		}
		// The name is another account's zone (or the platform copy's): not
		// this account's to repair.
		if zoneProvider != *providerID {
			return dnsreconcile.ErrZoneNotHosted
		}
		if created.RowsAffected() == 0 {
			return nil
		}
		return zones.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &actorUserID, Action: "dns.zone.create", ResourceType: "dns_zone",
			ResourceID: zoneID.String(), RequestID: requestID, Result: "success",
			Payload: map[string]any{"name": apex, "provider_id": providerID.String()},
		})
	})
	if err != nil {
		if errors.Is(err, dnsreconcile.ErrPermissionDenied) || errors.Is(err, dnsreconcile.ErrZoneNotHosted) {
			return dnscheck.ProviderSnapshot{}, err
		}
		return dnscheck.ProviderSnapshot{}, dnsreconcile.ErrUnavailable
	}
	records, err := zones.snapshot.OwnerRecords(ctx, tenantID, siteID, zoneID, name)
	if err != nil {
		var failure OwnerSnapshotFailure
		if errors.As(err, &failure) && failure.Code == string(dnsproviderremote.CodeZoneNotHosted) {
			return dnscheck.ProviderSnapshot{}, dnsreconcile.ErrZoneNotHosted
		}
		return dnscheck.ProviderSnapshot{}, dnsreconcile.ErrUnavailable
	}
	return dnscheck.ProviderSnapshot{TenantID: tenantID, SiteID: siteID, ZoneID: zoneID, Revision: revision,
		Records: records}, nil
}

// ZoneRevision is the zone's current revision under the same authority the
// reconcile mutations use (reconcileScopeQuery).
func (zones *SiteReconcileZones) ZoneRevision(ctx context.Context, tenantID, siteID, zoneID uuid.UUID) (int64, error) {
	if zones == nil {
		return 0, dnsreconcile.ErrUnavailable
	}
	revision, err := zones.source.CurrentRevision(ctx, dnscheck.ProviderRevisionRequest{
		TenantID: tenantID, SiteID: siteID, ZoneID: zoneID})
	if err != nil {
		return 0, dnsreconcile.ErrUnavailable
	}
	return revision, nil
}
