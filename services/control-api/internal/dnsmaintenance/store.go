package dnsmaintenance

import (
	"context"
	"fmt"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RepairTarget is one settled CNAME owner of a tenant scope with its frozen
// allocation facts (site, zone, line group and acting user).
type RepairTarget struct {
	TenantID, ScopeID, SiteID uuid.UUID
	ProviderID, ZoneID        uuid.UUID
	ZoneName                  string
	ZoneApex                  string // provider_zone_apex (473), "" before it is known
	ZoneRevision              int64
	NodeGroupID               uuid.UUID
	NodeGroupRevision         int64
	Owner                     string
	ActorUserID               uuid.UUID
	RequestID                 string
}

type Store struct {
	pool *pgxpool.Pool
	apex dnsproviderremote.ZoneApexResolver
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, ErrInvalidInput
	}
	return &Store{pool: pool, apex: dnsproviderremote.NewZoneApexResolver()}, nil
}

// The repair anchor (migration 507): the frozen target's site, or its stream.
// Only an allocation a live owner still binds is repaired (the in-use rule of
// cname_claim_released_476): an undeleted site's binding to it, or an
// undeleted CNAME-mode L4 forward's binding. A deleted site's owner is retired
// (476) and removed by the retirement worker or 清除CDN无关解析, never
// rewritten here (fix-dnsrepair: it failed dns_no_serving_endpoint).
const repairTargetSQL = `SELECT allocation.tenant_id, allocation.tenant_scope_id, COALESCE(frozen.site_id, frozen.stream_id),
		zone.provider_id, zone.id, zone.name, zone.revision, frozen.node_group_id, line_group.current_revision,
		frozen.owner_name, frozen.actor_user_id, frozen.request_id, COALESCE(zone.provider_zone_apex,'')
	FROM cname_allocations allocation
	JOIN cname_allocation_targets frozen ON frozen.tenant_id=allocation.tenant_id AND frozen.job_id=allocation.job_id
	JOIN dns_zones zone ON zone.scope_id=frozen.tenant_scope_id AND zone.id=frozen.zone_id AND zone.status<>'failed'
	JOIN node_line_groups line_group ON line_group.tenant_scope_id=frozen.node_group_scope_id
	 AND line_group.id=frozen.node_group_id AND line_group.deleted_at IS NULL
	WHERE allocation.state='done' AND allocation.tenant_scope_id=$1 AND zone.provider_id=$2
	  AND (EXISTS (SELECT 1 FROM cname_site_bindings binding
	        JOIN sites site ON site.scope_id=binding.tenant_scope_id AND site.id=binding.site_id AND site.deleted_at IS NULL
	        WHERE binding.tenant_scope_id=allocation.tenant_scope_id
          AND allocation.id IN (binding.current_allocation_id,binding.lkg_allocation_id))
	    OR EXISTS (SELECT 1 FROM cname_stream_bindings binding
	        JOIN l4_forwards forward ON forward.scope_id=binding.tenant_scope_id AND forward.id=binding.stream_id
	         AND forward.deleted_at IS NULL AND (forward.cname_domain IS NOT NULL OR forward.cname_mode IS NOT NULL)
	        WHERE binding.tenant_scope_id=allocation.tenant_scope_id AND binding.allocation_id=allocation.id))`

func scanRepairTarget(row pgx.CollectableRow) (RepairTarget, error) {
	var value RepairTarget
	err := row.Scan(&value.TenantID, &value.ScopeID, &value.SiteID, &value.ProviderID, &value.ZoneID, &value.ZoneName,
		&value.ZoneRevision, &value.NodeGroupID, &value.NodeGroupRevision, &value.Owner, &value.ActorUserID, &value.RequestID,
		&value.ZoneApex)
	value.Owner = canonicalOwner(value.Owner)
	return value, err
}

// RepairTargets lists the settled CNAME owners on the scope's provider.
func (store *Store) RepairTargets(ctx context.Context, scopeID, providerID uuid.UUID) ([]RepairTarget, error) {
	rows, err := store.pool.Query(ctx, repairTargetSQL+` ORDER BY frozen.owner_name`, scopeID, providerID)
	if err != nil {
		return nil, fmt.Errorf("list DNS repair targets: %w", err)
	}
	return pgx.CollectRows(rows, scanRepairTarget)
}

// RepairTarget loads the settled CNAME owner of a repair item.
func (store *Store) RepairTarget(ctx context.Context, scopeID, providerID uuid.UUID, owner string) (RepairTarget, error) {
	rows, err := store.pool.Query(ctx, repairTargetSQL+` AND lower(rtrim(frozen.owner_name, '.'))=lower(rtrim($3, '.')) LIMIT 1`,
		scopeID, providerID, owner)
	if err != nil {
		return RepairTarget{}, fmt.Errorf("load DNS repair target: %w", err)
	}
	targets, err := pgx.CollectRows(rows, scanRepairTarget)
	if err != nil {
		return RepairTarget{}, err
	}
	if len(targets) == 0 {
		return RepairTarget{}, pgx.ErrNoRows
	}
	return targets[0], nil
}

// ServingValues are the A/AAAA values a CNAME owner must publish now
// (node_line_endpoint_published), as the retarget planner computes them.
func (store *Store) ServingValues(ctx context.Context, target RepairTarget) (cnameallocation.TargetValues, error) {
	// A market- or aggregated-edge-served site is repaired to its default
	// line CNAME, never back to node addresses.
	market, err := cnameallocation.DefaultLineTarget(ctx, store.pool, target.ScopeID, target.SiteID)
	if err != nil {
		return cnameallocation.TargetValues{}, fmt.Errorf("load market target: %w", err)
	}
	if market != "" {
		return cnameallocation.TargetValues{CNAME: market}, nil
	}
	// The ACME HTTP-01 serving gate (migration 342) keeps nodes that owe the
	// site a cleanup, or joined during an open epoch, off it.
	rows, err := store.pool.Query(ctx, `SELECT host(address) FROM node_line_endpoint_published endpoint
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=$3 AND published
		  AND (endpoint.node_id IS NULL OR acme_http01_site_node_serving_blocked($1,$4,endpoint.node_id) IS NULL)
		ORDER BY address`,
		target.ScopeID, target.NodeGroupID, target.NodeGroupRevision, target.SiteID)
	if err != nil {
		return cnameallocation.TargetValues{}, fmt.Errorf("load serving endpoints: %w", err)
	}
	addresses, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return cnameallocation.TargetValues{}, err
	}
	values := cnameallocation.TargetValues{}
	for _, address := range addresses {
		if strings.Contains(address, ":") {
			values.AAAA = append(values.AAAA, address)
		} else {
			values.A = append(values.A, address)
		}
	}
	return values, nil
}

// PublishSettings are the TTL / IP weights the CNAME owner is written with.
func (store *Store) PublishSettings(ctx context.Context, target RepairTarget) (cnameallocation.PublishSettings, error) {
	return cnameallocation.LoadPublishSettings(ctx, store.pool, target.ScopeID, target.ZoneID,
		target.NodeGroupID, target.NodeGroupRevision)
}

// ClaimedHostnames are the CNAME hostnames allocated under the given zone
// copies (all tenants) and not released by a retirement, canonical with a
// trailing dot.
func (store *Store) ClaimedHostnames(ctx context.Context, zoneIDs []uuid.UUID) (map[string]bool, error) {
	result := map[string]bool{}
	if len(zoneIDs) == 0 {
		return result, nil
	}
	// A retired claim no live site serves (migration 478) is no longer in use.
	rows, err := store.pool.Query(ctx, `SELECT hostname FROM cname_hostname_claims
		WHERE zone_id = ANY($1) AND NOT cname_claim_released_476(id)`, zoneIDs)
	if err != nil {
		return nil, fmt.Errorf("load claimed CNAME hostnames: %w", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		result[canonicalOwner(name)] = true
	}
	return result, nil
}

func canonicalOwner(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")) + "."
}

// PendingTenants are the tenants with claimable 记录修复 / 清除CDN无关解析 jobs.
func (store *Store) PendingTenants(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := store.pool.Query(ctx, `SELECT DISTINCT tenant_id FROM background_jobs
		WHERE kind = ANY($1::text[]) AND state IN ('queued','running') AND claimable_at<=clock_timestamp()
		ORDER BY tenant_id LIMIT 128`, []string{RepairJobKind, CleanupJobKind})
	if err != nil {
		return nil, fmt.Errorf("list DNS maintenance tenants: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// TenantScope is the tenant's scope (one tenant scope per tenant).
func (store *Store) TenantScope(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, error) {
	var scopeID uuid.UUID
	err := store.pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='tenant' AND tenant_id=$1 ORDER BY id LIMIT 1`,
		tenantID).Scan(&scopeID)
	return scopeID, err
}

// ZoneApex returns target.ZoneApex or looks it up once (dnsacme.EnsureZoneApex).
func (store *Store) ZoneApex(ctx context.Context, target RepairTarget, providerType string,
	credentials map[string]string) (string, error) {
	return dnsacme.EnsureZoneApex(ctx, store.pool, store.apex, target.ScopeID, target.ZoneID, providerType, credentials,
		target.ZoneName, target.ZoneApex)
}
