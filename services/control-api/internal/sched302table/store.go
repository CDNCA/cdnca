package sched302table

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// onlineWithin / loadWithin: presence and load older than this do not count.
const loadWithin = 2 * time.Minute

// LoadSites reads every enabled schedule302 site with the published
// endpoints of its line group. The line group is the one DNS schedules the
// site on: its CNAME allocation's frozen group (cname_allocation_targets),
// else the site's own node_group_id.
func LoadSites(ctx context.Context, pool *pgxpool.Pool, now time.Time) ([]Site, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `WITH scheduled AS (
			SELECT setting.site_id,setting.target,setting.sign_key,site.scope_id,site.http_ports,
			       ARRAY(SELECT DISTINCT current_domain.canonical_domain FROM (
			           SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain,fact.action
			           FROM site_domain_facts fact WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
			           ORDER BY fact.canonical_domain,fact.global_sequence DESC) current_domain
			         WHERE current_domain.action='activate') AS domains,
			       site.domain,
			       COALESCE((SELECT frozen.node_group_scope_id FROM cname_site_bindings binding
			                 JOIN cname_allocations allocation ON allocation.tenant_scope_id=binding.tenant_scope_id
			                  AND allocation.id=binding.current_allocation_id AND allocation.state='done'
			                 JOIN cname_allocation_targets frozen ON frozen.tenant_id=allocation.tenant_id AND frozen.job_id=allocation.job_id
			                 WHERE binding.site_id=site.id LIMIT 1),
			                (SELECT line_group.tenant_scope_id FROM node_line_groups line_group
			                 WHERE line_group.id=COALESCE(site.node_group_id,(subscription.product_snapshot->'spec'->>'node_group_id')::uuid)
			                   AND line_group.deleted_at IS NULL)) AS group_scope_id,
			       COALESCE((SELECT frozen.node_group_id FROM cname_site_bindings binding
			                 JOIN cname_allocations allocation ON allocation.tenant_scope_id=binding.tenant_scope_id
			                  AND allocation.id=binding.current_allocation_id AND allocation.state='done'
			                 JOIN cname_allocation_targets frozen ON frozen.tenant_id=allocation.tenant_id AND frozen.job_id=allocation.job_id
			                 WHERE binding.site_id=site.id LIMIT 1), site.node_group_id,
			                (subscription.product_snapshot->'spec'->>'node_group_id')::uuid) AS group_id
			FROM site_schedule302_settings setting
			JOIN sites site ON site.id=setting.site_id AND site.scope_id=setting.scope_id
			-- a site following its package uses the package's primary group (sec-followup)
			LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
			 AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
			WHERE site.deleted_at IS NULL AND site.enabled
		)
		SELECT scheduled.site_id,scheduled.target,scheduled.sign_key,scheduled.http_ports,scheduled.domains,scheduled.domain,
		       endpoint.node_id,host(published.address),endpoint.region,endpoint.carrier,endpoint.weight,
		       COALESCE(presence.status='online',false),COALESCE(node.management_settings->>'schedule302_hostname',''),
		       COALESCE((SELECT round(load.cpu_percent)::int FROM node_load_latest load
		                 WHERE load.node_id=endpoint.node_id AND load.metrics_known AND load.observed_at>$1),-1)
		FROM scheduled
		JOIN node_line_groups line_group ON line_group.tenant_scope_id=scheduled.group_scope_id
		 AND line_group.id=scheduled.group_id AND line_group.deleted_at IS NULL
		JOIN node_line_endpoint_published published ON published.tenant_scope_id=line_group.tenant_scope_id
		 AND published.line_group_id=line_group.id AND published.config_revision=line_group.current_revision
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=published.tenant_scope_id
		 AND endpoint.line_group_id=published.line_group_id AND endpoint.config_revision=published.config_revision
		 AND endpoint.id=published.endpoint_id
		JOIN nodes node ON node.id=endpoint.node_id AND node.admin_state='active'
		LEFT JOIN node_presence presence ON presence.node_id=node.id
		WHERE published.published AND endpoint.node_id IS NOT NULL
		ORDER BY scheduled.site_id,endpoint.node_id,published.address`, now.Add(-loadWithin))
	if err != nil {
		return nil, fmt.Errorf("load schedule302 sites: %w", err)
	}
	defer rows.Close()
	var sites []Site
	for rows.Next() {
		var siteID, nodeID uuid.UUID
		var target, primary, address, region, carrier, hostname string
		var key []byte
		var httpPorts, domains []string
		var weight, load int
		var online bool
		if err := rows.Scan(&siteID, &target, &key, &httpPorts, &domains, &primary, &nodeID, &address, &region, &carrier,
			&weight, &online, &hostname, &load); err != nil {
			return nil, fmt.Errorf("scan schedule302 site: %w", err)
		}
		parsed, err := netip.ParseAddr(address)
		if err != nil {
			return nil, fmt.Errorf("schedule302 endpoint address %q: %w", address, err)
		}
		if len(sites) == 0 || sites[len(sites)-1].ID != siteID {
			sites = append(sites, Site{ID: siteID, Target: target, Key: key, Hosts: siteHosts(primary, domains),
				HTTPPorts: ports(httpPorts)})
		}
		current := &sites[len(sites)-1]
		current.Endpoints = append(current.Endpoints, Endpoint{NodeID: nodeID, Address: parsed, Region: region,
			Carrier: carrier, Weight: weight, Online: online, Hostname: hostname, Load: load})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read schedule302 sites: %w", err)
	}
	return sites, nil
}

// siteHosts: the primary first, then the other active names sorted.
func siteHosts(primary string, domains []string) []string {
	hosts := []string{primary}
	others := make([]string, 0, len(domains))
	for _, domain := range domains {
		if domain != primary {
			others = append(others, domain)
		}
	}
	sort.Strings(others)
	return append(hosts, others...)
}

func ports(values []string) []int {
	result := make([]int, 0, len(values))
	for _, value := range values {
		if port, err := strconv.Atoi(value); err == nil && port > 0 && port < 65536 {
			result = append(result, port)
		}
	}
	sort.Ints(result)
	return result
}

// pushState is a node's last pushed table.
type pushState struct {
	revision int64
	digest   [32]byte
	pushedAt time.Time
}

func loadPushStates(ctx context.Context, pool *pgxpool.Pool) (map[uuid.UUID]pushState, error) {
	rows, err := pool.Query(ctx, `SELECT node_id,revision,content_sha256,pushed_at FROM node_schedule302_tables`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := map[uuid.UUID]pushState{}
	for rows.Next() {
		var nodeID uuid.UUID
		var state pushState
		var digest []byte
		if err := rows.Scan(&nodeID, &state.revision, &digest, &state.pushedAt); err != nil {
			return nil, err
		}
		copy(state.digest[:], digest)
		states[nodeID] = state
	}
	return states, rows.Err()
}

func savePushState(ctx context.Context, pool *pgxpool.Pool, nodeID uuid.UUID, state pushState) error {
	_, err := pool.Exec(ctx, `INSERT INTO node_schedule302_tables(node_id,revision,content_sha256,pushed_at)
		VALUES($1,$2,$3,$4) ON CONFLICT(node_id) DO UPDATE SET revision=EXCLUDED.revision,
			content_sha256=EXCLUDED.content_sha256,pushed_at=EXCLUDED.pushed_at
		WHERE node_schedule302_tables.revision<EXCLUDED.revision`, nodeID, state.revision, state.digest[:], state.pushedAt)
	return err
}
