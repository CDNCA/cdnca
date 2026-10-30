package edgepublish

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CurrentNodeNetworksTx is the DDoS node network exemption a publication
// compiled now would carry (system.ddos.node_networks): every non-retired
// node's primary IPv4/IPv6 and secondary IPs, canonical.
func CurrentNodeNetworksTx(ctx context.Context, tx pgx.Tx) ([]string, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInvalidInput
	}
	addresses, err := loadNodeNetworks(ctx, tx)
	if err != nil {
		return nil, err
	}
	value, err := edgeconfig.NewSiteRuntimeDDoS(edgeconfig.DefaultDDoSProtection(), addresses)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return value.NodeNetworks, nil
}

// StaleNodeNetworkScopesTx is, in scope order (the lock order of their
// republication), every tenant scope whose latest publication carries DDoS
// protection with node networks other than networks:
// its nodes may ban node to node traffic.
func StaleNodeNetworkScopesTx(ctx context.Context, tx pgx.Tx, networks []string) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInvalidInput
	}
	releases, err := latestTenantReleasesTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	var scopes []uuid.UUID
	for _, release := range releases {
		var document struct {
			System *struct {
				DDoS *edgeconfig.SiteRuntimeDDoS `json:"ddos"`
			} `json:"system"`
		}
		if json.Unmarshal(release.snapshot, &document) != nil || document.System == nil || document.System.DDoS == nil {
			continue
		}
		if !slices.Equal(document.System.DDoS.NodeNetworks, networks) {
			scopes = append(scopes, release.scopeID)
		}
	}
	return scopes, nil
}

// refreshNodeNetworks replaces a redelivered document's node networks with
// the current ones: node addresses are platform facts, never a tenant edit
// the stop overlay must hold back.
func refreshNodeNetworks(ctx context.Context, tx pgx.Tx, system *edgeconfig.SiteRuntimeSystem) (*edgeconfig.SiteRuntimeSystem, error) {
	if system == nil || system.DDoS == nil {
		return system, nil
	}
	networks, err := CurrentNodeNetworksTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	refreshed := *system
	ddos := *system.DDoS
	ddos.NodeNetworks = networks
	refreshed.DDoS = &ddos
	return &refreshed, nil
}

// NodeRegionsTx is every live node's region catalog display ID ("" = none)
// as "node=display_id" lines in node order: region overrides follow it, so
// a node changing region changes this (NodeNetworksWatcher).
func NodeRegionsTx(ctx context.Context, tx pgx.Tx) ([]string, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, `SELECT node.id::text||'='||COALESCE((SELECT region.display_id::text FROM region_catalog region
			JOIN access_scopes platform ON platform.id=region.platform_scope_id AND platform.kind='platform'
			WHERE region.name=btrim(node.region) LIMIT 1),'')
		FROM nodes node WHERE node.admin_state<>'retired' ORDER BY node.id`)
	if err != nil {
		return nil, fmt.Errorf("%w: load node regions", ErrPersistence)
	}
	lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("%w: load node regions", ErrPersistence)
	}
	return lines, nil
}

// StaleNodeNginxScopesTx is, in scope order, every tenant scope whose latest
// publication carries other per-node nginx bases (region and node
// overrides) than its nodes' current regions give: a node changed region.
func StaleNodeNginxScopesTx(ctx context.Context, tx pgx.Tx) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInvalidInput
	}
	releases, err := latestTenantReleasesTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	var scopes []uuid.UUID
	for _, release := range releases {
		var document struct {
			System *edgeconfig.SiteRuntimeSystem `json:"system"`
		}
		if json.Unmarshal(release.snapshot, &document) != nil || document.System == nil {
			continue
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT deployment.node_id FROM node_deployments deployment
			JOIN edge_config_publications publication ON publication.rollout_id=deployment.rollout_id
			WHERE publication.configuration_scope_id=$1 AND publication.source_revision=$2 ORDER BY 1`,
			release.scopeID, release.sourceRevision)
		if err != nil {
			return nil, fmt.Errorf("%w: load publication nodes", ErrPersistence)
		}
		nodeIDs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return nil, fmt.Errorf("%w: load publication nodes", ErrPersistence)
		}
		current, err := refreshNodeNginx(ctx, tx, document.System, nodeIDs)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(current.NodeNginx, document.System.NodeNginx) {
			scopes = append(scopes, release.scopeID)
		}
	}
	return scopes, nil
}

// NodeLocationsDigestTx digests every live node's IP 归属 as L2 node
// conditions match it (country code, ISP, province, city; fix-nodeipgeo).
func NodeLocationsDigestTx(ctx context.Context, tx pgx.Tx) ([]byte, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInvalidInput
	}
	var digest []byte
	// chr(31) (unit separator): PostgreSQL text cannot hold chr(0).
	err := tx.QueryRow(ctx, `SELECT sha256(convert_to(COALESCE(string_agg(node.id::text||chr(31)||
		COALESCE(node.management_settings#>>'{ip_location,country_code}','')||chr(31)||
		COALESCE(node.management_settings#>>'{ip_location,isp}','')||chr(31)||
		COALESCE(node.management_settings#>>'{ip_location,province}','')||chr(31)||
		COALESCE(node.management_settings#>>'{ip_location,city}',''),chr(10) ORDER BY node.id),''),'UTF8'))
		FROM nodes node WHERE node.admin_state<>'retired'`).Scan(&digest)
	if err != nil {
		return nil, fmt.Errorf("%w: load node locations", ErrPersistence)
	}
	return digest, nil
}

// NodeLocationScopesTx is, in scope order, every tenant scope with a live L2
// condition matching node country code, ISP, province or city: what a node
// IP 归属 change can move.
func NodeLocationScopesTx(ctx context.Context, tx pgx.Tx) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT condition.tenant_scope_id FROM l2_topology_conditions condition
		WHERE condition.deleted_at IS NULL AND EXISTS (SELECT 1 FROM jsonb_array_elements(condition.rules) rule
			WHERE rule->>'field' IN ('node_country','node_isp','node_province','node_city'))
		ORDER BY 1`)
	if err != nil {
		return nil, fmt.Errorf("%w: load node location scopes", ErrPersistence)
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("%w: scan node location scopes", ErrPersistence)
	}
	return scopes, nil
}
