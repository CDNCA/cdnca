//go:build integration

package edgepublish

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Fixtures of the withdrawal tests (edgepublish_test).

// DeclareStreamSelection gives nodeID a session declaring the fixture
// forwards' PROXY protocol and L4_STREAM_SELECTION (the forwards it does not
// serve are withheld).
func (scope *SystemRepublishScope) DeclareStreamSelection(t *testing.T, nodeID uuid.UUID) {
	t.Helper()
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeID, "1.0.35-sel", append(systemRepublishFeatures(12),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_PROXY_PROTOCOL, ApiVersion: 1},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_STREAM_SELECTION, ApiVersion: 1}))
}

// AddStreamLineGroup is a sealed line group of the scope whose enabled
// endpoints are nodes.
func (scope *SystemRepublishScope) AddStreamLineGroup(t *testing.T, address string, nodes ...uuid.UUID) uuid.UUID {
	t.Helper()
	return seedStreamLineGroup(t, scope, address, nodes...)
}

// AddStreamOn adds a TCP forward of the scope on line group groupID.
func (scope *SystemRepublishScope) AddStreamOn(t *testing.T, name string, port uint16, groupID uuid.UUID) uuid.UUID {
	t.Helper()
	id := scope.fixture.createStream(t, name, port, "203.0.113.90", port+100).Forward.ID
	scope.Exec(t, `UPDATE l4_forwards SET node_group_id=$2,backup_node_group_id=NULL WHERE id=$1`, id, groupID)
	return id
}

// DeleteStream soft-deletes a forward as the L4 forward service does.
func (scope *SystemRepublishScope) DeleteStream(t *testing.T, id uuid.UUID) {
	t.Helper()
	scope.Exec(t, `UPDATE l4_forwards SET deleted_at=clock_timestamp(),updated_at=clock_timestamp(),
		revision=revision+1 WHERE id=$1`, id)
}

// DeleteSite soft-deletes a website as the site delete did before its
// cleanups (the row only).
func (scope *SystemRepublishScope) DeleteSite(t *testing.T, id uuid.UUID) {
	t.Helper()
	scope.Exec(t, `UPDATE sites SET deleted_at=clock_timestamp(),updated_at=clock_timestamp(),
		revision=revision+1 WHERE id=$1`, id)
}

// DisableLineGroupNode takes nodeID out of groupID's current endpoints (the
// sealed revision is immutable: the fixture bypasses the triggers).
func (scope *SystemRepublishScope) DisableLineGroupNode(t *testing.T, groupID, nodeID uuid.UUID) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_line_endpoints SET enabled=false
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND node_id=$3`, scope.ScopeID, groupID, nodeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// NodeRelease is what nodeID receives from the scope's latest publication:
// the websites and forwards it serves (root minus its withheld websites and
// forwards).
type NodeRelease struct {
	Sites, Streams []string
}

func (scope *SystemRepublishScope) LatestNodeRelease(t *testing.T, nodeID uuid.UUID) NodeRelease {
	t.Helper()
	var result PublishResult
	if err := scope.Pool.QueryRow(t.Context(), `SELECT rollout_id,config_version_id FROM edge_config_publications
		WHERE configuration_scope_id=$1 ORDER BY source_revision DESC LIMIT 1`, scope.ScopeID).
		Scan(&result.RolloutID, &result.ConfigVersionID); err != nil {
		t.Fatal(err)
	}
	release := receivedV2Release(t, scope.fixture, result, nodeID, scope.fixture.nodeKeys[nodeID])
	var served NodeRelease
	for _, site := range release.Sites {
		if !slices.Contains(release.WithheldSites, site.SiteID) {
			served.Sites = append(served.Sites, site.SiteID)
		}
	}
	if release.Scope.Streams != nil {
		for _, stream := range release.Scope.Streams.StreamsV2 {
			if !slices.Contains(release.L4WithheldStreams, stream.StreamID) {
				served.Streams = append(served.Streams, stream.StreamID)
			}
		}
	}
	slices.Sort(served.Sites)
	slices.Sort(served.Streams)
	return served
}

// HeldConfigVersion is the scope's version nodeID currently runs
// (node_config_state), nil when none.
func (scope *SystemRepublishScope) HeldConfigVersion(t *testing.T, nodeID uuid.UUID) *uuid.UUID {
	t.Helper()
	var held *uuid.UUID
	if err := scope.Pool.QueryRow(t.Context(), `SELECT current_config_version_id FROM node_config_state
		WHERE node_id=$1 AND configuration_scope_id=$2`, nodeID, scope.ScopeID).Scan(&held); err != nil {
		t.Fatal(err)
	}
	return held
}

// DeclareSiteSelection is DeclareStreamSelection plus SITE_SELECTION (the
// websites it does not serve are withheld too).
func (scope *SystemRepublishScope) DeclareSiteSelection(t *testing.T, nodeID uuid.UUID) {
	t.Helper()
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeID, "1.0.35-sitesel", append(systemRepublishFeatures(12),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_PROXY_PROTOCOL, ApiVersion: 1},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_STREAM_SELECTION, ApiVersion: 1},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_SELECTION, ApiVersion: 1}))
}

// AddSiteOn adds an HTTP website of the scope on line group groupID.
func (scope *SystemRepublishScope) AddSiteOn(t *testing.T, domain string, port int, groupID uuid.UUID) uuid.UUID {
	t.Helper()
	id := scope.fixture.createSite(t, domain, port, false).Site.ID
	scope.MoveSite(t, id, groupID)
	return id
}

// MoveSite puts website siteID on line group groupID (修改线路分组).
func (scope *SystemRepublishScope) MoveSite(t *testing.T, siteID, groupID uuid.UUID) {
	t.Helper()
	scope.Exec(t, `UPDATE sites SET node_group_id=$2 WHERE id=$1`, siteID, groupID)
}

// SiteSelectionUnsupported is the latest publication audit's
// site_selection_unsupported_nodes (nil when absent).
func (scope *SystemRepublishScope) SiteSelectionUnsupported(t *testing.T) []string {
	t.Helper()
	var nodes []string
	if err := scope.Pool.QueryRow(t.Context(), `SELECT ARRAY(SELECT jsonb_array_elements_text(
		COALESCE(payload->'site_selection_unsupported_nodes','[]'::jsonb)))
		FROM audit_events WHERE action='edge_publication.publish' AND payload->>'configuration_scope_id'=$1::uuid::text
		ORDER BY occurred_at DESC,stream_position DESC LIMIT 1`, scope.ScopeID).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes) == 0 {
		return nil
	}
	return nodes
}

// DeclareSiteSelectionL2 is DeclareSiteSelection plus L2_ROUTING (a target
// of a publication with an L2 website must declare it).
func (scope *SystemRepublishScope) DeclareSiteSelectionL2(t *testing.T, nodeID uuid.UUID) {
	t.Helper()
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeID, "1.0.35-sitesel-l2", append(systemRepublishFeatures(12),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_PROXY_PROTOCOL, ApiVersion: 1},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_STREAM_SELECTION, ApiVersion: 1},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_SELECTION, ApiVersion: 1},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L2_ROUTING, ApiVersion: edgeconfig.L2RoutingAPIVersion}))
}

// AddL2Config is an L2 configuration of the scope whose enabled members
// are nodes; it returns the configuration and each member's row id.
func (scope *SystemRepublishScope) AddL2Config(t *testing.T, name string, nodes ...uuid.UUID) (uuid.UUID, map[uuid.UUID]uuid.UUID) {
	t.Helper()
	config := uuid.New()
	scope.Exec(t, `INSERT INTO l2_topology_configs(id,tenant_scope_id,name,region,mode,load_method,
		created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,'华东','global','rr',$4,$4,now(),now())`,
		config, scope.ScopeID, name, scope.UserID)
	members := map[uuid.UUID]uuid.UUID{}
	for _, node := range nodes {
		members[node] = uuid.New()
		scope.Exec(t, `INSERT INTO l2_topology_nodes(id,tenant_scope_id,config_id,node_id,created_by_user_id,updated_by_user_id,
			created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5,now(),now())`, members[node], scope.ScopeID, config, node, scope.UserID)
	}
	return config, members
}

// SetL2MemberEnabled enables or disables an L2 configuration member (as
// 停用/启用 in the L2 node list does).
func (scope *SystemRepublishScope) SetL2MemberEnabled(t *testing.T, memberID uuid.UUID, enabled bool) {
	t.Helper()
	scope.Exec(t, `UPDATE l2_topology_nodes SET enabled=$2,updated_at=now() WHERE id=$1`, memberID, enabled)
}

// SetSiteL2 sets a website's L2: mode package (its line group's L2
// configuration), custom (configID) or off.
func (scope *SystemRepublishScope) SetSiteL2(t *testing.T, siteID uuid.UUID, mode string, configID *uuid.UUID) {
	t.Helper()
	scope.Exec(t, `UPDATE site_origin_pools SET l2_mode=$2,l2_config_id=$3 WHERE site_id=$1`, siteID, mode, configID)
}

// SetLineGroupL2 names configID as groupID's L2 configuration (current
// revision row and group; the sealed revision is immutable: the fixture
// bypasses the triggers).
func (scope *SystemRepublishScope) SetLineGroupL2(t *testing.T, groupID uuid.UUID, configID *uuid.UUID) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE node_line_groups SET l2_config_id=$3 WHERE tenant_scope_id=$1 AND id=$2`,
			scope.ScopeID, groupID, configID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_line_group_revisions SET l2_config_id=$3
			WHERE tenant_scope_id=$1 AND line_group_id=$2`, scope.ScopeID, groupID, configID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
