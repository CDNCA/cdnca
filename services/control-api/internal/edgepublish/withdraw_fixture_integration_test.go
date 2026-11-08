//go:build integration

package edgepublish

import (
	"slices"
	"testing"

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
// the websites and forwards it serves (root minus its withheld forwards).
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
		served.Sites = append(served.Sites, site.SiteID)
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
