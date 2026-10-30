//go:build integration

package edgepublish

import (
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// fz-x12（待出包前全量跑）: a node's key document carries its region's
// catalog code (a Chinese-named region's region-<display_id>) when the node
// declares NODE_REGION; an older node, and a node without a region, get
// none. Every node still gets the one signed root.
func TestSiteObjectKeyCarriesNodeRegionCode(t *testing.T) {
	scope := NewSystemRepublishScope(t)
	nodeEast, nodeOld, nodeNone := scope.AddNode(t, 6), scope.AddNode(t, 6), scope.AddNode(t, 6)
	withRegion := append(systemRepublishFeatures(6),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_REGION, ApiVersion: 1})
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeEast, "1.0.35-region", withRegion)
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeNone, "1.0.35-region", withRegion)
	var platform uuid.UUID
	if err := scope.Pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' ORDER BY id LIMIT 1`).Scan(&platform); err != nil {
		t.Fatal(err)
	}
	var code string
	if err := scope.Pool.QueryRow(t.Context(), `INSERT INTO region_catalog(id,platform_scope_id,name)
		VALUES(gen_random_uuid(),$1,'华东') RETURNING code`, platform).Scan(&code); err != nil {
		t.Fatal(err)
	}
	scope.Exec(t, `UPDATE nodes SET region='华东' WHERE id=ANY($1::uuid[])`, []uuid.UUID{nodeEast, nodeOld})
	scope.Exec(t, `UPDATE nodes SET region='' WHERE id=$1`, nodeNone)
	scope.AdvanceRevision(t)

	request := scope.fixture.publishRequest("node-region", nodeEast)
	request.NodeIDs = []uuid.UUID{nodeEast, nodeOld, nodeNone}
	result, err := scope.fixture.service.Publish(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	roots := map[string]bool{}
	regions := map[uuid.UUID]string{}
	for _, nodeID := range request.NodeIDs {
		release := receivedV2Release(t, scope.fixture, result, nodeID, scope.fixture.nodeKeys[nodeID])
		roots[release.RootSHA256] = true
		regions[nodeID] = release.NodeRegion
	}
	if len(roots) != 1 {
		t.Fatalf("nodes got %d roots", len(roots))
	}
	if !strings.HasPrefix(code, "region-") || regions[nodeEast] != code || regions[nodeOld] != "" || regions[nodeNone] != "" {
		t.Fatalf("regions = %v (华东 code %q)", regions, code)
	}
}
