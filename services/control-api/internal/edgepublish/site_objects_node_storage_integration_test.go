//go:build integration

package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// fix-nodesettings: a node's key document carries its 节点设置 storage
// (cache directory, limit in bytes, log directory) when the node declares
// NODE_STORAGE; an older node, and a node with nothing set, get none. Only a
// NODE_STORAGE v2 node gets node_facts_at, later on each publication.
func TestSiteObjectKeyCarriesNodeStorage(t *testing.T) {
	scope := NewSystemRepublishScope(t)
	nodeNew, nodeOld, nodeUnset, nodeFacts := scope.AddNode(t, 6), scope.AddNode(t, 6), scope.AddNode(t, 6), scope.AddNode(t, 6)
	withStorage := append(systemRepublishFeatures(6),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_STORAGE, ApiVersion: 1})
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeNew, "1.0.35-storage", withStorage)
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeUnset, "1.0.35-storage", withStorage)
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeFacts, "1.0.35-storage", append(systemRepublishFeatures(6),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_STORAGE, ApiVersion: siteobject.NodeStorageNodeFactsAPIVersion}))
	scope.Exec(t, `UPDATE nodes SET management_settings=management_settings ||
		'{"cache_directory":"/data/cdnca-cache","cache_limit_gb":20,"log_directory":"/data/cdnca-logs"}'::jsonb
		WHERE id=ANY($1::uuid[])`, []uuid.UUID{nodeNew, nodeOld, nodeFacts})
	want := siteobject.NodeStorage{CacheDirectory: "/data/cdnca-cache", CacheMaxBytes: 20 << 30, LogDirectory: "/data/cdnca-logs"}
	var factsAt int64
	for round, name := range []string{"node-storage", "node-storage-again"} {
		scope.AdvanceRevision(t)
		request := scope.fixture.publishRequest(name, nodeNew)
		request.NodeIDs = []uuid.UUID{nodeNew, nodeOld, nodeUnset, nodeFacts}
		result, err := scope.fixture.service.Publish(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		roots := map[string]bool{}
		storage := map[uuid.UUID]*siteobject.NodeStorage{}
		at := map[uuid.UUID]int64{}
		for _, nodeID := range request.NodeIDs {
			release := receivedV2Release(t, scope.fixture, result, nodeID, scope.fixture.nodeKeys[nodeID])
			roots[release.RootSHA256] = true
			storage[nodeID] = release.NodeStorage
			at[nodeID] = release.NodeFactsAt
		}
		if len(roots) != 1 {
			t.Fatalf("nodes got %d roots", len(roots))
		}
		if storage[nodeNew] == nil || *storage[nodeNew] != want || storage[nodeOld] != nil || storage[nodeUnset] != nil ||
			storage[nodeFacts] == nil || *storage[nodeFacts] != want {
			t.Fatalf("storage = new %+v old %+v unset %+v v2 %+v", storage[nodeNew], storage[nodeOld], storage[nodeUnset], storage[nodeFacts])
		}
		// A NODE_STORAGE v1 node refuses the unknown field: none for it.
		if at[nodeNew] != 0 || at[nodeOld] != 0 || at[nodeUnset] != 0 || at[nodeFacts] <= factsAt {
			t.Fatalf("round %d node_facts_at = v1 %d/%d/%d v2 %d (previous %d)", round, at[nodeNew], at[nodeOld], at[nodeUnset],
				at[nodeFacts], factsAt)
		}
		factsAt = at[nodeFacts]
		scope.SettleDeployments(t)
	}
}
