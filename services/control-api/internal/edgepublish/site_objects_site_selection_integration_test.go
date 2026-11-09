//go:build integration

package edgepublish

import (
	"slices"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// Two nodes, each in its own line group, a website on each
// group and one following no group, plus an older node in group B. Every
// node gets the same signed root; a node declaring SITE_SELECTION is
// withheld the other group's website, the groupless website goes to every
// node, and the older node is withheld nothing: the publication succeeds
// and its result names it.
func TestSiteObjectKeyWithholdsSitesOfOtherLineGroups(t *testing.T) {
	scope := NewSystemRepublishScope(t)
	nodeA, nodeB, nodeOld := scope.AddNode(t, 12), scope.AddNode(t, 12), scope.AddNode(t, 12)
	older := append(systemRepublishFeatures(12),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_STREAM_SELECTION, ApiVersion: 1})
	selection := append(slices.Clone(older),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_SELECTION, ApiVersion: 1})
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeA, "1.0.35-sitesel", selection)
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeB, "1.0.35-sitesel", selection)
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeOld, "1.0.35-old", older)
	groupA := seedStreamLineGroup(t, scope, "198.51.100.61", nodeA)
	groupB := seedStreamLineGroup(t, scope, "198.51.100.62", nodeB, nodeOld)
	siteA := scope.AddSiteOn(t, "sel-group-a.example.com", 18191, groupA)
	siteB := scope.AddSiteOn(t, "sel-group-b.example.com", 18192, groupB)
	// The fixture website: no line group of its own, and the fixture
	// package's snapshot names none.
	siteAll := scope.SiteID
	scope.Exec(t, `UPDATE sites SET node_group_id=NULL WHERE id=$1`, siteAll)
	scope.AdvanceRevision(t)

	request := scope.fixture.publishRequest("per-node-sites", nodeA)
	request.NodeIDs = []uuid.UUID{nodeA, nodeB, nodeOld}
	result, err := scope.fixture.service.Publish(t.Context(), request)
	if err != nil {
		t.Fatalf("publication with an older node: %v", err)
	}
	roots := map[string]bool{}
	withheld := map[uuid.UUID][]string{}
	for _, nodeID := range request.NodeIDs {
		release := receivedV2Release(t, scope.fixture, result, nodeID, scope.fixture.nodeKeys[nodeID])
		roots[release.RootSHA256] = true
		if len(release.Sites) != 3 {
			t.Fatalf("node %s root has %d websites, want the scope's 3", nodeID, len(release.Sites))
		}
		withheld[nodeID] = release.WithheldSites
	}
	if len(roots) != 1 {
		t.Fatalf("nodes got %d roots, want one shared signed root", len(roots))
	}
	if !slices.Equal(withheld[nodeA], []string{siteB.String()}) || !slices.Equal(withheld[nodeB], []string{siteA.String()}) {
		t.Fatalf("withheld A=%v B=%v (website A %s, B %s)", withheld[nodeA], withheld[nodeB], siteA, siteB)
	}
	if withheld[nodeOld] != nil {
		t.Fatalf("older node withheld %v", withheld[nodeOld])
	}
	if !slices.Equal(result.SiteSelectionUnsupportedNodeIDs, []uuid.UUID{nodeOld}) {
		t.Fatalf("result names %v as unable to withhold websites, want the older node %s", result.SiteSelectionUnsupportedNodeIDs, nodeOld)
	}
	if got := scope.SiteSelectionUnsupported(t); !slices.Equal(got, []string{nodeOld.String()}) {
		t.Fatalf("audit names %v, want the older node", got)
	}
}
