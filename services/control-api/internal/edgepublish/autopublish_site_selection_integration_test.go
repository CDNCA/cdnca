//go:build integration

package edgepublish_test

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// A node out of a website's line group kept serving
// the website while the scope had other websites for it, and a website moved
// from line group A to B stayed on A's nodes. A node that declares
// SITE_SELECTION is withheld the scope's websites none of whose line groups
// has it; an older node keeps them all, and the publication says so
// (site_selection_unsupported_nodes) without failing.

func siteSelectionNodes(t *testing.T, scope *edgepublish.SystemRepublishScope, selecting, older int) []uuid.UUID {
	t.Helper()
	nodes := make([]uuid.UUID, 0, selecting+older)
	for index := range selecting + older {
		node := scope.AddNode(t, 12)
		if index < selecting {
			scope.DeclareSiteSelection(t, node)
		} else {
			scope.DeclareStreamSelection(t, node) // L4 selection only: an older Agent
		}
		scope.SetPresence(t, node, true, 1)
		nodes = append(nodes, node)
	}
	return nodes
}

func sortedIDs(ids ...uuid.UUID) []string {
	result := make([]string, len(ids))
	for index, id := range ids {
		result[index] = id.String()
	}
	slices.Sort(result)
	return result
}

// Line group 1 has nodes A, B and an older node O; line group 2 has B and O.
// Website 1 is on group 1, website 2 on group 2. Taking B and O out of group
// 1 withholds website 1 from B while website 2 stays on B, A keeps website 1,
// and O (no SITE_SELECTION) still gets both, named in the audit.
func TestAutomaticPublicationWithholdsSiteFromNodeLeavingLineGroup(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	scope.DeleteSite(t, scope.SiteID)
	nodes := siteSelectionNodes(t, scope, 2, 1)
	nodeA, nodeB, nodeO := nodes[0], nodes[1], nodes[2]
	group1 := scope.AddStreamLineGroup(t, "198.51.100.71", nodeA, nodeB, nodeO)
	group2 := scope.AddStreamLineGroup(t, "198.51.100.72", nodeB, nodeO)
	site1 := scope.AddSiteOn(t, "sitesel-1.example.com", 18181, group1)
	site2 := scope.AddSiteOn(t, "sitesel-2.example.com", 18182, group2)
	enablePackagePolicy(t, scope)
	worker := withdrawWorker(t, scope)

	state, code := publishLineGroupChange(t, scope, worker)
	requireReconciling(t, "first publication", state, code)
	if got := scope.LatestNodeRelease(t, nodeA).Sites; !slices.Equal(got, sortedIDs(site1)) {
		t.Fatalf("node A (group 1 only) serves %v, want website 1", got)
	}
	if got := scope.LatestNodeRelease(t, nodeB).Sites; !slices.Equal(got, sortedIDs(site1, site2)) {
		t.Fatalf("node B (both groups) serves %v, want both websites", got)
	}
	// O is in both groups: it would be withheld nothing, so it is not named.
	if got := scope.SiteSelectionUnsupported(t); got != nil {
		t.Fatalf("first publication names %v as unable to withhold websites", got)
	}
	scope.SettleDeployments(t)

	scope.DisableLineGroupNode(t, group1, nodeB)
	scope.DisableLineGroupNode(t, group1, nodeO)
	state, code = publishLineGroupChange(t, scope, worker)
	requireReconciling(t, "after group 1 dropped B and O", state, code)
	if latest := scope.LatestPublication(t); !slices.Equal(latest.NodeIDs, sortedNodes(nodeA, nodeB, nodeO)) {
		t.Fatalf("publication went to %v, want A, B and O", latest.NodeIDs)
	}
	if got := scope.LatestNodeRelease(t, nodeB).Sites; !slices.Equal(got, sortedIDs(site2)) {
		t.Fatalf("node B out of group 1 serves %v, want website 2 only", got)
	}
	if got := scope.LatestNodeRelease(t, nodeA).Sites; !slices.Equal(got, sortedIDs(site1)) {
		t.Fatalf("node A serves %v, want website 1 untouched", got)
	}
	if got := scope.LatestNodeRelease(t, nodeO).Sites; !slices.Equal(got, sortedIDs(site1, site2)) {
		t.Fatalf("older node O serves %v, want every website as before", got)
	}
	if got := scope.SiteSelectionUnsupported(t); !slices.Equal(got, sortedIDs(nodeO)) {
		t.Fatalf("audit names %v as unable to withhold websites, want O", got)
	}
}

// Website 1 moves from line group A to B: A's node is withheld it (and keeps
// its other website), B's node gets it.
func TestAutomaticPublicationMovesSiteBetweenLineGroups(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	scope.DeleteSite(t, scope.SiteID)
	nodes := siteSelectionNodes(t, scope, 2, 0)
	nodeA, nodeB := nodes[0], nodes[1]
	groupA := scope.AddStreamLineGroup(t, "198.51.100.73", nodeA)
	groupB := scope.AddStreamLineGroup(t, "198.51.100.74", nodeB)
	moved := scope.AddSiteOn(t, "sitesel-move.example.com", 18183, groupA)
	stays := scope.AddSiteOn(t, "sitesel-stay.example.com", 18184, groupA)
	other := scope.AddSiteOn(t, "sitesel-other.example.com", 18185, groupB)
	enablePackagePolicy(t, scope)
	worker := withdrawWorker(t, scope)

	state, code := publishLineGroupChange(t, scope, worker)
	requireReconciling(t, "first publication", state, code)
	if got := scope.LatestNodeRelease(t, nodeA).Sites; !slices.Equal(got, sortedIDs(moved, stays)) {
		t.Fatalf("node A serves %v before the move", got)
	}
	if got := scope.LatestNodeRelease(t, nodeB).Sites; !slices.Equal(got, sortedIDs(other)) {
		t.Fatalf("node B serves %v before the move", got)
	}
	scope.SettleDeployments(t)

	scope.MoveSite(t, moved, groupB)
	state, code = publishLineGroupChange(t, scope, worker)
	requireReconciling(t, "after the move", state, code)
	if got := scope.LatestNodeRelease(t, nodeA).Sites; !slices.Equal(got, sortedIDs(stays)) {
		t.Fatalf("node A after the move serves %v, want only the website that stayed", got)
	}
	if got := scope.LatestNodeRelease(t, nodeB).Sites; !slices.Equal(got, sortedIDs(moved, other)) {
		t.Fatalf("node B after the move serves %v, want the moved website too", got)
	}
	if got := scope.SiteSelectionUnsupported(t); got != nil {
		t.Fatalf("audit names %v, want none (every node declares SITE_SELECTION)", got)
	}
}
