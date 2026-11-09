//go:build integration

package edgepublish_test

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// L2: an L2 member of a website's L2
// configuration serves the website (its L1 nodes send requests through it)
// even when it is in none of the website's line groups, so it must not be
// withheld the website; a disabled member, or a website with its L2 off, goes
// by the line groups only. Node L is the website's line group, node M is in
// another group (another website, so it stays a target) and is the L2.
func TestAutomaticPublicationKeepsSiteOnItsL2Members(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	scope.DeleteSite(t, scope.SiteID)
	nodeL, nodeM := scope.AddNode(t, 12), scope.AddNode(t, 12)
	for _, node := range []uuid.UUID{nodeL, nodeM} {
		scope.DeclareSiteSelectionL2(t, node)
		scope.SetPresence(t, node, true, 1)
	}
	groupS := scope.AddStreamLineGroup(t, "198.51.100.75", nodeL)
	groupT := scope.AddStreamLineGroup(t, "198.51.100.76", nodeM)
	site := scope.AddSiteOn(t, "sitesel-l2.example.com", 18186, groupS)
	other := scope.AddSiteOn(t, "sitesel-l2-other.example.com", 18187, groupT)
	custom, members := scope.AddL2Config(t, "sitesel L2 custom", nodeM)
	scope.SetSiteL2(t, site, "custom", &custom)
	enablePackagePolicy(t, scope)
	worker := withdrawWorker(t, scope)

	publish := func(label string) (served map[uuid.UUID][]string) {
		t.Helper()
		state, code := publishLineGroupChange(t, scope, worker)
		requireReconciling(t, label, state, code)
		if latest := scope.LatestPublication(t); !slices.Equal(latest.NodeIDs, sortedNodes(nodeL, nodeM)) {
			t.Fatalf("%s: publication went to %v, want L and M", label, latest.NodeIDs)
		}
		served = map[uuid.UUID][]string{nodeL: scope.LatestNodeRelease(t, nodeL).Sites, nodeM: scope.LatestNodeRelease(t, nodeM).Sites}
		if !slices.Equal(served[nodeL], sortedIDs(site)) {
			t.Fatalf("%s: node L (the website's line group) serves %v, want the website", label, served[nodeL])
		}
		scope.SettleDeployments(t)
		return served
	}

	// 1. custom L2 with M enabled: M is in no line group of the website and
	// keeps it.
	if got := publish("custom L2, member enabled")[nodeM]; !slices.Equal(got, sortedIDs(site, other)) {
		t.Fatalf("L2 member M serves %v, want the website it is the L2 of and its own", got)
	}
	// 2. the member disabled: M is no L2 of the website any more.
	scope.SetL2MemberEnabled(t, members[nodeM], false)
	if got := publish("custom L2, member disabled")[nodeM]; !slices.Equal(got, sortedIDs(other)) {
		t.Fatalf("disabled L2 member M serves %v, want the website withheld", got)
	}
	// 3. enabled again, through the package mode (the line group's L2
	// configuration) instead of the website's own.
	scope.SetL2MemberEnabled(t, members[nodeM], true)
	scope.SetSiteL2(t, site, "package", nil)
	scope.SetLineGroupL2(t, groupS, &custom)
	if got := publish("package L2, member enabled")[nodeM]; !slices.Equal(got, sortedIDs(site, other)) {
		t.Fatalf("L2 member M of the line group's configuration serves %v, want the website", got)
	}
	// 4. the website's L2 off: the line groups only.
	scope.SetSiteL2(t, site, "off", nil)
	if got := publish("L2 off")[nodeM]; !slices.Equal(got, sortedIDs(other)) {
		t.Fatalf("with the website's L2 off M serves %v, want the website withheld", got)
	}
}
