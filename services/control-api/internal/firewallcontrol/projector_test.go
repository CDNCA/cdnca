package firewallcontrol

import (
	"slices"
	"testing"

	"github.com/google/uuid"
)

func TestGlobalCommandTargetsKeepDefaultDenyOutsideUnconditionalCoverage(t *testing.T) {
	tenantID, policyID, siteID, ruleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	publication := globalPublication{TenantScopeID: tenantID, PolicyID: policyID, Document: PolicyInput{
		Enabled: true, DefaultAction: ActionDeny,
		Rules: []RuleInput{{ID: ruleID, Priority: 1, Action: ActionAllow, CIDRs: []string{"0.0.0.0/1"}, Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443}},
	}}
	targets, err := globalCommandTargets(publication, siteID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 5 {
		t.Fatalf("targets=%d, want scoped allow plus four default-deny ranges", len(targets))
	}
	if targets[1].Cidr != "0.0.0.0/1" || targets[1].ReasonCode != "default-deny" {
		t.Fatalf("port-scoped allow widened default action: %+v", targets[1])
	}
	for index, target := range targets {
		if target.Ordinal != uint32(index+1) || target.TenantId != tenantID.String() || target.SiteId != siteID.String() {
			t.Fatalf("target %d lost stable ownership/order: %+v", index, target)
		}
	}

	publication.Document.Rules[0].Protocol = ProtocolAny
	publication.Document.Rules[0].PortStart, publication.Document.Rules[0].PortEnd = 0, 0
	targets, err = globalCommandTargets(publication, siteID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 4 {
		t.Fatalf("unconditional coverage should replace one default range, targets=%d", len(targets))
	}

	publication.Document.Enabled = false
	targets, err = globalCommandTargets(publication, siteID, true)
	if err != nil || len(targets) != 0 {
		t.Fatalf("disabled policy targets=%v err=%v", targets, err)
	}
}

// per-node-dist: a rule bound to a site reaches only nodes serving the site
// (its line groups); rules of every site and the default deny reach every
// owned node; a site without a line group counts as served everywhere.
func TestGlobalCommandTargetsBindSiteRulesToServingNodes(t *testing.T) {
	siteID, nodeA, nodeB := uuid.New(), uuid.New(), uuid.New()
	publication := globalPublication{TenantScopeID: uuid.New(), PolicyID: uuid.New(), Document: PolicyInput{
		Enabled: true, DefaultAction: ActionAllow,
		Rules: []RuleInput{
			{ID: uuid.New(), Priority: 1, Action: ActionDeny, CIDRs: []string{"192.0.2.0/24"}, Protocol: ProtocolAny, SiteIDs: []uuid.UUID{siteID}},
			{ID: uuid.New(), Priority: 2, Action: ActionDeny, CIDRs: []string{"198.51.100.0/24"}, Protocol: ProtocolAny},
		},
	}}
	serving := map[uuid.UUID]map[uuid.UUID]struct{}{siteID: {nodeA: {}}}
	for node, want := range map[uuid.UUID][]string{nodeA: {"192.0.2.0/24", "198.51.100.0/24"}, nodeB: {"198.51.100.0/24"}} {
		targets, err := globalCommandTargets(publication, siteID, servesSite(serving, siteID, node))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, target := range targets {
			got = append(got, target.Cidr)
		}
		if !slices.Equal(got, want) || targets[0].Ordinal != 1 {
			t.Fatalf("node %s targets = %v, want %v", node, got, want)
		}
	}
	if !servesSite(map[uuid.UUID]map[uuid.UUID]struct{}{}, siteID, nodeB) {
		t.Fatal("a site without a line group must count as served by every node")
	}
	if servesSite(map[uuid.UUID]map[uuid.UUID]struct{}{siteID: {}}, siteID, nodeA) {
		t.Fatal("a site whose groups have no node is served by none")
	}
}
