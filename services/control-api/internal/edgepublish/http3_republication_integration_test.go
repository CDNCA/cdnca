//go:build integration

package edgepublish_test

import (
	"errors"
	"slices"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// A v2 HTTPS site published to a node without a working
// a QUIC-capable OpenResty (no SITE_QUIC declared) is refused with the node named
// and held; once the node is upgraded and declares SITE_QUIC, the capability watcher
// republishes it through the system channel to every node.
func TestSystemRepublishDeliversHTTPSAfterNodeDeclaresSiteQUIC(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA, nodeB := scope.AddNode(t, 6), scope.AddNode(t, 6)
	scope.AddHTTPSSite(t, "h3-republish.example.com")
	scope.SetSiteQUIC(t, nodeB, false)
	watcher := newWatcher(t, scope)
	if _, err := watcher.SweepOnce(t.Context()); err != nil { // baselines
		t.Fatal(err)
	}

	err := scope.PublishManuallyDefault(t, "h3-refused", nodeA, nodeB)
	var refusal *edgepublish.TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.NodeID != nodeB || len(refusal.OtherNodeIDs) != 0 ||
		refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC || refusal.Required != 1 || refusal.Advertised != 0 {
		t.Fatalf("v2 HTTPS publication to a node without SITE_QUIC: %v (%+v)", err, refusal)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_config_publications WHERE configuration_scope_id=$1`); got != 0 {
		t.Fatalf("refused publication persisted %d publications", got)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_capability_publication_holds WHERE scope_id=$1
		AND refused_node_ids=$2`, []uuid.UUID{nodeB}); got != 1 {
		t.Fatalf("SITE_QUIC capability holds naming B = %d", got)
	}
	if queued, err := watcher.SweepOnce(t.Context()); err != nil || queued != 0 {
		t.Fatalf("sweep without a change queued %d (%v)", queued, err)
	}

	scope.SetSiteQUIC(t, nodeB, true)
	if queued, err := watcher.SweepOnce(t.Context()); err != nil || queued != 1 {
		t.Fatalf("sweep after B declared SITE_QUIC queued %d (%v)", queued, err)
	}
	scope.MakeDue(t)
	scope.Run(t)
	attempt := scope.LatestAttempt(t)
	if attempt.Outcome != edgepublish.SystemOutcomePublished || !slices.Equal(attempt.NodeIDs, sortedNodes(nodeA, nodeB)) ||
		len(attempt.RefusedNodes) != 0 || !slices.Equal(attempt.Triggers, []string{"node_capability"}) {
		t.Fatalf("attempt after B declared SITE_QUIC = %+v", attempt)
	}
	if publication := scope.LatestPublication(t); !slices.Equal(publication.NodeIDs, sortedNodes(nodeA, nodeB)) {
		t.Fatalf("republication nodes = %v", publication.NodeIDs)
	}
}
