//go:build integration

package edgepublish_test

import (
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/packageautopublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// An automatic publication targets the
// nodes of the line groups the scope's live sites and forwards use. Deleting
// the last one left no target (no_target_nodes) and the nodes kept the
// listener, proxying to the origin. The nodes still running a release of the
// scope with something in it (node_config_state) are targets too: they get
// the release that no longer has it.

// enablePackagePolicy is the automatic policy opening a package writes (no
// nodes: the line groups decide, migration 457).
func enablePackagePolicy(t *testing.T, scope *edgepublish.SystemRepublishScope) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		_, err := packageautopublish.EnsureTx(t.Context(), tx, scope.ScopeID, scope.ScopeID, scope.UserID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func withdrawWorker(t *testing.T, scope *edgepublish.SystemRepublishScope) *edgeautopublish.Worker {
	t.Helper()
	store := edgeautopublish.NewStore(scope.Pool)
	worker, err := edgeautopublish.NewWorker(store, scope.AutomaticService(t, store), edgeautopublish.WorkerConfig{
		WorkerID: "autopub-withdraw", LeaseDuration: time.Minute, RetryDelay: 0})
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

// publishLineGroupChange advances the scope and runs one automatic request
// (a line group change: the targets are computed at publish time, whatever
// the trigger), returning its final state and code.
func publishLineGroupChange(t *testing.T, scope *edgepublish.SystemRepublishScope, worker *edgeautopublish.Worker) (string, string) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT advance_edge_configuration_scope_revision($1)`, scope.ScopeID); err != nil {
			return err
		}
		_, err := edgeautopublish.EnqueueSystemTx(t.Context(), tx, edgeautopublish.SystemEnqueueInput{
			TargetScopeID: scope.ScopeID, SourceKind: edgeautopublish.SourceLineGroup, SourceResourceID: uuid.New(),
			SourceRequestID: "withdraw-" + uuid.NewString()})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("worker: worked=%v err=%v", worked, err)
	}
	return latestAutomaticState(t, scope)
}

func requireReconciling(t *testing.T, label string, state, code string) {
	t.Helper()
	if state != edgeautopublish.StateReconciling {
		t.Fatalf("%s: automatic request = %s/%s, want reconciling", label, state, code)
	}
}

func onlineNodes(t *testing.T, scope *edgepublish.SystemRepublishScope, count int) []uuid.UUID {
	t.Helper()
	nodes := make([]uuid.UUID, count)
	for index := range nodes {
		nodes[index] = scope.AddNode(t, 12)
		scope.DeclareStreamSelection(t, nodes[index])
		scope.SetPresence(t, nodes[index], true, 1)
	}
	return nodes
}

// Two forwards on two line groups. Deleting the first withdraws it from its
// node and leaves the other node's forward alone; deleting the last one sends
// both nodes the empty release; once they run it nothing is left to withdraw.
func TestAutomaticPublicationWithdrawsDeletedLastForward(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	scope.DeleteSite(t, scope.SiteID) // a forward-only tenant
	nodes := onlineNodes(t, scope, 2)
	nodeA, nodeC := nodes[0], nodes[1]
	streamA := scope.AddStreamOn(t, "withdraw-a", 9611, scope.AddStreamLineGroup(t, "198.51.100.91", nodeA))
	streamC := scope.AddStreamOn(t, "withdraw-c", 9612, scope.AddStreamLineGroup(t, "198.51.100.92", nodeC))
	enablePackagePolicy(t, scope)
	worker := withdrawWorker(t, scope)

	state, code := publishLineGroupChange(t, scope, worker)
	requireReconciling(t, "first publication", state, code)
	if got := scope.LatestNodeRelease(t, nodeA).Streams; !slices.Equal(got, []string{streamA.String()}) {
		t.Fatalf("node A serves %v, want forward A", got)
	}
	scope.SettleDeployments(t)

	scope.DeleteStream(t, streamA)
	state, code = publishLineGroupChange(t, scope, worker)
	requireReconciling(t, "after deleting forward A", state, code)
	latest := scope.LatestPublication(t)
	if want := sortedNodes(nodeA, nodeC); !slices.Equal(latest.NodeIDs, want) {
		t.Fatalf("publication after deleting forward A went to %v, want A (withdrawal) and C %v", latest.NodeIDs, want)
	}
	if got := scope.LatestNodeRelease(t, nodeA); len(got.Streams) != 0 || len(got.Sites) != 0 {
		t.Fatalf("node A after its forward was deleted serves %+v, want nothing", got)
	}
	if got := scope.LatestNodeRelease(t, nodeC).Streams; !slices.Equal(got, []string{streamC.String()}) {
		t.Fatalf("node C serves %v, want its forward untouched", got)
	}
	scope.SettleDeployments(t)

	scope.DeleteStream(t, streamC)
	state, code = publishLineGroupChange(t, scope, worker)
	requireReconciling(t, "after deleting the last forward", state, code)
	// node A runs the root that still had forward C (withheld from it): the
	// held release is not empty, so A takes this one too, harmlessly.
	if latest = scope.LatestPublication(t); !slices.Equal(latest.NodeIDs, sortedNodes(nodeA, nodeC)) {
		t.Fatalf("withdrawal of the last forward went to %v, want A and C", latest.NodeIDs)
	}
	if got := scope.LatestNodeRelease(t, nodeC); len(got.Streams) != 0 || len(got.Sites) != 0 {
		t.Fatalf("node C after the last forward was deleted serves %+v, want nothing", got)
	}
	scope.SettleDeployments(t)

	// Every node runs an empty release: nothing to withdraw, no target.
	state, code = publishLineGroupChange(t, scope, worker)
	if state != edgeautopublish.StateFailed || code != edgeautopublish.FailureNoTargetNodes {
		t.Fatalf("publication with nothing left = %s/%s, want failed/no_target_nodes", state, code)
	}
}

// The scope's only website on a line group: deleting it sends the node the
// release without it; once the node runs that nothing is left to withdraw.
func TestAutomaticPublicationWithdrawsDeletedLastSite(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := onlineNodes(t, scope, 1)[0]
	groupID := scope.AddStreamLineGroup(t, "198.51.100.93", nodeA)
	scope.Exec(t, `UPDATE sites SET node_group_id=$2 WHERE id=$1`, scope.SiteID, groupID)
	enablePackagePolicy(t, scope)
	worker := withdrawWorker(t, scope)

	state, code := publishLineGroupChange(t, scope, worker)
	requireReconciling(t, "first publication", state, code)
	if got := scope.LatestNodeRelease(t, nodeA).Sites; !slices.Equal(got, []string{scope.SiteID.String()}) {
		t.Fatalf("node A serves sites %v, want the website", got)
	}
	scope.SettleDeployments(t)

	scope.DeleteSite(t, scope.SiteID)
	state, code = publishLineGroupChange(t, scope, worker)
	requireReconciling(t, "after deleting the last website", state, code)
	if latest := scope.LatestPublication(t); !slices.Equal(latest.NodeIDs, []uuid.UUID{nodeA}) {
		t.Fatalf("withdrawal went to %v, want node A", latest.NodeIDs)
	}
	if got := scope.LatestNodeRelease(t, nodeA); len(got.Sites) != 0 || len(got.Streams) != 0 {
		t.Fatalf("node A after the website was deleted serves %+v, want nothing", got)
	}
	scope.SettleDeployments(t)

	state, code = publishLineGroupChange(t, scope, worker)
	if state != edgeautopublish.StateFailed || code != edgeautopublish.FailureNoTargetNodes {
		t.Fatalf("publication with nothing left = %s/%s, want failed/no_target_nodes", state, code)
	}
}

// A node taken out of the forward's line group still runs the forward: the
// next publication reaches it with the forward withheld while the group's
// remaining node keeps it. A node out of the group that is offline is left
// alone (a dead node must not hold the scope's publications).
func TestAutomaticPublicationWithdrawsForwardFromNodeLeavingLineGroup(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	scope.DeleteSite(t, scope.SiteID)
	nodes := onlineNodes(t, scope, 3)
	nodeA, nodeB, nodeD := nodes[0], nodes[1], nodes[2]
	groupID := scope.AddStreamLineGroup(t, "198.51.100.94", nodeA, nodeB, nodeD)
	stream := scope.AddStreamOn(t, "withdraw-group", 9613, groupID)
	enablePackagePolicy(t, scope)
	worker := withdrawWorker(t, scope)

	state, code := publishLineGroupChange(t, scope, worker)
	requireReconciling(t, "first publication", state, code)
	scope.SettleDeployments(t)

	scope.DisableLineGroupNode(t, groupID, nodeB)
	scope.DisableLineGroupNode(t, groupID, nodeD)
	scope.SetPresence(t, nodeD, false, 1)
	state, code = publishLineGroupChange(t, scope, worker)
	requireReconciling(t, "after the group dropped nodes B and D", state, code)
	if latest := scope.LatestPublication(t); !slices.Equal(latest.NodeIDs, sortedNodes(nodeA, nodeB)) {
		t.Fatalf("publication went to %v, want A (group) and B (withdrawal), not offline D", latest.NodeIDs)
	}
	if got := scope.LatestNodeRelease(t, nodeB).Streams; len(got) != 0 {
		t.Fatalf("node B out of the group serves %v, want the forward withheld", got)
	}
	if got := scope.LatestNodeRelease(t, nodeA).Streams; !slices.Equal(got, []string{stream.String()}) {
		t.Fatalf("node A in the group serves %v, want the forward", got)
	}
}
