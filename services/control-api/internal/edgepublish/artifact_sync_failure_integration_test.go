//go:build integration

package edgepublish_test

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/jackc/pgx/v5"
)

// O2 (live-site2 10-22): on a new node the managed WAF's CRS profile packs
// arrive through its node artifact set minutes after the node declares
// every capability. An automatic publication refused only for those packs
// ends with node_artifacts_syncing, not node_capability_unavailable, and the
// publication page reads it back (no progress before the node has a set).
func TestAutomaticPublicationWaitingForNodeArtifactsSaysSo(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	scope.DeclareCRSModule(t, nodeA)
	catalog := newCatalogSync(t, scope)
	catalog.sync(t)
	scope.BindManagedWAF(t)
	scope.EnableAutomaticPolicy(t, nodeA)
	store := edgeautopublish.NewStore(scope.Pool)
	worker, err := edgeautopublish.NewWorker(store, scope.AutomaticService(t, store), edgeautopublish.WorkerConfig{
		WorkerID: "autopub-artifacts", LeaseDuration: time.Minute, RetryDelay: 0})
	if err != nil {
		t.Fatal(err)
	}
	queueSiteUpdate(t, scope)
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("worker: worked=%v err=%v", worked, err)
	}
	if state, code := latestAutomaticState(t, scope); state != edgeautopublish.StateFailed ||
		code != edgeautopublish.FailureNodeArtifactsSyncing {
		t.Fatalf("automatic request before the CRS packs arrived = %s/%s, want failed/%s", state, code,
			edgeautopublish.FailureNodeArtifactsSyncing)
	}
	var failure *edgepublish.AutomaticPublicationFailure
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		var err error
		failure, err = edgepublish.LatestAutomaticFailureTx(t.Context(), tx, scope.ScopeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if failure == nil || failure.Reason != edgepublish.AutomaticFailureNodeArtifactsSyncing || failure.ArtifactSync != nil {
		t.Fatalf("publication page failure = %+v", failure)
	}
}
