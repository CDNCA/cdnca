//go:build integration

package edgepublish_test

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type conflictPublisher struct{ node uuid.UUID }

func (publisher conflictPublisher) PublishAutomatic(context.Context, edgepublish.AutomaticClaimReference) (edgepublish.PublishResult, error) {
	return edgepublish.PublishResult{}, &edgepublish.CrossScopeConflictError{NodeID: publisher.node,
		Reason: "managed WAF system/crs-pl2 is already loaded for another tenant"}
}

// B15 NODE-PUB-01 (73 retried one site.update 284 times every 5 s): an
// automatic request another tenant's configuration on a shared node refuses
// ends at once with node_scope_conflict, and the publication page reads the
// reason back (it was outside LatestAutomaticFailureTx's reasons).
func TestAutomaticPublicationRefusedByAnotherTenantSaysSo(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	scope.EnableAutomaticPolicy(t, nodeA)
	store := edgeautopublish.NewStore(scope.Pool)
	worker, err := edgeautopublish.NewWorker(store, conflictPublisher{node: nodeA}, edgeautopublish.WorkerConfig{
		WorkerID: "autopub-conflict", LeaseDuration: time.Minute, RetryDelay: 0})
	if err != nil {
		t.Fatal(err)
	}
	queueSiteUpdate(t, scope)
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("worker: worked=%v err=%v", worked, err)
	}
	if state, code := latestAutomaticState(t, scope); state != edgeautopublish.StateFailed ||
		code != edgeautopublish.FailureNodeScopeConflict {
		t.Fatalf("automatic request = %s/%s, want failed/%s", state, code, edgeautopublish.FailureNodeScopeConflict)
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || worked {
		t.Fatalf("second claim: worked=%v err=%v, want nothing left to retry", worked, err)
	}
	var failure *edgepublish.AutomaticPublicationFailure
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		var err error
		failure, err = edgepublish.LatestAutomaticFailureTx(t.Context(), tx, scope.ScopeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if failure == nil || failure.Reason != edgepublish.AutomaticFailureNodeScopeConflict {
		t.Fatalf("publication page failure = %+v, want node_scope_conflict", failure)
	}
}
