//go:build integration

package cachecontrol

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// tp-b4b: re-submitting an automatic operation (or its follow-up) goes to the
// nodes carrying the site now; whole-site targets need no target list.
func TestResubmitAutomaticOperationUsesCurrentCarryingNodes(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "resubmit-auto", 3)
	carryNode(t, pool, fixture, fixture.nodeIDs[0], "first")
	created, err := store.CreateOperation(context.Background(), fixture.actor, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetWholeSite,
		IdempotencyKey: "resubmit-auto", RequestID: "resubmit-auto-request",
	})
	if err != nil || !created.Operation.AutoNodes || len(created.Operation.Nodes) != 1 {
		t.Fatalf("automatic operation = %+v, %v", created.Operation, err)
	}
	carryNode(t, pool, fixture, fixture.nodeIDs[1], "second")
	resubmitted, err := store.Resubmit(context.Background(), fixture.actor, ResubmitRequest{
		OperationID: created.Operation.ID, BatchKey: "batch", RequestID: "resubmit-auto-1",
	})
	if err != nil || resubmitted.Replayed || !resubmitted.Operation.AutoNodes || len(resubmitted.Operation.Nodes) != 2 ||
		resubmitted.Operation.TargetType != TargetWholeSite || len(resubmitted.Operation.Targets) != 1 {
		t.Fatalf("resubmitted = %+v, %v", resubmitted.Operation, err)
	}
	if resubmitted.Operation.IdempotencyKey != resubmitKey(created.Operation.ID, "batch") {
		t.Fatalf("idempotency key = %q", resubmitted.Operation.IdempotencyKey)
	}
	// A key collision with an unrelated create under the same key conflicts.
	if _, err := store.CreateOperation(context.Background(), fixture.actor, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{"http://" + fixture.domain + "/x"}, NodeIDs: fixture.nodeIDs[:1],
		IdempotencyKey: resubmitKey(created.Operation.ID, "batch"), RequestID: "collide",
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("collision = %v", err)
	}
	if _, err := store.Resubmit(context.Background(), fixture.actor, ResubmitRequest{
		OperationID: uuid.New(), BatchKey: "batch", RequestID: "missing",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing operation = %v", err)
	}
}
