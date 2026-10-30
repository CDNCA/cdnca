//go:build integration

package cachecontrol

import (
	"context"
	"testing"
)

// ADD-08（待出包前全量跑）: retrying an automatic-node create with the same
// idempotency key after the carrying node set changed replays the original
// operation instead of conflicting or creating a new one.
func TestAutomaticNodeCreateReplaysAfterCarryingSetChanges(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "auto-digest", 3)
	carryNode(t, pool, fixture, fixture.nodeIDs[0], "first")
	request := CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetWholeSite,
		IdempotencyKey: "auto-digest", RequestID: "auto-digest-1",
	}
	created, err := store.CreateOperation(context.Background(), fixture.actor, request)
	if err != nil || created.Replayed || len(created.Operation.Nodes) != 1 {
		t.Fatalf("created = %+v, %v", created.Operation, err)
	}
	carryNode(t, pool, fixture, fixture.nodeIDs[1], "second")
	request.RequestID = "auto-digest-2"
	replay, err := store.CreateOperation(context.Background(), fixture.actor, request)
	if err != nil || !replay.Replayed || replay.Operation.ID != created.Operation.ID || len(replay.Operation.Nodes) != 1 {
		t.Fatalf("replay = %+v, replayed=%v, %v", replay.Operation, replay.Replayed, err)
	}
}
