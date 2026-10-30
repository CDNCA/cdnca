//go:build integration

package cachecontrol

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// CACHE-ADD-07（待出包前全量跑）：取消运行中的任务时，声明 CACHE_CONTROL_CANCEL 的
// 节点得到一条待确认取消（outbox），旧节点记“版本不支持”；回执、迟到回执、超时与
// 节点投影 cancel_confirmation 三种状态区分。
func TestCancelDeliveriesConfirmPerNode(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "cancel-delivery", 2)
	ctx := context.Background()
	declareNodeCapabilities(t, pool, fixture.nodeIDs[0], 1, agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL_CANCEL)
	operation := createSimpleOperation(t, store, fixture, "cancel-delivery", 1, fixture.nodeIDs)
	claims := claimForNodes(t, store, fixture.actor.ScopeID, "cancel-delivery-worker", fixture.nodeIDs, 2, "cancel-delivery-claim")
	if len(claims) != 2 {
		t.Fatalf("claims=%d", len(claims))
	}
	if _, err := store.Cancel(ctx, fixture.actor, CancelRequest{
		OperationID: operation.ID, IdempotencyKey: "cancel-delivery", RequestID: "cancel-delivery-request",
	}); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingCancels(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].NodeID != fixture.nodeIDs[0] || pending[0].OperationID != operation.ID {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	projection := func() map[uuid.UUID]CancelConfirmation {
		loaded, err := store.GetOperation(ctx, fixture.actor, operation.ID)
		if err != nil {
			t.Fatal(err)
		}
		result := map[uuid.UUID]CancelConfirmation{}
		for _, node := range loaded.Nodes {
			result[node.NodeID] = node.CancelConfirmation
		}
		return result
	}
	if got := projection(); got[fixture.nodeIDs[0]] != CancelPending || got[fixture.nodeIDs[1]] != CancelUnsupported {
		t.Fatalf("projection after cancel=%v", got)
	}
	// A replayed cancel command adds no delivery.
	if _, err := store.Cancel(ctx, fixture.actor, CancelRequest{
		OperationID: operation.ID, IdempotencyKey: "cancel-delivery", RequestID: "cancel-delivery-replay",
	}); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cache_operation_cancel_deliveries WHERE operation_id=$1`, operation.ID).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("delivery rows=%d err=%v", rows, err)
	}
	if err := store.MarkCancelPublished(ctx, pending[0].ID); err != nil {
		t.Fatal(err)
	}
	if again, err := store.PendingCancels(ctx, 10); err != nil || len(again) != 0 {
		t.Fatalf("published cancel listed again: %+v %v", again, err)
	}
	// The window passes: not responding. A late receipt still settles it.
	clock.value = cacheTestNow.Add(CancelConfirmationWindow + time.Second)
	if expired, err := store.ExpireCancels(ctx); err != nil || expired != 1 {
		t.Fatalf("expired=%d err=%v", expired, err)
	}
	if got := projection(); got[fixture.nodeIDs[0]] != CancelUnresponsive {
		t.Fatalf("projection after window=%v", got)
	}
	receipt := CancelReceipt{
		DeliveryID: pending[0].ID, NodeID: pending[0].NodeID, LeaseID: pending[0].LeaseID, Attempt: pending[0].Attempt,
		EventID: uuid.New(), Outcome: CancelConfirmed, SucceededTargets: 0, CancelledTargets: 1, SettledAt: clock.value,
	}
	wrongLease := receipt
	wrongLease.LeaseID = uuid.New()
	if applied, err := store.SettleCancel(ctx, wrongLease); err != nil || applied {
		t.Fatalf("receipt for another lease applied=%v err=%v", applied, err)
	}
	if applied, err := store.SettleCancel(ctx, receipt); err != nil || !applied {
		t.Fatalf("late receipt applied=%v err=%v", applied, err)
	}
	if got := projection(); got[fixture.nodeIDs[0]] != CancelConfirmed {
		t.Fatalf("projection after receipt=%v", got)
	}
	if applied, err := store.SettleCancel(ctx, receipt); err != nil || applied {
		t.Fatalf("redelivered receipt applied=%v err=%v", applied, err)
	}
	// Only the applied receipt is audited (the wrong lease and the redelivery are not).
	var audited int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='cache.cancel.receipt'
		AND resource_type='cache_operation' AND resource_id=$1 AND actor_user_id IS NULL
		AND payload->>'outcome'='cancelled' AND payload->>'cancel_id'=$2`,
		pending[0].OperationID.String(), pending[0].ID.String()).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("cache.cancel.receipt audit rows=%d err=%v", audited, err)
	}
}
