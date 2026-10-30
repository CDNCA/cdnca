//go:build integration

package cachecontrol

import (
	"context"
	"errors"
	"testing"
)

// fix-cacheflow5: a write's receipt by key is accepted (the operation),
// rejected (the code, kept without a business row) or not found; another
// actor of the same scope never reads it.
func TestWriteReceiptReadsAcceptedRejectedAndHidesOtherActors(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "write-receipt", 1)
	ctx := context.Background()

	created := createSimpleOperation(t, store, fixture, "write-receipt-create", 0, fixture.nodeIDs)
	receipt, err := store.WriteReceipt(ctx, fixture.actor, WriteReceiptRequest{
		Action: WriteCreate, IdempotencyKey: "write-receipt-create",
	})
	if err != nil || receipt.Status != WriteAccepted || receipt.Operation.ID != created.ID ||
		!receipt.DecidedAt.Equal(created.CreatedAt) {
		t.Fatalf("create receipt=%+v err=%v", receipt, err)
	}

	// A refused create: a target the site does not serve. No operation row,
	// a cache.write.reject receipt with the target details.
	_, err = store.CreateOperation(ctx, fixture.actor, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{"http://" + fixture.domain + "/a", "http://not-served.example.test/b"},
		NodeIDs: fixture.nodeIDs, IdempotencyKey: "write-receipt-refused", RequestID: "write-receipt-refused-request",
	})
	var targetErr *TargetError
	if !errors.As(err, &targetErr) {
		t.Fatalf("refused create err=%v", err)
	}
	receipt, err = store.WriteReceipt(ctx, fixture.actor, WriteReceiptRequest{
		Action: WriteCreate, IdempotencyKey: "write-receipt-refused",
	})
	if err != nil || receipt.Status != WriteRejected || receipt.Rejection.Code != "invalid_request" ||
		receipt.Rejection.TargetOrdinal != 2 || receipt.Rejection.TargetReason != TargetReasonHostNotServed {
		t.Fatalf("refused receipt=%+v err=%v", receipt, err)
	}
	var operations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cache_operations
		WHERE scope_id=$1 AND idempotency_key='write-receipt-refused'`, fixture.actor.ScopeID).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if operations != 0 {
		t.Fatalf("refused create persisted %d operations", operations)
	}

	// A refused cancel of a finished operation, then a retry nobody sent.
	if _, err := store.Cancel(ctx, fixture.actor, CancelRequest{
		OperationID: created.ID, IdempotencyKey: "write-receipt-cancel", RequestID: "write-receipt-cancel-request",
	}); err != nil {
		t.Fatalf("cancel queued operation err=%v", err)
	}
	receipt, err = store.WriteReceipt(ctx, fixture.actor, WriteReceiptRequest{
		Action: WriteCancel, OperationID: created.ID, IdempotencyKey: "write-receipt-cancel",
	})
	if err != nil || receipt.Status != WriteAccepted || receipt.Operation.ID != created.ID {
		t.Fatalf("cancel receipt=%+v err=%v", receipt, err)
	}
	if _, err := store.Cancel(ctx, fixture.actor, CancelRequest{
		OperationID: created.ID, IdempotencyKey: "write-receipt-cancel-again", RequestID: "write-receipt-cancel-again-request",
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("second cancel err=%v, want %v", err, ErrInvalidTransition)
	}
	receipt, err = store.WriteReceipt(ctx, fixture.actor, WriteReceiptRequest{
		Action: WriteCancel, OperationID: created.ID, IdempotencyKey: "write-receipt-cancel-again",
	})
	if err != nil || receipt.Status != WriteRejected || receipt.Rejection.Code != "invalid_operation_transition" {
		t.Fatalf("second cancel receipt=%+v err=%v", receipt, err)
	}
	if _, err := store.WriteReceipt(ctx, fixture.actor, WriteReceiptRequest{
		Action: WriteRetry, OperationID: created.ID, IdempotencyKey: "write-receipt-never-sent",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unsent retry receipt err=%v, want %v", err, ErrNotFound)
	}

	// The same keys read by another member of the scope: never received.
	other := seedCacheActor(t, pool, fixture, "write-receipt-other")
	for _, request := range []WriteReceiptRequest{
		{Action: WriteCreate, IdempotencyKey: "write-receipt-create"},
		{Action: WriteCreate, IdempotencyKey: "write-receipt-refused"},
		{Action: WriteCancel, OperationID: created.ID, IdempotencyKey: "write-receipt-cancel"},
	} {
		if _, err := store.WriteReceipt(ctx, other, request); !errors.Is(err, ErrNotFound) {
			t.Fatalf("other actor %+v err=%v, want %v", request, err, ErrNotFound)
		}
	}
}

// A re-submit's receipt is found by its batch key and source operation.
func TestWriteReceiptFindsResubmitByBatchKey(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "write-receipt-resubmit", 1)
	ctx := context.Background()
	source := createSimpleOperation(t, store, fixture, "write-receipt-source", 0, fixture.nodeIDs)
	if _, err := store.Cancel(ctx, fixture.actor, CancelRequest{
		OperationID: source.ID, IdempotencyKey: "write-receipt-source-cancel", RequestID: "write-receipt-source-cancel-request",
	}); err != nil {
		t.Fatal(err)
	}
	resubmitted, err := store.Resubmit(ctx, fixture.actor, ResubmitRequest{
		OperationID: source.ID, BatchKey: "write-receipt-batch", RequestID: "write-receipt-batch-request",
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.WriteReceipt(ctx, fixture.actor, WriteReceiptRequest{
		Action: WriteResubmit, OperationID: source.ID, IdempotencyKey: "write-receipt-batch",
	})
	if err != nil || receipt.Status != WriteAccepted || receipt.Operation.ID != resubmitted.Operation.ID {
		t.Fatalf("resubmit receipt=%+v err=%v", receipt, err)
	}
	if _, err := store.WriteReceipt(ctx, fixture.actor, WriteReceiptRequest{
		Action: WriteCreate, IdempotencyKey: resubmitKey(source.ID, "write-receipt-batch"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a re-submit read as a create err=%v, want %v", err, ErrNotFound)
	}
}
