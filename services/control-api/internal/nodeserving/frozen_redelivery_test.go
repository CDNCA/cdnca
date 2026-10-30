package nodeserving

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fakeFrozenStore keeps refusal marks in memory with Store's rules: a pair is
// pending while any refusal has no redelivered_at and its node serves.
type fakeFrozenStore struct {
	pending map[frozenRefusal]bool
	serving map[uuid.UUID]bool
	audits  int
}

func (store *fakeFrozenStore) PendingUnfrozen(context.Context) ([]frozenRefusal, error) {
	var result []frozenRefusal
	for refusal, waiting := range store.pending {
		if waiting && store.serving[refusal.nodeID] {
			result = append(result, refusal)
		}
	}
	return result, nil
}

func (store *fakeFrozenStore) MarkRedelivered(_ context.Context, refusal frozenRefusal, republish func(pgx.Tx) error) (bool, error) {
	if !store.pending[refusal] {
		return false, nil
	}
	if err := republish(nil); err != nil {
		return false, err // the transaction rolls back: still pending
	}
	store.pending[refusal] = false
	store.audits++
	return true, nil
}

type fakeFrozenRepublisher struct {
	calls map[frozenRefusal]int
	err   error
}

func (republisher *fakeFrozenRepublisher) RepublishFrozenTx(_ context.Context, _ pgx.Tx, nodeID, scopeID uuid.UUID) error {
	if republisher.err != nil {
		return republisher.err
	}
	republisher.calls[frozenRefusal{nodeID, scopeID}]++
	return nil
}

func TestFrozenRedeliveryOnlyAfterUnfreezeAndOnce(t *testing.T) {
	node, scope := uuid.New(), uuid.New()
	refusal := frozenRefusal{node, scope}
	store := &fakeFrozenStore{pending: map[frozenRefusal]bool{refusal: true}, serving: map[uuid.UUID]bool{}}
	republisher := &fakeFrozenRepublisher{calls: map[frozenRefusal]int{}}
	evaluator := NewFrozenRedeliveryEvaluator(store, republisher)
	ctx := context.Background()

	// Still frozen: nothing is redelivered (and nothing counts as failed).
	if err := evaluator.Evaluate(ctx); err != nil || republisher.calls[refusal] != 0 {
		t.Fatalf("frozen node redelivered: %v, %d", err, republisher.calls[refusal])
	}
	// Renewed ticket: one redelivery, audited.
	store.serving[node] = true
	if err := evaluator.Evaluate(ctx); err != nil || republisher.calls[refusal] != 1 || store.audits != 1 {
		t.Fatalf("unfreeze: %v, calls %d, audits %d", err, republisher.calls[refusal], store.audits)
	}
	// Unfreezing again (another serving receipt, another tick) is idempotent.
	for range 3 {
		if err := evaluator.Evaluate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if republisher.calls[refusal] != 1 || store.audits != 1 {
		t.Fatalf("repeated unfreeze redelivered again: calls %d, audits %d", republisher.calls[refusal], store.audits)
	}
}

func TestFrozenRedeliveryFailureStaysPending(t *testing.T) {
	refusal := frozenRefusal{uuid.New(), uuid.New()}
	store := &fakeFrozenStore{pending: map[frozenRefusal]bool{refusal: true}, serving: map[uuid.UUID]bool{refusal.nodeID: true}}
	republisher := &fakeFrozenRepublisher{calls: map[frozenRefusal]int{}, err: errors.New("database unavailable")}
	evaluator := NewFrozenRedeliveryEvaluator(store, republisher)
	if err := evaluator.Evaluate(context.Background()); err == nil || !store.pending[refusal] {
		t.Fatalf("failed redelivery: %v, pending %v", err, store.pending[refusal])
	}
	republisher.err = nil
	if err := evaluator.Evaluate(context.Background()); err != nil || republisher.calls[refusal] != 1 || store.pending[refusal] {
		t.Fatalf("retry after failure: %v, calls %d", err, republisher.calls[refusal])
	}
}
