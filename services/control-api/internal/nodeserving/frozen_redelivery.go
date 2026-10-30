package nodeserving

import (
	"context"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FrozenRedeliveryAuditAction is written when the system republishes a scope
// to a node that refused it while frozen (fix-stoppolicy2).
const FrozenRedeliveryAuditAction = "node.deployment.frozen_redeliver"

// frozenRefusal is one node and scope with publications the node refused
// while frozen, not yet redelivered.
type frozenRefusal struct{ nodeID, scopeID uuid.UUID }

// FrozenRedeliveryStore reads and marks the frozen refusals (migration 608).
type FrozenRedeliveryStore interface {
	// PendingUnfrozen lists the node/scope pairs whose refusals wait while
	// the node's last receipt says it serves again (renewed ticket).
	PendingUnfrozen(ctx context.Context) ([]frozenRefusal, error)
	// MarkRedelivered sets redelivered_at on the pair's pending refusals
	// (none left: false) and audits it, in one transaction with republish.
	MarkRedelivered(ctx context.Context, refusal frozenRefusal, republish func(pgx.Tx) error) (bool, error)
}

// FrozenRedeliveryEvaluator republishes, once, every scope a node refused
// while frozen as soon as the node serves again: user 10-28 -- an expired
// ticket only freezes new publications; after renewal they land without the
// tenant publishing again. It runs in the node serving worker.
type FrozenRedeliveryEvaluator struct {
	store       FrozenRedeliveryStore
	republisher FrozenRepublisher
}

// FrozenRepublisher queues the system republication of a scope to a node
// inside tx (edgeautopublish node_sync channel).
type FrozenRepublisher interface {
	RepublishFrozenTx(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID) error
}

func NewFrozenRedeliveryEvaluator(store FrozenRedeliveryStore, republisher FrozenRepublisher) *FrozenRedeliveryEvaluator {
	return &FrozenRedeliveryEvaluator{store: store, republisher: republisher}
}

func (evaluator *FrozenRedeliveryEvaluator) Evaluate(ctx context.Context) error {
	if evaluator == nil || evaluator.store == nil || evaluator.republisher == nil {
		return ErrInvalidInput
	}
	pending, err := evaluator.store.PendingUnfrozen(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, refusal := range pending {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_, err := evaluator.store.MarkRedelivered(ctx, refusal, func(tx pgx.Tx) error {
			return evaluator.republisher.RepublishFrozenTx(ctx, tx, refusal.nodeID, refusal.scopeID)
		})
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

// PendingUnfrozen: a node serves again when its stored receipt status is
// serving (installation_ban_node_state, the node's own report).
func (store *Store) PendingUnfrozen(ctx context.Context) ([]frozenRefusal, error) {
	rows, err := store.pool.Query(ctx, `SELECT DISTINCT refusal.node_id,refusal.configuration_scope_id
		FROM node_deployment_frozen_refusals refusal
		JOIN installation_ban_node_state node_state ON node_state.node_id=refusal.node_id AND node_state.status='serving'
		JOIN nodes node ON node.id=refusal.node_id AND node.admin_state='active'
		WHERE refusal.redelivered_at IS NULL
		ORDER BY refusal.node_id,refusal.configuration_scope_id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (frozenRefusal, error) {
		var item frozenRefusal
		return item, row.Scan(&item.nodeID, &item.scopeID)
	})
}

// MarkRedelivered claims the pair's pending refusals (FOR UPDATE SKIP LOCKED:
// a concurrent worker leaves them), queues the republication and audits it.
// Nothing pending (already redelivered): no republication, false.
func (store *Store) MarkRedelivered(ctx context.Context, refusal frozenRefusal, republish func(pgx.Tx) error) (bool, error) {
	marked := false
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE node_deployment_frozen_refusals SET redelivered_at=$3
			WHERE (deployment_id,attempt) IN (SELECT deployment_id,attempt FROM node_deployment_frozen_refusals
				WHERE node_id=$1 AND configuration_scope_id=$2 AND redelivered_at IS NULL FOR UPDATE SKIP LOCKED)`,
			refusal.nodeID, refusal.scopeID, now)
		if err != nil || command.RowsAffected() == 0 {
			return err
		}
		if err := republish(tx); err != nil {
			return err
		}
		marked = true
		return store.auditor.Append(ctx, tx, audit.Event{ScopeID: refusal.scopeID, Action: FrozenRedeliveryAuditAction,
			ResourceType: "node", ResourceID: refusal.nodeID.String(), Result: "success",
			ActorKind: audit.ActorSystem, ActorRef: "job:node-serving",
			Payload:    map[string]any{"node_id": refusal.nodeID.String(), "deployments": command.RowsAffected()},
			OccurredAt: now})
	})
	return marked, err
}

var _ FrozenRedeliveryStore = (*Store)(nil)
