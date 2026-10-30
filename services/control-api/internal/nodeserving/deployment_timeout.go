package nodeserving

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DeploymentTimeoutGrace: a deployment times out one minute after its
// deadline, so a node's report sent at the deadline still wins the race.
// Migration 348 checks the same minute (node_deployment_timeouts).
const DeploymentTimeoutGrace = time.Minute

// deploymentTimeoutBatch bounds one tick; the next tick takes the rest.
const deploymentTimeoutBatch = 500

// DeploymentTimesOut reports whether a deployment in state may end as failed
// for its deadline. An activated or reverting deployment never does: the node
// may already run its configuration, so only the node's report ends it.
func DeploymentTimesOut(state string) bool {
	switch state {
	case "queued", "delivered", "agent_queued", "started", "staged", "prechecked":
		return true
	}
	return false
}

// DeploymentTimeoutDue reports whether the grace after deadline has passed.
func DeploymentTimeoutDue(deadline, now time.Time) bool {
	return !now.Before(deadline.Add(DeploymentTimeoutGrace))
}

// DeploymentTimeoutEvaluator ends overdue deployments, so a node the
// deployment never finished on is free for the next one of the scope (the
// one-running-deployment indexes of migrations 288/291).
type DeploymentTimeoutEvaluator struct {
	store *Store
}

func NewDeploymentTimeoutEvaluator(store *Store) *DeploymentTimeoutEvaluator {
	return &DeploymentTimeoutEvaluator{store: store}
}

func (evaluator *DeploymentTimeoutEvaluator) Evaluate(ctx context.Context) error {
	due, err := evaluator.store.overdueDeployments(ctx, deploymentTimeoutBatch)
	if err != nil {
		return err
	}
	var first error
	for _, deployment := range due {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := evaluator.store.timeOutDeployment(ctx, deployment); err != nil && first == nil {
			first = err
		}
	}
	return first
}

type deploymentKey struct {
	id      uuid.UUID
	attempt int32
}

// overdueDeployments lists, oldest deadline first, deployments that may time
// out now on the database clock.
func (store *Store) overdueDeployments(ctx context.Context, limit int) ([]deploymentKey, error) {
	rows, err := store.pool.Query(ctx, `SELECT id,attempt FROM node_deployments
		WHERE state IN ('queued','delivered','agent_queued','started','staged','prechecked')
		  AND deadline_at + $1::bigint * interval '1 microsecond' <= clock_timestamp()
		ORDER BY deadline_at,id,attempt LIMIT $2`, DeploymentTimeoutGrace.Microseconds(), limit)
	if err != nil {
		return nil, fmt.Errorf("list overdue node deployments: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (deploymentKey, error) {
		var key deploymentKey
		return key, row.Scan(&key.id, &key.attempt)
	})
}

// timeOutDeployment records the timeout (the fact the failed state rests on),
// cancels the command not yet sent, fails the deployment and advances its
// rollout, as a failed node report would. A deployment the node advanced or
// finished in the meantime is left alone.
func (store *Store) timeOutDeployment(ctx context.Context, key deploymentKey) error {
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var rolloutID uuid.UUID
		var state string
		var deadline, now time.Time
		err := tx.QueryRow(ctx, `SELECT rollout_id,state,deadline_at,clock_timestamp() FROM node_deployments
			WHERE id=$1 AND attempt=$2 FOR UPDATE`, key.id, key.attempt).Scan(&rolloutID, &state, &deadline, &now)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !DeploymentTimesOut(state) || !DeploymentTimeoutDue(deadline, now) {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_deployment_timeouts(deployment_id,attempt,previous_state,deadline_at,timed_out_at)
			VALUES($1,$2,$3,$4,$5)`, key.id, key.attempt, state, deadline, now); err != nil {
			return err
		}
		// A command being published is left to the publisher; the node
		// rejects it past its deadline.
		if _, err := tx.Exec(ctx, `UPDATE edge_command_outbox SET status='cancelled',updated_at=$3
			WHERE deployment_id=$1 AND deployment_attempt=$2 AND status IN ('held','pending','failed')`,
			key.id, key.attempt, now); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE node_deployments SET state='failed',updated_at=$4
			WHERE id=$1 AND attempt=$2 AND state=$3`, key.id, key.attempt, state, now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return edgedeployment.ErrInvalidTransition
		}
		return edgedeployment.AdvanceRolloutAfterStatusTx(ctx, tx, rolloutID, now)
	})
	if err != nil {
		return fmt.Errorf("time out node deployment %s attempt %d: %w", key.id, key.attempt, err)
	}
	return nil
}
