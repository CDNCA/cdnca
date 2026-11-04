package edgedeployment

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// HostReplacedReason is the reason code of a deployment a reinstall ended.
const HostReplacedReason = "host_replaced"

// CloseReplacedHostDeploymentsTx ends, in the enrollment transaction of a node
// a new host took over ("重装此节点", re_enrollment; or a re-enrollment after
// its certificate expired), every running deployment of the node created
// before its newest enrollment certificate: none of them can finish on the new
// host, and an activated or reverting one would hold the node's
// one-running-deployment indexes (migrations 288/291) forever, so the next
// publication was refused with ErrNodeDeploymentActive. Like a timeout (348),
// it records the fact the failed state rests on (node_deployment_host_replacements,
// migration 627), cancels the commands not yet sent and advances the
// rollouts. It returns the deployments it ended.
func CloseReplacedHostDeploymentsTx(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID) (int, error) {
	if ctx == nil || tx == nil || nodeID == uuid.Nil {
		return 0, ErrInvalidInput
	}
	// A node enrolled once has no previous host.
	var certificateID uuid.UUID
	var enrollments int
	var now time.Time
	err := tx.QueryRow(ctx, `SELECT id,count(*) OVER (),clock_timestamp() FROM node_certificates
		WHERE node_id=$1 AND issuance_kind='initial' ORDER BY issued_at DESC LIMIT 1`, nodeID).Scan(&certificateID, &enrollments, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read node enrollment: %w", err)
	}
	if enrollments < 2 {
		return 0, nil
	}
	rows, err := tx.Query(ctx, `SELECT deployment.id,deployment.attempt,deployment.rollout_id,deployment.state
		FROM node_deployments deployment
		WHERE deployment.node_id=$1
		  AND deployment.state NOT IN ('healthy','failed','reverted','rollback_failed','cancelled')
		  AND NOT `+CurrentHostDeployment("deployment")+`
		ORDER BY deployment.id,deployment.attempt FOR UPDATE`, nodeID)
	if err != nil {
		return 0, fmt.Errorf("lock previous host deployments: %w", err)
	}
	type running struct {
		id      uuid.UUID
		attempt int32
		rollout uuid.UUID
		state   string
	}
	deployments, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (running, error) {
		var value running
		return value, row.Scan(&value.id, &value.attempt, &value.rollout, &value.state)
	})
	if err != nil {
		return 0, fmt.Errorf("read previous host deployments: %w", err)
	}
	rollouts := make([]uuid.UUID, 0, len(deployments))
	seen := make(map[uuid.UUID]bool, len(deployments))
	for _, deployment := range deployments {
		if _, err := tx.Exec(ctx, `INSERT INTO node_deployment_host_replacements(deployment_id,attempt,previous_state,
			reason_code,node_id,certificate_id,replaced_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, deployment.id, deployment.attempt,
			deployment.state, HostReplacedReason, nodeID, certificateID, now); err != nil {
			return 0, fmt.Errorf("record host replacement of deployment %s: %w", deployment.id, err)
		}
		// A command being published is left to the publisher; the new
		// host cannot open a command sealed to the previous host's key.
		if _, err := tx.Exec(ctx, `UPDATE edge_command_outbox SET status='cancelled',updated_at=$3
			WHERE deployment_id=$1 AND deployment_attempt=$2 AND status IN ('held','pending','failed')`,
			deployment.id, deployment.attempt, now); err != nil {
			return 0, fmt.Errorf("cancel command of deployment %s: %w", deployment.id, err)
		}
		command, err := tx.Exec(ctx, `UPDATE node_deployments SET state='failed',updated_at=$4
			WHERE id=$1 AND attempt=$2 AND state=$3`, deployment.id, deployment.attempt, deployment.state, now)
		if err != nil {
			return 0, fmt.Errorf("fail deployment %s: %w", deployment.id, err)
		}
		if command.RowsAffected() != 1 {
			return 0, ErrInvalidTransition
		}
		if !seen[deployment.rollout] {
			seen[deployment.rollout] = true
			rollouts = append(rollouts, deployment.rollout)
		}
	}
	for _, rolloutID := range rollouts {
		if err := AdvanceRolloutAfterStatusTx(ctx, tx, rolloutID, now); err != nil {
			return 0, fmt.Errorf("advance rollout %s: %w", rolloutID, err)
		}
	}
	return len(deployments), nil
}
