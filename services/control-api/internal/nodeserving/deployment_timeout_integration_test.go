package nodeserving

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type timeoutDeployment struct {
	id, rolloutID uuid.UUID
}

// deployV1 records a contract-v1 deployment (the node status fact trigger of
// 046 applies) with its command outbox row. deadlineAgo is how long before
// now its deadline passed (negative: still ahead).
func (harness *servingHarness) deployV1(nodeID uuid.UUID, state, outbox string, deadlineAgo time.Duration) timeoutDeployment {
	harness.t.Helper()
	configID, rolloutID, deploymentID := uuid.New(), uuid.New(), uuid.New()
	command := []byte(deploymentID.String())
	digest := sha256.Sum256(command)
	if err := pgx.BeginFunc(harness.ctx, harness.pool, func(tx pgx.Tx) error {
		// The seed states have no status events: write them as a replica.
		statements := []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
				generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
				VALUES($1,$2,$3,$4,'integration','1','releasable',$5,$6,now(),now())`,
				[]any{configID, harness.scopeID, command, digest[:], configID.String(), make([]byte, 32)}},
			{`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,contract_version,idempotency_key,
				request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
				required_consecutive_successes,deadline_at,created_at,updated_at)
				VALUES($1,$2,$3,'apply','building',1,$4,$5,$6,$6,60000,60000,1,
				clock_timestamp()-$7::interval,clock_timestamp()-interval '3 hours',clock_timestamp()-interval '3 hours')`,
				[]any{rolloutID, harness.scopeID, configID, rolloutID.String(), make([]byte, 32), uuid.New(), deadlineAgo.String()}},
			{`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
				command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
				VALUES($1,$2,$3,1,$4,'apply',$5,$6,$7,$8,clock_timestamp()-$9::interval,
				clock_timestamp()-interval '3 hours',clock_timestamp()-interval '3 hours',$10)`,
				[]any{deploymentID, rolloutID, nodeID, configID, state, uuid.New(), command, digest[:], deadlineAgo.String(), harness.scopeID}},
			{`INSERT INTO edge_command_outbox(id,deployment_id,deployment_attempt,node_id,subject,payload,payload_sha256,
				status,available_at,published_at,created_at,updated_at)
				VALUES($1,$2,1,$3,$7,$4,$5,$6,now(),
				CASE WHEN $6='published' THEN now() END,now(),now())`,
				[]any{uuid.New(), deploymentID, nodeID, command, digest[:], outbox, "cdnca.agent.commands." + nodeID.String()}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(harness.ctx, statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		harness.t.Fatal(err)
	}
	return timeoutDeployment{id: deploymentID, rolloutID: rolloutID}
}

func (harness *servingHarness) deploymentState(deployment timeoutDeployment) (state, outbox string, timedOut bool) {
	harness.t.Helper()
	if err := harness.pool.QueryRow(harness.ctx, `SELECT deployment.state,outbox.status,
			EXISTS (SELECT 1 FROM node_deployment_timeouts timeout
			        WHERE timeout.deployment_id=deployment.id AND timeout.attempt=deployment.attempt)
		FROM node_deployments deployment
		JOIN edge_command_outbox outbox ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		WHERE deployment.id=$1 AND deployment.attempt=1`, deployment.id).Scan(&state, &outbox, &timedOut); err != nil {
		harness.t.Fatal(err)
	}
	return state, outbox, timedOut
}

// TestDeploymentTimeoutEndsOverdueDeploymentsAndFreesTheNode: a deployment
// one minute past its deadline that the node never finished ends as failed,
// its unsent command is cancelled, and the node takes the next deployment of
// the scope. Activated and reverting deployments, and deployments still
// within the minute's grace, are left alone.
func TestDeploymentTimeoutEndsOverdueDeploymentsAndFreesTheNode(t *testing.T) {
	harness := newServingHarness(t)
	queuedNode, deliveredNode, activatedNode, revertingNode, graceNode, aheadNode :=
		harness.addNode(), harness.addNode(), harness.addNode(), harness.addNode(), harness.addNode(), harness.addNode()
	queued := harness.deployV1(queuedNode, "queued", "pending", time.Hour)
	delivered := harness.deployV1(deliveredNode, "delivered", "published", 2*time.Minute)
	activated := harness.deployV1(activatedNode, "activated", "published", time.Hour)
	reverting := harness.deployV1(revertingNode, "reverting", "published", time.Hour)
	grace := harness.deployV1(graceNode, "staged", "published", 30*time.Second)
	ahead := harness.deployV1(aheadNode, "prechecked", "published", -time.Hour)

	// The defect: the overdue deployment holds the node's per-scope index.
	if err := harness.insertNextDeployment(queuedNode); !activeIndexConflict(err) {
		t.Fatalf("next deployment before the timeout: %v, want the one-active-per-node-scope conflict", err)
	}

	worker, err := NewWorker(harness.store, time.Second, nil, NewDeploymentTimeoutEvaluator(harness.store))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 { // the second tick finds nothing left to time out
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}

	for name, test := range map[string]struct {
		deployment    timeoutDeployment
		state, outbox string
		wantTimedOut  bool
	}{
		"overdue queued":    {queued, "failed", "cancelled", true},
		"overdue delivered": {delivered, "failed", "published", true},
		"activated":         {activated, "activated", "published", false},
		"reverting":         {reverting, "reverting", "published", false},
		"within the grace":  {grace, "staged", "published", false},
		"deadline ahead":    {ahead, "prechecked", "published", false},
	} {
		state, outbox, timedOut := harness.deploymentState(test.deployment)
		if state != test.state || outbox != test.outbox || timedOut != test.wantTimedOut {
			t.Errorf("%s: state=%s outbox=%s timed out=%v, want %s %s %v",
				name, state, outbox, timedOut, test.state, test.outbox, test.wantTimedOut)
		}
	}
	var previous string
	if err := harness.pool.QueryRow(harness.ctx, `SELECT previous_state FROM node_deployment_timeouts
		WHERE deployment_id=$1`, queued.id).Scan(&previous); err != nil || previous != "queued" {
		t.Fatalf("timeout fact of the queued deployment: %q %v", previous, err)
	}
	if err := harness.insertNextDeployment(queuedNode); err != nil {
		t.Fatalf("next deployment after the timeout: %v", err)
	}
}

func activeIndexConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" &&
		pgErr.ConstraintName == "node_deployments_one_active_per_node_scope_288_idx"
}

// insertNextDeployment queues a new deployment of the harness scope to nodeID.
func (harness *servingHarness) insertNextDeployment(nodeID uuid.UUID) error {
	harness.t.Helper()
	configID, rolloutID, deploymentID := uuid.New(), uuid.New(), uuid.New()
	command := []byte(deploymentID.String())
	digest := sha256.Sum256(command)
	return pgx.BeginFunc(harness.ctx, harness.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(harness.ctx, `INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,
			canonical_snapshot_sha256,generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
			VALUES($1,$2,$3,$4,'integration','1','releasable',$5,$6,now(),now())`,
			configID, harness.scopeID, command, digest[:], configID.String(), make([]byte, 32)); err != nil {
			harness.t.Fatal(err)
		}
		if _, err := tx.Exec(harness.ctx, `INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,
			idempotency_key,request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
			required_consecutive_successes,deadline_at,created_at,queued_at,updated_at)
			VALUES($1,$2,$3,'apply','queued',$4,$5,$6,$6,60000,60000,1,now()+interval '1 hour',now(),now(),now())`,
			rolloutID, harness.scopeID, configID, rolloutID.String(), make([]byte, 32), uuid.New()); err != nil {
			harness.t.Fatal(err)
		}
		_, err := tx.Exec(harness.ctx, `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,
			state,command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
			VALUES($1,$2,$3,1,$4,'apply','queued',$5,$6,$7,now()+interval '1 hour',now(),now(),$8)`,
			deploymentID, rolloutID, nodeID, configID, uuid.New(), command, digest[:], harness.scopeID)
		return err
	})
}
