//go:build integration

package edgestatus

import (
	"context"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
)

// fix-stoppolicy2 (PG): a frozen node refuses an APPLY (FAILED_PRECONDITION
// installation_frozen, running config unchanged). The controller marks it
// "waiting for redelivery" (migration 608) and it is no failure: neither the
// failure threshold nor the rollout outcome counts it. A plain precondition
// failure stays a failure.
func TestFrozenRefusalIsMarkedAndNotAFailure(t *testing.T) {
	pool, store, validator, prefix := n13Setup(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		message string
		frozen  bool
	}{
		"frozen":             {edgedeployment.InstallationFrozenReason + ": the node service ticket expired", true},
		"other precondition": {"capability missing", false},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
			projectFixtureState(t, store, validator, prefix, fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
			failed := fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, 2)
			failed.RunningConfigUnchanged = true
			failed.Error = &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION,
				Message: tc.message, Retryable: true}
			projectFixtureStatus(t, store, validator, prefix, fixture, failed)
			assertDeploymentState(t, pool, fixture.deploymentID, "failed", 2)

			var marks int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_deployment_frozen_refusals
				WHERE deployment_id=$1 AND node_id=$2 AND configuration_scope_id=$3 AND redelivered_at IS NULL`,
				fixture.deploymentID, fixture.nodeID, fixture.scopeID).Scan(&marks); err != nil || (marks == 1) != tc.frozen {
				t.Fatalf("frozen marks = %d, %v; want frozen %v", marks, err, tc.frozen)
			}
			var notFailure bool
			if err := pool.QueryRow(ctx, `SELECT `+supersededSQLForTest+` FROM node_deployments deployment
				WHERE deployment.id=$1`, fixture.deploymentID).Scan(&notFailure); err != nil || notFailure != tc.frozen {
				t.Fatalf("excluded from failures = %v, %v; want %v", notFailure, err, tc.frozen)
			}
			var status string
			if err := pool.QueryRow(ctx, `SELECT status FROM rollouts WHERE id=$1`, fixture.rolloutID).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if tc.frozen && status == "failed" {
				t.Fatalf("rollout status after a frozen refusal = %s", status)
			}
		})
	}
}

// The 608 guard: a mark is written once, redelivered_at is set once and never
// cleared (a second unfreeze changes nothing).
func TestFrozenRefusalMarkIsRedeliveredOnce(t *testing.T) {
	pool, store, validator, prefix := n13Setup(t)
	ctx := context.Background()
	fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	projectFixtureState(t, store, validator, prefix, fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	failed := fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, 2)
	failed.RunningConfigUnchanged = true
	failed.Error = &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION,
		Message: edgedeployment.InstallationFrozenReason + ": the node service ticket expired", Retryable: true}
	projectFixtureStatus(t, store, validator, prefix, fixture, failed)

	update := `UPDATE node_deployment_frozen_refusals SET redelivered_at=clock_timestamp()
		WHERE deployment_id=$1 AND redelivered_at IS NULL`
	if command, err := pool.Exec(ctx, update, fixture.deploymentID); err != nil || command.RowsAffected() != 1 {
		t.Fatalf("first redelivery mark: %v", err)
	}
	if command, err := pool.Exec(ctx, update, fixture.deploymentID); err != nil || command.RowsAffected() != 0 {
		t.Fatalf("second redelivery mark: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_deployment_frozen_refusals SET redelivered_at=NULL WHERE deployment_id=$1`,
		fixture.deploymentID); err == nil {
		t.Fatal("redelivered_at was cleared")
	}
}
