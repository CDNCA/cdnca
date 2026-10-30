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

// fix-cfgflow2 §1 (PG): a node that refuses an old APPLY because it already
// runs a newer revision reports FAILED, STALE_ATTEMPT, running config
// unchanged. The code is stored with the event (migration 564) and the
// rollout ends as succeeded, not failed: an ignored old release.
func TestIgnoredOldReleaseEndsRolloutWithoutFailure(t *testing.T) {
	pool, store, validator, prefix := n13Setup(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		code       commonv1.ErrorCode
		wantStored string
		ignored    bool
	}{
		"stale":       {commonv1.ErrorCode_ERROR_CODE_STALE_ATTEMPT, "ERROR_CODE_STALE_ATTEMPT", true},
		"rolled back": {commonv1.ErrorCode_ERROR_CODE_REVOKED, "ERROR_CODE_REVOKED", true},
		"conflict":    {commonv1.ErrorCode_ERROR_CODE_CONFLICT, "ERROR_CODE_CONFLICT", false},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
			projectFixtureState(t, store, validator, prefix, fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
			failed := fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, 2)
			failed.RunningConfigUnchanged = true
			failed.Error = &commonv1.ProtocolError{Code: tc.code, Message: "refused before activation"}
			projectFixtureStatus(t, store, validator, prefix, fixture, failed)
			assertDeploymentState(t, pool, fixture.deploymentID, "failed", 2)

			var stored string
			if err := pool.QueryRow(ctx, `SELECT error_code FROM deployment_status_events
				WHERE deployment_id=$1 AND state='failed'`, fixture.deploymentID).Scan(&stored); err != nil || stored != tc.wantStored {
				t.Fatalf("stored error code = %q, %v", stored, err)
			}
			var superseded bool
			if err := pool.QueryRow(ctx, `SELECT `+supersededSQLForTest+` FROM node_deployments deployment
				WHERE deployment.id=$1`, fixture.deploymentID).Scan(&superseded); err != nil || superseded != tc.ignored {
				t.Fatalf("superseded = %v, %v; want %v", superseded, err, tc.ignored)
			}
			var status string
			if err := pool.QueryRow(ctx, `SELECT status FROM rollouts WHERE id=$1`, fixture.rolloutID).Scan(&status); err != nil {
				t.Fatal(err)
			}
			// v1 rollouts keep their persisted status; v2 ones complete. Either
			// way an ignored old release must never read as failed.
			if tc.ignored && status == "failed" {
				t.Fatalf("rollout status after an ignored old release = %s", status)
			}
		})
	}
}

var supersededSQLForTest = edgedeployment.SupersededDeploymentSQL
