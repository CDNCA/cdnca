//go:build integration

package edgestatus

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func n13Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_URL and TEST_DATABASE_TEMPLATE are required")
	}
	return pool
}

func n13Setup(t *testing.T) (*pgxpool.Pool, *Store, *Validator, string) {
	t.Helper()
	pool := n13Pool(t)
	prefix := "cdnca.integration.n13.deployment-status"
	config := DefaultValidatorConfig()
	config.SubjectPrefix = prefix
	validator, err := NewValidator(config)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	return pool, store, validator, prefix
}

// statusAt is fixtureStatus with the node's clock: offset from the command's
// (controller) time.
func statusAt(fixture deploymentFixture, state agentv1.NodeDeploymentState, sequence uint64, offset time.Duration) *agentv1.DeploymentStatus {
	status := fixtureStatus(fixture, state, sequence)
	status.Event.OccurredTime = timestamppb.New(fixture.command.Event.OccurredTime.AsTime().Add(offset))
	return status
}

// Reproduction (PG): node 85's STARTED, stamped by a node clock
// behind the controller, was a binding conflict. Statuses tens of
// milliseconds before or after the command time now project.
func TestN13StatusesWithinClockSkewProject(t *testing.T) {
	pool, store, validator, prefix := n13Setup(t)
	for name, offset := range map[string]time.Duration{"node behind": -40 * time.Millisecond, "node ahead": 40 * time.Millisecond} {
		t.Run(name, func(t *testing.T) {
			fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
			for sequence, state := range []agentv1.NodeDeploymentState{
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			} {
				projectFixtureStatus(t, store, validator, prefix, fixture, statusAt(fixture, state, uint64(sequence+1), offset))
			}
			assertDeploymentState(t, pool, fixture.deploymentID, "prechecked", 3)
		})
	}
}

// Reproduction (PG): a refused status (beyond the skew, then every
// later one as a skipped step) left the deployment running forever and its
// node's per-scope slot taken. The refusal now fails the deployment once,
// with a recorded refusal and an audit event, and the next deployment of the
// scope can be queued to the node.
func TestN13RefusedStatusEndsDeploymentAndFreesScope(t *testing.T) {
	pool, store, validator, prefix := n13Setup(t)
	ctx := context.Background()
	fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	projectFixtureStatus(t, store, validator, prefix, fixture,
		statusAt(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1, 0))

	// Before the refusal the node's per-scope slot is held.
	var pgErr *pgconn.PgError
	if err := queueNextDeployment(ctx, pool, fixture); !errors.As(err, &pgErr) || pgErr.Code != "23505" ||
		!strings.Contains(pgErr.ConstraintName, "one_active") {
		t.Fatalf("next deployment of the scope while one runs: %v, want the one-active index", err)
	}

	refused := decodeFixtureStatus(t, validator, prefix, fixture.nodeID,
		statusAt(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, 2, -CrossHostClockSkew-time.Second))
	_, projectErr := store.Project(ctx, refused)
	if !permanentProjectionError(projectErr) {
		t.Fatalf("status beyond the skew projected: %v", projectErr)
	}
	// A stale or non-adjacent status ends nothing.
	gap := decodeFixtureStatus(t, validator, prefix, fixture.nodeID,
		statusAt(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED, 4, 0))
	if ended, err := store.FinalizeRefused(ctx, gap, ErrInvalidTransition); err != nil || ended {
		t.Fatalf("non-adjacent skipped step finalized = (%v, %v)", ended, err)
	}
	ended, err := store.FinalizeRefused(ctx, refused, projectErr)
	if err != nil || !ended {
		t.Fatalf("FinalizeRefused = (%v, %v), want ended", ended, err)
	}
	assertDeploymentState(t, pool, fixture.deploymentID, "failed", 1)
	// Idempotent: the redelivered refusal ends nothing more.
	if again, err := store.FinalizeRefused(ctx, refused, projectErr); err != nil || again {
		t.Fatalf("second FinalizeRefused = (%v, %v)", again, err)
	}
	var reason, previous string
	var audits int
	if err := pool.QueryRow(ctx, `SELECT reason_code,previous_state FROM node_deployment_status_refusals
		WHERE deployment_id=$1`, fixture.deploymentID).Scan(&reason, &previous); err != nil ||
		reason != RefusalBindingConflict || previous != "delivered" {
		t.Fatalf("refusal = (%q, %q, %v)", reason, previous, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action=$1 AND resource_id=$2 AND result='failure'
		AND reason_code=$3`, StatusRefusalAuditAction, fixture.deploymentID.String(), RefusalBindingConflict).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("refusal audit events = %d, %v", audits, err)
	}
	var rollout string
	if err := pool.QueryRow(ctx, `SELECT status FROM rollouts WHERE id=$1`, fixture.rolloutID).Scan(&rollout); err != nil {
		t.Fatal(err)
	}
	t.Logf("rollout after the refusal: %s", rollout)
	if err := queueNextDeployment(ctx, pool, fixture); err != nil {
		t.Fatalf("next deployment of the scope after the refusal: %v", err)
	}
	// A refusal row cannot be changed or forged for another state.
	if _, err := pool.Exec(ctx, `DELETE FROM node_deployment_status_refusals WHERE deployment_id=$1`, fixture.deploymentID); err == nil {
		t.Fatal("refusal deleted")
	}
}

// queueNextDeployment inserts, as a replica (only unique indexes apply), the
// scope's next deployment to the fixture's node (its retry, attempt 2).
func queueNextDeployment(ctx context.Context, pool *pgxpool.Pool, fixture deploymentFixture) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,
			configuration_scope_id,command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
			SELECT id,rollout_id,node_id,2,config_version_id,action,'queued',configuration_scope_id,$1,command_bytes,
			       command_sha256,now()+interval '1 hour',now(),now()
			FROM node_deployments WHERE id=$2 AND attempt=1`, uuid.New(), fixture.deploymentID)
		return err
	})
}
