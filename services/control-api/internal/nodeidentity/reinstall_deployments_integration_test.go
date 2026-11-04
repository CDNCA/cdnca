//go:build integration

package nodeidentity

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The previous host's deployment held the reinstalled node
// (node already has an active deployment) until its deadline. Both the
// re_enrollment transaction and control-api reset-node-host-delivery (nodes
// reinstalled on an older control plane) end it as failed (host_replaced).
func TestReinstallEndsPreviousHostDeploymentsInTheEnrollment(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), clock)
	ctx := context.Background()
	fixture := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	first := validAuthorizeRequest(t, testCSR(t, false))
	first.EnrollmentToken = fixture.token
	enrollIdentity(t, service, first)
	configID := seedTelemetryConfig(t, pool, fixture, uuid.New(), now)
	activated := seedRunningV1Deployment(t, pool, fixture, configID, "activated", now.Add(time.Minute))

	clock.set(now.Add(10 * time.Minute))
	reinstall := reenrollRequest(t, pool, fixture, clock)
	reinstall.EnrollmentToken = issueIdentityToken(t, pool, fixture, clock.now(), "re_enrollment")
	enrollIdentity(t, service, reinstall)
	if state := deploymentEnd(t, pool, activated); state != "failed/activated" {
		t.Fatalf("previous host's activated deployment after the reinstall = %s", state)
	}

	// An older control plane left a previous host's deployment running.
	reverting := seedRunningV1Deployment(t, pool, fixture, configID, "reverting", now.Add(5*time.Minute))
	if _, err := service.store.ResetReinstalledHost(ctx, fixture.nodeID, "repair-deployments"); err != nil {
		t.Fatal(err)
	}
	if state := deploymentEnd(t, pool, reverting); state != "failed/reverting" {
		t.Fatalf("previous host's reverting deployment after the repair = %s", state)
	}
	// The new host's deployment is not touched by a repeated repair.
	current := seedRunningV1Deployment(t, pool, fixture, configID, "started", now.Add(20*time.Minute))
	if _, err := service.store.ResetReinstalledHost(ctx, fixture.nodeID, "repair-again"); err != nil {
		t.Fatal(err)
	}
	if state := deploymentEnd(t, pool, current); state != "started/" {
		t.Fatalf("current host's deployment after a repeated repair = %s", state)
	}
}

// seedRunningV1Deployment records a contract-v1 deployment of configID to the
// node in state, created at createdAt (written as a replica: the seed states
// have no status events).
func seedRunningV1Deployment(t *testing.T, pool *pgxpool.Pool, fixture identityFixture, configID uuid.UUID,
	state string, createdAt time.Time) uuid.UUID {
	t.Helper()
	rolloutID, deploymentID := uuid.New(), uuid.New()
	command := []byte(deploymentID.String())
	digest := sha256.Sum256(command)
	if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,contract_version,idempotency_key,
				request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
				required_consecutive_successes,deadline_at,created_at,updated_at)
				VALUES($1,$2,$3,'apply','building',1,$4,$5,$6,$6,60000,60000,1,$7,$8,$8)`,
				[]any{rolloutID, fixture.scopeID, configID, rolloutID.String(), make([]byte, 32), uuid.New(),
					createdAt.Add(time.Hour), createdAt}},
			{`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
				command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
				VALUES($1,$2,$3,1,$4,'apply',$5,$6,$7,$8,$9,$10,$10,$11)`,
				[]any{deploymentID, rolloutID, fixture.nodeID, configID, state, uuid.New(), command, digest[:],
					createdAt.Add(time.Hour), createdAt, fixture.scopeID}},
		} {
			if _, err := tx.Exec(context.Background(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return deploymentID
}

// deploymentEnd is state/previous_state of the deployment's host replacement
// fact ("" when there is none).
func deploymentEnd(t *testing.T, pool *pgxpool.Pool, deploymentID uuid.UUID) string {
	t.Helper()
	var state, previous string
	if err := pool.QueryRow(context.Background(), `SELECT deployment.state,COALESCE(replaced.previous_state,'')
		FROM node_deployments deployment
		LEFT JOIN node_deployment_host_replacements replaced ON replaced.deployment_id=deployment.id
		 AND replaced.attempt=deployment.attempt AND replaced.reason_code='host_replaced'
		WHERE deployment.id=$1`, deploymentID).Scan(&state, &previous); err != nil {
		t.Fatal(err)
	}
	return state + "/" + previous
}
