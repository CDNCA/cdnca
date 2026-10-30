//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestNodeDeploymentTimeouts348: before 348 an overdue queued deployment
// cannot fail at all and an overdue contract-v1 deployment cannot fail
// without a node status event, so it holds its node's per-scope index. After
// it a recorded timeout is the fact of both; without one both stay refused,
// timeouts must name the deployment as it is (overdue, not activated) and are
// immutable, and down refuses while a timeout is recorded.
func TestNodeDeploymentTimeouts348(t *testing.T) {
	const version = 348
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	seed := seedTimeout348(t, pool)

	fail := func(id uuid.UUID) error {
		_, err := pool.Exec(ctx, `UPDATE node_deployments SET state='failed',updated_at=now() WHERE id=$1`, id)
		return err
	}
	// 347: queued -> failed is no transition; staged -> failed needs a status event.
	if err := fail(seed.queued); sqlState(err) != "P0001" {
		t.Fatalf("347 queued -> failed: %v, want P0001", err)
	}
	if err := fail(seed.staged); sqlState(err) != "P0001" {
		t.Fatalf("347 staged -> failed without a status event: %v, want P0001", err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}

	// Without a recorded timeout the triggers still refuse.
	if err := fail(seed.queued); sqlState(err) != "P0001" {
		t.Fatalf("queued -> failed without a timeout: %v, want P0001", err)
	}
	if err := fail(seed.staged); sqlState(err) != "P0001" {
		t.Fatalf("staged -> failed without a timeout or status event: %v, want P0001", err)
	}

	timeout := func(id uuid.UUID, previous string) error {
		_, err := pool.Exec(ctx, `INSERT INTO node_deployment_timeouts(deployment_id,attempt,previous_state,deadline_at,timed_out_at)
			SELECT id,attempt,$2,deadline_at,clock_timestamp() FROM node_deployments WHERE id=$1`, id, previous)
		return err
	}
	if err := timeout(seed.ahead, "prechecked"); sqlState(err) != "23514" {
		t.Fatalf("timeout before deadline + 1 minute: %v, want 23514", err)
	}
	if err := timeout(seed.activated, "activated"); sqlState(err) != "23514" {
		t.Fatalf("timeout of an activated deployment: %v, want 23514", err)
	}
	if err := timeout(seed.staged, "queued"); sqlState(err) != "P3483" {
		t.Fatalf("timeout naming another state: %v, want P3483", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO node_deployment_timeouts(deployment_id,attempt,previous_state,deadline_at,timed_out_at)
		SELECT id,attempt,'staged',deadline_at,clock_timestamp()+interval '1 hour' FROM node_deployments WHERE id=$1`,
		seed.staged); sqlState(err) != "P3483" {
		t.Fatalf("timeout ahead of the database clock: %v, want P3483", err)
	}
	// A timeout of one deployment is no fact for another.
	if err := timeout(seed.staged, "staged"); err != nil {
		t.Fatal(err)
	}
	if err := fail(seed.otherStaged); sqlState(err) != "P0001" {
		t.Fatalf("staged -> failed on another deployment's timeout: %v, want P0001", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3482" {
		t.Fatalf("down with a recorded timeout: %v, want P3482", err)
	}

	// The node's per-scope index stays held until the deployment ends.
	if err := seed.next(); sqlState(err) != "23505" {
		t.Fatalf("next deployment while the overdue one runs: %v, want 23505", err)
	}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO node_deployment_timeouts(deployment_id,attempt,previous_state,deadline_at,timed_out_at)
			SELECT id,attempt,'queued',deadline_at,clock_timestamp() FROM node_deployments WHERE id=$1`, seed.queued); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE node_deployments SET state='failed',updated_at=now() WHERE id=$1`, seed.queued)
		return err
	}); err != nil {
		t.Fatalf("timed-out queued -> failed: %v", err)
	}
	if err := fail(seed.staged); err != nil {
		t.Fatalf("timed-out staged -> failed: %v", err)
	}
	if err := seed.next(); err != nil {
		t.Fatalf("next deployment after the timeout: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_deployment_timeouts SET timed_out_at=timed_out_at+interval '1 second'
		WHERE deployment_id=$1`, seed.queued); sqlState(err) != "P3484" {
		t.Fatalf("update of a timeout: %v, want P3484", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM node_deployment_timeouts WHERE deployment_id=$1`, seed.queued); sqlState(err) != "P3484" {
		t.Fatalf("delete of a timeout: %v, want P3484", err)
	}
}

type timeout348Seed struct {
	queued, staged, otherStaged, activated, ahead uuid.UUID
	next                                          func() error
}

// seedTimeout348 writes, as a replica (no status events exist), one
// contract-v1 rollout to five nodes: overdue queued, overdue staged (twice),
// overdue activated and prechecked with its deadline ahead.
func seedTimeout348(t *testing.T, pool *pgxpool.Pool) timeout348Seed {
	t.Helper()
	ctx := t.Context()
	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); errors.Is(err, pgx.ErrNoRows) {
		platform = uuid.New()
	} else if err != nil {
		t.Fatal(err)
	}
	tenant, user, configVersion, rollout := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed := timeout348Seed{queued: uuid.New(), staged: uuid.New(), otherStaged: uuid.New(), activated: uuid.New(), ahead: uuid.New()}
	nodes := map[uuid.UUID]uuid.UUID{}
	now := time.Now().UTC()
	command := []byte{1}
	digest := sha256.Sum256(command)
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		exec := func(sql string, args ...any) {
			if _, execErr := tx.Exec(ctx, sql, args...); execErr != nil {
				t.Fatalf("%.80s: %v", sql, execErr)
			}
		}
		exec(`SET LOCAL session_replication_role = replica`)
		exec(`INSERT INTO access_scopes(id,kind) SELECT $1,'platform' WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`, platform)
		exec(`INSERT INTO tenants(id,display_name) VALUES($1,'timeout348')`, tenant)
		exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, tenant)
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'timeout348','x')`, user, "timeout348-"+user.String()[:8])
		exec(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at) VALUES($1,$2,'\x01',$3,'test','1','building',$4,$3,$5)`,
			configVersion, tenant, digest[:], "timeout348-"+configVersion.String()[:8], now.Add(-3*time.Hour))
		exec(`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,contract_version,idempotency_key,
			request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,
			deadline_at,created_at,updated_at) VALUES($1,$2,$3,'apply','building',1,$4,$5,$6,$6,1000,1000,1,$7,$8,$8)`,
			rollout, tenant, configVersion, "timeout348-"+rollout.String()[:8], digest[:], uuid.New(), now.Add(time.Hour), now.Add(-3*time.Hour))
		index := 0
		for id, deployment := range map[uuid.UUID]struct {
			state    string
			deadline time.Time
		}{
			seed.queued: {"queued", now.Add(-time.Hour)}, seed.staged: {"staged", now.Add(-time.Hour)},
			seed.otherStaged: {"staged", now.Add(-time.Hour)}, seed.activated: {"activated", now.Add(-time.Hour)},
			seed.ahead: {"prechecked", now.Add(time.Hour)},
		} {
			node := uuid.New()
			nodes[id] = node
			exec(`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,$2,$3,$4,'active',$5)`,
				node, 93460+index, platform, "timeout348-"+node.String()[:8], user)
			index++
			exec(`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,configuration_scope_id,
				command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
				VALUES($1,$2,$3,1,$4,'apply',$5,$6,$7,$8,$9,$10,$11,$11)`,
				id, rollout, node, configVersion, deployment.state, tenant, uuid.New(), command, digest[:],
				deployment.deadline, now.Add(-3*time.Hour))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// next queues another rollout's deployment of the scope to the queued
	// deployment's node (as a replica: only the unique indexes apply).
	seed.next = func() error {
		return pgx.BeginFunc(context.WithoutCancel(ctx), pool, func(tx pgx.Tx) error {
			nextRollout := uuid.New()
			for _, statement := range []struct {
				sql  string
				args []any
			}{
				{`SET LOCAL session_replication_role = replica`, nil},
				{`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
					request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,deadline_at,
					created_at,updated_at) VALUES($1,$2,$3,'apply','building',$4,$5,$6,$6,1000,1000,1,now()+interval '1 hour',now(),now())`,
					[]any{nextRollout, tenant, configVersion, "timeout348-" + nextRollout.String()[:8], digest[:], uuid.New()}},
				{`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,configuration_scope_id,
					command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
					VALUES($1,$2,$3,1,$4,'apply','queued',$5,$6,$7,$8,now()+interval '1 hour',now(),now())`,
					[]any{uuid.New(), nextRollout, nodes[seed.queued], configVersion, tenant, uuid.New(), command, digest[:]}},
			} {
				if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return seed
}
