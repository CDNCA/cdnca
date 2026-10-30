//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestMultiTenantNodeGateMigration checks that after 291 a node holds one
// state and one running deployment per scope, that deployments an agent does
// not queue itself still run alone on the node, and that reconciling one
// scope does not pause another.
func TestMultiTenantNodeGateMigration(t *testing.T) {
	const version = 291
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}

	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); errors.Is(err, pgx.ErrNoRows) {
		platform = uuid.New()
	} else if err != nil {
		t.Fatal(err)
	}
	tenants := []uuid.UUID{uuid.New(), uuid.New()}
	versions, rollouts := []uuid.UUID{uuid.New(), uuid.New()}, []uuid.UUID{uuid.New(), uuid.New()}
	user, node := uuid.New(), uuid.New()
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
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'gate291','x')`, user, "gate291-"+user.String()[:8])
		exec(`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,94000,$2,$3,'active',$4)`,
			node, platform, "gate291-"+node.String()[:8], user)
		for index, scope := range tenants {
			exec(`INSERT INTO tenants(id,display_name) VALUES($1,'gate291')`, scope)
			exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, scope)
			exec(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
				generator_version,status,idempotency_key,request_digest,created_at) VALUES($1,$2,'\x01',$3,'test','1','building',$4,$3,$5)`,
				versions[index], scope, digest[:], "gate291-"+versions[index].String()[:8], now)
			exec(`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
				request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,deadline_at,
				created_at,updated_at,max_attempts) VALUES($1,$2,$3,'apply','building',$4,$5,$6,$6,1000,1000,1,
				$7::timestamptz+interval '1 hour',$7,$7,3)`,
				rollouts[index], scope, versions[index], "gate291-"+rollouts[index].String()[:8], digest[:], uuid.New(), now)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var pgErr *pgconn.PgError
	claim := func(scope uuid.UUID) error {
		_, err := pool.Exec(ctx, `INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at) VALUES($1,$2,now())`,
			node, scope)
		return err
	}
	for _, scope := range tenants {
		if err := claim(scope); err != nil {
			t.Fatalf("claim scope %s on one node: %v", scope, err)
		}
	}
	// Each deployment gets its own rollout of the tenant's version.
	deploy := func(index int, queued bool) (uuid.UUID, error) {
		id, rollout := uuid.New(), uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,
			idempotency_key,request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
			required_consecutive_successes,deadline_at,created_at,updated_at,max_attempts)
			SELECT $1,configuration_scope_id,config_version_id,'apply','building',$2,request_digest,$3,$3,1000,1000,1,
			       now()+interval '1 hour',now(),now(),3 FROM rollouts WHERE id=$4`,
			rollout, "gate291-"+rollout.String()[:8], uuid.New(), rollouts[index]); err != nil {
			return uuid.Nil, err
		}
		_, err := pool.Exec(ctx, `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,
			command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at,queued_per_scope)
			VALUES($1,$2,$3,1,$4,'apply','queued',$5,$6,$7,now()+interval '1 hour',now(),now(),$8)`,
			id, rollout, node, versions[index], uuid.New(), command, digest[:], queued)
		return id, err
	}
	finish := func(id uuid.UUID) {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE node_deployments SET state='cancelled',updated_at=now() WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}

	// An agent that queues per scope runs both tenants' deployments.
	first, err := deploy(0, true)
	if err != nil {
		t.Fatalf("first queued deployment: %v", err)
	}
	second, err := deploy(1, true)
	if err != nil {
		t.Fatalf("second scope's queued deployment on the same node: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_deployments SET queued_per_scope=false WHERE id=$1`, first); !errors.As(err, &pgErr) ||
		pgErr.ConstraintName != "node_deployments_scope_288" {
		t.Fatalf("queued_per_scope changed after insert: %v", err)
	}
	finish(first)
	finish(second)

	// Without the agent queue, a node still runs one deployment at a time.
	legacy, err := deploy(0, false)
	if err != nil {
		t.Fatalf("unqueued deployment: %v", err)
	}
	if _, err := deploy(1, false); !errors.As(err, &pgErr) ||
		pgErr.ConstraintName != "node_deployments_one_active_unqueued_per_node_291_idx" {
		t.Fatalf("second unqueued deployment on one node: %v", err)
	}
	finish(legacy)

	// Reconciling tenant 0 pauses only tenant 0.
	reconciliationSource, err := deploy(0, true)
	if err != nil {
		t.Fatal(err)
	}
	finish(reconciliationSource)
	if _, err := pool.Exec(ctx, `UPDATE node_config_state SET reconciliation_required=true,reconciliation_reason='rollback_failed',
		reconciliation_deployment_id=$3,reconciliation_deployment_attempt=1,reconciliation_requested_at=now()
		WHERE node_id=$1 AND configuration_scope_id=$2`, node, tenants[0], reconciliationSource); err != nil {
		t.Fatal(err)
	}
	if _, err := deploy(0, true); !errors.As(err, &pgErr) || pgErr.ConstraintName != "node_deployments_reconciliation_gate" {
		t.Fatalf("deployment of the reconciling scope: %v", err)
	}
	if _, err := deploy(1, true); err != nil {
		t.Fatalf("other scope paused by a reconciliation it does not share: %v", err)
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P2911" {
		t.Fatalf("down with two scopes on one node: %v", err)
	}
}
