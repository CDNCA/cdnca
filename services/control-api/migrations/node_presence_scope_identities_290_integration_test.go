//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestNodePresenceScopeIdentitiesMigration checks that a scoped heartbeat
// identity needs the scope's claim, names only this node's deployment in
// that scope, and goes away with the claim.
func TestNodePresenceScopeIdentitiesMigration(t *testing.T) {
	const version = 290
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
	tenant, other, user, node := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	configVersion, otherVersion, rollout, otherRollout := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	deployment, otherDeployment := uuid.New(), uuid.New()
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
		for _, scope := range []uuid.UUID{tenant, other} {
			exec(`INSERT INTO tenants(id,display_name) VALUES($1,'presence290')`, scope)
			exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, scope)
		}
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'presence290','x')`, user, "presence290-"+user.String()[:8])
		exec(`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,93000,$2,$3,'active',$4)`,
			node, platform, "presence290-"+node.String()[:8], user)
		exec(`INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at) VALUES($1,$2,$3)`, node, tenant, now)
		exec(`INSERT INTO node_presence(node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,
			occurred_at,projected_at,offline_since,openresty_state,firewall_state,filesystem_total_bytes,
			filesystem_available_bytes,cache_used_bytes,active_deployments,revision,updated_at)
			VALUES($1,'offline',1,1,$2,$2,$3,$4,$4,$4,'running','running',1,1,0,'[]',1,$4)`, node, uuid.New(), digest[:], now)
		for _, item := range []struct{ scope, version, rollout, deployment uuid.UUID }{
			{tenant, configVersion, rollout, deployment}, {other, otherVersion, otherRollout, otherDeployment},
		} {
			exec(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
				generator_version,status,idempotency_key,request_digest,created_at) VALUES($1,$2,'\x01',$3,'test','1','building',$4,$3,$5)`,
				item.version, item.scope, digest[:], "presence290-"+item.version.String()[:8], now)
			exec(`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
				request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,deadline_at,
				created_at,updated_at) VALUES($1,$2,$3,'apply','building',$4,$5,$6,$6,1000,1000,1,$7::timestamptz+interval '1 hour',$7,$7)`,
				item.rollout, item.scope, item.version, "presence290-"+item.rollout.String()[:8], digest[:], uuid.New(), now)
			exec(`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,configuration_scope_id,
				command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
				VALUES($1,$2,$3,1,$4,'apply','failed',$5,$6,$7,$8,$9::timestamptz+interval '1 hour',$9,$9)`,
				item.deployment, item.rollout, node, item.version, item.scope, uuid.New(), command, digest[:], now)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// A scope whose first apply failed reports only the result.
	if _, err := pool.Exec(ctx, `INSERT INTO node_presence_scope_identities(node_id,configuration_scope_id,session_epoch,
		heartbeat_sequence,last_apply_deployment_id,last_apply_attempt,last_apply_config_version_id,last_apply_state,
		last_apply_error_code,updated_at) VALUES($1,$2,1,1,$3,1,$4,'failed','RATE_LIMITED',now())`,
		node, tenant, deployment, configVersion); err != nil {
		t.Fatalf("first-apply failure of a claimed scope: %v", err)
	}
	var pgErr *pgconn.PgError
	expect := func(name, code, sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); !errors.As(err, &pgErr) || pgErr.Code != code {
			t.Errorf("%s: %v, want %s", name, err, code)
		}
	}
	expect("unclaimed scope", "23503", `INSERT INTO node_presence_scope_identities(node_id,configuration_scope_id,session_epoch,
		heartbeat_sequence,last_apply_deployment_id,last_apply_attempt,last_apply_config_version_id,last_apply_state,
		last_apply_error_code,updated_at) VALUES($1,$2,1,1,$3,1,$4,'failed','RATE_LIMITED',now())`,
		node, other, otherDeployment, otherVersion)
	update := `UPDATE node_presence_scope_identities SET %s WHERE node_id=$1 AND configuration_scope_id=$2`
	expect("another scope's deployment", "P8702", fmt.Sprintf(update,
		"last_apply_deployment_id=$3,last_apply_config_version_id=$4"), node, tenant, otherDeployment, otherVersion)
	expect("failure without an error", "23514", fmt.Sprintf(update, "last_apply_error_code=NULL"), node, tenant)
	expect("in-flight state as a result", "23514", fmt.Sprintf(update,
		"last_apply_state='started',last_apply_error_code=NULL"), node, tenant)
	expect("neither a current version nor an apply result", "23514", fmt.Sprintf(update,
		"last_apply_deployment_id=NULL,last_apply_attempt=NULL,last_apply_config_version_id=NULL,"+
			"last_apply_state=NULL,last_apply_error_code=NULL"), node, tenant)

	// Unclaiming the scope removes what the node reported for it.
	if _, err := pool.Exec(ctx, `DELETE FROM node_config_state WHERE node_id=$1 AND configuration_scope_id=$2`, node, tenant); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_presence_scope_identities WHERE node_id=$1`, node).Scan(&remaining); err != nil ||
		remaining != 0 {
		t.Fatalf("scoped identities after unclaim = %d, %v", remaining, err)
	}
}
