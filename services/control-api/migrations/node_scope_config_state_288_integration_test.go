//go:build integration

package migrations_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestNodeScopeConfigStateMigration checks that 288 keys node configuration
// state and running deployments by (node, scope) while still holding a node
// to one scope, and that rolling back refuses several scopes on one node.
func TestNodeScopeConfigStateMigration(t *testing.T) {
	const version = 288
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()

	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); errors.Is(err, pgx.ErrNoRows) {
		platform = uuid.New()
	} else if err != nil {
		t.Fatal(err)
	}
	tenant, other, user := uuid.New(), uuid.New(), uuid.New()
	unclaimed, claimed, spare := uuid.New(), uuid.New(), uuid.New()
	configVersion, rollout, seeded := uuid.New(), uuid.New(), uuid.New()
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
			exec(`INSERT INTO tenants(id,display_name) VALUES($1,'scope288')`, scope)
			exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, scope)
		}
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'scope288','x')`, user, "scope288-"+user.String()[:8])
		for index, id := range []uuid.UUID{unclaimed, claimed, spare} {
			exec(`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,$2,$3,$4,'active',$5)`,
				id, 91000+index, platform, "scope288-"+id.String()[:8], user)
		}
		// 287 writers leave an unscoped placeholder on nodes they looked at.
		exec(`INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at) VALUES($1,NULL,$3),($2,$4,$3)`,
			unclaimed, claimed, now, tenant)
		exec(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at) VALUES($1,$2,'\x01',$3,'test','1','building',$4,$3,$5)`,
			configVersion, tenant, digest[:], "scope288-"+configVersion.String()[:8], now)
		exec(`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
			request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,deadline_at,
			created_at,updated_at) VALUES($1,$2,$3,'apply','building',$4,$5,$6,$6,1000,1000,1,$7::timestamptz+interval '1 hour',$7,$7)`,
			rollout, tenant, configVersion, "scope288-"+rollout.String()[:8], digest[:], uuid.New(), now)
		exec(`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
			command_bytes,command_sha256,deadline_at,created_at,updated_at)
			VALUES($1,$2,$3,1,$4,'apply','healthy',$5,$6,$7,$8::timestamptz+interval '1 hour',$8,$8)`,
			seeded, rollout, claimed, configVersion, uuid.New(), command, digest[:], now)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	isolate := func(scope uuid.UUID) error {
		_, err := pool.Exec(ctx, `INSERT INTO node_isolation_states(scope_id,node_id,status,desired_config_version_id,
			desired_artifact_sha256,desired_identity_schema,consecutive_failures,consecutive_healthy,last_session_epoch,
			last_health_sequence,last_report_id,last_outcome,reason_code,revision,updated_at)
			VALUES($1,$2,'active',$3,$4,1,0,0,0,0,$5,'succeeded','healthy',1,now())`,
			scope, claimed, configVersion, digest[:], uuid.New())
		return err
	}
	// Before 288 the owner of a platform node a tenant claimed cannot record
	// isolation: the trigger demanded the tenant's configuration scope.
	if err := isolate(platform); err == nil {
		t.Fatal("287 accepted isolation of a claimed platform node; the defect this migration fixes is gone")
	}

	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	var placeholders int
	var seededScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM node_config_state WHERE node_id=$1),
		(SELECT configuration_scope_id FROM node_deployments WHERE id=$2)`, unclaimed, seeded).Scan(&placeholders, &seededScope); err != nil ||
		placeholders != 0 || seededScope != tenant {
		t.Fatalf("placeholders=%d seeded scope=%s err=%v", placeholders, seededScope, err)
	}

	// A second scope on one node cannot be expressed in 287.
	if _, err := pool.Exec(ctx, `DROP INDEX node_config_state_single_scope_288_idx`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at) VALUES($1,$2,now())`,
		claimed, other); err != nil {
		t.Fatal(err)
	}
	var pgErr *pgconn.PgError
	if err := migrateVersionIsolated(ctx, pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P2881" {
		t.Fatalf("down with two scopes on one node: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM node_config_state WHERE node_id=$1 AND configuration_scope_id=$2`, claimed, other); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE UNIQUE INDEX node_config_state_single_scope_288_idx ON node_config_state (node_id)`); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}

	expect := func(name, code, constraint string, sql string, args ...any) {
		t.Helper()
		_, err := pool.Exec(ctx, sql, args...)
		if !errors.As(err, &pgErr) || pgErr.Code != code || constraint != "" && pgErr.ConstraintName != constraint {
			t.Errorf("%s: %v, want %s %s", name, err, code, constraint)
		}
	}
	expect("unscoped state", "23502", "",
		`INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at) VALUES($1,NULL,now())`, unclaimed)
	expect("second scope on a single-scope node", "23505", "node_config_state_single_scope_288_idx",
		`INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at) VALUES($1,$2,now())`, claimed, other)

	// Writers name only the rollout; the deployment takes the rollout's scope.
	inserted := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,
		command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
		VALUES($1,$2,$3,1,$4,'apply','queued',$5,$6,$7,now()+interval '1 hour',now(),now())`,
		inserted, rollout, unclaimed, configVersion, uuid.New(), command, digest[:]); err != nil {
		t.Fatal(err)
	}
	var insertedScope uuid.UUID
	var commandSHA []byte
	if err := pool.QueryRow(ctx, `SELECT configuration_scope_id,command_sha256 FROM node_deployments WHERE id=$1`, inserted).
		Scan(&insertedScope, &commandSHA); err != nil || insertedScope != tenant || !bytes.Equal(commandSHA, digest[:]) {
		t.Fatalf("inserted deployment scope=%s err=%v", insertedScope, err)
	}
	// Isolation is node-level: the owner scope records it, a claiming tenant cannot.
	if err := isolate(platform); err != nil {
		t.Fatalf("isolation of a claimed platform node: %v", err)
	}
	if err := isolate(tenant); !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Errorf("claiming tenant isolated a platform node: %v", err)
	}
	expect("deployment scope change", "23514", "node_deployments_scope_288",
		`UPDATE node_deployments SET configuration_scope_id=$2 WHERE id=$1`, inserted, other)
	expect("deployment scope outside its rollout", "23503", "node_deployments_rollout_scope_288_fkey",
		`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,configuration_scope_id,
		command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
		VALUES($1,$2,$3,1,$4,'apply','healthy',$5,$6,$7,$8,now()+interval '1 hour',now(),now())`,
		uuid.New(), rollout, spare, configVersion, other, uuid.New(), command, digest[:])
}
