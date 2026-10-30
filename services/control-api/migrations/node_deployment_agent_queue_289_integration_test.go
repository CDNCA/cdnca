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

// TestNodeDeploymentAgentQueueMigration checks the agent queue path
// delivered -> agent_queued -> started -> staged, that it cannot be skipped,
// and that rolling back refuses recorded queue states.
func TestNodeDeploymentAgentQueueMigration(t *testing.T) {
	const version = 289
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()

	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); errors.Is(err, pgx.ErrNoRows) {
		platform = uuid.New()
	} else if err != nil {
		t.Fatal(err)
	}
	tenant, user, queuedNode, legacyNode := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	configVersion, rollout := uuid.New(), uuid.New()
	queued, legacy := uuid.New(), uuid.New()
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
		exec(`INSERT INTO tenants(id,display_name) VALUES($1,'queue289')`, tenant)
		exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, tenant)
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'queue289','x')`, user, "queue289-"+user.String()[:8])
		for index, id := range []uuid.UUID{queuedNode, legacyNode} {
			exec(`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,$2,$3,$4,'active',$5)`,
				id, 92000+index, platform, "queue289-"+id.String()[:8], user)
		}
		exec(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at) VALUES($1,$2,'\x01',$3,'test','1','building',$4,$3,$5)`,
			configVersion, tenant, digest[:], "queue289-"+configVersion.String()[:8], now)
		exec(`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
			request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,deadline_at,
			created_at,updated_at) VALUES($1,$2,$3,'apply','building',$4,$5,$6,$6,1000,1000,1,$7::timestamptz+interval '1 hour',$7,$7)`,
			rollout, tenant, configVersion, "queue289-"+rollout.String()[:8], digest[:], uuid.New(), now)
		// One delivered deployment per node: one takes the agent queue path,
		// the other the direct path of agents without MULTI_TENANT_RUNTIME.
		for id, nodeID := range map[uuid.UUID]uuid.UUID{queued: queuedNode, legacy: legacyNode} {
			exec(`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,configuration_scope_id,
				command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
				VALUES($1,$2,$3,1,$4,'apply','delivered',$5,$6,$7,$8,$9::timestamptz+interval '1 hour',$9,$9)`,
				id, rollout, nodeID, configVersion, tenant, uuid.New(), command, digest[:], now)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}

	advance := func(id uuid.UUID, state string) error {
		_, err := pool.Exec(ctx, `UPDATE node_deployments SET state=$2,updated_at=now() WHERE id=$1`, id, state)
		return err
	}
	var pgErr *pgconn.PgError
	if err := advance(queued, "started"); !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("delivered -> started skipped the agent queue: %v", err)
	}
	if err := advance(queued, "agent_queued"); err != nil {
		t.Fatalf("delivered -> agent_queued: %v", err)
	}
	if err := advance(queued, "staged"); !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("agent_queued -> staged skipped start: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P2891" {
		t.Fatalf("down with a queued deployment: %v", err)
	}
	for _, state := range []string{"started", "staged"} {
		if err := advance(queued, state); err != nil {
			t.Fatalf("advance to %s: %v", state, err)
		}
	}
	// Agents without MULTI_TENANT_RUNTIME keep the direct path.
	if err := advance(legacy, "staged"); err != nil {
		t.Fatalf("legacy delivered -> staged: %v", err)
	}
	for _, step := range []string{"down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d after queue drained: %v", step, version, err)
		}
	}
}
