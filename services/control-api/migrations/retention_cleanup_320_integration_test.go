//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRetentionCleanup320 (FX01): node_metric_samples stays append-only for
// everyone except the dedicated cdnca_retention_cleanup role, which may only
// delete rows older than the platform retention setting and never the newest
// sample of a node; 0 days disables cleanup.
func TestRetentionCleanup320(t *testing.T) {
	const version = 320
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	ensureRetentionCleanupRole(t, pool)
	platformScope, userID := uuid.New(), uuid.New()
	nodeA, nodeB := uuid.New(), uuid.New()
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{platformScope}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'retention-320','Retention','unused')`, []any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{platformScope, userID}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES
			($1,$3,'retention-a','active',$4,1),($2,$3,'retention-b','active',$4,2)`, []any{nodeA, nodeB, platformScope, userID}},
	} {
		if _, err := pool.Exec(ctx, seed.sql, seed.args...); err != nil {
			t.Fatalf("seed %q: %v", seed.sql, err)
		}
	}
	sequence := int64(0)
	sample := func(node uuid.UUID, age string) uuid.UUID {
		t.Helper()
		sequence++
		id := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO node_metric_samples(event_id,request_id,node_id,schema_version,config_revision,
			publication_sequence,observed_at,metrics_known,puback_stream,puback_sequence,consumer_durable,consumer_sequence,
			num_delivered,wire_sha256,ingested_at,record_kind,active_config_revision,probe_port,healthy,probe_succeeded,
			consecutive_failures,consecutive_successes,probes_total,probe_failures_total,recovered,recovery_notified,rolled_back)
			VALUES($1,$2,$3,1,1,$4,now()-$5::interval,false,'NODE_MONITORING_STATUS',$4,'control_api_node_metrics',$4,
			1,$6,now(),'metric',1,80,true,true,0,1,1,0,false,false,false)`,
			id, uuid.New(), node, sequence, age, make([]byte, 32)); err != nil {
			t.Fatalf("insert sample: %v", err)
		}
		return id
	}
	oldA := sample(nodeA, "10 days")
	recentA := sample(nodeA, "1 day")
	onlyB := sample(nodeB, "20 days")
	_ = recentA

	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	remaining := func() map[uuid.UUID]bool {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT event_id FROM node_metric_samples`)
		if err != nil {
			t.Fatal(err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			t.Fatal(err)
		}
		result := map[uuid.UUID]bool{}
		for _, id := range ids {
			result[id] = true
		}
		return result
	}
	asCleanup := func(statement string, args ...any) error {
		return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE cdnca_retention_cleanup`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, statement, args...)
			return err
		})
	}

	// The application login still cannot delete history.
	if _, err := pool.Exec(ctx, `DELETE FROM node_metric_samples WHERE event_id=$1`, oldA); !pgCode(err, "P1502") {
		t.Fatalf("owner delete = %v, want P1502", err)
	}
	// The cleanup role cannot update or touch rows inside retention (default 7 days).
	if err := asCleanup(`UPDATE node_metric_samples SET num_delivered=2 WHERE event_id=$1`, oldA); !pgCode(err, "42501") {
		t.Fatalf("cleanup update = %v, want 42501", err)
	}
	if err := asCleanup(`DELETE FROM node_metric_samples WHERE event_id=$1`, recentA); !pgCode(err, "P3202") {
		t.Fatalf("cleanup delete inside retention = %v, want P3202", err)
	}
	// The newest sample of a node survives even when old.
	if err := asCleanup(`DELETE FROM node_metric_samples WHERE event_id=$1`, onlyB); !pgCode(err, "P3202") {
		t.Fatalf("cleanup delete of newest sample = %v, want P3202", err)
	}
	// 0 days disables cleanup entirely.
	if _, err := pool.Exec(ctx, `INSERT INTO platform_system_cleanup_settings(platform_scope_id,revision,settings,updated_at)
		VALUES($1,1,'{"node_metrics_days":0}',now())`, platformScope); err != nil {
		t.Fatal(err)
	}
	if err := asCleanup(`DELETE FROM node_metric_samples WHERE event_id=$1`, oldA); !pgCode(err, "P3202") {
		t.Fatalf("cleanup delete with 0 days = %v, want P3202", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE platform_system_cleanup_settings SET settings='{"node_metrics_days":7}' WHERE platform_scope_id=$1`,
		platformScope); err != nil {
		t.Fatal(err)
	}
	if err := asCleanup(`DELETE FROM node_metric_samples WHERE event_id=$1`, oldA); err != nil {
		t.Fatalf("cleanup delete of an expired sample = %v", err)
	}
	if left := remaining(); left[oldA] || !left[recentA] || !left[onlyB] || len(left) != 2 {
		t.Fatalf("remaining samples = %v", left)
	}
}

// ensureRetentionCleanupRole mirrors scripts/install-control.sh: the NOLOGIN
// cleanup role exists and is granted (without inherit) to the application login.
func ensureRetentionCleanupRole(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DO $$ BEGIN
		IF to_regrole('cdnca_retention_cleanup') IS NULL THEN
			CREATE ROLE cdnca_retention_cleanup NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
		END IF;
		IF NOT pg_has_role(current_user, 'cdnca_retention_cleanup', 'MEMBER') THEN
			EXECUTE format('GRANT cdnca_retention_cleanup TO %I', current_user);
		END IF;
	END $$`); err != nil {
		t.Fatalf("ensure retention cleanup role: %v", err)
	}
}
