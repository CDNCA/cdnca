//go:build integration

package retentioncleanup

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FX01: the worker deletes only expired node metric samples (keeping each
// node's newest), in batches, as the cleanup role, and audits each batch.
func TestWorkerPrunesExpiredNodeMetricsAndAudits(t *testing.T) {
	pool := retentionTestPool(t)
	ctx := context.Background()
	grantCleanupRole(t, pool)
	scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'retention-worker','Retention','unused')`, []any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'retention-worker','active',$3,1)`,
			[]any{nodeID, scopeID, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	ages := []string{"30 days", "20 days", "10 days", "8 days", "2 days", "1 hour"}
	for index, age := range ages {
		sequence := int64(index + 1)
		if _, err := pool.Exec(ctx, `INSERT INTO node_metric_samples(event_id,request_id,node_id,schema_version,config_revision,
			publication_sequence,observed_at,metrics_known,puback_stream,puback_sequence,consumer_durable,consumer_sequence,
			num_delivered,wire_sha256,ingested_at,record_kind,active_config_revision,probe_port,healthy,probe_succeeded,
			consecutive_failures,consecutive_successes,probes_total,probe_failures_total,recovered,recovery_notified,rolled_back)
			VALUES($1,$2,$3,1,1,$4,now()-$5::interval,false,'NODE_MONITORING_STATUS',$4,'control_api_node_metrics',$4,
			1,$6,now(),'metric',1,80,true,true,0,1,1,0,false,false,false)`,
			uuid.New(), uuid.New(), nodeID, sequence, age, make([]byte, 32)); err != nil {
			t.Fatalf("insert sample: %v", err)
		}
	}
	// Node traffic history (45 days by default): 60/50/40 days and 1 hour old.
	policyID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO node_traffic_policies(id,scope_id,node_id,monthly_limit_bytes,timezone,
		override_mode,override_revision,revision,created_by_user_id,created_at,updated_at,next_evaluation_at)
		VALUES($1,$2,$3,0,'UTC','none',0,1,$4,now()-interval '90 days',now(),now())`, policyID, scopeID, nodeID, userID); err != nil {
		t.Fatalf("seed traffic policy: %v", err)
	}
	evaluations := map[string]uuid.UUID{}
	for _, age := range []string{"60 days", "50 days", "40 days", "1 hour"} {
		id := uuid.New()
		evaluations[age] = id
		if _, err := pool.Exec(ctx, `INSERT INTO node_traffic_policy_evaluations(id,scope_id,node_id,policy_revision,
			period_key,period_start,period_end,usage_bytes,monthly_limit_bytes,suppressed,sync_required,reason_code,
			override_revision,evaluated_at,source_snapshot_at,source_finalized_through,source_digest,request_id)
			VALUES($1,$2,$3,1,'2026-01','2026-01-01','2026-02-01',0,0,false,false,'within_policy',0,
			now()-$4::interval,now()-$4::interval,now()-$4::interval,$5,'retention-traffic')`,
			id, scopeID, nodeID, age, make([]byte, 32)); err != nil {
			t.Fatalf("seed traffic evaluation: %v", err)
		}
	}
	worker, err := NewWorker(pool, audit.New(pool), Config{BatchSize: 3, BatchPause: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	results := worker.RunOnce(ctx)
	if len(results) != len(targets)+1 || results[0].Err != nil || results[0].Deleted != 4 {
		t.Fatalf("results = %+v", results)
	}
	var left int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_metric_samples WHERE observed_at < now()-interval '7 days'`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("expired samples left = %d (%v)", left, err)
	}
	var kept int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_metric_samples`).Scan(&kept); err != nil || kept != 2 {
		t.Fatalf("kept samples = %d (%v)", kept, err)
	}
	var batches, audited int64
	if err := pool.QueryRow(ctx, `SELECT count(*), COALESCE(sum((payload->>'deleted')::bigint),0) FROM audit_events
		WHERE action=$1 AND resource_id='node_metric_samples' AND scope_id=$2`, AuditAction, scopeID).Scan(&batches, &audited); err != nil ||
		batches != 2 || audited != 4 {
		t.Fatalf("audit batches=%d deleted=%d (%v)", batches, audited, err)
	}
	if results[1].Table != "node_traffic_policy_evaluations" || results[1].Err != nil || results[1].Deleted != 2 {
		t.Fatalf("traffic results = %+v", results[1])
	}
	var trafficLeft int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_traffic_policy_evaluations WHERE id = ANY($1)`,
		[]uuid.UUID{evaluations["40 days"], evaluations["1 hour"]}).Scan(&trafficLeft); err != nil || trafficLeft != 2 {
		t.Fatalf("kept traffic evaluations = %d (%v)", trafficLeft, err)
	}
	// Other roles still cannot delete node traffic history.
	if _, err := pool.Exec(ctx, `DELETE FROM node_traffic_policy_evaluations WHERE id=$1`, evaluations["40 days"]); err == nil {
		t.Fatal("plain delete of node traffic evaluation succeeded")
	}
	// A second run finds nothing more.
	if again := worker.RunOnce(ctx); again[0].Err != nil || again[0].Deleted != 0 {
		t.Fatalf("second run = %+v", again)
	}

	// Without membership in the cleanup role the worker deletes nothing and
	// reports it. The test login may be a superuser (member of every role), so
	// the check runs as a plain role that was never granted cdnca_retention_cleanup.
	if _, err := pool.Exec(ctx, `DO $$ BEGIN
		IF to_regrole('retention_test_nonmember') IS NULL THEN
			CREATE ROLE retention_test_nonmember NOLOGIN NOINHERIT;
		END IF;
	END $$`); err != nil {
		t.Fatal(err)
	}
	config := pool.Config()
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, err := connection.Exec(ctx, "SET ROLE retention_test_nonmember")
		return err
	}
	plain, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	plainWorker, err := NewWorker(plain, audit.New(plain), Config{BatchSize: 3, BatchPause: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range plainWorker.RunOnce(ctx) {
		if !errors.Is(result.Err, ErrRoleUnavailable) || result.Deleted != 0 || result.Archived != 0 {
			t.Fatalf("without role %s = %+v", result.Table, result)
		}
	}
}

func retentionTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "retention_cleanup_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("migrate isolated schema: %v", err)
	}
	return pool
}
