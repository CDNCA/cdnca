//go:build integration

package retentioncleanup

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// FX01: expired audit history is archived with a chain checkpoint. Unpinned
// rows leave audit_events (unified-log: their archive copies are purged too);
// pinned rows (newest of their group, cache.*, chain
// head) stay; the chain still verifies from the checkpoint; nobody else may
// delete audit rows or forge archive rows.
func TestWorkerArchivesExpiredAuditPrefix(t *testing.T) {
	pool := retentionTestPool(t)
	ctx := context.Background()
	grantCleanupRole(t, pool)
	// Migrations create no platform scope (identity bootstrap does), so the
	// fixture creates the single one the cleanup settings and audits attach to.
	tenantID, scopeID, platformScope := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{platformScope}},
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Audit archive')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if err := SaveAuditRetention(ctx, pool, platformScope, map[string]int{"auth": 10, "site": 10, "other": 10}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	events := []struct {
		age                      time.Duration
		action, resource, result string
	}{
		{20 * 24 * time.Hour, "auth.login", "user-a", "success"},       // 1 superseded by 3: deleted
		{19 * 24 * time.Hour, "site.update", "site-a", "success"},      // 2 superseded by 4: deleted
		{18 * 24 * time.Hour, "auth.login", "user-a", "success"},       // 3 newest of its group: kept
		{17 * 24 * time.Hour, "site.update", "site-a", "success"},      // 4 newest of its group: kept
		{16 * 24 * time.Hour, "cache.archive_test", "op-a", "success"}, // 5 cache.*: kept
		{24 * time.Hour, "site.update", "site-b", "success"},           // 6 within retention
		{12 * time.Hour, "auth.login", "user-b", "success"},            // 7 within retention, head
	}
	for _, event := range events {
		clock := now.Add(-event.age)
		log := audit.NewWithClock(pool, func() time.Time { return clock })
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			return log.Append(ctx, tx, audit.Event{ScopeID: scopeID, Action: event.action, ResourceType: "test",
				ResourceID: event.resource, RequestID: "archive-" + uuid.NewString(), Result: event.result,
				Payload: map[string]any{"resource": event.resource}})
		}); err != nil {
			t.Fatalf("append %s: %v", event.action, err)
		}
	}
	worker, err := NewWorker(pool, audit.New(pool), Config{BatchSize: 3, BatchPause: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	result := worker.archiveAudit(ctx)
	if result.Err != nil {
		t.Fatalf("archive: %+v", result)
	}
	var remaining []int64
	rows, err := pool.Query(ctx, `SELECT stream_position FROM audit_events WHERE scope_id=$1 ORDER BY 1`, scopeID)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err = pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil || len(remaining) != 5 || remaining[0] != 3 || remaining[4] != 7 {
		t.Fatalf("remaining positions = %v (%v)", remaining, err)
	}
	var archived, through int64
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM audit_event_archive WHERE scope_id=$1),
		(SELECT through_position FROM audit_chain_checkpoints WHERE scope_id=$1)`, scopeID).Scan(&archived, &through); err != nil ||
		archived != 3 || through != 5 {
		t.Fatalf("archived=%d checkpoint=%d (%v)", archived, through, err)
	}
	if err := audit.New(pool).VerifyScope(ctx, scopeID); err != nil {
		t.Fatalf("verify after archive: %v", err)
	}
	var batches int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action=$1 AND resource_id=$2`,
		AuditArchiveAction, scopeID.String()).Scan(&batches); err != nil || batches != 2 {
		t.Fatalf("archive audit batches = %d (%v)", batches, err)
	}
	// Nothing more is expired: a second run archives nothing.
	if again := worker.archiveAudit(ctx); again.Err != nil || again.Archived != 0 {
		t.Fatalf("second run = %+v", again)
	}

	asCleanup := func(sql string, args ...any) error {
		return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+Role); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
	}
	// A pinned row stays even for the cleanup role; an unarchived row too.
	if err := asCleanup(`DELETE FROM audit_events WHERE scope_id=$1 AND stream_position=3`, scopeID); !hasCode(err, "P3314") {
		t.Fatalf("pinned delete err = %v", err)
	}
	if err := asCleanup(`DELETE FROM audit_events WHERE scope_id=$1 AND stream_position=6`, scopeID); !hasCode(err, "P3314") {
		t.Fatalf("unarchived delete err = %v", err)
	}
	// Everyone else still sees an append-only table.
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events WHERE scope_id=$1 AND stream_position=3`, scopeID); err == nil {
		t.Fatal("plain delete of audit_events succeeded")
	}
	// The archive accepts only exact copies, and is immutable.
	if err := asCleanup(`INSERT INTO audit_event_archive(id,scope_id,stream_position,action,resource_type,resource_id,
		request_id,result,payload,event_hash,occurred_at) VALUES($1,$2,99,'forged','test','x','x','success','{}',$3,now())`,
		uuid.New(), scopeID, make([]byte, 32)); !hasCode(err, "P3612") {
		t.Fatalf("forged archive err = %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_event_archive WHERE scope_id=$1`, scopeID); !hasCode(err, "P3312") {
		t.Fatalf("archive delete err = %v", err)
	}
	// The checkpoint never moves backwards.
	if err := asCleanup(`UPDATE audit_chain_checkpoints SET through_position=4,
		through_hash=(SELECT event_hash FROM audit_event_archive WHERE scope_id=$1 AND stream_position=4)
		WHERE scope_id=$1`, scopeID); !hasCode(err, "P3313") {
		t.Fatalf("checkpoint rewind err = %v", err)
	}
}

func grantCleanupRole(t *testing.T, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `DO $$ BEGIN
		IF to_regrole('cdnca_retention_cleanup') IS NULL THEN
			CREATE ROLE cdnca_retention_cleanup NOLOGIN NOINHERIT;
		END IF;
		IF NOT pg_has_role(current_user, 'cdnca_retention_cleanup', 'MEMBER') THEN
			EXECUTE format('GRANT cdnca_retention_cleanup TO %I', current_user);
		END IF;
		EXECUTE format('GRANT USAGE ON SCHEMA %I TO cdnca_retention_cleanup', current_schema());
		GRANT SELECT, DELETE ON node_metric_samples, audit_events TO cdnca_retention_cleanup;
		GRANT SELECT, INSERT, DELETE ON audit_event_archive TO cdnca_retention_cleanup;
		GRANT SELECT, INSERT, UPDATE ON audit_chain_checkpoints TO cdnca_retention_cleanup;
		GRANT SELECT, DELETE ON node_traffic_policy_evaluations TO cdnca_retention_cleanup;
		GRANT SELECT ON node_traffic_sync_tasks TO cdnca_retention_cleanup;
		GRANT SELECT, DELETE ON cache_operations, cache_operation_commands, cache_operation_targets,
			cache_operation_nodes, cache_operation_node_targets, cache_operation_node_attempts,
			cache_operation_target_results, cache_operation_cancel_deliveries, security_ban_entries TO cdnca_retention_cleanup;
	END $$`); err != nil {
		t.Fatal(err)
	}
}

func hasCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
