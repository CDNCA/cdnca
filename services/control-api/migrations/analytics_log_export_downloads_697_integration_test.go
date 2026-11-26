//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
)

// TestAnalyticsLogExportDownloads697:
// 697 backfills one download row per success download audit of an existing
// export (denied audits and audits of unknown exports are skipped); rows are
// append-only; down drops the table and keeps the audit.
func TestAnalyticsLogExportDownloads697(t *testing.T) {
	const version = 697
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID, exportID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'export 697')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'test-only-hash')`,
		userID, "export-697-"+userID.String()[:8])
	mustExec(t, pool, `INSERT INTO analytics_log_exports_v1(id,scope_id,tenant_id,actor_scope_id,actor_user_id,
		credential_kind,credential_id,idempotency_key,request_digest,filter,created_at,scope_generation)
		VALUES($1,$2,$3,$2,$4,'session',$5,'export-697-key-0001',decode(repeat('ab',32),'hex'),'{}'::jsonb,now(),1)`,
		exportID, scopeID, tenantID, userID, uuid.New())
	log := audit.New(pool)
	appendAudit := func(resourceID, action, result string, at time.Time) uuid.UUID {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := log.Append(ctx, tx, audit.Event{ScopeID: scopeID, ActorUserID: &userID, Action: action,
			ResourceType: "analytics_log_export", ResourceID: resourceID, RequestID: "request-697", Result: result,
			OccurredAt: at, Payload: map[string]any{"reason": "grant_consumed"}}); err != nil {
			t.Fatal(err)
		}
		var id uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM audit_events WHERE scope_id=$1 ORDER BY stream_position DESC LIMIT 1`,
			scopeID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	firstID := appendAudit(exportID.String(), "analytics_log.export.download", "success", first)
	lastID := appendAudit(exportID.String(), "analytics_log.export.download", "success", first.Add(time.Minute))
	appendAudit(exportID.String(), "analytics_log.export.reject", "denied", first.Add(2*time.Minute))
	appendAudit(uuid.NewString(), "analytics_log.export.download", "success", first.Add(3*time.Minute))

	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	rows, err := pool.Query(ctx, `SELECT id,actor_user_id,downloaded_at FROM analytics_log_export_downloads_v1
		WHERE export_id=$1 ORDER BY downloaded_at`, exportID)
	if err != nil {
		t.Fatal(err)
	}
	var got []uuid.UUID
	for rows.Next() {
		var id, actor uuid.UUID
		var at time.Time
		if err := rows.Scan(&id, &actor, &at); err != nil {
			t.Fatal(err)
		}
		if actor != userID {
			t.Errorf("backfilled actor = %s, want %s", actor, userID)
		}
		got = append(got, id)
	}
	rows.Close()
	if len(got) != 2 || got[0] != firstID || got[1] != lastID {
		t.Fatalf("backfilled downloads = %v, want [%s %s]", got, firstID, lastID)
	}
	var total int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM analytics_log_export_downloads_v1`).Scan(&total); err != nil || total != 2 {
		t.Fatalf("all backfilled downloads = %d, %v; want 2", total, err)
	}
	for name, sql := range map[string]string{
		"update":   `UPDATE analytics_log_export_downloads_v1 SET downloaded_at=now() WHERE export_id='` + exportID.String() + `'`,
		"delete":   `DELETE FROM analytics_log_export_downloads_v1 WHERE export_id='` + exportID.String() + `'`,
		"truncate": `TRUNCATE analytics_log_export_downloads_v1`,
	} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Errorf("%s of a download row was accepted", name)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO analytics_log_export_downloads_v1(id,export_id,actor_user_id,downloaded_at)
		VALUES($1,$2,$3,now())`, uuid.New(), uuid.New(), userID); err == nil {
		t.Error("download row of an unknown export was accepted")
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	var table bool
	var audits int
	if err := pool.QueryRow(ctx, `SELECT to_regclass(current_schema() || '.analytics_log_export_downloads_v1') IS NOT NULL,
		(SELECT count(*) FROM audit_events WHERE action='analytics_log.export.download' AND resource_id=$1)`,
		exportID.String()).Scan(&table, &audits); err != nil {
		t.Fatal(err)
	}
	if table || audits != 2 {
		t.Fatalf("after down table=%v download audits=%d, want dropped table and 2 audits", table, audits)
	}
}
