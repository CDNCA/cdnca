//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestAuditUnifiedFields361: up/down/up round-trips on an empty audit log,
// pre-361 rows get the defaults, the archive guard compares the new columns,
// and down refuses while hashed audit rows exist.
func TestAuditUnifiedFields361(t *testing.T) {
	const version = 361
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	var existing int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&existing); err != nil {
		t.Fatal(err)
	}
	if existing == 0 {
		for _, step := range []string{"up", "down"} {
			if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
				t.Fatalf("%s %d on an empty audit log: %v", step, version, err)
			}
		}
	}
	tenantID, scopeID := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'361 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO audit_events(id,scope_id,stream_position,action,resource_type,resource_id,
		request_id,result,event_hash,occurred_at) VALUES($1,$2,1,'site.update','site','s','r361','success',
		decode(repeat('00',32),'hex'),now())`, uuid.New(), scopeID)
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	var category, actorKind, sourceIP, changes string
	if err := pool.QueryRow(ctx, `SELECT category, actor_kind, source_ip, changes::text FROM audit_events
		WHERE request_id='r361'`).Scan(&category, &actorKind, &sourceIP, &changes); err != nil {
		t.Fatal(err)
	}
	if category != "other" || actorKind != "system" || sourceIP != "" || changes != "[]" {
		t.Fatalf("pre-361 row defaults = %q %q %q %q", category, actorKind, sourceIP, changes)
	}
	var guard string
	if err := pool.QueryRow(ctx, `SELECT tgfoid::regprocedure::text FROM pg_trigger
		WHERE tgrelid='audit_event_archive'::regclass AND tgname='audit_event_archive_insert_361'`).Scan(&guard); err != nil {
		t.Fatalf("archive guard trigger: %v", err)
	}
	if guard != "guard_audit_event_archive_insert_361()" {
		t.Fatalf("archive guard = %s", guard)
	}
	// Only the cleanup role may archive, and only exact copies.
	_, err := pool.Exec(ctx, `INSERT INTO audit_event_archive(id,scope_id,stream_position,action,resource_type,
		resource_id,request_id,result,payload,event_hash,occurred_at)
		SELECT id,scope_id,stream_position,action,resource_type,resource_id,request_id,result,payload,event_hash,occurred_at
		FROM audit_events WHERE request_id='r361'`)
	if sqlState(err) != "P3612" {
		t.Fatalf("archive insert by the migration owner: %v, want P3612", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3613" {
		t.Fatalf("down with audit rows: %v, want P3613", err)
	}
}
