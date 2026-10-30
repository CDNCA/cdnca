//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestAuditUserAgent491 (tp-b6b): up/down/up round-trips, pre-491 rows get
// '' (shown as —), the column refuses control characters and over-long
// values, the archive guard is the 491 one, and down refuses while a stored
// (hashed) user agent exists but allows rows without one.
func TestAuditUserAgent491(t *testing.T) {
	const version = 491
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'491 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO audit_events(id,scope_id,stream_position,action,resource_type,resource_id,
		request_id,result,event_hash,occurred_at) VALUES($1,$2,1,'site.update','site','s','r491','success',
		decode(repeat('00',32),'hex'),now())`, uuid.New(), scopeID)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d with rows lacking a user agent: %v", step, version, err)
		}
	}
	var userAgent string
	if err := pool.QueryRow(ctx, `SELECT user_agent FROM audit_events WHERE request_id='r491'`).Scan(&userAgent); err != nil {
		t.Fatal(err)
	}
	if userAgent != "" {
		t.Fatalf("pre-491 row user_agent = %q", userAgent)
	}
	var guard string
	if err := pool.QueryRow(ctx, `SELECT tgfoid::regprocedure::text FROM pg_trigger
		WHERE tgrelid='audit_event_archive'::regclass AND tgname='audit_event_archive_insert_491'`).Scan(&guard); err != nil {
		t.Fatalf("archive guard trigger: %v", err)
	}
	if guard != "guard_audit_event_archive_insert_491()" {
		t.Fatalf("archive guard = %s", guard)
	}
	insert := `INSERT INTO audit_events(id,scope_id,stream_position,action,resource_type,resource_id,
		request_id,result,event_hash,occurred_at,user_agent) VALUES($1,$2,$3,'site.update','site','s','r491b','success',
		decode(repeat('00',32),'hex'),now(),$4)`
	for name, value := range map[string]string{"control": "Mozilla\n5.0", "too long": strings.Repeat("a", 513), "padded": " Mozilla"} {
		if _, err := pool.Exec(ctx, insert, uuid.New(), scopeID, 2, value); sqlState(err) != "23514" {
			t.Errorf("%s user agent: %v, want 23514", name, err)
		}
	}
	mustExec(t, pool, insert, uuid.New(), scopeID, 2, "Mozilla/5.0")
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4912" {
		t.Fatalf("down with a stored user agent: %v, want P4912", err)
	}
}
