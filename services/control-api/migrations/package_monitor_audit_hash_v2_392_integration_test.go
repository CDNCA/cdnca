//go:build integration

package migrations_test

import (
	"bytes"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
)

// TestPackageMonitorAuditHashV2387: package_monitor_audit_hash_392 yields the
// exact version-2 hash audit.AppendTx stores (all unified-log columns,
// escaping, changes), the 078 clock trigger uses it after up and goes back to
// the 078 hash after down.
func TestPackageMonitorAuditHashV2387(t *testing.T) {
	const version = 392
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	// Today's audit.AppendTx also writes 491's user_agent (empty here, so the
	// canonical bytes and the 392 SQL hash are unchanged).
	mustExec(t, pool, `ALTER TABLE audit_events ADD COLUMN user_agent text NOT NULL DEFAULT ''`)
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'373 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'373 user','unused')`,
		userID, "u373-"+userID.String()[:8])
	control := "quote\" backslash\\ \n\t <>&   中文"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, event := range []audit.Event{
		{ScopeID: scopeID, Action: "site.update", ResourceType: "site<>", ResourceID: control,
			RequestID: "r373-1", Result: "success", Payload: map[string]any{"note": control, "count": 7}},
		{ScopeID: scopeID, ActorUserID: &userID, Action: "site.update", ResourceType: "site",
			ResourceID: "s", RequestID: "r373-2", Result: "denied", ReasonCode: "quota_exceeded",
			SourceIP: "192.0.2.10", ActorRef: "api_key:k1",
			Changes: []audit.Change{{Field: "cc.enabled", Before: false, After: control},
				{Field: "api_token", Before: "old", After: "new"}}},
	} {
		if _, err := audit.AppendTx(ctx, tx, event); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, `SELECT request_id, event_hash, package_monitor_audit_hash_392(
			id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,request_id,
			result,payload,previous_hash,occurred_at,category,actor_kind,actor_ref,source_ip,
			reason_code,changes)
		FROM audit_events WHERE scope_id=$1 ORDER BY stream_position`, scopeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	checked := 0
	for rows.Next() {
		var requestID string
		var stored, computed []byte
		if err := rows.Scan(&requestID, &stored, &computed); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(stored, computed) {
			t.Fatalf("%s: SQL v2 hash %x, Go stored %x", requestID, computed, stored)
		}
		checked++
	}
	if err := rows.Err(); err != nil || checked != 2 {
		t.Fatalf("checked %d rows: %v", checked, err)
	}

	var bound string
	if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('bind_package_monitor_audit_clock_078()'::regprocedure)`).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(bound), []byte("package_monitor_audit_hash_392(")) {
		t.Fatal("078 clock trigger still uses the version-1 hash after 392 up")
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d with audit rows: %v", version, err)
	}
	if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('bind_package_monitor_audit_clock_078()'::regprocedure)`).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(bound), []byte("package_monitor_audit_hash_078(")) {
		t.Fatal("392 down did not restore the 078 clock trigger")
	}
}
