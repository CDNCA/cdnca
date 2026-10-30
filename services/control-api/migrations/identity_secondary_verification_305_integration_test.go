//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestIdentitySecondaryVerificationMigration rolls 305 up, down and up on a
// 304 schema and checks the event becomes supported and the rollback refuses
// to discard a stored request.
func TestIdentitySecondaryVerificationMigration(t *testing.T) {
	const version = 305
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var supported, granted bool
	var templates int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT supported AND enabled AND sms_enabled AND email_enabled FROM notification_event_policies WHERE event_type='identity.secondary_verification'),
		(SELECT count(*) FROM notification_templates WHERE template_id='identity_secondary_verification'),
		has_table_privilege('cdnca_control_runtime','identity_user_secondary_verification','UPDATE') AND
		NOT has_table_privilege('cdnca_control_app','identity_user_secondary_verification','DELETE')`).
		Scan(&supported, &templates, &granted); err != nil || !supported || templates != 2 || !granted {
		t.Fatalf("supported=%v templates=%d grants=%v err=%v", supported, templates, granted, err)
	}
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'secver305')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'secver305','secver305','hash')`, []any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
	} {
		if _, err := pool.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	// lock_sites requires a deadline
	if _, err := pool.Exec(ctx, `INSERT INTO identity_user_secondary_verification
		(scope_id,user_id,revision,enabled,expiry_action,requested_at,updated_by_user_id,updated_at)
		VALUES($1,$2,1,true,'lock_sites',now(),$2,now())`, scopeID, userID); err == nil {
		t.Fatal("lock_sites without a deadline was accepted")
	}
	// valid row
	if _, err := pool.Exec(ctx, `INSERT INTO identity_user_secondary_verification
		(scope_id,user_id,revision,enabled,deadline,expiry_action,requested_at,updated_by_user_id,updated_at)
		VALUES($1,$2,1,true,now()+'30 days','lock_sites',now(),$2,now())`, scopeID, userID); err != nil {
		t.Fatalf("valid secondary verification insert: %v", err)
	}
	// rollback refused when row exists
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("rollback discarded a secondary verification request")
	}
}
