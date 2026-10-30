//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestImpersonationDirectSwitch464 rolls 464 up, down and up on an empty grant
// table, checks the ticket/step-up columns are gone after up, and that down
// refuses once a grant exists (it cannot restore the dropped NOT NULL facts).
func TestImpersonationDirectSwitch464(t *testing.T) {
	const version = 464
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	columns := func() int {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='admin_impersonation_grants'
			  AND column_name IN ('ticket','step_up_method','step_up_evidence_id','step_up_at','step_up_expires_at')`).
			Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	for _, step := range []struct {
		direction string
		want      int
	}{{"up", 0}, {"down", 5}, {"up", 0}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := columns(); got != step.want {
			t.Fatalf("after %s: ticket/step-up columns = %d, want %d", step.direction, got, step.want)
		}
	}
	// A grant row (inserted without its principal triggers; the service path is
	// covered by internal/impersonation) must block the rollback.
	mustExec(t, pool, `ALTER TABLE admin_impersonation_grants DISABLE TRIGGER USER`)
	mustExec(t, pool, `ALTER TABLE admin_impersonation_grants DROP CONSTRAINT admin_impersonation_grants_tenant_id_fkey,
		DROP CONSTRAINT admin_impersonation_grants_primary_auth_session_id_fkey,
		DROP CONSTRAINT admin_impersonation_grants_tenant_scope_id_tenant_id_fkey,
		DROP CONSTRAINT admin_impersonation_grants_actor_scope_id_actor_user_id_fkey,
		DROP CONSTRAINT admin_impersonation_grants_tenant_scope_id_subject_user_id_fkey`)
	mustExec(t, pool, `INSERT INTO admin_impersonation_grants(id,tenant_id,tenant_scope_id,actor_user_id,actor_scope_id,
		primary_auth_session_id,subject_user_id,code_digest,subject_permissions_digest,reason,idempotency_key,
		request_digest,request_id,trace_id,created_at,expires_at)
		VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),
		gen_random_uuid(),gen_random_uuid(),sha256('code'),sha256('perm'),'user_list_switch','switch-464',
		sha256('req'),'request-464','trace-464',now(),now()+interval '1 minute')`)
	err := migrateVersionIsolated(ctx, pool, "down", version)
	if err == nil || !strings.Contains(err.Error(), "cannot restore ticket and step-up facts") {
		t.Fatalf("down with an existing grant error = %v", err)
	}
}
