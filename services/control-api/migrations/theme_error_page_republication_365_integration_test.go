//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestThemeErrorPageRepublication365: up/down/up keeps 046's rollout
// contract guard intact apart from the error page branch; the system
// republication channel takes trigger theme_activation and an attempt that
// published only an error page rollout; down refuses once such facts exist.
func TestThemeErrorPageRepublication365(t *testing.T) {
	const version = 365
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	// 同库另一 schema 带同名约束时，守卫只数当前 schema（否则 P3650）。
	seedSiblingSchemaConstraints(t, pool, "edge_system_republication_heads_triggers_check",
		"edge_system_republication_attempts_triggers_check", "edge_system_republication_attempts_check")
	guard := func() string {
		var definition string
		if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('assert_rollout_contract_046()'::regprocedure)`).Scan(&definition); err != nil {
			t.Fatal(err)
		}
		return definition
	}
	before := guard()
	if strings.Contains(before, "edge-error-page-snapshot") {
		t.Fatal("364 guard already accepts error page rollouts")
	}
	for _, step := range []string{"up", "down"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	if after := guard(); after != before {
		t.Fatalf("down did not restore the 046 guard:\n%s", after)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	if !strings.Contains(guard(), "'edge_error_page.publish'") {
		t.Fatal("365 guard does not accept audited error page rollouts")
	}

	var scopeID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='tenant' LIMIT 1`).Scan(&scopeID); err != nil {
		tenantID := uuid.New()
		scopeID = uuid.New()
		mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'365 tenant')`, tenantID)
		mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	}
	head := func(triggers string) error {
		_, err := pool.Exec(ctx, `INSERT INTO edge_system_republication_heads(scope_id,generation,state,triggers,due_at,attempt,
			created_at,updated_at) VALUES($1,1,'pending',$2::text[],now(),0,now(),now())`, scopeID, triggers)
		return err
	}
	if err := head("{theme_unknown}"); sqlState(err) != "23514" {
		t.Fatalf("unknown trigger: %v, want 23514", err)
	}
	if err := head("{theme_activation}"); err != nil {
		t.Fatalf("theme_activation head: %v", err)
	}
	attempt := func(outcome string) error {
		_, err := pool.Exec(ctx, `INSERT INTO edge_system_republication_attempts(id,scope_id,generation,attempt,triggers,outcome,occurred_at)
			VALUES($1,$2,1,1,'{theme_activation}',$3,now())`, uuid.New(), scopeID, outcome)
		return err
	}
	if err := attempt("published"); sqlState(err) != "23514" {
		t.Fatalf("published without a publication or rollout: %v, want 23514", err)
	}
	if err := attempt("no_baseline"); err != nil {
		t.Fatalf("no_baseline attempt: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3651" {
		t.Fatalf("down with theme facts: %v, want P3651", err)
	}
}
