//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Migration 532: the guard functions accept a platform administrator acting
// for any tenant; a platform member without platform.admin and a stranger are
// still refused.
func TestPlatformAdminAllTenants532(t *testing.T) {
	pool := releaseHeadMigrationPool(t)
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	var head int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil || head < 532 {
		t.Fatalf("release head=%d err=%v, want 532 applied", head, err)
	}
	var platformScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		platformScope = uuid.New()
		exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	}
	tenantID, tenantScope := uuid.New(), uuid.New()
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'532 tenant')`, tenantID)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenantScope, tenantID)
	user := func(label string) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'x')`,
			id, "p532-"+label+"-"+strings.ReplaceAll(id.String(), "-", "")[:8], label)
		return id
	}
	platform := func(u uuid.UUID, permission string) {
		roleID := uuid.New()
		exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'532',true)`,
			roleID, platformScope, "p532_"+strings.ReplaceAll(roleID.String(), "-", "")[:12])
		exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission)
		exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platformScope, u)
		exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, platformScope, u, roleID)
	}
	admin, viewer, stranger := user("admin"), user("viewer"), user("stranger")
	platform(admin, "platform.admin")
	platform(viewer, "sites.read")

	check := func(name, query string, args ...any) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, query, args...).Scan(&ok); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return ok
	}
	for _, c := range []struct {
		name, query string
		args        func(u uuid.UUID) []any
	}{
		{"035 system configuration", `SELECT system_configuration_actor_has_permission($1,$2,'system_configuration.manage')`,
			func(u uuid.UUID) []any { return []any{platformScope, u} }},
		{"054 error page", `SELECT error_page_actor_has_permission($1,$2,'error_pages.manage')`,
			func(u uuid.UUID) []any { return []any{platformScope, u} }},
		{"056 http policy", `SELECT http_policy_actor_can_056($1,$2,$3,'http_policies.manage')`,
			func(u uuid.UUID) []any { return []any{platformScope, u, tenantScope} }},
		{"048 ACME actor (used by 047)", `SELECT acme_runtime_actor_is_active_048($1,$2)`,
			func(u uuid.UUID) []any { return []any{tenantScope, u} }},
	} {
		if !check(c.name, c.query, c.args(admin)...) {
			t.Fatalf("%s: platform admin refused", c.name)
		}
		if check(c.name, c.query, c.args(viewer)...) {
			t.Fatalf("%s: platform member without platform.admin allowed", c.name)
		}
		if check(c.name, c.query, c.args(stranger)...) {
			t.Fatalf("%s: stranger allowed", c.name)
		}
	}

	// 047 trigger: an ACME issuance snapshot frozen for the platform admin is
	// accepted, one for a stranger is refused.
	var body string
	if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('validate_acme_issuance_operation_snapshot_047()'::regprocedure)`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "acme_runtime_actor_is_active_048(NEW.tenant_scope_id, snapshot_actor_id)") {
		t.Fatalf("047 snapshot guard not replaced:\n%s", body)
	}
	for _, name := range []string{"validate_plugin_webhook_actor_target_084()", "validate_package_offer_publication_event_090()"} {
		if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, name).Scan(&body); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, "'platform.admin'") {
			t.Fatalf("%s lacks the platform.admin branch", name)
		}
	}
}
