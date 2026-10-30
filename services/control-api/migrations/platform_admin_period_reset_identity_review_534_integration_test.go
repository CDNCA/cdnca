//go:build integration

package migrations_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Migration 534: a platform administrator may create
// a package period reset authority binding for any tenant and may claim and
// decide that tenant's identity verification cases, recorded under the
// administrator's own identity (not as a tenant member). A platform member
// without platform.admin and a stranger are still refused.
func TestPlatformAdminPeriodResetAndIdentityReview534(t *testing.T) {
	pool := releaseHeadMigrationPool(t)
	ctx := t.Context()
	exec := func(q string, args ...any) error {
		t.Helper()
		_, err := pool.Exec(ctx, q, args...)
		return err
	}
	must := func(q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	var head int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil || head < 534 {
		t.Fatalf("release head=%d err=%v, want 534 applied", head, err)
	}
	var platformScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		platformScope = uuid.New()
		must(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	}
	tenantID, tenantScope := uuid.New(), uuid.New()
	must(`INSERT INTO tenants(id,display_name) VALUES($1,'534 tenant')`, tenantID)
	must(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenantScope, tenantID)
	user := func(label string) uuid.UUID {
		id := uuid.New()
		must(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'x')`,
			id, "p534-"+label+"-"+strings.ReplaceAll(id.String(), "-", "")[:8], label)
		return id
	}
	grant := func(scope, u uuid.UUID, permissions ...string) {
		roleID := uuid.New()
		must(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'534',true)`,
			roleID, scope, "p534_"+strings.ReplaceAll(roleID.String(), "-", "")[:12])
		for _, permission := range permissions {
			must(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission)
		}
		must(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scope, u)
		must(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scope, u, roleID)
	}
	admin, viewer, stranger, member := user("admin"), user("viewer"), user("stranger"), user("member")
	grant(platformScope, admin, "platform.admin")
	grant(platformScope, viewer, "sites.read", "identity_verification.read")
	grant(tenantScope, member, "sites.manage")

	// 第 2 项：周期重置授权绑定。
	now := time.Now().UTC().Truncate(time.Microsecond)
	insertBinding := func(actor uuid.UUID, actorScope *uuid.UUID) (uuid.UUID, error) {
		id := uuid.New()
		return id, exec(`INSERT INTO package_period_reset_workload_authority_bindings_165(
			id,tenant_scope_id,actor_user_id,actor_scope_id,audience,permission_name,status,revision,
			not_before,expires_at,created_at,updated_at)
			VALUES($1,$2,$3,$4,'package_period_reset','sites.manage','active',1,$5,$6,$5,$5)`,
			id, tenantScope, actor, actorScope, now, now.Add(time.Hour))
	}
	for name, actor := range map[string]uuid.UUID{"viewer": viewer, "stranger": stranger} {
		if _, err := insertBinding(actor, &platformScope); err == nil || !strings.Contains(err.Error(), "P1651") {
			t.Fatalf("%s platform binding err=%v, want P1651", name, err)
		}
	}
	if _, err := insertBinding(admin, nil); err == nil {
		t.Fatal("admin binding without actor_scope_id must still require tenant membership")
	}
	if _, err := insertBinding(admin, &tenantScope); err == nil {
		t.Fatal("actor_scope_id must be a platform scope")
	}
	adminBinding, err := insertBinding(admin, &platformScope)
	if err != nil {
		t.Fatalf("platform admin binding refused: %v", err)
	}
	if err := exec(`UPDATE package_period_reset_workload_authority_bindings_165
		SET status='revoked',revision=2,revoked_at=$2,updated_at=$2,actor_scope_id=NULL WHERE id=$1`,
		adminBinding, now.Add(time.Second)); err == nil {
		t.Fatal("actor_scope_id must be immutable")
	}
	must(`UPDATE package_period_reset_workload_authority_bindings_165
		SET status='revoked',revision=2,revoked_at=$2,updated_at=$2 WHERE id=$1`, adminBinding, now.Add(time.Second))
	if _, err := insertBinding(member, nil); err != nil {
		t.Fatalf("tenant member binding refused: %v", err)
	}

	// 第 3 项：实名审核权限函数与外键。
	check := func(u uuid.UUID, permission string) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT identity_verification_actor_has_permission($1,$2,$3)`,
			tenantScope, u, permission).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for _, permission := range []string{"identity_verification.read", "identity_verification.review"} {
		if !check(admin, permission) {
			t.Fatalf("platform admin refused %s", permission)
		}
		if check(viewer, permission) || check(stranger, permission) {
			t.Fatalf("non-admin allowed %s", permission)
		}
	}
	if check(admin, "identity_verification.self.manage") {
		t.Fatal("platform admin must not act as the applicant (self.manage)")
	}
	var body string
	if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('validate_identity_verification_assignment_insert()'::regprocedure)`).
		Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "identity_verification_actor_has_permission(") {
		t.Fatalf("assignment guard still inlines tenant membership:\n%s", body)
	}
	rows, err := pool.Query(ctx, `SELECT conrelid::regclass::text||'.'||conname FROM pg_constraint
		WHERE contype='f' AND confrelid='memberships'::regclass AND conrelid::regclass::text IN (
		  'identity_verification_cases','identity_verification_state_events','identity_verification_review_assignments',
		  'identity_verification_reviews','identity_verification_write_requests',
		  'package_period_reset_workload_authority_bindings_165')
		AND NOT (pg_get_constraintdef(oid) LIKE '%applicant_user_id%')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		_ = rows.Scan(&name)
		t.Errorf("reviewer/actor still bound to tenant membership: %s", name)
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
}
