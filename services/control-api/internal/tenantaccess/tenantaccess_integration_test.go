//go:build integration

package tenantaccess_test

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/tenantaccess"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Fixture: one tenant, its member, a platform admin (platform.admin), a
// platform member without it, and a stranger.
type fixture struct {
	platformScope, tenantScope, member, admin, platformViewer, stranger uuid.UUID
}

func seed(t *testing.T, pool *pgxpool.Pool) fixture {
	t.Helper()
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	f := fixture{tenantScope: uuid.New()}
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&f.platformScope); err != nil {
		f.platformScope = uuid.New()
		exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, f.platformScope)
	}
	tenantID := uuid.New()
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'adminall tenant')`, tenantID)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, f.tenantScope, tenantID)
	user := func(label string) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'x')`,
			id, "aa-"+label+"-"+strings.ReplaceAll(id.String(), "-", "")[:8], label)
		return id
	}
	role := func(permission string) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'adminall',true)`,
			id, f.platformScope, "aa_"+strings.ReplaceAll(id.String(), "-", "")[:12])
		exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, id, permission)
		return id
	}
	platform := func(u, r uuid.UUID) {
		exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, f.platformScope, u)
		exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, f.platformScope, u, r)
	}
	f.member, f.admin, f.platformViewer, f.stranger = user("member"), user("admin"), user("viewer"), user("stranger")
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, f.tenantScope, f.member)
	platform(f.admin, role("platform.admin"))
	platform(f.platformViewer, role("sites.read"))
	return f
}

func TestActorMayActOnTenant(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	f := seed(t, pool)
	for _, c := range []struct {
		name string
		user uuid.UUID
		want bool
	}{
		{"tenant member", f.member, true},
		{"platform admin (not a tenant member)", f.admin, true},
		{"platform member without platform.admin", f.platformViewer, false},
		{"stranger", f.stranger, false},
	} {
		got, err := tenantaccess.ActorMayActOnTenant(ctx, pool, c.user, f.tenantScope)
		if err != nil || got != c.want {
			t.Fatalf("%s: got=%t err=%v want %t", c.name, got, err, c.want)
		}
	}
	if ok, err := tenantaccess.IsPlatformAdmin(ctx, pool, f.admin, f.platformScope); err != nil || !ok {
		t.Fatalf("IsPlatformAdmin(admin)=%t err=%v", ok, err)
	}
	if ok, err := tenantaccess.IsPlatformAdmin(ctx, pool, f.platformViewer, f.platformScope); err != nil || ok {
		t.Fatalf("IsPlatformAdmin(viewer)=%t err=%v", ok, err)
	}
	// A suspended tenant is refused even for the platform admin's predicate.
	if _, err := pool.Exec(ctx, `UPDATE tenants SET status='suspended' WHERE id=(SELECT tenant_id FROM access_scopes WHERE id=$1)`, f.tenantScope); err != nil {
		t.Fatal(err)
	}
	if ok, err := tenantaccess.ActorMayActOnTenant(ctx, pool, f.admin, f.tenantScope); err != nil || ok {
		t.Fatalf("suspended tenant: ok=%t err=%v", ok, err)
	}
	// A disabled platform admin is refused.
	if _, err := pool.Exec(ctx, `UPDATE tenants SET status='active' WHERE id=(SELECT tenant_id FROM access_scopes WHERE id=$1)`, f.tenantScope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, f.admin); err != nil {
		t.Fatal(err)
	}
	if ok, err := tenantaccess.ActorMayActOnTenant(ctx, pool, f.admin, f.tenantScope); err != nil || ok {
		t.Fatalf("disabled admin: ok=%t err=%v", ok, err)
	}
}
