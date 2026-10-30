//go:build integration

package migrations_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration 531 (fix-acme/fix-acme2): a platform member with platform.admin
// or certificates.manage on the platform scope may place a certificate order
// for an active tenant (actor foreign keys point at users); a member of
// another tenant, a stranger or a platform member without the permission is
// refused. Up, down and up again; down refuses once platform orders exist.
func TestACMEPlatformActor531(t *testing.T) {
	const version = 531
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID := uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	// 048 compared membership.scope_id to itself (a column shadows the same
	// named parameter): before 531 a member of another tenant passed.
	shadowTenantID, shadowScopeID, shadowMember := uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'531 shadow tenant')`, shadowTenantID)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, shadowScopeID, shadowTenantID)
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'531 tenant')`, tenantID)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'shadow','test-hash')`,
		shadowMember, "p531-shadow-"+strings.ReplaceAll(shadowMember.String(), "-", "")[:8])
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, shadowScopeID, shadowMember)
	// 530 reached from below still has the shadowed 048 body (the defect);
	// reached by rolling back 531, the down keeps the fixed body on purpose.
	var shadowed bool
	if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('acme_runtime_actor_is_active_048(uuid,uuid)'::regprocedure) LIKE '%membership.user_id = actor_id%'`).
		Scan(&shadowed); err != nil {
		t.Fatal(err)
	}
	assertP531ActorFunction(t, pool, scopeID, shadowMember, shadowed)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		assertP531ForeignKeys(t, pool, step == "up")
	}
	var platformBranch bool
	if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('acme_runtime_actor_is_active_048(uuid,uuid)'::regprocedure) LIKE '%platform_scope%'`).
		Scan(&platformBranch); err != nil || !platformBranch {
		t.Fatalf("platform branch=%t err=%v, want migration 531 applied", platformBranch, err)
	}
	assertP531ActorFunction(t, pool, scopeID, shadowMember, false)
	var platformScopeID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' ORDER BY created_at,id LIMIT 1`).
		Scan(&platformScopeID); err != nil {
		platformScopeID = uuid.New()
		exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScopeID)
	}
	newUser := func(label string) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'test-hash')`,
			id, "p531-"+label+"-"+strings.ReplaceAll(id.String(), "-", "")[:8], label)
		return id
	}
	// Custom roles are created only through custom RBAC facts (042); platform
	// system roles take permissions directly.
	platformRole := func(permission string) uuid.UUID {
		roleID := uuid.New()
		exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'531',true)`,
			roleID, platformScopeID, "p531_"+strings.ReplaceAll(roleID.String(), "-", "")[:12])
		exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission)
		return roleID
	}
	grantPlatform := func(user uuid.UUID, roleID uuid.UUID) {
		exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platformScopeID, user)
		if roleID != uuid.Nil {
			exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, platformScopeID, user, roleID)
		}
	}
	adminRole := platformRole("platform.admin")

	admin := newUser("admin")
	grantPlatform(admin, adminRole)
	certManager := newUser("certs")
	grantPlatform(certManager, platformRole("certificates.manage"))
	readerRole := platformRole("certificates.read")
	platformNoPermission := newUser("viewer")
	grantPlatform(platformNoPermission, readerRole)
	stranger := newUser("stranger")
	tenantMember := newUser("member")
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, tenantMember)
	otherTenantID, otherScopeID := uuid.New(), uuid.New()
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'531 other tenant')`, otherTenantID)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, otherScopeID, otherTenantID)
	otherMember := newUser("other")
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, otherScopeID, otherMember)

	order := func(actor uuid.UUID) error {
		_, err := pool.Exec(ctx, `INSERT INTO certificate_orders(
			id,scope_id,domains,challenge_type,auto_renew,created_by_user_id,updated_by_user_id
		) VALUES($1,$2,ARRAY['p531.example.test'],'http-01',true,$3,$3)`, uuid.New(), scopeID, actor)
		return err
	}
	for name, actor := range map[string]uuid.UUID{
		"tenant member": tenantMember, "platform admin": admin, "platform certificates.manage": certManager,
	} {
		if err := order(actor); err != nil {
			t.Errorf("%s order: %v", name, err)
		}
	}
	for name, actor := range map[string]uuid.UUID{
		"stranger": stranger, "platform member without permission": platformNoPermission,
		"member of another tenant": otherMember,
	} {
		assertP531Rejected(t, order(actor), name)
	}

	// A suspended platform admin and a suspended tenant are refused.
	exec(`UPDATE users SET status='disabled' WHERE id=$1`, admin)
	assertP531Rejected(t, order(admin), "disabled platform admin")
	enabled := newUser("enabled")
	grantPlatform(enabled, adminRole)
	assertP531ActorFunction(t, pool, scopeID, enabled, true)
	assertP531ActorFunction(t, pool, scopeID, otherMember, false)

	// Orders by platform members cannot satisfy 048's tenant-member foreign
	// keys: the rollback refuses instead of dropping or rewriting them.
	err := migrateVersionIsolated(ctx, pool, "down", version)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P5312" {
		t.Fatalf("down with platform orders = %v, want P5312", err)
	}

	exec(`UPDATE tenants SET status='suspended' WHERE id=$1`, tenantID)
	assertP531ActorFunction(t, pool, scopeID, enabled, false)
}

func assertP531ForeignKeys(t *testing.T, pool *pgxpool.Pool, applied bool) {
	t.Helper()
	var users, memberships int
	if err := pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE conname LIKE '%\_actor\_fk\_531' AND confrelid='users'::regclass),
		count(*) FILTER (WHERE conname LIKE '%\_actor\_fk\_048' AND confrelid='memberships'::regclass)
		FROM pg_constraint WHERE contype='f' AND connamespace=current_schema()::regnamespace
		AND conrelid = ANY(ARRAY['acme_tenant_key_facts','acme_account_registration_facts','acme_issuance_operations',
			'certificate_orders','acme_renewal_claim_facts']::regclass[])`).Scan(&users, &memberships); err != nil {
		t.Fatal(err)
	}
	if applied && (users != 6 || memberships != 0) || !applied && (users != 0 || memberships != 6) {
		t.Fatalf("applied=%t actor foreign keys users=%d memberships=%d", applied, users, memberships)
	}
}

func assertP531Rejected(t *testing.T, err error, name string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P0001" ||
		pgErr.Message != "certificate order requires an active tenant actor" {
		t.Errorf("%s order error = %v, want active tenant actor rejection", name, err)
	}
}

func assertP531ActorFunction(t *testing.T, pool *pgxpool.Pool, scopeID, actor uuid.UUID, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT acme_runtime_actor_is_active_048($1,$2)`, scopeID, actor).Scan(&got); err != nil || got != want {
		t.Errorf("acme_runtime_actor_is_active_048 = %t err=%v, want %t", got, err, want)
	}
}
