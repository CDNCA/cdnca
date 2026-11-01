//go:build integration

package migrations_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// TestOperatorUserForeignKeys611: at 610 a platform administrator who is not a
// member of the tenant scope cannot be recorded as the operator (23503 on the
// (tenant_scope_id, actor)→memberships key). After 611 the administrator is
// accepted, a tenant member still is, a stranger and a platform member
// without platform.admin are refused (P6113), the guard refuses a second
// apply, down refuses while administrator facts exist, and 610→611 goes up,
// down and up again.
func TestOperatorUserForeignKeys611(t *testing.T) {
	const version = 611
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	var platformScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		platformScope = uuid.New()
		exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	}
	tenantID, tenantScope := uuid.New(), uuid.New()
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'611 tenant')`, tenantID)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenantScope, tenantID)
	user := func(label string) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'x')`,
			id, "p611-"+label+"-"+strings.ReplaceAll(id.String(), "-", "")[:8], label)
		return id
	}
	platform := func(u uuid.UUID, permission string) {
		roleID := uuid.New()
		exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'611',true)`,
			roleID, platformScope, "p611_"+strings.ReplaceAll(roleID.String(), "-", "")[:12])
		exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission)
		exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platformScope, u)
		exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, platformScope, u, roleID)
	}
	admin, viewer, member, stranger := user("admin"), user("viewer"), user("member"), user("stranger")
	platform(admin, "platform.admin")
	platform(viewer, "sites.read")
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, tenantScope, member)

	writeRequest := func(actor uuid.UUID) error {
		_, err := pool.Exec(ctx, `INSERT INTO announcement_write_requests(
			id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at
		) VALUES($1,$2,$3,'announcement.create',$4,decode(repeat('ab',32),'hex'),now())`,
			uuid.New(), tenantScope, actor, "k611-"+uuid.NewString()[:8])
		return err
	}
	sqlState := func(err error) string {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return pgErr.Code
		}
		return ""
	}

	// 610：平台管理员不是租户成员 → 外键拒绝（本迁移要修的缺陷）。
	if err := writeRequest(admin); sqlState(err) != "23503" {
		t.Fatalf("610 platform admin write: %v, want 23503", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	if err := writeRequest(member); err != nil {
		t.Fatalf("tenant member refused: %v", err)
	}
	for name, actor := range map[string]uuid.UUID{"stranger": stranger, "platform viewer": viewer} {
		if err := writeRequest(actor); sqlState(err) != "P6113" {
			t.Fatalf("%s write: %v, want P6113", name, err)
		}
	}
	if err := writeRequest(uuid.New()); sqlState(err) != "P6113" && sqlState(err) != "23503" {
		t.Fatalf("unknown user write: %v, want refusal", err)
	}

	// 12 个操作人列全部改为 →users(id)，且各表都挂了 611 触发器。
	var memberKeys, userKeys, triggers int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM pg_constraint WHERE contype='f' AND confrelid='memberships'::regclass
		   AND conrelid::regclass::text = ANY($1)
		   AND conname NOT LIKE '%audience%' AND conname NOT LIKE '%recipient%'),
		(SELECT count(*) FROM pg_constraint WHERE contype='f' AND confrelid='users'::regclass AND conname LIKE '%\_fk\_611'),
		(SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgname LIKE '%\_operator\_611')`,
		[]string{"node_line_groups", "node_line_group_revisions", "node_scheduling_write_requests", "announcements",
			"announcement_versions", "announcement_write_requests", "package_monitor_policy_versions",
			"announcement_archive_254", "announcement_lifecycle_facts_254"}).
		Scan(&memberKeys, &userKeys, &triggers); err != nil {
		t.Fatal(err)
	}
	if memberKeys != 0 || userKeys != 12 || triggers != 9 {
		t.Fatalf("after 611: membership keys %d (want 0), user keys %d (want 12), triggers %d (want 9)",
			memberKeys, userKeys, triggers)
	}

	up, err := controlmigrations.FS.ReadFile("611_operator_user_foreign_keys.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(up)); err == nil || !strings.Contains(err.Error(), "P6110") {
		t.Fatalf("611 re-applied on the head: %v", err)
	}
	// 只有成员写的记录时可以回退，再升回去。
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again %d: %v", version, err)
	}
	if err := writeRequest(admin); err != nil {
		t.Fatalf("platform admin (not a tenant member) refused after 611: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil || !strings.Contains(err.Error(), "P6112") {
		t.Fatalf("down with platform administrator facts: %v, want P6112", err)
	}
}
