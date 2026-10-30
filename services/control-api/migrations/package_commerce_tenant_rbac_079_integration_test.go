//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var packageCommerceRBAC079Functions = []string{
	"custom_rbac_effective_permissions(uuid,uuid)",
	"guard_system_role_permission_mutation()",
	"validate_custom_role_revision()",
	"validate_custom_role_grant()",
	"lock_custom_rbac_identity_assignment()",
}

func TestPackageCommerceTenantRBAC079LedgerProjectionAndRoundTrip(t *testing.T) {
	up := mustReadPackageCommerceRBAC079(t, "079_package_commerce_tenant_rbac.up.sql")
	down := mustReadPackageCommerceRBAC079(t, "079_package_commerce_tenant_rbac.down.sql")
	for _, marker := range []string{
		"('package_subscriptions.read', false)",
		"('package_subscriptions.manage', false)",
		"tenant owner and viewer assignments are mutually exclusive",
		"tenant viewer cannot receive package subscription management",
		"package_commerce_tenant_rbac_grant_additions_079",
	} {
		if !strings.Contains(string(up), marker) {
			t.Errorf("079 up is missing %q", marker)
		}
	}
	if strings.Contains(strings.ToUpper(string(down)), "CASCADE") {
		t.Fatal("079 down must not use CASCADE")
	}

	pool := packageCommerceRBAC079Pool(t, 78)
	baseline := packageCommerceRBAC079FunctionSources(t, pool)
	if _, err := pool.Exec(t.Context(), `ALTER FUNCTION validate_custom_role_grant() SECURITY DEFINER`); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Code(t, migrateVersionIsolated(t.Context(), pool, "up", 79), "P7900")
	assertPackageCommerceRBAC079Ledger(t, pool, 78)
	var leakedTables int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM (VALUES
		(to_regclass('package_commerce_tenant_rbac_catalog_additions_079')),
		(to_regclass('package_commerce_tenant_rbac_grant_additions_079'))
	) AS leaked(name) WHERE name IS NOT NULL`).Scan(&leakedTables); err != nil || leakedTables != 0 {
		t.Fatalf("rejected 079 up leaked tables=%d, err=%v", leakedTables, err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER FUNCTION validate_custom_role_grant() SECURITY INVOKER`); err != nil {
		t.Fatal(err)
	}
	existingScope, existingOwnerRole, existingViewerRole := insertPackageCommerceRBAC079Roles(t, pool, "existing")

	if err := migrateVersionIsolated(t.Context(), pool, "up", 79); err != nil {
		t.Fatalf("apply 079 through migration engine: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 79)
	assertPackageCommerceRBAC079RolePermissions(t, pool, existingOwnerRole, existingViewerRole)
	assertPackageCommerceRBAC079CatalogAndACL(t, pool)

	futureScope, futureOwnerRole, futureViewerRole := insertPackageCommerceRBAC079Roles(t, pool, "future")
	assertPackageCommerceRBAC079RolePermissions(t, pool, futureOwnerRole, futureViewerRole)
	for _, scopeID := range []uuid.UUID{existingScope, futureScope} {
		var additions int
		if err := pool.QueryRow(t.Context(), `SELECT count(*)
			FROM package_commerce_tenant_rbac_grant_additions_079
			WHERE tenant_scope_id=$1`, scopeID).Scan(&additions); err != nil || additions != 3 {
			t.Fatalf("scope %s provenance additions=%d, want 3, err=%v", scopeID, additions, err)
		}
	}

	userID := insertPackageCommerceRBAC079User(t, pool, existingScope, "ambiguous-role-user", "unused")
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, existingScope, userID, existingOwnerRole); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Code(t, func() error {
		_, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3)`, existingScope, userID, existingViewerRole)
		return err
	}(), "42501")

	if err := migrateVersionIsolated(t.Context(), pool, "down", 79); err != nil {
		t.Fatalf("rollback 079: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 78)
	if got := packageCommerceRBAC079FunctionSources(t, pool); !equalStringMap079(got, baseline) {
		t.Fatalf("079 down did not restore the five frozen 042 function bodies\ngot=%v\nwant=%v", got, baseline)
	}
	for _, table := range []string{
		"package_commerce_tenant_rbac_catalog_additions_079",
		"package_commerce_tenant_rbac_grant_additions_079",
	} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil || exists {
			t.Fatalf("table %s remains after down: exists=%t err=%v", table, exists, err)
		}
	}
	var catalogRows int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM custom_rbac_permission_catalog
		WHERE permission_name IN ('package_subscriptions.read','package_subscriptions.manage')`).Scan(&catalogRows); err != nil || catalogRows != 0 {
		t.Fatalf("079 catalog rows after down=%d, want 0, err=%v", catalogRows, err)
	}

	if err := migrateVersionIsolated(t.Context(), pool, "up", 79); err != nil {
		t.Fatalf("re-apply 079: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 79)
	assertPackageCommerceRBAC079RolePermissions(t, pool, existingOwnerRole, existingViewerRole)
	assertPackageCommerceRBAC079RolePermissions(t, pool, futureOwnerRole, futureViewerRole)
}

func TestPackageCommerceTenantRBAC079TamperBlocksRollbackAtomically(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 79)
	if _, err := pool.Exec(t.Context(), `ALTER TABLE custom_rbac_permission_catalog
		DISABLE TRIGGER custom_rbac_permission_catalog_no_update_or_truncate`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE custom_rbac_permission_catalog
		SET step_up_required=true WHERE permission_name='package_subscriptions.read'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE custom_rbac_permission_catalog
		ENABLE TRIGGER custom_rbac_permission_catalog_no_update_or_truncate`); err != nil {
		t.Fatal(err)
	}

	assertPackageCommerceRBAC079Code(t, migrateVersionIsolated(t.Context(), pool, "down", 79), "P7909")
	assertPackageCommerceRBAC079Ledger(t, pool, 79)
	var stepUp, tableExists, projectionExists bool
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT step_up_required FROM custom_rbac_permission_catalog
		 WHERE permission_name='package_subscriptions.read'),
		to_regclass('package_commerce_tenant_rbac_catalog_additions_079') IS NOT NULL,
		to_regprocedure('project_package_commerce_tenant_system_role_permissions_079()') IS NOT NULL`).Scan(
		&stepUp, &tableExists, &projectionExists,
	); err != nil || !stepUp || !tableExists || !projectionExists {
		t.Fatalf("rejected down left partial state: step_up=%t table=%t function=%t err=%v",
			stepUp, tableExists, projectionExists, err)
	}
	assertPackageCommerceRBAC079Code(t, func() error {
		_, err := pool.Exec(t.Context(), `INSERT INTO package_commerce_tenant_rbac_catalog_additions_079(permission_name)
			VALUES('package_subscriptions.read')`)
		return err
	}(), "P7901")
}

type packageCommerceRBAC079Migration struct {
	version      int64
	identifier   string
	upScript     []byte
	downScript   []byte
	upChecksum   string
	downChecksum string
}

func loadPackageCommerceRBAC079Migration(version int64) (packageCommerceRBAC079Migration, error) {
	upMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
	if err != nil || len(upMatches) != 1 {
		return packageCommerceRBAC079Migration{}, fmt.Errorf("resolve migration %03d up: matches=%v err=%v", version, upMatches, err)
	}
	downMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.down.sql", version))
	if err != nil || len(downMatches) != 1 {
		return packageCommerceRBAC079Migration{}, fmt.Errorf("resolve migration %03d down: matches=%v err=%v", version, downMatches, err)
	}
	identifier := strings.TrimSuffix(upMatches[0], ".up.sql")
	if strings.TrimSuffix(downMatches[0], ".down.sql") != identifier {
		return packageCommerceRBAC079Migration{}, fmt.Errorf("migration %03d identifiers differ", version)
	}
	upScript, err := fs.ReadFile(controlmigrations.FS, upMatches[0])
	if err != nil {
		return packageCommerceRBAC079Migration{}, err
	}
	downScript, err := fs.ReadFile(controlmigrations.FS, downMatches[0])
	if err != nil {
		return packageCommerceRBAC079Migration{}, err
	}
	return packageCommerceRBAC079Migration{
		version: version, identifier: identifier, upScript: upScript, downScript: downScript,
		upChecksum:   fmt.Sprintf("%x", sha256.Sum256(upScript)),
		downChecksum: fmt.Sprintf("%x", sha256.Sum256(downScript)),
	}, nil
}

// packageCommerceRBAC079Pool returns a private schema migrated through
// maximum (a clone of the per-version snapshot, migration_snapshot_integration_test.go).
func packageCommerceRBAC079Pool(t *testing.T, maximum int64) *pgxpool.Pool {
	t.Helper()
	return migrationSnapshotPool(t, maximum)
}

func assertPackageCommerceRBAC079Ledger(t *testing.T, pool *pgxpool.Pool, maximum int64) {
	t.Helper()
	var count, minimum, maximumFound, invalid int64
	if err := pool.QueryRow(t.Context(), `SELECT count(*),COALESCE(min(version),0),COALESCE(max(version),0),
		count(*) FILTER (WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
		 OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state <> 'verified'
		 OR metadata_recorded_at IS NULL OR applied_at IS NULL)
		FROM schema_migrations`).Scan(&count, &minimum, &maximumFound, &invalid); err != nil {
		t.Fatal(err)
	}
	if count != maximum || minimum != 1 || maximumFound != maximum || invalid != 0 {
		t.Fatalf("ledger count/min/max/invalid=%d/%d/%d/%d, want %d/1/%d/0",
			count, minimum, maximumFound, invalid, maximum, maximum)
	}
	for version := int64(1); version <= maximum; version++ {
		migration, err := loadPackageCommerceRBAC079Migration(version)
		if err != nil {
			t.Fatal(err)
		}
		var identifier, upChecksum, downChecksum string
		if err := pool.QueryRow(t.Context(), `SELECT migration_id,checksum_sha256,down_checksum_sha256
			FROM schema_migrations WHERE version=$1`, version).Scan(&identifier, &upChecksum, &downChecksum); err != nil {
			t.Fatal(err)
		}
		if identifier != migration.identifier || upChecksum != migration.upChecksum || downChecksum != migration.downChecksum {
			t.Fatalf("migration %03d ledger metadata mismatch", version)
		}
	}
}

func insertPackageCommerceRBAC079Roles(t *testing.T, pool *pgxpool.Pool, suffix string) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scopeID, ownerRoleID, viewerRoleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, "RBAC "+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
		($1,$3,'tenant_owner','Tenant owner',true),($2,$3,'tenant_viewer','Tenant viewer',true)`,
		ownerRoleID, viewerRoleID, scopeID); err != nil {
		t.Fatal(err)
	}
	return scopeID, ownerRoleID, viewerRoleID
}

func assertPackageCommerceRBAC079RolePermissions(t *testing.T, pool *pgxpool.Pool, ownerRoleID, viewerRoleID uuid.UUID) {
	t.Helper()
	for _, check := range []struct {
		roleID     uuid.UUID
		permission string
		want       bool
	}{
		{ownerRoleID, "package_subscriptions.read", true},
		{ownerRoleID, "package_subscriptions.manage", true},
		{viewerRoleID, "package_subscriptions.read", true},
		{viewerRoleID, "package_subscriptions.manage", false},
	} {
		var got bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM role_permissions
			WHERE role_id=$1 AND permission_name=$2)`, check.roleID, check.permission).Scan(&got); err != nil || got != check.want {
			t.Fatalf("role %s permission %s=%t, want %t, err=%v", check.roleID, check.permission, got, check.want, err)
		}
	}
}

func assertPackageCommerceRBAC079CatalogAndACL(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var catalogCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM custom_rbac_permission_catalog
		WHERE permission_name IN ('package_subscriptions.read','package_subscriptions.manage')
		  AND NOT step_up_required`).Scan(&catalogCount); err != nil || catalogCount != 2 {
		t.Fatalf("non-step-up package catalog entries=%d, want 2, err=%v", catalogCount, err)
	}
	for _, table := range []string{
		"package_commerce_tenant_rbac_catalog_additions_079",
		"package_commerce_tenant_rbac_grant_additions_079",
	} {
		var allowed bool
		if err := pool.QueryRow(t.Context(), `SELECT has_table_privilege('public',$1,'SELECT')`, table).Scan(&allowed); err != nil {
			t.Fatal(err)
		}
		if allowed {
			t.Fatalf("PUBLIC can SELECT %s", table)
		}
	}
	for _, signature := range []string{
		"protect_package_commerce_tenant_rbac_provenance_079()",
		"protect_package_commerce_tenant_rbac_catalog_079()",
		"protect_package_commerce_tenant_scope_classification_079()",
		"project_package_commerce_tenant_system_role_permissions_079()",
	} {
		var allowed bool
		if err := pool.QueryRow(t.Context(), `SELECT has_function_privilege('public',$1,'EXECUTE')`, signature).Scan(&allowed); err != nil {
			t.Fatal(err)
		}
		if allowed {
			t.Fatalf("PUBLIC can execute %s", signature)
		}
	}
}

func packageCommerceRBAC079FunctionSources(t *testing.T, pool *pgxpool.Pool) map[string]string {
	t.Helper()
	result := make(map[string]string, len(packageCommerceRBAC079Functions))
	for _, signature := range packageCommerceRBAC079Functions {
		var source string
		if err := pool.QueryRow(t.Context(), `SELECT prosrc FROM pg_proc WHERE oid=to_regprocedure($1)`, signature).Scan(&source); err != nil {
			t.Fatalf("read %s source: %v", signature, err)
		}
		result[signature] = source
	}
	return result
}

func equalStringMap079(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func mustReadPackageCommerceRBAC079(t *testing.T, name string) []byte {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func assertPackageCommerceRBAC079Code(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error=%v, want code %s", err, want)
	}
}

func insertPackageCommerceRBAC079User(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, username, passwordHash string) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,$2,$3)`, userID, username, passwordHash); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	return userID
}
