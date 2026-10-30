//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSecurityPolicySystemRoleProjection230RoundTrip(t *testing.T) {
	pool := securityPolicyProjection230Pool(t, 229)
	existing := insertSecurityPolicyProjection230Roles(t, pool, "existing")
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'security_policies.read')`, existing.owner); err != nil {
		t.Fatal(err)
	}

	if err := migrateVersionIsolated(t.Context(), pool, "up", 230); err != nil {
		t.Fatalf("apply migration 230: %v", err)
	}
	assertSecurityPolicyProjection230Roles(t, pool, existing)
	assertSecurityPolicyProjection230Provenance(t, pool, 2)

	assertSecurityPolicyProjection230Code(t, func() error {
		_, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
			VALUES($1,'security_policies.manage')`, existing.viewer)
		return err
	}(), "P0001")
	assertSecurityPolicyProjection230Code(t, func() error {
		_, err := pool.Exec(t.Context(), `INSERT INTO security_policy_system_role_grant_additions_230(
			role_id,tenant_scope_id,permission_name) VALUES($1,$2,'security_policies.read')`,
			existing.owner, existing.scope)
		return err
	}(), "P2301")

	future := insertSecurityPolicyProjection230Roles(t, pool, "future")
	assertSecurityPolicyProjection230Roles(t, pool, future)
	assertSecurityPolicyProjection230Provenance(t, pool, 5)

	if err := migrateVersionIsolated(t.Context(), pool, "down", 230); err != nil {
		t.Fatalf("rollback migration 230: %v", err)
	}
	assertSecurityPolicyProjection230Permission(t, pool, existing.owner, "security_policies.read", true)
	for _, role := range []uuid.UUID{existing.owner, existing.viewer, existing.admin, existing.custom,
		future.owner, future.viewer, future.admin, future.custom} {
		for _, permission := range []string{"security_policies.read", "security_policies.manage"} {
			want := role == existing.owner && permission == "security_policies.read"
			assertSecurityPolicyProjection230Permission(t, pool, role, permission, want)
		}
	}
	var projectionExists bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regprocedure(
		'project_security_policy_system_role_permissions_230()') IS NOT NULL`).Scan(&projectionExists); err != nil {
		t.Fatal(err)
	}
	if projectionExists {
		t.Fatal("migration 230 projection function remains after rollback")
	}

	if err := migrateVersionIsolated(t.Context(), pool, "up", 230); err != nil {
		t.Fatalf("reapply migration 230: %v", err)
	}
	assertSecurityPolicyProjection230Roles(t, pool, existing)
	assertSecurityPolicyProjection230Roles(t, pool, future)
	assertSecurityPolicyProjection230Provenance(t, pool, 5)
}

type securityPolicyProjection230RoleSet struct {
	scope         uuid.UUID
	owner, viewer uuid.UUID
	admin, custom uuid.UUID
}

func insertSecurityPolicyProjection230Roles(
	t *testing.T,
	pool *pgxpool.Pool,
	suffix string,
) securityPolicyProjection230RoleSet {
	t.Helper()
	roles := securityPolicyProjection230RoleSet{
		scope: uuid.New(), owner: uuid.New(), viewer: uuid.New(), admin: uuid.New(), custom: uuid.New(),
	}
	tenantID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`,
		tenantID, "Security projection "+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id)
		VALUES($1,'tenant',$2)`, roles.scope, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
		($1,$4,'tenant_owner','Tenant owner',true),
		($2,$4,'tenant_viewer','Tenant viewer',true),
		($3,$4,'tenant_admin','Tenant admin',true)`, roles.owner, roles.viewer, roles.admin, roles.scope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE roles DISABLE TRIGGER roles_system_role_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'Custom role',false)`, roles.custom, roles.scope, "custom_"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE roles ENABLE TRIGGER roles_system_role_guard`); err != nil {
		t.Fatal(err)
	}
	return roles
}

func assertSecurityPolicyProjection230Roles(
	t *testing.T,
	pool *pgxpool.Pool,
	roles securityPolicyProjection230RoleSet,
) {
	t.Helper()
	for _, check := range []struct {
		role       uuid.UUID
		permission string
		want       bool
	}{
		{roles.owner, "security_policies.read", true},
		{roles.owner, "security_policies.manage", true},
		{roles.viewer, "security_policies.read", true},
		{roles.viewer, "security_policies.manage", false},
		{roles.admin, "security_policies.read", false},
		{roles.admin, "security_policies.manage", false},
		{roles.custom, "security_policies.read", false},
		{roles.custom, "security_policies.manage", false},
	} {
		assertSecurityPolicyProjection230Permission(t, pool, check.role, check.permission, check.want)
	}
}

func assertSecurityPolicyProjection230Permission(
	t *testing.T,
	pool *pgxpool.Pool,
	role uuid.UUID,
	permission string,
	want bool,
) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM role_permissions
		WHERE role_id=$1 AND permission_name=$2)`, role, permission).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("role %s permission %s=%t, want %t", role, permission, got, want)
	}
}

func assertSecurityPolicyProjection230Provenance(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	var got, invalid int
	if err := pool.QueryRow(t.Context(), `SELECT count(*),count(*) FILTER (WHERE source_migration <> 230)
		FROM security_policy_system_role_grant_additions_230`).Scan(&got, &invalid); err != nil {
		t.Fatal(err)
	}
	if got != want || invalid != 0 {
		t.Fatalf("migration 230 provenance count/invalid=%d/%d, want %d/0", got, invalid, want)
	}
}

func securityPolicyProjection230Pool(t *testing.T, maximum int64) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "security_policy_projection_230_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^security_policy_projection_230_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		if cleanupErr := dropSecurityPolicyProjection230Schema(cleanupCtx, admin, schema); cleanupErr != nil {
			t.Errorf("drop migration 230 test schema: %v", cleanupErr)
		}
		admin.Close()
	})
	if err := migrateVersionIsolated(ctx, pool, "up", maximum); err != nil {
		t.Fatalf("apply migrations through %03d: %v", maximum, err)
	}
	return pool
}

func dropSecurityPolicyProjection230Schema(
	ctx context.Context,
	admin *pgxpool.Pool,
	schema string,
) error {
	if ctx == nil || admin == nil ||
		!regexp.MustCompile(`^security_policy_projection_230_[a-f0-9]{32}$`).MatchString(schema) {
		return errors.New("unsafe migration 230 schema cleanup")
	}
	type relationKind struct {
		name string
		kind string
	}
	for _, relation := range []relationKind{
		{name: "VIEW", kind: "v"},
		{name: "MATERIALIZED VIEW", kind: "m"},
		{name: "FOREIGN TABLE", kind: "f"},
		{name: "TABLE", kind: "p"},
		{name: "TABLE", kind: "r"},
		{name: "SEQUENCE", kind: "S"},
	} {
		rows, err := admin.Query(ctx, `SELECT relation.relname
			FROM pg_class relation
			JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
			WHERE namespace.nspname=$1 AND relation.relkind=$2
			ORDER BY relation.relname`, schema, relation.kind)
		if err != nil {
			return err
		}
		names := make([]string, 0)
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			names = append(names, name)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, name := range names {
			if _, err := admin.Exec(ctx, "DROP "+relation.name+" IF EXISTS "+
				pgx.Identifier{schema, name}.Sanitize()+" CASCADE"); err != nil {
				return err
			}
		}
	}
	rows, err := admin.Query(ctx, `SELECT routine.oid::regprocedure::text,routine.prokind::text
		FROM pg_proc routine
		JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace
		WHERE namespace.nspname=$1 ORDER BY routine.oid`, schema)
	if err != nil {
		return err
	}
	type routineIdentity struct{ identity, kind string }
	routines := make([]routineIdentity, 0)
	for rows.Next() {
		var routine routineIdentity
		if err := rows.Scan(&routine.identity, &routine.kind); err != nil {
			rows.Close()
			return err
		}
		routines = append(routines, routine)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, routine := range routines {
		kind := "FUNCTION"
		if routine.kind == "p" {
			kind = "PROCEDURE"
		} else if routine.kind == "a" {
			kind = "AGGREGATE"
		}
		if _, err := admin.Exec(ctx, "DROP "+kind+" IF EXISTS "+routine.identity+" CASCADE"); err != nil {
			return err
		}
	}
	_, err = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	return err
}

func assertSecurityPolicyProjection230Code(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error=%v, want code %s", err, want)
	}
}
