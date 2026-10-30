//go:build integration

package migrations_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var userGroups135Now = time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)

func TestUserGroups135MigrationContract(t *testing.T) {
	up := readUserGroups135(t, "135_user_groups.up.sql")
	down := readUserGroups135(t, "135_user_groups.down.sql")
	for _, fragment := range []string{
		"migration 135 requires the exact verified 134 release head",
		"cedf471ecef9136cf9480b298d2dfb9dcdfb98c6bd34011c5d3a56d649bd1624",
		"c36ab4bf4bf18253d1a7e357a45d60df38c0aaded3e26f4f31118b375feae22e",
		"CREATE TABLE identity_user_groups",
		"CREATE TABLE identity_user_group_memberships",
		"CREATE TABLE identity_user_group_write_requests",
		"UNIQUE (actor_user_id, operation, idempotency_key)",
		"BEFORE UPDATE OR DELETE",
		"BEFORE TRUNCATE",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("135 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"migration 135 rollback requires the verified 135 head",
		"cac03de016d85a2e4fbaf225b987e72cd72ecec406d3520adbc168b32097c121",
		"cedf471ecef9136cf9480b298d2dfb9dcdfb98c6bd34011c5d3a56d649bd1624",
		"c36ab4bf4bf18253d1a7e357a45d60df38c0aaded3e26f4f31118b375feae22e",
		"migration 135 rollback would discard user group facts",
		"DROP TABLE identity_user_group_write_requests",
		"DROP TABLE identity_user_group_memberships",
		"DROP TABLE identity_user_groups",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("135 down missing %q", fragment)
		}
	}
	if strings.Contains(down, "DELETE FROM schema_migrations") {
		t.Fatal("135 down must not delete its own schema migration row")
	}
	for _, stale := range []string{
		"a56f172be6a6a367f003d7b9956ed1ce6cd6bc5e9393230684660ea9f2a6f808",
		"2881dcad95df529e09a149b010403611ea5657f0c8a17bac383d5ffa173c4b3e",
		"1d513fd8f458f785c33b5d0f691b760d1d2bf9a83d186a7ad1239bad25c79c94",
	} {
		if strings.Contains(up, stale) || strings.Contains(down, stale) {
			t.Errorf("135 migration retained stale checksum %q", stale)
		}
	}
}

func TestUserGroups135RejectsTamperedPredecessor(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 134)
	// The Go migrator rejects identifier/checksum tampering itself (migrate.go) before any SQL runs;
	// it accepts a legacy_unverified 134 row, which only the 135 guard rejects.
	if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations
		SET integrity_state='legacy_unverified' WHERE version=134`); err != nil {
		t.Fatal(err)
	}
	assertUserGroups135Code(t, migrateVersionIsolated(t.Context(), pool, "up", 135), "P1350")
	var relation *string
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('identity_user_groups')::text`).Scan(&relation); err != nil {
		t.Fatal(err)
	}
	if relation != nil {
		t.Fatalf("failed migration left relation %q", *relation)
	}
}

func TestUserGroups135ScopeMembershipAndReceiptIntegrity(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 134)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 135); err != nil {
		t.Fatalf("apply 135: %v", err)
	}

	platformScopeID := uuid.New()
	tenantID := uuid.New()
	tenantScopeID := uuid.New()
	adminID := uuid.New()
	tenantUserID := uuid.New()
	// Several statements with arguments: only the simple protocol accepts them
	// (a parameterized extended-protocol Exec is one prepared statement, SQLSTATE 42601).
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name,status,revision,created_at,updated_at)
		VALUES($1,'Tenant','active',1,$5,$5);
		INSERT INTO access_scopes(id,kind,created_at) VALUES($2,'platform',$5);
		INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($3,'tenant',$1,$5);
		INSERT INTO users(id,username,display_name,password_hash,status,revision,created_at,updated_at)
		VALUES($4,'group-admin','Group Admin','hash','active',1,$5,$5),
		      ($6,'group-user','Group User','hash','active',1,$5,$5);
		INSERT INTO memberships(scope_id,user_id,status,created_at)
		VALUES($2,$4,'active',$5),($3,$6,'active',$5)`, pgx.QueryExecModeSimpleProtocol,
		tenantID, platformScopeID, tenantScopeID, adminID, userGroups135Now, tenantUserID,
	); err != nil {
		t.Fatal(err)
	}

	groupID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO identity_user_groups(
		id,platform_scope_id,name,revision,created_at,updated_at
	) VALUES($1,$2,'Support',1,$3,$3)`, groupID, platformScopeID, userGroups135Now); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(t.Context(), `INSERT INTO identity_user_groups(
		id,platform_scope_id,name,revision,created_at,updated_at
	) VALUES($1,$2,'support',1,$3,$3)`, uuid.New(), platformScopeID, userGroups135Now)
	assertUserGroups135Code(t, err, "23505")
	_, err = pool.Exec(t.Context(), `INSERT INTO identity_user_groups(
		id,platform_scope_id,name,revision,created_at,updated_at
	) VALUES($1,$2,'Tenant scoped',1,$3,$3)`, uuid.New(), tenantScopeID, userGroups135Now)
	assertUserGroups135Code(t, err, "P1351")

	if _, err := pool.Exec(t.Context(), `INSERT INTO identity_user_group_memberships(
		platform_scope_id,group_id,user_id,created_at,updated_at
	) VALUES($1,$2,$3,$4,$4)`, platformScopeID, groupID, tenantUserID, userGroups135Now); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `INSERT INTO identity_user_group_memberships(
		platform_scope_id,group_id,user_id,created_at,updated_at
	) VALUES($1,$2,$3,$4,$4)`, platformScopeID, groupID, adminID, userGroups135Now)
	assertUserGroups135Code(t, err, "P1353")
	_, err = pool.Exec(t.Context(), `DELETE FROM identity_user_groups WHERE id=$1`, groupID)
	assertUserGroups135Code(t, err, "23503")

	receiptID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO identity_user_group_write_requests(
		id,actor_user_id,actor_scope_id,operation,idempotency_key,request_digest,created_at
	) VALUES($1,$2,$3,'identity.user_group.create','create-support',$4,$5)`,
		receiptID, adminID, platformScopeID, make([]byte, 32), userGroups135Now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE identity_user_group_write_requests
		SET resource_id=$2,response_status=201,response_body='{}',completed_at=$3 WHERE id=$1`,
		receiptID, groupID, userGroups135Now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `UPDATE identity_user_group_write_requests
		SET response_body='{"changed":true}' WHERE id=$1`, receiptID)
	assertUserGroups135Code(t, err, "P1355")
	_, err = pool.Exec(t.Context(), `DELETE FROM identity_user_group_write_requests WHERE id=$1`, receiptID)
	assertUserGroups135Code(t, err, "P1355")
	_, err = pool.Exec(t.Context(), `TRUNCATE identity_user_group_write_requests`)
	assertUserGroups135Code(t, err, "P1355")

	assertUserGroups135Code(t, migrateVersionIsolated(t.Context(), pool, "down", 135), "P1356")
}

func TestUserGroups135EmptyRoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 134)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 135); err != nil {
		t.Fatalf("apply 135: %v", err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 135); err != nil {
		t.Fatalf("rollback 135: %v", err)
	}
	var relation *string
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('identity_user_groups')::text`).Scan(&relation); err != nil {
		t.Fatal(err)
	}
	if relation != nil {
		t.Fatalf("identity_user_groups remains after rollback: %q", *relation)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 135); err != nil {
		t.Fatalf("reapply 135: %v", err)
	}
}

func assertUserGroups135Code(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("error = %v, want PostgreSQL code %s", err, code)
	}
}

func readUserGroups135(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
