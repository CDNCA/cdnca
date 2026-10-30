//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRegionCatalog223PlatformFactsShortIDsAndRollback(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 222)
	platformScopeID, tenantScopeID, tenantID, userID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ownerRoleID, adminRoleID, tenantRoleID := uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Region catalog tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL),($2,'tenant',$3)`, []any{platformScopeID, tenantScopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at) VALUES($1,'region-catalog-223','Region Catalog 223','unused',$2,$2)`, []any{userID, now}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$3),($2,$3)`, []any{platformScopeID, tenantScopeID, userID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
			($1,$4,'platform_owner','Platform owner',true),
			($2,$4,'platform_admin','Platform administrator',true),
			($3,$5,'tenant_owner','Tenant owner',true)`, []any{ownerRoleID, adminRoleID, tenantRoleID, platformScopeID, tenantScopeID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$3,$4),($1,$3,$5),($2,$3,$6)`, []any{platformScopeID, tenantScopeID, userID, ownerRoleID, adminRoleID, tenantRoleID}},
		{`INSERT INTO nodes(id,display_id,scope_id,name,region,admin_state,created_by_user_id,created_at,updated_at) VALUES
			($1,1,$4,'east-node','华东','active',$6,$7,$7),
			($2,2,$4,'north-node','华北','active',$6,$7,$7),
			($3,1,$5,'tenant-node','租户区域','active',$6,$7,$7)`, []any{uuid.New(), uuid.New(), uuid.New(), platformScopeID, tenantScopeID, userID, now}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatalf("seed migration 223 fixture: %v", err)
		}
	}

	if err := migrateVersionIsolated(t.Context(), pool, "up", 223); err != nil {
		t.Fatalf("222 -> 223: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 223)

	var granted, tenantGranted int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM role_permissions permission
		JOIN roles role ON role.id=permission.role_id
		WHERE role.scope_id=$1 AND permission.permission_name='regions.read'`, platformScopeID).Scan(&granted); err != nil || granted != 2 {
		t.Fatalf("platform region grants=(%d,%v), want 2", granted, err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM role_permissions permission
		JOIN roles role ON role.id=permission.role_id
		WHERE role.scope_id=$1 AND permission.permission_name='regions.read'`, tenantScopeID).Scan(&tenantGranted); err != nil || tenantGranted != 0 {
		t.Fatalf("tenant region grants=(%d,%v), want 0", tenantGranted, err)
	}

	type catalogRow struct {
		ID   string
		Name string
	}
	readCatalog := func(search string, limit int) ([]catalogRow, int64) {
		t.Helper()
		rows, err := pool.Query(t.Context(), `SELECT display_id::text,name,count(*) OVER()
			FROM region_catalog WHERE platform_scope_id=$1 AND ($2='' OR strpos(name,$2)>0)
			ORDER BY name COLLATE "C",display_id LIMIT NULLIF($3,0)`, platformScopeID, search, limit)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		result := []catalogRow{}
		var count int64
		for rows.Next() {
			var item catalogRow
			if err := rows.Scan(&item.ID, &item.Name, &count); err != nil {
				t.Fatal(err)
			}
			result = append(result, item)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return result, count
	}
	page, pageCount := readCatalog("", 0)
	if pageCount != 3 || len(page) != 3 ||
		page[0] != (catalogRow{ID: "2", Name: "华东"}) ||
		page[1] != (catalogRow{ID: "3", Name: "华北"}) ||
		page[2] != (catalogRow{ID: "1", Name: "默认"}) {
		t.Fatalf("stable region rows=%+v count=%d", page, pageCount)
	}
	limited, limitedCount := readCatalog("", 1)
	if limitedCount != 3 || len(limited) != 1 || limited[0] != page[0] {
		t.Fatalf("limited region rows=%+v count=%d", limited, limitedCount)
	}

	percentNodeID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(
		id,display_id,scope_id,name,region,admin_state,created_by_user_id,created_at,updated_at
	) VALUES($1,3,$2,'percent-node','100%','active',$3,$4,$4)`, percentNodeID, platformScopeID, userID, now); err != nil {
		t.Fatal(err)
	}
	percentRows, percentCount := readCatalog("%", 0)
	if percentCount != 1 || len(percentRows) != 1 || percentRows[0] != (catalogRow{ID: "4", Name: "100%"}) {
		t.Fatalf("literal search rows=%+v count=%d", percentRows, percentCount)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE region_catalog SET display_id=99 WHERE platform_scope_id=$1 AND name='华东'`, platformScopeID); postgresCode223(err) != "P2231" {
		t.Fatalf("mutable short ID error=%v", err)
	}

	down, err := controlmigrations.FS.ReadFile("223_region_catalog.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	fenced, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer fenced.Rollback(context.Background())
	if _, err := fenced.Exec(t.Context(), `INSERT INTO schema_migrations(
		version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at,applied_at
	) VALUES(224,'unexpected_head',repeat('a',64),repeat('b',64),'verified',now(),now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := fenced.Exec(t.Context(), string(down)); postgresCode223(err) != "P2230" {
		t.Fatalf("rollback fence error=%v", err)
	}
	if err := fenced.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	if err := migrateVersionIsolated(t.Context(), pool, "down", 223); err != nil {
		t.Fatalf("223 -> 222: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 222)
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass(current_schema() || '.region_catalog') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("catalog after rollback=(%v,%v)", exists, err)
	}
}

func postgresCode223(err error) string {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		return databaseError.Code
	}
	return ""
}
