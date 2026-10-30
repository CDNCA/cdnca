//go:build integration

package migrations_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncatalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRegionCatalogManagement235StoreCRUDIdempotencyAndAudit(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 234)
	scopeID, userID, _ := seedRegionCatalogManagement235(t, pool, "store")
	if err := migrateVersionIsolated(t.Context(), pool, "up", 235); err != nil {
		t.Fatal(err)
	}
	// The store's audit.Append writes the columns of migration 361 (unified log).
	databasetest.AddUnifiedAuditColumns(t, pool)
	addRegionCatalogCode528Column(t, pool)
	store := regioncatalog.NewStore(pool)
	actor := regioncatalog.Actor{
		UserID: userID, ScopeID: scopeID, ScopeKind: "platform",
		Permissions: []string{regioncatalog.PermissionRead, regioncatalog.PermissionManage},
	}

	created, replayed, err := store.Create(t.Context(), actor, regioncatalog.CreateRequest{
		Name: "华南", Description: "主区域", L2CheckPort: 8080, Sort: 9,
		IdempotencyKey: "region-create-store", RequestID: "region-create-store-request",
	})
	if err != nil || replayed || created.ID == "" || created.Revision != 1 || created.Sort != 9 {
		t.Fatalf("create region=%+v replayed=%v error=%v", created, replayed, err)
	}
	replayedCreate, replayed, err := store.Create(t.Context(), actor, regioncatalog.CreateRequest{
		Name: "华南", Description: "主区域", L2CheckPort: 8080, Sort: 9,
		IdempotencyKey: "region-create-store", RequestID: "region-create-store-request",
	})
	if err != nil || !replayed || replayedCreate != created {
		t.Fatalf("replay region=%+v replayed=%v error=%v", replayedCreate, replayed, err)
	}
	if _, _, err := store.Create(t.Context(), actor, regioncatalog.CreateRequest{
		Name: "华南二", L2CheckPort: 80, Sort: 100,
		IdempotencyKey: "region-create-store", RequestID: "region-create-store-request-2",
	}); !errors.Is(err, regioncatalog.ErrIdempotencyConflict) {
		t.Fatalf("create idempotency conflict=%v", err)
	}

	if _, _, err := store.Update(t.Context(), actor, regioncatalog.UpdateRequest{
		ID: created.ID, ExpectedRevision: 2, Name: "华南二", Description: "更新",
		L2CheckPort: 443, Sort: 8, IdempotencyKey: "region-update-stale", RequestID: "region-update-stale-request",
	}); !errors.Is(err, regioncatalog.ErrRevisionConflict) {
		t.Fatalf("stale update error=%v", err)
	}
	updated, replayed, err := store.Update(t.Context(), actor, regioncatalog.UpdateRequest{
		ID: created.ID, ExpectedRevision: 1, Name: "华南二", Description: "更新",
		L2CheckPort: 443, Sort: 8, IdempotencyKey: "region-update-store", RequestID: "region-update-store-request",
	})
	if err != nil || replayed || updated.Revision != 2 || updated.Name != "华南二" || updated.L2CheckPort != 443 {
		t.Fatalf("update region=%+v replayed=%v error=%v", updated, replayed, err)
	}

	page, err := store.List(t.Context(), actor, regioncatalog.ListRequest{Paginated: true, Page: 1, PageSize: 1})
	if err != nil || page.Count != 2 || len(page.Data) != 1 || page.Data[0].ID != updated.ID {
		t.Fatalf("paginated page=%+v error=%v", page, err)
	}
	got, err := store.Get(t.Context(), actor, updated.ID)
	if err != nil || got != updated {
		t.Fatalf("get region=%+v error=%v", got, err)
	}

	nodeID := uuid.New()
	now := time.Date(2026, 9, 15, 11, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(
		id,display_id,scope_id,name,region,admin_state,created_by_user_id,created_at,updated_at)
		VALUES($1,1,$2,'store-region-node',$3,'active',$4,$5,$5)`, nodeID, scopeID, updated.Name, userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Delete(t.Context(), actor, regioncatalog.DeleteRequest{
		ID: updated.ID, ExpectedRevision: updated.Revision, IdempotencyKey: "region-delete-in-use", RequestID: "region-delete-in-use-request",
	}); !errors.Is(err, regioncatalog.ErrInUse) {
		t.Fatalf("delete in-use error=%v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE nodes SET admin_state='retired',updated_at=clock_timestamp() WHERE id=$1`, nodeID); err != nil {
		t.Fatal(err)
	}
	replayed, err = store.Delete(t.Context(), actor, regioncatalog.DeleteRequest{
		ID: updated.ID, ExpectedRevision: updated.Revision, IdempotencyKey: "region-delete-store", RequestID: "region-delete-store-request",
	})
	if err != nil || replayed {
		t.Fatalf("delete replayed=%v error=%v", replayed, err)
	}
	replayed, err = store.Delete(t.Context(), actor, regioncatalog.DeleteRequest{
		ID: updated.ID, ExpectedRevision: updated.Revision, IdempotencyKey: "region-delete-store", RequestID: "region-delete-store-request",
	})
	if err != nil || !replayed {
		t.Fatalf("delete replay replayed=%v error=%v", replayed, err)
	}

	var audits, receipts int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2 AND action LIKE 'region_catalog.%'),
		(SELECT count(*) FROM region_catalog_write_requests WHERE actor_scope_id=$1 AND actor_user_id=$2 AND completed_at IS NOT NULL)`,
		scopeID, userID).Scan(&audits, &receipts); err != nil {
		t.Fatal(err)
	}
	if audits != 3 || receipts != 3 {
		t.Fatalf("audits=%d receipts=%d", audits, receipts)
	}
}

// TestRegionCatalogManagement235ListOrdersDisplayIDNumerically guards the list
// contract in api/control-regions.openapi.yaml: rows sharing a sort value come
// back in numerically ascending display_id order. Selecting display_id::text
// makes the unqualified ORDER BY bind to that text output column, which sorts
// 1,17,18,3 instead of 1,3,17,18 once a scope passes display_id 9.
func TestRegionCatalogManagement235ListOrdersDisplayIDNumerically(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 234)
	scopeID, userID, _ := seedRegionCatalogManagement235(t, pool, "ordering")
	if err := migrateVersionIsolated(t.Context(), pool, "up", 235); err != nil {
		t.Fatal(err)
	}
	// The store's audit.Append writes the columns of migration 361 (unified log).
	databasetest.AddUnifiedAuditColumns(t, pool)
	addRegionCatalogCode528Column(t, pool)
	store := regioncatalog.NewStore(pool)
	actor := regioncatalog.Actor{
		UserID: userID, ScopeID: scopeID, ScopeKind: "platform",
		Permissions: []string{regioncatalog.PermissionRead, regioncatalog.PermissionManage},
	}

	// The seeded 默认 row keeps the migration's default sort_order of 100, so the
	// created rows (display_id 2..13, sort 7) lead and it trails; within the created
	// group the display_ids cross 9 into two digits, where text order turns into
	// 10,11,12,13,2,3,… and the text-ordered list lands 1 last.
	for index := 0; index < 12; index++ {
		if _, _, err := store.Create(t.Context(), actor, regioncatalog.CreateRequest{
			Name: fmt.Sprintf("排序%02d", index), L2CheckPort: 80, Sort: 7,
			IdempotencyKey: fmt.Sprintf("region-ordering-%02d", index),
			RequestID:      fmt.Sprintf("region-ordering-request-%02d", index),
		}); err != nil {
			t.Fatalf("create ordering region %d: %v", index, err)
		}
	}

	page, err := store.List(t.Context(), actor, regioncatalog.ListRequest{Paginated: true, Page: 1, PageSize: 300})
	if err != nil || page.Count != 13 || len(page.Data) != 13 {
		t.Fatalf("ordering page count=%d len=%d error=%v", page.Count, len(page.Data), err)
	}
	got := make([]string, 0, len(page.Data))
	for _, region := range page.Data {
		got = append(got, region.ID)
	}
	want := []string{"2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "1"}
	if !slices.Equal(got, want) {
		t.Fatalf("ordering display ids=%v, want %v", got, want)
	}
}

func TestRegionCatalogManagement235RepresentableUpDownUp(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 234)
	scopeID, userID, roleIDs := seedRegionCatalogManagement235(t, pool, "roundtrip")

	if err := migrateVersionIsolated(t.Context(), pool, "up", 235); err != nil {
		t.Fatalf("234 -> 235: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 235)
	assertRegionCatalogManagement235Columns(t, pool, true)
	assertRegionCatalogManagement235Permission(t, pool, scopeID, roleIDs, true)
	assertRegionCatalogManagement235Defaults(t, pool, scopeID)

	if err := migrateVersionIsolated(t.Context(), pool, "down", 235); err != nil {
		t.Fatalf("235 -> 234: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 234)
	assertRegionCatalogManagement235Columns(t, pool, false)
	assertRegionCatalogManagement235Permission(t, pool, scopeID, roleIDs, false)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 235); err != nil {
		t.Fatalf("234 -> 235 reapply: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 235)
	assertRegionCatalogManagement235Columns(t, pool, true)
	assertRegionCatalogManagement235Permission(t, pool, scopeID, roleIDs, true)
	_ = userID
}

func TestRegionCatalogManagement235ReferenceAndReceiptGuards(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 234)
	scopeID, userID, _ := seedRegionCatalogManagement235(t, pool, "guards")
	if err := migrateVersionIsolated(t.Context(), pool, "up", 235); err != nil {
		t.Fatal(err)
	}

	var regionID uuid.UUID
	var displayID int64
	if err := pool.QueryRow(t.Context(), `SELECT id,display_id FROM region_catalog
		WHERE platform_scope_id=$1 AND name='默认'`, scopeID).Scan(&regionID, &displayID); err != nil {
		t.Fatal(err)
	}
	nodeID := uuid.New()
	now := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(
		id,display_id,scope_id,name,region,admin_state,created_by_user_id,created_at,updated_at)
		VALUES($1,1,$2,'region-guard-node','默认','active',$3,$4,$4)`, nodeID, scopeID, userID, now); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(t.Context(), `UPDATE region_catalog SET name='新默认',revision=revision+1,updated_at=clock_timestamp()
		WHERE platform_scope_id=$1 AND display_id=$2`, scopeID, displayID)
	assertRegionCatalogManagement235Code(t, err, "P2352")
	_, err = pool.Exec(t.Context(), `DELETE FROM region_catalog WHERE platform_scope_id=$1 AND display_id=$2`, scopeID, displayID)
	assertRegionCatalogManagement235Code(t, err, "P2352")

	if _, err := pool.Exec(t.Context(), `UPDATE nodes SET admin_state='retired',updated_at=clock_timestamp() WHERE id=$1`, nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE region_catalog SET name='新默认',revision=revision+1,updated_at=clock_timestamp()
		WHERE platform_scope_id=$1 AND display_id=$2`, scopeID, displayID); err != nil {
		t.Fatalf("rename unused region: %v", err)
	}

	requestID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO region_catalog_write_requests(
		id,actor_user_id,actor_scope_id,operation,idempotency_key,request_digest,created_at)
		VALUES($1,$2,$3,'region_catalog.update','receipt-guard',$4,$5)`,
		requestID, userID, scopeID, make([]byte, 32), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE region_catalog_write_requests
		SET response_status=200,response_body='{"id":"1"}'::jsonb,completed_at=$2 WHERE id=$1`,
		requestID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string]string{
		"second completion": `UPDATE region_catalog_write_requests SET response_body='{"id":"2"}'::jsonb WHERE id='` + requestID.String() + `'`,
		"delete":            `DELETE FROM region_catalog_write_requests WHERE id='` + requestID.String() + `'`,
		"truncate":          `TRUNCATE region_catalog_write_requests`,
	} {
		if _, err := pool.Exec(t.Context(), query); err == nil {
			t.Fatalf("%s unexpectedly succeeded", name)
		}
	}
	assertRegionCatalogManagement235Code(t, migrateVersionIsolated(t.Context(), pool, "down", 235), "P2353")
	assertPackageCommerceRBAC079Ledger(t, pool, 235)
	_ = regionID
}

func seedRegionCatalogManagement235(
	t *testing.T,
	pool *pgxpool.Pool,
	suffix string,
) (uuid.UUID, uuid.UUID, []uuid.UUID) {
	t.Helper()
	scopeID, userID := uuid.New(), uuid.New()
	ownerRoleID, adminRoleID := uuid.New(), uuid.New()
	now := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL)`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
			VALUES($1,$2,$3,'unused',$4,$4)`, []any{userID, "region-235-" + suffix, "Region 235 " + suffix, now}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
			($1,$3,'platform_owner','Platform owner',true),
			($2,$3,'platform_admin','Platform administrator',true)`, []any{ownerRoleID, adminRoleID, scopeID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3),($1,$2,$4)`, []any{scopeID, userID, ownerRoleID, adminRoleID}},
		{`INSERT INTO region_catalog(id,platform_scope_id,name,created_at,updated_at)
			VALUES($1,$2,'默认',$3,$3)`, []any{uuid.New(), scopeID, now}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatalf("seed region catalog 235: %v", err)
		}
	}
	return scopeID, userID, []uuid.UUID{ownerRoleID, adminRoleID}
}

func assertRegionCatalogManagement235Columns(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var columns int
	var receipts bool
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='region_catalog' AND
		column_name IN ('description','l2_check_port','sort_order','revision')`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass(current_schema()||'.region_catalog_write_requests') IS NOT NULL`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if (columns == 4) != want || receipts != want {
		t.Fatalf("columns=%d receipts=%v want present=%v", columns, receipts, want)
	}
}

func assertRegionCatalogManagement235Permission(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID uuid.UUID,
	roleIDs []uuid.UUID,
	want bool,
) {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM role_permissions permission
		JOIN roles role ON role.id=permission.role_id
		WHERE role.scope_id=$1 AND permission.permission_name='regions.manage'`, scopeID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if (count == len(roleIDs)) != want {
		t.Fatalf("regions.manage grants=%d roles=%d want=%v", count, len(roleIDs), want)
	}
}

func assertRegionCatalogManagement235Defaults(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) {
	t.Helper()
	var description string
	var port, sort int
	var revision int64
	if err := pool.QueryRow(t.Context(), `SELECT description,l2_check_port,sort_order,revision
		FROM region_catalog WHERE platform_scope_id=$1 AND name='默认'`, scopeID).Scan(
		&description, &port, &sort, &revision); err != nil {
		t.Fatal(err)
	}
	if description != "" || port != 80 || sort != 100 || revision != 1 {
		t.Fatalf("defaults=(%q,%d,%d,%d)", description, port, sort, revision)
	}
}

func assertRegionCatalogManagement235Code(t *testing.T, err error, want string) {
	t.Helper()
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != want {
		t.Fatalf("migration 235 error=%v, want SQLSTATE %s", err, want)
	}
}

// addRegionCatalogCode528Column: the store reads region_catalog.code (migration
// 528, fz-x12); a 235-head fixture gets the column (generated values are 528's
// concern, see TestRegionCatalogCode528).
func addRegionCatalogCode528Column(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `ALTER TABLE region_catalog ADD COLUMN code text NOT NULL DEFAULT ''`); err != nil {
		t.Fatal(err)
	}
}
