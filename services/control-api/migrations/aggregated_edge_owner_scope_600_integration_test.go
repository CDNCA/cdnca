//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestAggregatedEdgeOwnerScope600 rolls 600 up, down and up, then checks:
// tenant system roles (existing and new) get the edge.tenant.* codes; a
// tenant supply carries only its own sites and uses only its own accounts;
// the owner never changes; the package limits accept the two new optional
// keys; down refuses while a tenant owns a row.
func TestAggregatedEdgeOwnerScope600(t *testing.T) {
	// Keep equal to the 600 contract's version.
	const version = 600
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Now().UTC()

	tenantA, tenantB := uuid.New(), uuid.New()
	platform, scopeA, scopeB, user := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ownerBefore := uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'ae600a'),($2,'ae600b')`, tenantA, tenantB)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'tenant',$4)`,
		scopeA, tenantA, scopeB, tenantB)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ae-600','AE 600','unused')`, user)
	// sites(scope_id,owner_user_id) 引用 memberships：站点所有者须是 scopeA 成员（同 362 用例）。
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeA, user)
	mustExec(t, pool, `INSERT INTO roles(id,scope_id,name,description,system_role,created_at)
		VALUES($1,$2,'tenant_owner','Tenant owner',true,$3)`, ownerBefore, scopeA, now)

	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}

	granted := func(role uuid.UUID) map[string]bool {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT permission_name FROM role_permissions
			WHERE role_id=$1 AND permission_name LIKE 'edge.tenant.%'`, role)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		got := map[string]bool{}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			got[name] = true
		}
		return got
	}
	if got := granted(ownerBefore); len(got) != 3 {
		t.Fatalf("backfilled tenant_owner = %v, want all three", got)
	}
	ownerAfter, viewerAfter := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO roles(id,scope_id,name,description,system_role,created_at)
		VALUES($1,$3,'tenant_owner','Tenant owner',true,$4),($2,$3,'tenant_viewer','Tenant viewer',true,$4)`,
		ownerAfter, viewerAfter, scopeB, now)
	if got := granted(ownerAfter); len(got) != 3 {
		t.Fatalf("new tenant_owner = %v, want all three", got)
	}
	if got := granted(viewerAfter); len(got) != 1 || !got["edge.tenant.read"] {
		t.Fatalf("new tenant_viewer = %v, want edge.tenant.read only", got)
	}
	var stepUp bool
	if err := pool.QueryRow(ctx, `SELECT step_up_required FROM custom_rbac_permission_catalog
		WHERE permission_name='edge.tenant.accounts.manage'`).Scan(&stepUp); err != nil || !stepUp {
		t.Fatalf("accounts.manage step-up = %v, %v", stepUp, err)
	}

	account := func(owner uuid.UUID) uuid.UUID {
		id := uuid.New()
		mustExec(t, pool, `INSERT INTO cdn_provider_accounts(id,owner_scope_id,provider,name,credential_key_id,
			credential_ciphertext,hostname_limit,created_by,updated_by,created_at,updated_at)
			VALUES($1,$2,'cloudflare',$3,'key-a',$4,100,$5,$5,$6,$6)`, id, owner, "cf-"+id.String()[:8],
			make([]byte, 64), user, now)
		return id
	}
	supply := func(owner uuid.UUID) uuid.UUID {
		id := uuid.New()
		mustExec(t, pool, `INSERT INTO site_supplies(id,owner_scope_id,kind,name,target,created_at,updated_at)
			VALUES($1,$2,'third_party_cdn',$3,'edge.example.test',$4,$4)`, id, owner, "s-"+id.String()[:8], now)
		return id
	}
	config := func(supplyID, accountID uuid.UUID) error {
		_, err := pool.Exec(ctx, `INSERT INTO site_supply_cdn_configs(supply_id,provider,mode,account_id,created_at,updated_at)
			VALUES($1,'cloudflare','config_sync',$2,$3,$3)`, supplyID, accountID, now)
		return err
	}
	accountA, accountPlatform := account(scopeA), account(platform)
	supplyA, supplyB, supplyPlatform := supply(scopeA), supply(scopeB), supply(platform)
	if err := config(supplyA, accountPlatform); sqlState(err) != "P6002" {
		t.Fatalf("tenant supply on platform account: %v, want P6002", err)
	}
	if err := config(supplyPlatform, accountA); sqlState(err) != "P6002" {
		t.Fatalf("platform supply on tenant account: %v, want P6002", err)
	}
	if err := config(supplyA, accountA); err != nil {
		t.Fatalf("own account: %v", err)
	}
	if err := config(supplyPlatform, accountPlatform); err != nil {
		t.Fatalf("platform account: %v", err)
	}

	siteA := uuid.New()
	seedSite362(ctx, t, pool, scopeA, user, siteA, 60001, "www.owner-600.test")
	bind := func(supplyID uuid.UUID) error {
		_, err := pool.Exec(ctx, `INSERT INTO site_supply_bindings(site_id,supply_id,role,priority,line_scope,created_at)
			VALUES($1,$2,'backup',100,'',$3)`, siteA, supplyID, now)
		return err
	}
	if err := bind(supplyB); sqlState(err) != "P6001" {
		t.Fatalf("tenant B supply on tenant A site: %v, want P6001", err)
	}
	if err := bind(supplyA); err != nil {
		t.Fatalf("own supply: %v", err)
	}
	if err := bind(supplyPlatform); err != nil {
		t.Fatalf("platform supply (方案 E): %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE site_supply_bindings SET supply_id=$2 WHERE site_id=$1 AND supply_id=$3`,
		siteA, supplyB, supplyA); sqlState(err) != "P6001" {
		t.Fatalf("rebind to tenant B supply: %v, want P6001", err)
	}
	for table, id := range map[string]uuid.UUID{"cdn_provider_accounts": accountA, "site_supplies": supplyA} {
		if _, err := pool.Exec(ctx, `UPDATE `+table+` SET owner_scope_id=$2 WHERE id=$1`, id, scopeB); sqlState(err) != "P6003" {
			t.Fatalf("%s owner change: %v, want P6003", table, err)
		}
	}

	publishable := func(limits string) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT package_offer_spec_publishable_090(
			jsonb_set($1::jsonb,'{limits}',$1::jsonb->'limits' || $2::jsonb), now())`, validPackageOfferSpec090(), limits).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !publishable(`{}`) {
		t.Fatal("base spec without the new keys is not publishable")
	}
	for limits, want := range map[string]bool{
		`{"aggregated_edge":true,"aggregated_edge_accounts":3}`:   true,
		`{"aggregated_edge":false,"aggregated_edge_accounts":-1}`: true,
		`{"aggregated_edge":"yes"}`:                               false,
		`{"aggregated_edge_accounts":1001}`:                       false,
		`{"aggregated_edge_accounts":-2}`:                         false,
		`{"aggregated_edge_accounts":1.5}`:                        false,
		`{"unknown_key":true}`:                                    false,
	} {
		if got := publishable(limits); got != want {
			t.Errorf("publishable(%s) = %v, want %v", limits, got, want)
		}
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P6006" {
		t.Fatalf("down with tenant-owned rows: %v, want P6006", err)
	}
}
