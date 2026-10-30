//go:build integration

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestAggregatedEdgeImport362 rolls 362 up, down and up, then checks: the
// account access level is fixed; a read-only account backs no supply; a
// platform site whose hostname is a read-only imported view cannot be
// bound to any supply until the view is migrated; down refuses with an
// import present.
func TestAggregatedEdgeImport362(t *testing.T) {
	const version = 362
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}

	platform, user := uuid.New(), uuid.New()
	now := time.Now().UTC()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ae-362','AE 362','unused')`, user)
	account := func(access string) uuid.UUID {
		id := uuid.New()
		mustExec(t, pool, `INSERT INTO cdn_provider_accounts(id,platform_scope_id,provider,name,credential_key_id,
			credential_ciphertext,hostname_limit,created_by,updated_by,created_at,updated_at,access)
			VALUES($1,$2,'cloudflare',$3,'key-a',$4,100,$5,$5,$6,$6,$7)`, id, platform, "cf-"+id.String()[:8],
			make([]byte, 64), user, now, access)
		return id
	}
	readOnly, manage := account("read_only"), account("manage")
	if _, err := pool.Exec(ctx, `UPDATE cdn_provider_accounts SET access='manage' WHERE id=$1`, readOnly); sqlState(err) != "P3621" {
		t.Fatalf("access change: %v, want P3621", err)
	}

	supply := uuid.New()
	mustExec(t, pool, `INSERT INTO site_supplies(id,platform_scope_id,kind,name,created_at,updated_at)
		VALUES($1,$2,'third_party_cdn','cf supply',$3,$3)`, supply, platform, now)
	if _, err := pool.Exec(ctx, `INSERT INTO site_supply_cdn_configs(supply_id,provider,mode,account_id,endpoint,created_at,updated_at)
		VALUES($1,'cloudflare','schedule_only',$2,'edge.example.net',$3,$3)`, supply, readOnly, now); sqlState(err) != "P3623" {
		t.Fatalf("read-only account on a supply: %v, want P3623", err)
	}
	mustExec(t, pool, `INSERT INTO site_supply_cdn_configs(supply_id,provider,mode,account_id,created_at,updated_at)
		VALUES($1,'cloudflare','config_sync',$2,$3,$3)`, supply, manage, now)
	if _, err := pool.Exec(ctx, `UPDATE site_supply_cdn_configs SET account_id=$2 WHERE supply_id=$1`, supply, readOnly); sqlState(err) != "P3623" {
		t.Fatalf("switch supply to read-only account: %v, want P3623", err)
	}

	importID := uuid.New()
	mustExec(t, pool, `INSERT INTO cdn_zone_imports(id,platform_scope_id,account_id,provider,zone_ref,next_refresh_at,
		created_by,created_at,updated_at) VALUES($1,$2,$3,'cloudflare','0123456789abcdef0123456789abcdef',$4,$5,$4,$4)`,
		importID, platform, readOnly, now, user)
	mustExec(t, pool, `INSERT INTO cdn_import_sites(import_id,hostname,updated_at) VALUES($1,'www.import-362.test',$2)`, importID, now)
	if _, err := pool.Exec(ctx, `INSERT INTO cdn_import_sites(import_id,hostname,state,updated_at)
		VALUES($1,'api.import-362.test','migrated',$2)`, importID, now); sqlState(err) != "23514" {
		t.Fatalf("migrated without a site: %v, want check violation", err)
	}

	tenant, scope, owner := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'362 tenant')`, tenant)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scope, tenant)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'site-362','Site 362','unused')`, owner)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scope, owner)
	imported, other := uuid.New(), uuid.New()
	seedSite362(ctx, t, pool, scope, owner, imported, 1, "www.import-362.test")
	seedSite362(ctx, t, pool, scope, owner, other, 2, "other-362.example.test")

	bind := func(site uuid.UUID) error {
		_, err := pool.Exec(ctx, `INSERT INTO site_supply_bindings(site_id,supply_id,role,created_at) VALUES($1,$2,'primary',$3)`,
			site, supply, now)
		return err
	}
	if err := bind(imported); sqlState(err) != "P3622" {
		t.Fatalf("bind read-only imported hostname: %v, want P3622", err)
	}
	if err := bind(other); err != nil {
		t.Fatalf("bind an unrelated site: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE site_supply_bindings SET site_id=$1 WHERE site_id=$2`, imported, other); sqlState(err) != "P3622" {
		t.Fatalf("move a binding onto the imported hostname: %v, want P3622", err)
	}
	mustExec(t, pool, `UPDATE cdn_import_sites SET state='migrated',migrated_site_id=$2,migrated_at=$3
		WHERE import_id=$1`, importID, imported, now)
	if err := bind(imported); err != nil {
		t.Fatalf("bind after migration: %v", err)
	}

	planned := func(hostname string) error {
		_, err := pool.Exec(ctx, `INSERT INTO cdn_import_migrations(id,import_id,hostname,target_site_id,target_cname,
			writer_account_id,state,import_revision,plan,plan_sha256,expires_at,created_by,created_at)
			VALUES($1,$2,$3,$4,'s1.cname.example.net',$5,'planned',1,'[{"op":"update"}]',$6,$7,$8,$7)`,
			uuid.New(), importID, hostname, imported, manage, "0000000000000000000000000000000000000000000000000000000000000000",
			now, user)
		return err
	}
	if err := planned("www.import-362.test"); err != nil {
		t.Fatalf("plan: %v", err)
	}
	if err := planned("www.import-362.test"); sqlState(err) != "23505" {
		t.Fatalf("second open plan: %v, want unique violation", err)
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3625" {
		t.Fatalf("down with an import: %v, want P3625", err)
	}
}

func seedSite362(ctx context.Context, t *testing.T, pool *pgxpool.Pool, scopeID, userID, siteID uuid.UUID, displayID int, domain string) {
	t.Helper()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id) VALUES($1,$2,$3,$4,$5,ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$4,$4)`,
			siteID, scopeID, displayID, userID, domain); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, siteID)
		return err
	}); err != nil {
		t.Fatalf("seed site: %v", err)
	}
}
