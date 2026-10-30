//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestSiteCacheSharedAcrossDomains356: an existing site keys its cache by
// host (the column defaults to false), the option can be turned on, and the
// change advances the scope's edge source revision so the site republishes;
// down drops the column and up adds it again.
func TestSiteCacheSharedAcrossDomains356(t *testing.T) {
	const version = 356
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'356 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'cache-356','Cache 356','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id) VALUES($1,$2,1,$3,'*.x356.example',ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3)`,
			siteID, scopeID, userID); err != nil {
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
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var shared bool
	if err := pool.QueryRow(ctx, `SELECT cache_shared_across_domains FROM sites WHERE id=$1`, siteID).Scan(&shared); err != nil || shared {
		t.Fatalf("existing site shares its cache = %v, %v; want false", shared, err)
	}
	revision := func() int64 {
		t.Helper()
		var value int64
		if err := pool.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, scopeID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := revision()
	mustExec(t, pool, `UPDATE sites SET cache_shared_across_domains=true WHERE id=$1`, siteID)
	if after := revision(); after != before+1 {
		t.Fatalf("turning the shared cache on moved the edge source revision %d -> %d, want +1", before, after)
	}
}
