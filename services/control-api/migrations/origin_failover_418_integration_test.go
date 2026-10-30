//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestOriginFailover418: up/down/up; backup origins become level 1 and back,
// a pool needs an enabled level 0 origin, levels stay 0..15, a level 2
// origin or a recorded switch blocks the rollback.
func TestOriginFailover418(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_origin_failover.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("origin failover migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'418 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'of-418','OF 418','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,http_ports,https_ports,
			origins,origin_hosts,created_by_user_id,updated_by_user_id) VALUES($1,$2,1,$3,'of418.example.test',ARRAY['80'],
			ARRAY['443'],ARRAY['192.0.2.1','192.0.2.2'],ARRAY['192.0.2.1','192.0.2.2'],$3,$3)`, siteID, scopeID, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port,backup)
			VALUES($1,1,'192.0.2.1',80,false),($1,2,'192.0.2.2',80,true)`, siteID)
		return err
	}); err != nil {
		t.Fatalf("insert site: %v", err)
	}

	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up: %v", err)
	}
	var levels string
	if err := pool.QueryRow(ctx, `SELECT string_agg(level::text, ',' ORDER BY position) FROM site_origins WHERE site_id=$1`,
		siteID).Scan(&levels); err != nil || levels != "0,1" {
		t.Fatalf("levels %q %v", levels, err)
	}
	var mode, path string
	if err := pool.QueryRow(ctx, `SELECT failback_mode, health_check_path FROM site_origin_pools WHERE site_id=$1`, siteID).
		Scan(&mode, &path); err != nil || mode != "auto" || path != "/" {
		t.Fatalf("pool defaults %q %q %v", mode, path, err)
	}
	for name, statement := range map[string]string{
		"level 16":          `UPDATE site_origins SET level=16 WHERE site_id=$1 AND position=2`,
		"no primary":        `UPDATE site_origins SET level=1 WHERE site_id=$1`,
		"bad failback mode": `UPDATE site_origin_pools SET failback_mode='later' WHERE site_id=$1`,
		"bad health path":   `UPDATE site_origin_pools SET health_check_path='health' WHERE site_id=$1`,
		"active level 16":   `INSERT INTO site_origin_failover_states(site_id,active_level,updated_at) VALUES($1,16,now())`,
	} {
		if _, err := pool.Exec(ctx, statement, siteID); sqlState(err) != "23514" {
			t.Fatalf("%s: %v, want 23514", name, err)
		}
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	var backups int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM site_origins WHERE site_id=$1 AND backup`, siteID).Scan(&backups); err != nil || backups != 1 {
		t.Fatalf("backup after down %d %v", backups, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
	// level 2 cannot be expressed by the old schema
	mustExec(t, pool, `UPDATE site_origins SET level=2 WHERE site_id=$1 AND position=2`, siteID)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4182" {
		t.Fatalf("down with level 2: %v, want P4182", err)
	}
	mustExec(t, pool, `UPDATE site_origins SET level=1 WHERE site_id=$1 AND position=2`, siteID)
	mustExec(t, pool, `INSERT INTO edge_system_revision_segments(scope_id,from_revision,to_revision,source,recorded_at)
		VALUES($1,1,2,'origin_failover',now())`, scopeID)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4182" {
		t.Fatalf("down with a switch segment: %v, want P4182", err)
	}
}
