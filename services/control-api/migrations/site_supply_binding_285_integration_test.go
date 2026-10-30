//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// siteSupplyBindingVersion finds this migration's number from its file name,
// so renumbering at merge time needs no test edit.
func siteSupplyBindingVersion(t *testing.T) int64 {
	t.Helper()
	matches, err := fs.Glob(controlmigrations.FS, "*_site_supply_binding.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("site supply binding migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(strings.SplitN(matches[0], "_", 2)[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func TestSiteSupplyBindingMigration(t *testing.T) {
	version := siteSupplyBindingVersion(t)
	pool := packageCommerceRBAC079Pool(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	for _, table := range []string{"site_supplies", "site_supply_bindings", "site_supply_leaf_sites", "site_supply_config_revisions"} {
		var granted bool
		if err := pool.QueryRow(ctx, `SELECT has_table_privilege('cdnca_control_runtime',$1,'INSERT')`, table).Scan(&granted); err != nil || !granted {
			t.Fatalf("%s runtime grant = %v, %v", table, granted, err)
		}
	}
	scope := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO site_supplies(id,platform_scope_id,kind,name,created_at,updated_at)
		VALUES($1,$2,'market_subscription','no subscription',now(),now())`, uuid.New(), scope); err == nil {
		t.Fatal("market supply without market_subscription_id accepted")
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM site_supply_bindings_effective`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("effective bindings on an empty schema = %d, %v", rows, err)
	}
}
