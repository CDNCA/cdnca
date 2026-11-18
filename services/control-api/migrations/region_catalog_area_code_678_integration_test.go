//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestRegionCatalogAreaCode678: 677 -> 678 -> 677 -> 678. A region starts without an
// area; the area is a libs/geoarea code and excludes a country (and so a province).
func TestRegionCatalogAreaCode678(t *testing.T) {
	const version = 678
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	platform := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
		t.Fatal(err)
	}
	var displayID int64
	if err := pool.QueryRow(ctx, `INSERT INTO region_catalog(id,platform_scope_id,name,country_code) VALUES(gen_random_uuid(),$1,'华南','CN')
		RETURNING display_id`, platform).Scan(&displayID); err != nil {
		t.Fatal(err)
	}
	columnExists := func() bool {
		t.Helper()
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
			AND table_name='region_catalog' AND column_name='area_code')`).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists
	}
	if columnExists() {
		t.Fatal("677 head already has region_catalog.area_code")
	}
	for _, step := range []struct {
		direction string
		exists    bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if columnExists() != step.exists {
			t.Fatalf("after %s: area_code exists = %v", step.direction, !step.exists)
		}
	}
	var area, country string
	if err := pool.QueryRow(ctx, `SELECT area_code,country_code FROM region_catalog WHERE display_id=$1`, displayID).
		Scan(&area, &country); err != nil || area != "" || country != "CN" {
		t.Fatalf("after up = %q %q, %v", area, country, err)
	}
	set := func(area, country, province string) error {
		_, err := pool.Exec(ctx, `UPDATE region_catalog SET area_code=$2,country_code=$3,province_code=$4,revision=revision+1
			WHERE display_id=$1`, displayID, area, country, province)
		return err
	}
	for _, ok := range [][3]string{{"southeast_asia", "", ""}, {"global", "", ""}, {"", "CN", "440000"}, {"", "", ""}} {
		if err := set(ok[0], ok[1], ok[2]); err != nil {
			t.Errorf("%q/%q/%q refused: %v", ok[0], ok[1], ok[2], err)
		}
	}
	for _, bad := range [][3]string{{"oceania", "", ""}, {"Europe", "", ""}, {"europe", "DE", ""}, {"east_asia", "CN", "440000"}} {
		if err := set(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("%q/%q/%q accepted", bad[0], bad[1], bad[2])
		}
	}
}
