//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestRegionCatalogGeoCodes576 (fix-mktsiteconf4，占位号 576，合入改号后才能跑): regions
// start without codes; a country is two upper-case letters, a province only a
// CN six digit province-level code. Up, down and up again.
func TestRegionCatalogGeoCodes576(t *testing.T) {
	const version = 576
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	platform := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
		t.Fatal(err)
	}
	var displayID int64
	if err := pool.QueryRow(ctx, `INSERT INTO region_catalog(id,platform_scope_id,name) VALUES(gen_random_uuid(),$1,'华南')
		RETURNING display_id`, platform).Scan(&displayID); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var country, province string
	if err := pool.QueryRow(ctx, `SELECT country_code,province_code FROM region_catalog WHERE display_id=$1`, displayID).
		Scan(&country, &province); err != nil || country != "" || province != "" {
		t.Fatalf("defaults = %q %q, %v", country, province, err)
	}
	set := func(country, province string) error {
		_, err := pool.Exec(ctx, `UPDATE region_catalog SET country_code=$2,province_code=$3,revision=revision+1
			WHERE display_id=$1`, displayID, country, province)
		return err
	}
	if err := set("CN", "440000"); err != nil {
		t.Fatalf("CN/440000: %v", err)
	}
	if err := set("US", ""); err != nil {
		t.Fatalf("US: %v", err)
	}
	for _, bad := range [][2]string{{"cn", ""}, {"CHN", ""}, {"US", "440000"}, {"", "440000"}, {"CN", "440300"}, {"CN", "44000"}} {
		if err := set(bad[0], bad[1]); err == nil {
			t.Errorf("%q/%q accepted", bad[0], bad[1])
		}
	}
}
