//go:build integration

package regioncatalog

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

// LoadCodeGeos at the migration head carries a region's macro area (678) or
// its country and province (576).
func TestLoadCodeGeosCarriesAreaOrCountryPostgreSQL(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	platform := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
		t.Fatal(err)
	}
	for _, row := range [][4]string{{"asia-se", "southeast_asia", "", ""}, {"cn-south", "", "CN", "440000"}} {
		// the code is generated: the lower-cased name when it fits (528)
		if _, err := pool.Exec(ctx, `INSERT INTO region_catalog(id,platform_scope_id,name,area_code,country_code,province_code)
			VALUES(gen_random_uuid(),$1,$2,$3,$4,$5)`, platform, row[0], row[1], row[2], row[3]); err != nil {
			t.Fatalf("%s: %v", row[0], err)
		}
	}
	geos, err := LoadCodeGeos(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if got := geos["asia-se"]; got != (CodeGeo{Code: "asia-se", AreaCode: "southeast_asia"}) {
		t.Fatalf("asia-se = %+v", got)
	}
	if got := geos["cn-south"]; got != (CodeGeo{Code: "cn-south", CountryCode: "CN", ProvinceCode: "440000"}) {
		t.Fatalf("cn-south = %+v", got)
	}
}
