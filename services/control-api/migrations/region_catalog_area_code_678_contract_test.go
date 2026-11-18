package migrations

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/geoarea"
)

// Migration 678: region_catalog.area_code, one of the
// geoarea v1 codes or empty, never together with a country. 678 is frozen at
// the v1 list (geoareaV1Codes); 680 widens it to geoarea.Areas.
// geoareaV1Codes are the libs/geoarea codes of 678/679 (geoarea v1).
var geoareaV1Codes = []string{"global", "east_asia", "southeast_asia", "south_asia", "west_asia", "central_asia",
	"europe", "north_america", "south_america", "africa"}

func TestRegionCatalogAreaCode678Contract(t *testing.T) {
	up, err := FS.ReadFile("678_region_catalog_area_code.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("678_region_catalog_area_code.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 677", "(SELECT max(version) FROM schema_migrations) <> 677",
		"migration_id='677_upgrade_cancel_expired_nodes'", "ERRCODE='P6780'",
		"ADD COLUMN area_code text NOT NULL DEFAULT ''", "area_code = '' OR country_code = ''",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("678 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 678", "migration_id='678_region_catalog_area_code'",
		"ERRCODE='P6781'", "DROP COLUMN area_code",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("678 down missing %q", fragment)
		}
	}
	list := regexp.MustCompile(`area_code IN \(([^)]*)\)`).FindStringSubmatch(string(up))
	if list == nil {
		t.Fatal("678 up has no area_code IN (...) list")
	}
	var sqlCodes, codes []string
	for _, item := range strings.Split(list[1], ",") {
		sqlCodes = append(sqlCodes, strings.Trim(strings.TrimSpace(item), "'"))
	}
	codes = geoareaV1Codes
	if !slices.Equal(sqlCodes, codes) {
		t.Fatalf("678 CHECK codes %v, geoarea v1 %v", sqlCodes, codes)
	}
	for _, code := range codes {
		if !geoarea.Valid(code) {
			t.Fatalf("v1 code %s is no longer a geoarea code", code)
		}
	}
}
