package migrations

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/geoarea"
)

// Migration 680: region_catalog.area_code takes every
// geoarea code, cname_carrier_line_records.line_scope every geoarea code but
// global; down puts back the 678/679 lists and refuses data on the v2 codes.
// The lists are compared item by item with geoarea.Areas.
func TestGeoareaV2Codes680Contract(t *testing.T) {
	up, err := FS.ReadFile("680_geoarea_v2_codes.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("680_geoarea_v2_codes.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 679", "(SELECT max(version) FROM schema_migrations) <> 679",
		"migration_id='679_cname_line_area_scopes'", "ERRCODE='P6800'",
		"DROP CONSTRAINT region_catalog_area_code_678_check", "ADD CONSTRAINT region_catalog_area_code_680_check",
		"DROP CONSTRAINT cname_carrier_line_records_line_scope_679_check",
		"ADD CONSTRAINT cname_carrier_line_records_line_scope_680_check",
		"line_scope IN ('telecom', 'unicom', 'mobile', 'overseas')",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("680 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 680", "migration_id='680_geoarea_v2_codes'",
		"ERRCODE='P6801'", "ERRCODE='P6802'",
		"ADD CONSTRAINT region_catalog_area_code_678_check", "ADD CONSTRAINT cname_carrier_line_records_line_scope_679_check",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("680 down missing %q", fragment)
		}
	}
	var all, scopes []string
	for _, area := range geoarea.Areas {
		all = append(all, area.Code)
		if area.Code != geoarea.Global {
			scopes = append(scopes, area.Code)
		}
	}
	var v1Scopes []string
	for _, code := range geoareaV1Codes {
		if code != geoarea.Global {
			v1Scopes = append(v1Scopes, code)
		}
	}
	v1Scopes = append([]string{"asia"}, v1Scopes...)
	lists := func(sql []byte, column string) [][]string {
		var out [][]string
		for _, m := range regexp.MustCompile(column+` (?:NOT )?IN \(('[a-z_]+'[^)]*)\)`).FindAllStringSubmatch(string(sql), -1) {
			var items []string
			for _, item := range strings.Split(m[1], ",") {
				items = append(items, strings.Trim(strings.TrimSpace(item), "'"))
			}
			if !slices.Equal(items, []string{"telecom", "unicom", "mobile", "overseas"}) {
				out = append(out, items)
			}
		}
		return out
	}
	if got := lists(up, "area_code"); len(got) != 1 || !slices.Equal(got[0], all) {
		t.Fatalf("680 up area_code lists %v, want %v", got, all)
	}
	if got := lists(up, "line_scope"); len(got) != 1 || !slices.Equal(got[0], scopes) {
		t.Fatalf("680 up line_scope lists %v, want %v", got, scopes)
	}
	// down: the refusal checks (v1 lists, then the v2 scopes) and the restored CHECKs (v1 lists).
	if got := lists(down, "area_code"); len(got) != 2 || !slices.Equal(got[0], geoareaV1Codes) || !slices.Equal(got[1], geoareaV1Codes) {
		t.Fatalf("680 down area_code lists %v, want v1 %v twice", got, geoareaV1Codes)
	}
	if got := lists(down, "line_scope"); len(got) != 3 || !slices.Equal(got[0], scopes) || !slices.Equal(got[1], v1Scopes) ||
		!slices.Equal(got[2], v1Scopes) {
		t.Fatalf("680 down line_scope lists %v", got)
	}
	// Every v1 code keeps being accepted, and the 609 province pattern is kept verbatim.
	for _, code := range geoareaV1Codes {
		if !slices.Contains(all, code) {
			t.Fatalf("v1 code %s dropped", code)
		}
	}
	province := regexp.MustCompile(`line_scope ~ '[^']*'`)
	p679, err := FS.ReadFile("679_cname_line_area_scopes.up.sql")
	if err != nil || province.FindString(string(p679)) == "" ||
		!strings.Contains(string(up), province.FindString(string(p679))) || !strings.Contains(string(down), province.FindString(string(p679))) {
		t.Fatalf("680 must keep the 609 province pattern (%v)", err)
	}
	// down restores exactly the 678/679 CHECK bodies.
	for file, name := range map[string]string{"678_region_catalog_area_code.up.sql": "area_code = '' OR area_code IN (",
		"679_cname_line_area_scopes.up.sql": "line_scope IN ('asia'"} {
		old, err := FS.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		line := regexp.MustCompile(regexp.QuoteMeta(name) + `[^)]*\)`).FindString(string(old))
		if line == "" || !strings.Contains(string(down), line) {
			t.Fatalf("680 down does not restore %s's %q", file, line)
		}
	}
}
