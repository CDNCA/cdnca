package migrations

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/geoarea"
)

// Migration 679: cname_carrier_line_records.line_scope
// also takes the macro-area scopes of cnamelines (every libs/geoarea code but
// global, plus "asia", the 亚洲 line Asian areas fall back to). 679 is
// frozen at the v1 codes; 680 widens it to geoarea.Areas.
func TestCNAMELineAreaScopes679Contract(t *testing.T) {
	up, err := FS.ReadFile("679_cname_line_area_scopes.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("679_cname_line_area_scopes.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 678", "(SELECT max(version) FROM schema_migrations) <> 678",
		"migration_id='678_region_catalog_area_code'", "ERRCODE='P6790'",
		"DROP CONSTRAINT cname_carrier_line_records_line_scope_609_check",
		"ADD CONSTRAINT cname_carrier_line_records_line_scope_679_check",
		"line_scope IN ('telecom', 'unicom', 'mobile', 'overseas')",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("679 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 679", "migration_id='679_cname_line_area_scopes'",
		"ERRCODE='P6791'", "ERRCODE='P6792'", "DROP CONSTRAINT cname_carrier_line_records_line_scope_679_check",
		"ADD CONSTRAINT cname_carrier_line_records_line_scope_609_check",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("679 down missing %q", fragment)
		}
	}
	want := []string{"asia"}
	for _, code := range geoareaV1Codes {
		if code != geoarea.Global {
			want = append(want, code)
		}
	}
	for name, sql := range map[string][]byte{"up": up, "down": down} {
		list := regexp.MustCompile(`line_scope IN \(('asia'[^)]*)\)`).FindStringSubmatch(string(sql))
		if list == nil {
			t.Fatalf("679 %s has no area scope list", name)
		}
		var got []string
		for _, item := range strings.Split(list[1], ",") {
			got = append(got, strings.Trim(strings.TrimSpace(item), "'"))
		}
		if !slices.Equal(got, want) {
			t.Fatalf("679 %s area scopes %v, want %v", name, got, want)
		}
	}
	// The province pattern of 609 is kept verbatim.
	province := regexp.MustCompile(`line_scope ~ '[^']*'`)
	if p609, err := FS.ReadFile("609_smart_schedule.up.sql"); err != nil ||
		province.FindString(string(p609)) == "" || !strings.Contains(string(up), province.FindString(string(p609))) {
		t.Fatalf("679 up must keep the 609 province pattern (%v)", err)
	}
}
