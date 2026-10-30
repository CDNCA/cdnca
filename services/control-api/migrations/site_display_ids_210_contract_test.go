package migrations

import (
	"strings"
	"testing"
)

func TestSiteDisplayIDs210Contract(t *testing.T) {
	up, err := FS.ReadFile("210_site_display_ids.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("210_site_display_ids.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"site_display_id_sequences",
		"ADD COLUMN display_id bigint",
		"PARTITION BY scope_id ORDER BY created_at, id",
		"ALTER COLUMN display_id SET NOT NULL",
		"UNIQUE (scope_id,display_id)",
		"CHECK (display_id > 0)",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"DROP COLUMN display_id",
		"DROP TABLE site_display_id_sequences",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("down migration missing %q", required)
		}
	}
}
