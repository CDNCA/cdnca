package migrations

import (
	"strings"
	"testing"
)

func TestNodeDisplayIDs211Contract(t *testing.T) {
	upBytes, err := FS.ReadFile("211_node_display_ids.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := FS.ReadFile("211_node_display_ids.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"version=210 AND migration_id='210_site_display_ids'",
		"checksum_sha256='50bab1bb882ec577b5248ebd5e4bbca44a8daa6c843a22a3713a3cfb4b47d83e'",
		"down_checksum_sha256='5cd72bd4d48abe99d06fb1a3c3261b3b7c92d49283590f3d502ac82404ddb964'",
		"node_display_id_sequences",
		"ADD COLUMN display_id bigint",
		"PARTITION BY scope_id ORDER BY created_at, id",
		"WHERE scope.kind='platform'",
		"ALTER COLUMN display_id SET NOT NULL",
		"UNIQUE (scope_id,display_id)",
		"CHECK (display_id > 0)",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"version=211 AND migration_id='211_node_display_ids'",
		"DROP COLUMN display_id",
		"DROP TABLE node_display_id_sequences",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("down migration missing %q", required)
		}
	}
	combined := strings.ToUpper(up + down)
	for _, forbidden := range []string{" CASCADE", "TRUNCATE", "DROP SCHEMA", "DELETE FROM SCHEMA_MIGRATIONS", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration contains forbidden token %q", forbidden)
		}
	}
}
