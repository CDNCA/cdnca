package migrations

import (
	"strings"
	"testing"
)

func TestNodeLineGroupDisplayIDs215Contract(t *testing.T) {
	upBytes, err := FS.ReadFile("215_node_line_group_display_ids.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := FS.ReadFile("215_node_line_group_display_ids.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"version=214 AND migration_id='214_l4_forward_display_ids'",
		"checksum_sha256='0e9a89ca9fc14ed72d72d937e19c166d8c3de6e2c2daca12d23924515186063e'",
		"down_checksum_sha256='07055d134e57886af3a1597da91346dd416ca163c9ef6a7cdc52c0ad77d1e673'",
		"CREATE TABLE node_line_group_display_id_sequences",
		"ALTER TABLE node_line_groups ADD COLUMN display_id bigint",
		"PARTITION BY tenant_scope_id ORDER BY created_at,id",
		"node_line_groups_scope_display_id_unique UNIQUE(tenant_scope_id,display_id)",
		"allocate_node_line_group_display_id_215", "protect_node_line_group_display_id_215",
		"NEW.display_id IS DISTINCT FROM OLD.display_id",
		"'{group,display_id}'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"version=215 AND migration_id='215_node_line_group_display_ids'",
		"#- '{group,display_id}'",
		"DROP COLUMN display_id", "DROP TABLE node_line_group_display_id_sequences",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("down migration missing %q", required)
		}
	}
	combined := strings.ToUpper(up + down)
	for _, forbidden := range []string{
		" CASCADE", "TRUNCATE", "DROP SCHEMA", "DELETE FROM SCHEMA_MIGRATIONS",
		"__UP_SHA256__", "__DOWN_SHA256__",
	} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration contains forbidden token %q", forbidden)
		}
	}
}
