package migrations

import (
	"strings"
	"testing"
)

func TestL4ForwardDisplayIDs214Contract(t *testing.T) {
	upBytes, err := FS.ReadFile("214_l4_forward_display_ids.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := FS.ReadFile("214_l4_forward_display_ids.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"version=213 AND migration_id='213_certificate_cache_display_ids'",
		"checksum_sha256='d09c119ca14d7f0363ebbfa55b6440aaa234f751f2316847028a7d2723eeacc8'",
		"down_checksum_sha256='ddcb4224072b95ef397cd136b17c3e8c293a013406af477e34edcbef6f46198c'",
		"CREATE TABLE l4_forward_display_id_sequences",
		"ALTER TABLE l4_forwards ADD COLUMN display_id bigint",
		"DISABLE TRIGGER l4_forwards_bump_edge_configuration_revision",
		"PARTITION BY scope_id ORDER BY created_at,id",
		"jsonb_build_object('display_id',forward.display_id::text)",
		"ENABLE TRIGGER l4_forwards_bump_edge_configuration_revision",
		"l4_forwards_scope_display_id_unique UNIQUE(scope_id,display_id)",
		"allocate_l4_forward_display_id_214", "protect_l4_forward_display_id_214",
		"NEW.display_id IS DISTINCT FROM OLD.display_id",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"version=214 AND migration_id='214_l4_forward_display_ids'",
		"response_body=response_body-'display_id'",
		"DROP COLUMN display_id", "DROP TABLE l4_forward_display_id_sequences",
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
