package migrations

import (
	"strings"
	"testing"
)

// Migration 690: on the exact verified 689 head,
// the stored 源IP请求头 (read by nobody until now) becomes "" (direct) with
// the revision bumped; the rest of the settings row is untouched, and down
// only checks the head.
func TestSourceIPHeaderReset690Contract(t *testing.T) {
	up, err := FS.ReadFile("690_source_ip_header_reset.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("690_source_ip_header_reset.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 689", "(SELECT max(version) FROM schema_migrations) <> 689",
		"migration_id='689_certificate_publication_actor_refreshed_session'", "ERRCODE='P6908'",
		"SET settings=jsonb_set(settings, '{source_ip_header}', '\"\"'::jsonb), revision=revision+1",
		"WHERE settings ? 'source_ip_header' AND settings->'source_ip_header' IS DISTINCT FROM '\"\"'::jsonb",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("690 up missing %q", fragment)
		}
	}
	if strings.Count(string(up), "UPDATE ") != 1 || strings.Count(string(up), "jsonb_set(") != 1 ||
		strings.Contains(string(up), "DELETE FROM") || strings.Contains(string(up), "ALTER TABLE") || strings.Contains(string(up), "INSERT INTO") {
		t.Error("690 up must only reset source_ip_header")
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 690",
		"migration_id='690_source_ip_header_reset'", "ERRCODE='P6909'",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("690 down missing %q", fragment)
		}
	}
	if strings.Contains(string(down), "UPDATE ") || strings.Contains(string(down), "platform_system_other_settings") {
		t.Error("690 down must not change settings")
	}
}
