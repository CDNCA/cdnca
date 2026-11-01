package migrations

import (
	"strings"
	"testing"
)

// Migration 602:
// url_auth_policies.migration_marker values drop the brand name
// (cdnfly_type_*_md5 -> legacy_type_*_md5). 030 stays byte-for-byte; 602
// drops the PG auto-named column check, rewrites stored rows and re-adds the
// check with only the new values. Predecessor 601 is pinned by checksum.
func TestURLAuthLegacyMarker602Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"602_url_auth_legacy_marker.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 601", "(SELECT max(version) FROM schema_migrations) <> 601",
			"migration_id='601_aggregated_edge_tenant_chain'",
			"checksum_sha256='376d89284298907cee97b51501691ac64e39f00d9d5f0722e2d2fa5eceaa1311'",
			"down_checksum_sha256='7327430409a8df4d9e1bc80fb8f0c7df287744afd2af53566717d9dcae4fd1bc'",
			"ERRCODE='P6020'", "conname='url_auth_policies_migration_marker_check'",
			"DROP CONSTRAINT url_auth_policies_migration_marker_check",
			"SET migration_marker = 'legacy_type_a_md5' WHERE migration_marker = 'cdnfly_type_a_md5'",
			"SET migration_marker = 'legacy_type_b_md5' WHERE migration_marker = 'cdnfly_type_b_md5'",
			"CHECK (migration_marker IN ('legacy_type_a_md5', 'legacy_type_b_md5'))",
		}, []string{"IN ('cdnfly_type_a_md5'"}},
		{"602_url_auth_legacy_marker.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 602", "migration_id='602_url_auth_legacy_marker'",
			"ERRCODE='P6021'", "DROP CONSTRAINT url_auth_policies_migration_marker_check",
			"SET migration_marker = 'cdnfly_type_a_md5' WHERE migration_marker = 'legacy_type_a_md5'",
			"SET migration_marker = 'cdnfly_type_b_md5' WHERE migration_marker = 'legacy_type_b_md5'",
			"CHECK (migration_marker IN ('cdnfly_type_a_md5', 'cdnfly_type_b_md5'))",
		}, nil},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
		for _, fragment := range script.forbidden {
			if strings.Contains(string(body), fragment) {
				t.Errorf("%s must not contain %q", script.name, fragment)
			}
		}
	}
}
