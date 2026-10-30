package migrations

import (
	"strings"
	"testing"
)

// Migration 554 (fix-codexd2, L08): persistent usage report sequence and the
// one unconfirmed report per installation. The 551 predecessor is pinned by
// checksum (re-pinned to 553 when 547–553 merge).
func TestUsageReportState552Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"552_usage_report_state.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 551", "(SELECT max(version) FROM schema_migrations) <> 551",
			"migration_id='551_certificate_asset_disabled'",
			"checksum_sha256='0584ec0c0f862722d02c643ed15053dd81f8f88f460e9980a3a7b1c51ec4bbf0'",
			"down_checksum_sha256='c7c56bc5bf3c16b34aad054867fdbb4b4905726b657a93672023dfd5be19efd5'",
			"ERRCODE='P5520'", "CREATE TABLE control_usage_report_state", "installation_id uuid PRIMARY KEY",
			"pending_sequence = last_sequence", "REVOKE ALL ON control_usage_report_state FROM PUBLIC",
			"GRANT SELECT, INSERT, UPDATE ON control_usage_report_state TO cdnca_control_app, cdnca_control_runtime",
		}},
		{"552_usage_report_state.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 552", "migration_id='552_usage_report_state'",
			"ERRCODE='P5521'", "DROP TABLE control_usage_report_state",
		}},
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
	}
}
