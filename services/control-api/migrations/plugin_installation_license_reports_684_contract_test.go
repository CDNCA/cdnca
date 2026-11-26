package migrations

import (
	"strings"
	"testing"
)

// Migration 684: an append-only acknowledgement per plugin installation receipt the license
// service signed for, on the exact verified 683 head. Receipts older than the license's 30-day acceptance window
// are backfilled as acknowledged; recent ones are left for one replay. A failed background report backs off its own
// authorization only (attempts table). Down drops both tables again.
func TestPluginInstallationLicenseReports684Contract(t *testing.T) {
	up, err := FS.ReadFile("684_plugin_installation_license_reports.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("684_plugin_installation_license_reports.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations, plugin_installation_receipts IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 683", "(SELECT max(version) FROM schema_migrations) <> 683",
		"migration_id='683_login_captcha_binding'", "ERRCODE='P6840'",
		"receipt_id uuid PRIMARY KEY REFERENCES plugin_installation_receipts(id) ON DELETE RESTRICT",
		"lifecycle_revision IS NULL OR lifecycle_revision > 0",
		"BEFORE UPDATE OR DELETE ON plugin_installation_license_reports", "ERRCODE = 'P6841'",
		"receipt.occurred_at < transaction_timestamp() - interval '30 days'",
		"CREATE TABLE plugin_installation_license_report_attempts",
		"receipt_id uuid PRIMARY KEY REFERENCES plugin_installation_receipts(id) ON DELETE RESTRICT,\n    failures integer NOT NULL CHECK (failures > 0)",
		"next_attempt_at timestamptz NOT NULL CHECK (next_attempt_at >= last_attempted_at)",
		"REVOKE ALL ON plugin_installation_license_report_attempts FROM PUBLIC",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("684 up missing %q", fragment)
		}
	}
	if strings.Contains(string(up), "UPDATE plugin_installation_receipts") || strings.Contains(string(up), "DELETE FROM") {
		t.Error("684 up must not rewrite receipts")
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 684", "migration_id='684_plugin_installation_license_reports'",
		"ERRCODE='P6842'", "DROP TABLE plugin_installation_license_report_attempts", "DROP TABLE plugin_installation_license_reports",
		"DROP FUNCTION protect_plugin_installation_license_report_684()",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("684 down missing %q", fragment)
		}
	}
}
