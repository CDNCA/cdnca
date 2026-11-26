package migrations

import (
	"strings"
	"testing"
)

// Migration 697: on the
// exact verified 696 head, analytics_log_export_downloads_v1 keeps one
// append-only row per successful export download (consumed grants are cleaned
// up after 5 minutes), backfilled from the success download audit including
// the archive; down drops the table.
func TestAnalyticsLogExportDownloads697Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("697_analytics_log_export_downloads.up.sql"), read("697_analytics_log_export_downloads.down.sql")
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations, analytics_log_exports_v1 IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 696", "(SELECT max(version) FROM schema_migrations) <> 696",
		"migration_id='696_origin_failover_hold_template'",
		"to_regclass(current_schema() || '.analytics_log_export_downloads_v1') IS NOT NULL", "ERRCODE='P6970'",
		"CREATE TABLE analytics_log_export_downloads_v1 (",
		"export_id uuid NOT NULL REFERENCES analytics_log_exports_v1(id) ON DELETE RESTRICT",
		"ON analytics_log_export_downloads_v1(export_id,downloaded_at DESC,id DESC)",
		"BEFORE UPDATE OR DELETE ON analytics_log_export_downloads_v1",
		"BEFORE TRUNCATE ON analytics_log_export_downloads_v1",
		"EXECUTE FUNCTION prevent_analytics_log_export_fact_mutation_132()",
		"FROM audit_events\n    WHERE action='analytics_log.export.download' AND resource_type='analytics_log_export' AND result='success'",
		"FROM audit_event_archive\n    WHERE action='analytics_log.export.download' AND resource_type='analytics_log_export' AND result='success'",
		"JOIN analytics_log_exports_v1 request ON request.id::text=event.resource_id",
		"ON CONFLICT (id) DO NOTHING;",
		"GRANT SELECT, INSERT ON analytics_log_export_downloads_v1 TO cdnca_control_app, cdnca_control_runtime;",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("697 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 697", "migration_id='697_analytics_log_export_downloads'",
		"ERRCODE='P6971'", "DROP TABLE analytics_log_export_downloads_v1;",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("697 down missing %q", fragment)
		}
	}
}
