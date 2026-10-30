package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAnalyticsAccessSourceWindowContributions208Contract(t *testing.T) {
	up, err := FS.ReadFile("208_analytics_access_source_window_contributions.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("208_analytics_access_source_window_contributions.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"version=207 AND migration_id='207_account_order_records'",
		"ADD CONSTRAINT analytics_history_streams_epoch_installation_208_key",
		"CREATE TABLE analytics_access_source_window_contributions_208",
		"REFERENCES analytics_ingest_receipts(history_epoch,stream_sequence) ON DELETE RESTRICT",
		"FOREIGN KEY(history_epoch,installation_id)",
		"REFERENCES analytics_history_streams(history_epoch,installation_id) ON DELETE RESTRICT",
		"FOREIGN KEY(scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT",
		"FOREIGN KEY(scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT",
		"source_watermark numeric(20,0) NOT NULL",
		"finalized_through=window_end",
		"dependency_state='ready'",
		"evidence_sha256<>decode(repeat('00',32),'hex')",
		"analytics_access_source_window_contributions_208_immutable",
		"analytics_access_source_window_contributions_208_no_truncate",
		"final source-window facts remain in migration 184",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("migration 208 up missing %q", required)
		}
	}
	if strings.Contains(string(up), "INSERT INTO analytics_realtime_source_windows_184") ||
		strings.Contains(string(up), "UPDATE analytics_realtime_source_windows_184") {
		t.Fatal("migration 208 mutates immutable finalized source-window facts")
	}
	digest := sha256.Sum256(up)
	for _, required := range []string{
		"version=208 AND migration_id='208_analytics_access_source_window_contributions'",
		hex.EncodeToString(digest[:]),
		"rollback would discard access source window contributions",
		"DROP TABLE analytics_access_source_window_contributions_208",
		"DROP CONSTRAINT analytics_history_streams_epoch_installation_208_key",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("migration 208 down missing %q", required)
		}
	}
}
