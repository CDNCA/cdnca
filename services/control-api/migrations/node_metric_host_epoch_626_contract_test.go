package migrations

import (
	"strings"
	"testing"
)

// Migration 626 (on top of 625): node metric sequences, keys and "latest" compare within the
// node's current host (host_epoch = enrollments so far - 1), so a reinstalled
// host numbering its reports from 1 again is no longer refused as stale
// (P1501). 150/320 functions stay; the triggers move to the 626 functions.
func TestNodeMetricHostEpoch626Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"626_node_metric_host_epoch.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 625", "(SELECT max(version) FROM schema_migrations) <> 625",
			"migration_id='625_market_offer_delisted_notice'", "ERRCODE='P6260'", "ADD COLUMN host_epoch integer NOT NULL DEFAULT 0",
			"PRIMARY KEY (event_id, host_epoch)", "UNIQUE (node_id, host_epoch, publication_sequence)",
			"issuance_kind = 'initial'", "host_epoch = NEW.host_epoch AND", "ERRCODE = 'P1501'",
			"DROP TRIGGER node_metric_sequence_guard_150", "EXECUTE FUNCTION guard_node_metric_sequence_626()",
			"DROP TRIGGER node_metric_samples_retention_320", "EXECUTE FUNCTION guard_retention_delete_node_metric_626()",
			"(newer.host_epoch, newer.publication_sequence) > (OLD.host_epoch, OLD.publication_sequence)",
			"CREATE OR REPLACE VIEW node_metric_latest", "CREATE OR REPLACE VIEW node_recovery_latest",
			"CREATE OR REPLACE VIEW node_load_latest", "ORDER BY node_id, host_epoch DESC, publication_sequence DESC;",
		}, []string{"DROP FUNCTION", "UPDATE node_metric_samples", "DELETE FROM", "DISABLE TRIGGER"}},
		{"626_node_metric_host_epoch.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 626", "migration_id='626_node_metric_host_epoch'",
			"ERRCODE='P6261'", "WHERE host_epoch <> 0", "ERRCODE='P6262'",
			"EXECUTE FUNCTION guard_node_metric_sequence_150()", "EXECUTE FUNCTION guard_retention_delete_node_metric_320()",
			"DROP FUNCTION guard_node_metric_sequence_626()", "DROP FUNCTION guard_retention_delete_node_metric_626()",
			"PRIMARY KEY (event_id)", "UNIQUE (node_id, publication_sequence)", "DROP COLUMN host_epoch",
			"ORDER BY node_id, publication_sequence DESC;",
		}, []string{"guard_node_metric_sequence_150() CASCADE", "DELETE FROM", "host_epoch DESC"}},
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
