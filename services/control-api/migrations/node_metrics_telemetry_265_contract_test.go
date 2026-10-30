package migrations

import (
	"strings"
	"testing"
)

func TestNodeMetricsTelemetry265Contract(t *testing.T) {
	up, err := FS.ReadFile("265_node_metrics_telemetry.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("265_node_metrics_telemetry.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration 265 requires the exact verified 264 release head",
		"ADD COLUMN telemetry_json jsonb",
		"ADD COLUMN total_rx_bytes bigint",
		"ADD COLUMN total_tx_bytes bigint",
		"node_metric_samples_telemetry_shape_265",
		"CREATE OR REPLACE VIEW node_metric_latest",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("migration 265 up is missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 265 rollback requires the exact verified 265 release head",
		"migration 265 rollback would discard durable node telemetry",
		"DROP COLUMN telemetry_json",
		"DROP COLUMN total_rx_bytes",
		"DROP COLUMN total_tx_bytes",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("migration 265 down is missing %q", required)
		}
	}
}
