package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	nodeMetrics149UpSHA256   = "32099eee305e8bd90c0b4e86392b3b7859267f9d9dd4aa5c379c8b6d1d028336"
	nodeMetrics149DownSHA256 = "465b9544a68a59997217e1e24b9154637fcf463afc838cb14211c0e2dc3dac90"
)

func TestNODE01NodeMetrics150Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("150_node_metrics.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("150_node_metrics.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 150 requires the exact verified 149 release head",
		"version = 149 AND migration_id = '149_api_key_pepper_rotation'",
		nodeMetrics149UpSHA256, nodeMetrics149DownSHA256,
		"CREATE TABLE node_metric_samples", "UNIQUE (node_id, publication_sequence)",
		"UNIQUE (puback_stream, puback_sequence)", "metrics_known boolean NOT NULL",
		"cpu_percent IS NULL", "memory_used_bytes IS NULL", "memory_total_bytes IS NULL",
		"active_connections IS NULL", "rx_bandwidth_bps IS NULL", "tx_bandwidth_bps IS NULL",
		"guard_node_metric_sequence_150", "node metric publication sequence is stale",
		"node metric samples are append-only", "CREATE VIEW node_metric_latest",
		"ORDER BY node_id, publication_sequence DESC", "REVOKE ALL ON node_metric_samples",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("150 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 150 requires the exact verified 149 release head"), strings.Index(up, "CREATE TABLE node_metric_samples"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("150 predecessor guard must run before the first mutation")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 150 rollback requires the exact verified 150 head",
		"version = 150 AND migration_id = '150_node_metrics'", upSHA,
		"migration 150 rollback would discard durable node metric samples",
		"DROP VIEW node_metric_latest", "DROP TABLE node_metric_samples",
		"version = 149 AND migration_id = '149_api_key_pepper_rotation'",
		nodeMetrics149UpSHA256, nodeMetrics149DownSHA256,
	} {
		if !strings.Contains(down, required) {
			t.Errorf("150 down missing %q", required)
		}
	}
	if guard, mutation := strings.Index(down, "migration 150 rollback requires the exact verified 150 head"), strings.Index(down, "DROP VIEW"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("150 rollback guard must run before the first mutation")
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "CASCADE", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("150 migration contains forbidden marker %q", forbidden)
		}
	}
}
