package migrations

import (
	"strings"
	"testing"
)

// Migration 609: line-group smart scheduling settings,
// minute latency samples, ingest cursors, per-line selections and province
// line scopes on cname_carrier_line_records. Predecessor pinned by checksum
// (renum-one.sh rewrites the const values on merge).
const (
	smartSchedule609PreviousID   = "608_node_ssh_access"
	smartSchedule609PreviousUp   = "bddca0189e651b9a1a2ec502517d74561a064268fa62682965416fee7beb1263"
	smartSchedule609PreviousDown = "e2114a38aba9485d1ae854428fc1bde19086b18e29cfe8d8d68ba80d6e37483d"
)

func TestSmartSchedule609Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"609_smart_schedule.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 608", "(SELECT max(version) FROM schema_migrations) <> 608",
			"migration_id='" + smartSchedule609PreviousID + "'",
			"checksum_sha256='" + smartSchedule609PreviousUp + "'",
			"down_checksum_sha256='" + smartSchedule609PreviousDown + "'",
			"ERRCODE='P6090'", "CREATE TABLE node_line_group_smart_schedules",
			"enabled boolean NOT NULL DEFAULT false", "top_n smallint NOT NULL DEFAULT 3 CHECK (top_n BETWEEN 1 AND 20)",
			"granularity IN ('carrier', 'province_carrier')", "latency_window_minutes smallint NOT NULL DEFAULT 15",
			"max_load_percent smallint NOT NULL DEFAULT 85", "CREATE TABLE node_line_latency_samples",
			"source IN ('dnspup', 'peer')", "bucket = date_trunc('minute', bucket)",
			"CREATE TABLE smart_schedule_ingest_cursors", "CREATE TABLE node_line_smart_selections",
			"source IN ('latency', 'static', 'fallback')", "fallback_from IN ('', 'province_carrier', 'carrier')",
			"ON DELETE CASCADE", "cname_carrier_line_records_line_scope_609_check",
		}},
		{"609_smart_schedule.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 609", "migration_id='609_smart_schedule'",
			"ERRCODE='P6093'", "position(':' IN line_scope) > 0", "ERRCODE='P6094'",
			"DROP TABLE node_line_group_smart_schedules",
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
