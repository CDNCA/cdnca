package migrations

import (
	"strings"
	"testing"
)

// Migration 640 (predecessor 639_probe_dnspup_unified): two more
// node_scheduling_write_requests operations and one DNS hub batch idempotency table. Down restores the
// 233 operation list after deleting the idempotency rows of the new operations (trigger paused).
func TestLineGroupDNSHubBatchIdempotency640Contract(t *testing.T) {
	read := func(direction string) string {
		body, err := FS.ReadFile("640_line_group_dnshub_batch_idempotency." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("up"), read("down")
	for _, fragment := range []string{
		"ERRCODE='P6400'", "migration_id='639_probe_dnspup_unified'",
		"to_regclass(current_schema() || '.tenant_dns_record_batch_requests') IS NOT NULL",
		"'node_scheduling.group.platform_default',\n        'node_scheduling.group.smart_schedule'\n    ));",
		"CREATE TABLE tenant_dns_record_batch_requests",
		"PRIMARY KEY (scope_id, actor_user_id, idempotency_key)",
		"request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$')",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("640 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{"ERRCODE='P6401'",
		"migration_id='640_line_group_dnshub_batch_idempotency'", "DROP TABLE tenant_dns_record_batch_requests",
		"'node_scheduling.target_snapshot.create'\n    ));",
		"DISABLE TRIGGER node_scheduling_write_requests_state;\nDELETE FROM node_scheduling_write_requests\nWHERE operation IN ('node_scheduling.group.platform_default', 'node_scheduling.group.smart_schedule');\nALTER TABLE node_scheduling_write_requests ENABLE TRIGGER node_scheduling_write_requests_state;"} {
		if !strings.Contains(down, fragment) {
			t.Errorf("640 down missing %q", fragment)
		}
	}
	if strings.Contains(down, "'node_scheduling.group.platform_default',\n") {
		t.Error("640 down must restore the 233 operation list")
	}
	for _, forbidden := range []string{"DELETE FROM", "UPDATE ", "INSERT INTO", "DISABLE TRIGGER"} {
		if strings.Contains(up, forbidden) {
			t.Errorf("640 must not contain %q", forbidden)
		}
	}
}
