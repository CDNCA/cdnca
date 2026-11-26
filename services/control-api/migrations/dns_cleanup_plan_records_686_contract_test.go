package migrations

import (
	"strings"
	"testing"
)

// Migration 686: 清除CDN无关解析 stores the full
// record (canonical owner, type, value, provider record ID) of each item next
// to the item, on the exact verified 685 head; rows go with their item; down
// drops the table.
func TestDNSCleanupPlanRecords686Contract(t *testing.T) {
	up, err := FS.ReadFile("686_dns_cleanup_plan_records.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("686_dns_cleanup_plan_records.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations, background_job_items IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 685", "(SELECT max(version) FROM schema_migrations) <> 685",
		"migration_id='685_registration_proof_consumed_digest_index'",
		"to_regclass(current_schema() || '.dns_cleanup_plan_records') IS NOT NULL", "ERRCODE='P6860'",
		"CREATE TABLE dns_cleanup_plan_records (",
		"owner_name = lower(owner_name) AND right(owner_name, 1) = '.'",
		"record_type IN ('A', 'AAAA', 'CNAME')",
		"PRIMARY KEY (tenant_id, job_id, item_id)",
		"REFERENCES background_job_items(tenant_id, job_id, item_id) ON DELETE CASCADE",
		"GRANT SELECT, INSERT ON dns_cleanup_plan_records TO cdnca_control_app, cdnca_control_runtime;",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("686 up missing %q", fragment)
		}
	}
	if strings.Contains(string(up), "INSERT INTO") || strings.Contains(string(up), "UPDATE ") {
		t.Error("686 up must not backfill plans created before it")
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 686", "migration_id='686_dns_cleanup_plan_records'",
		"ERRCODE='P6861'", "DROP TABLE dns_cleanup_plan_records;",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("686 down missing %q", fragment)
		}
	}
}
