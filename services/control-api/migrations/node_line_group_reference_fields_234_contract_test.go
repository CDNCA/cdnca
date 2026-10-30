package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const (
	nodeLineGroupReferenceFields234UpSHA      = "a5d30907333cf8c888f83477828c094e5b9d4a518c8ee4c56c067ed2f521b328"
	nodeLineGroupReferenceFields234DownSHA    = "13eb7df03a065c9d0208f161f9e195ac3deb82d160b38fd4fdc019aab51f426c"
	nodeLineGroupReferenceFields234ParentUp   = nodeLineGroupPlatformScopeDelete233UpSHA
	nodeLineGroupReferenceFields234ParentDown = nodeLineGroupPlatformScopeDelete233DownSHA
)

func TestNodeLineGroupReferenceFields234Contract(t *testing.T) {
	files := map[string]struct {
		name string
		sha  string
	}{
		"up":   {"234_node_line_group_reference_fields.up.sql", nodeLineGroupReferenceFields234UpSHA},
		"down": {"234_node_line_group_reference_fields.down.sql", nodeLineGroupReferenceFields234DownSHA},
	}
	contents := make(map[string]string, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read migration 234 %s: %v", label, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(payload)); got != file.sha {
			t.Fatalf("migration 234 %s checksum = %s, want %s", label, got, file.sha)
		}
		contents[label] = string(payload)
	}

	up := contents["up"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 233",
		"version = 233 AND migration_id = '233_node_line_group_platform_scope_delete'",
		nodeLineGroupReferenceFields234ParentUp,
		nodeLineGroupReferenceFields234ParentDown,
		"ADD COLUMN ipv4_resolved_value text NOT NULL DEFAULT ''",
		"ADD COLUMN l2_config_id uuid",
		"ADD COLUMN failover_mode text NOT NULL DEFAULT 'primary_offline'",
		"'v4-' || replace(id::text, '-', '')",
		"'v4-' || replace(line_group_id::text, '-', '')",
		"node_line_groups_scope_ipv4_resolved_value_unique_234",
		"FOREIGN KEY (tenant_scope_id, l2_config_id)",
		"failover_mode IN ('primary_offline', 'online_less_than_backup_count', 'interval')",
		"CREATE FUNCTION assert_node_line_group_reference_234()",
		"FOR KEY SHARE",
		"node_line_groups_reference_insert_234",
		"node_line_groups_reference_update_234",
		"USING ERRCODE = 'P2342'",
		"'ipv4_resolved_value', revision.ipv4_resolved_value",
		"?& ARRAY['ipv4_resolved_value', 'l2_config_id', 'failover_mode']",
		"USING ERRCODE = 'P2343'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("migration 234 up is missing %q", required)
		}
	}

	down := contents["down"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 234",
		"version = 234 AND migration_id = '234_node_line_group_reference_fields'",
		nodeLineGroupReferenceFields234UpSHA,
		"migration 234 rollback cannot represent custom IPv4 resolution, L2 references, or failover modes",
		"USING ERRCODE = 'P2341'",
		"#- '{group,ipv4_resolved_value}'",
		"DROP TRIGGER node_line_groups_reference_insert_234",
		"DROP TRIGGER node_line_groups_reference_update_234",
		"DROP FUNCTION assert_node_line_group_reference_234()",
		"DROP INDEX node_line_groups_scope_ipv4_resolved_value_unique_234",
		"DROP CONSTRAINT node_line_group_revisions_l2_scope_234_fk",
		"DROP CONSTRAINT node_line_groups_l2_scope_234_fk",
		"DROP COLUMN ipv4_resolved_value",
		"IF NEW.resolved_value IS NULL OR NEW.resolved_value = '' THEN",
		"snapshot_resolved_value IS DISTINCT FROM NEW.resolved_value",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("migration 234 down is missing %q", required)
		}
	}

	combined := strings.ToUpper(up + down)
	for _, forbidden := range []string{
		" CASCADE", "DELETE FROM SCHEMA_MIGRATIONS", "DROP SCHEMA", "__UP_SHA256__", "__DOWN_SHA256__",
	} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration 234 contains forbidden token %q", forbidden)
		}
	}
	if guard, mutation := strings.Index(down, "migration 234 rollback requires the exact verified 234 head"),
		strings.Index(down, "ALTER TABLE node_scheduling_write_requests DISABLE TRIGGER"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("migration 234 rollback guards must run before the first rollback mutation")
	}
}
