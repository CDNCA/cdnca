package migrations

import (
	"strings"
	"testing"
)

// Migration 571: line group backup IP state per address
// family and its two notifications. The 552 predecessor is pinned by checksum.
func TestNodeLineBackupStates571Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"571_node_line_backup_states.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 570", "(SELECT max(version) FROM schema_migrations) <> 570",
			"migration_id='570_certificate_renewal_delivery'",
			"checksum_sha256='1e1a5d0171c7c74c0e1071cc935aec004f3cd2d33db21ea126f6f7d9722f0e1c'",
			"down_checksum_sha256='72e84282f1dadefb541e581ee0719b7ab28f1eba8a29b26bb530fedba4ac35aa'",
			"ERRCODE='P5710'", "CREATE TABLE node_line_group_backup_states",
			"PRIMARY KEY (tenant_scope_id, line_group_id, address_family)",
			"state IN ('normal', 'backup_active')",
			"REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE CASCADE",
			"(state = 'backup_active') = (cardinality(backup_addresses) > 0)",
			"('node.line_group.backup_ip_activated', true, true, true, 1, 1, true, true, false, now())",
			"('node.line_group.primary_ip_restored', true, true, true, 1, 1, true, true, false, now())",
			"('node.line_group.backup_ip_activated.zh-cn', 1, 'sms'", "('node.line_group.backup_ip_activated.zh-cn', 1, 'email'",
			"('node.line_group.primary_ip_restored.zh-cn', 1, 'sms'", "('node.line_group.primary_ip_restored.zh-cn', 1, 'email'",
			"REVOKE ALL ON node_line_group_backup_states FROM PUBLIC",
			"GRANT SELECT, INSERT, UPDATE ON node_line_group_backup_states TO cdnca_control_app, cdnca_control_runtime",
		}},
		{"571_node_line_backup_states.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 571", "migration_id='571_node_line_backup_states'",
			"ERRCODE='P5711'", "ERRCODE='P5712'", "DELETE FROM notification_event_policies",
			"DELETE FROM admin_inbox_messages", "DROP TABLE node_line_group_backup_states",
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
