package firewallactioncontrol

import (
	"os"
	"strings"
	"testing"
)

func TestMigration174Contract(t *testing.T) {
	up, err := os.ReadFile("../../migrations/174_firewall_action_authority.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../migrations/174_firewall_action_authority.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"firewall_action_policy_heads", "firewall_action_policy_revisions", "firewall_action_write_receipts",
		"firewall_action_publication_outbox", "lkg_revision", "document_sha256", "idempotency_key",
		"document_bytes", "claim_expires_at",
		"firewall.read", "firewall.manage", "prevent_firewall_action_fact_mutation_174", "version=173",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("up migration missing %q", fragment)
		}
	}
	for _, fragment := range []string{"version=174", "rollback would discard firewall action facts", "DROP TABLE firewall_action_policy_heads"} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("down migration missing %q", fragment)
		}
	}
}

// migration 606 (was 608): enabled column, a guard that only lets enabled change alone,
// and the edge publication filter.
func TestMigration608Contract(t *testing.T) {
	up, err := os.ReadFile("../../migrations/606_firewall_action_enabled.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../migrations/606_firewall_action_enabled.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"ADD COLUMN enabled boolean NOT NULL DEFAULT true", "guard_firewall_action_head_606", "DROP TRIGGER firewall_action_head_guard_174",
		"ERRCODE='P6060'", "ERRCODE='P6061'", "(SELECT max(version) FROM schema_migrations) <> 605",
		// 前驱 605的真实 up/down sha；启停须保持 605 的 inherited。
		"migration_id='605_firewall_action_tenant_default'",
		"checksum_sha256='8cc0b9a80c8ad9d4376442823b43ec161cc206f70c0a5a5324ab9db70d73294e'",
		"down_checksum_sha256='5897c4abd70d72b2bac1483f3384b48716cee48d3d5f411b19db24aa65934d4f'",
		"NEW.deployment_state,NEW.inherited)",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("up migration missing %q", fragment)
		}
	}
	for _, fragment := range []string{"migration_id='606_firewall_action_enabled'", "WHERE NOT enabled", "CREATE TRIGGER firewall_action_head_guard_174", "DROP COLUMN enabled"} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("down migration missing %q", fragment)
		}
	}
}
