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
