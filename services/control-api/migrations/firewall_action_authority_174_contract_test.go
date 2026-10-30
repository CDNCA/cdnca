package migrations

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFirewallActionAuthority174Contract(t *testing.T) {
	up, err := FS.ReadFile("174_firewall_action_authority.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("174_firewall_action_authority.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	wantUpSHA := sha256.Sum256(up)
	for _, required := range [][]byte{
		[]byte("migration 174 requires the exact verified 173 release head"),
		[]byte("firewall_action_policy_heads"),
		[]byte("firewall_action_policy_revisions"),
		[]byte("firewall_action_write_receipts"),
		[]byte("firewall_action_publication_outbox"),
		[]byte("candidate must preserve active LKG"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("up migration missing %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte("migration 174 rollback requires the exact verified 174 head"),
		[]byte(hex.EncodeToString(wantUpSHA[:])),
		[]byte("migration 174 rollback would discard firewall action facts"),
		[]byte("DROP TRIGGER firewall_action_outbox_no_truncate_174"),
		[]byte("DROP CONSTRAINT firewall_action_policy_heads_current_revision_174"),
		[]byte("DROP TABLE firewall_action_policy_heads"),
	} {
		if !bytes.Contains(down, required) {
			t.Fatalf("down migration missing %q", required)
		}
	}
	if bytes.Contains(down, []byte("DELETE FROM schema_migrations")) ||
		bytes.Contains(down, []byte("DROP PERMISSION")) || bytes.Contains(down, []byte("DELETE FROM permissions")) {
		t.Fatal("rollback must retain the ledger and existing firewall permissions")
	}
}
